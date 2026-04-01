// Package api provides the high-level client and server API for Veil.
//
// This file implements a local DNS proxy that tunnels DNS queries through
// the Veil connection, preventing DNS leaks. It listens for UDP DNS queries
// locally and forwards them as DNS-over-TCP through the encrypted tunnel.
package api

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// defaultDNSTarget is the DNS server used when none is configured.
	defaultDNSTarget = "1.1.1.1:53"

	// dnsMaxSize is the maximum DNS message size we handle.
	dnsMaxSize = 4096

	// dnsStreamTimeout is the timeout for a single DNS query through the tunnel.
	dnsStreamTimeout = 5 * time.Second
)

// StreamOpener abstracts opening a tunneled stream to a target address.
// Both Client.OpenStream and ManagedClient.OpenStream satisfy this via adapter.
type StreamOpener func(target string) (io.ReadWriteCloser, error)

// DNSProxy intercepts local DNS queries and tunnels them through Veil,
// preventing DNS leaks to the local ISP.
//
// Architecture:
//
//	App DNS query (UDP) → DNSProxy (local) → Veil tunnel → Server → upstream DNS
//	                    ← DNS response (UDP) ← tunnel     ←        ←
type DNSProxy struct {
	listenAddr string
	dnsTarget  string
	opener     StreamOpener
	logger     *Logger

	conn   net.PacketConn
	mu     sync.Mutex
	closed int32 // atomic

	// Stats
	queries   int64
	succeeded int64
	failed    int64
}

// DNSStats holds DNS proxy statistics.
type DNSStats struct {
	Queries   int64
	Succeeded int64
	Failed    int64
}

// NewDNSProxy creates a DNS proxy that tunnels queries through Veil.
//
// Parameters:
//   - listenAddr: local UDP address to listen on (e.g., "127.0.0.1:5353")
//   - dnsTarget: upstream DNS server for the tunnel server to connect to (e.g., "1.1.1.1:53")
//   - opener: function to open a Veil stream to the target
//   - logger: logger instance (can be nil for silent operation)
func NewDNSProxy(listenAddr, dnsTarget string, opener StreamOpener, logger *Logger) *DNSProxy {
	if dnsTarget == "" {
		dnsTarget = defaultDNSTarget
	}
	if logger == nil {
		logger = NewLogger("dns", LogInfo)
	}
	return &DNSProxy{
		listenAddr: listenAddr,
		dnsTarget:  dnsTarget,
		opener:     opener,
		logger:     logger,
	}
}

// Start begins listening for DNS queries on the configured UDP address.
func (d *DNSProxy) Start() error {
	conn, err := net.ListenPacket("udp", d.listenAddr)
	if err != nil {
		return fmt.Errorf("dns proxy listen: %w", err)
	}
	d.conn = conn

	d.logger.Info("DNS proxy listening on %s → tunnel → %s", d.listenAddr, d.dnsTarget)

	go d.serve()
	return nil
}

// Stats returns current DNS proxy statistics.
func (d *DNSProxy) Stats() DNSStats {
	return DNSStats{
		Queries:   atomic.LoadInt64(&d.queries),
		Succeeded: atomic.LoadInt64(&d.succeeded),
		Failed:    atomic.LoadInt64(&d.failed),
	}
}

// Addr returns the actual listen address (useful when port is 0).
func (d *DNSProxy) Addr() net.Addr {
	if d.conn == nil {
		return nil
	}
	return d.conn.LocalAddr()
}

// Close stops the DNS proxy.
func (d *DNSProxy) Close() error {
	if !atomic.CompareAndSwapInt32(&d.closed, 0, 1) {
		return nil
	}
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

func (d *DNSProxy) serve() {
	buf := make([]byte, dnsMaxSize)
	for {
		n, addr, err := d.conn.ReadFrom(buf)
		if err != nil {
			if atomic.LoadInt32(&d.closed) == 1 {
				return
			}
			d.logger.Debug("dns read error: %v", err)
			continue
		}

		if n < 12 {
			// Too short to be a valid DNS message (header is 12 bytes)
			continue
		}

		query := make([]byte, n)
		copy(query, buf[:n])

		atomic.AddInt64(&d.queries, 1)
		go d.handleQuery(query, addr)
	}
}

func (d *DNSProxy) handleQuery(query []byte, clientAddr net.Addr) {
	resp, err := d.tunnelDNS(query)
	if err != nil {
		atomic.AddInt64(&d.failed, 1)
		d.logger.Debug("dns tunnel failed: %v", err)
		return
	}

	if _, err := d.conn.WriteTo(resp, clientAddr); err != nil {
		atomic.AddInt64(&d.failed, 1)
		d.logger.Debug("dns response write failed: %v", err)
		return
	}

	atomic.AddInt64(&d.succeeded, 1)
}

// tunnelDNS sends a DNS query through the Veil tunnel using DNS-over-TCP format.
//
// DNS-over-TCP prepends a 2-byte big-endian length to the raw DNS message.
// We open a stream to the upstream DNS server, send the length-prefixed query,
// read the length-prefixed response, and return the raw DNS response.
func (d *DNSProxy) tunnelDNS(query []byte) ([]byte, error) {
	// Open stream to DNS server through tunnel
	stream, err := d.opener(d.dnsTarget)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	// Set deadline if the stream supports it
	if dc, ok := stream.(interface{ SetDeadline(time.Time) error }); ok {
		dc.SetDeadline(time.Now().Add(dnsStreamTimeout))
	}

	// Write DNS-over-TCP: 2-byte length prefix + query
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(query)))
	if _, err := stream.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("write length: %w", err)
	}
	if _, err := stream.Write(query); err != nil {
		return nil, fmt.Errorf("write query: %w", err)
	}

	// Read response: 2-byte length prefix
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return nil, fmt.Errorf("read response length: %w", err)
	}
	respLen := binary.BigEndian.Uint16(lenBuf)

	if respLen == 0 || respLen > dnsMaxSize {
		return nil, fmt.Errorf("invalid response length: %d", respLen)
	}

	// Read response body
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(stream, resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return resp, nil
}
