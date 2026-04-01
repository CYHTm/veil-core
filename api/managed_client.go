// Package api — managed_client.go is the production-ready client.
// It wraps the base Client with:
//   - Automatic reconnection with exponential backoff
//   - Graceful shutdown of all streams
//   - Timeout enforcement on every operation
//   - Panic recovery in all goroutines
//   - Leveled logging
//   - Connection health monitoring
package api

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/veil-protocol/veil-core/mux"
)

// ManagedClient is the production client with reconnect, timeouts, recovery.
type ManagedClient struct {
	mu          sync.RWMutex
	config      ClientConfig
	base        *Client
	reconnector *Reconnector
	shutdown    *GracefulShutdown
	timeouts    Timeouts
	logger      *Logger
	events      *EventBus

	connected   int32
	socksLn     net.Listener
	dnsProxy    *DNSProxy
	ctx         context.Context
	cancel      context.CancelFunc

	totalBytes  int64
	activeConns int64
}

// ManagedClientConfig extends ClientConfig with reliability options.
type ManagedClientConfig struct {
	ClientConfig
	Reconnect ReconnectPolicy
	Timeouts  Timeouts
	LogLevel  LogLevel
}

// DefaultManagedConfig returns production-ready configuration.
func DefaultManagedConfig() ManagedClientConfig {
	return ManagedClientConfig{
		ClientConfig: DefaultClientConfig(),
		Reconnect:    DefaultReconnectPolicy(),
		Timeouts:     DefaultTimeouts(),
		LogLevel:     LogInfo,
	}
}

// NewManagedClient creates a production-ready client.
func NewManagedClient(cfg ManagedClientConfig) (*ManagedClient, error) {
	if cfg.ServerAddr == "" || cfg.Secret == "" {
		return nil, fmt.Errorf("veil: server and secret are required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	mc := &ManagedClient{
		config:   cfg.ClientConfig,
		timeouts: cfg.Timeouts,
		logger:   NewLogger("[veil] ", cfg.LogLevel),
		events:   NewEventBus(256),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Setup reconnector
	mc.reconnector = NewReconnector(cfg.Reconnect)
	mc.reconnector.SetHandlers(
		func() error {
			mc.logger.Info("reconnecting to %s...", cfg.ServerAddr)
			return mc.connectInternal()
		},
		func(attempt int, delay time.Duration, err error) {
			if err != nil {
				mc.logger.Warn("reconnect attempt %d failed: %v (next in %v)", attempt, err, delay)
				mc.events.Emit(Event{Type: EventError, Error: err,
					Message: fmt.Sprintf("reconnect attempt %d failed", attempt)})
			} else if delay > 0 {
				mc.logger.Info("reconnect attempt %d in %v...", attempt, delay)
			}
		},
	)

	// Setup graceful shutdown
	mc.shutdown = NewGracefulShutdown(10 * time.Second)
	mc.shutdown.Register("dns", 0, func(ctx context.Context) error {
		if mc.dnsProxy != nil {
			mc.dnsProxy.Close()
		}
		return nil
	})

	mc.shutdown.Register("socks", 1, func(ctx context.Context) error {
		mc.mu.Lock()
		if mc.socksLn != nil {
			mc.socksLn.Close()
		}
		mc.mu.Unlock()
		return nil
	})
	mc.shutdown.Register("session", 2, func(ctx context.Context) error {
		mc.mu.Lock()
		base := mc.base
		mc.mu.Unlock()
		if base != nil {
			return base.Close()
		}
		return nil
	})
	mc.shutdown.Register("reconnector", 3, func(ctx context.Context) error {
		mc.reconnector.Stop()
		return nil
	})
	mc.shutdown.Register("events", 4, func(ctx context.Context) error {
		mc.events.Close()
		return nil
	})

	return mc, nil
}

// Events returns the event bus.
func (mc *ManagedClient) Events() *EventBus {
	return mc.events
}

// Logger returns the logger.
func (mc *ManagedClient) Log() *Logger {
	return mc.logger
}

// Connect establishes connection with timeout.
func (mc *ManagedClient) Connect() error {
	ctx, cancel := context.WithTimeout(mc.ctx, mc.timeouts.Connect)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		PanicRecovery("connect", mc.logger, func() {
			errCh <- mc.connectInternal()
		})
	}()

	select {
	case err := <-errCh:
		if err != nil {
			errClass := ClassifyError(err)
			if errClass == ErrTransient {
				mc.logger.Info("connection failed (transient), will reconnect: %v", err)
				mc.reconnector.Trigger()
			} else {
				mc.logger.Error("connection failed (permanent): %v", err)
			}
			return err
		}
		mc.reconnector.Reset()
		return nil
	case <-ctx.Done():
		return fmt.Errorf("connect timeout after %v", mc.timeouts.Connect)
	}
}

func (mc *ManagedClient) connectInternal() error {
	mc.config.OnDisconnect = func(err error) {
		atomic.StoreInt32(&mc.connected, 0)
		mc.events.Emit(Event{Type: EventDisconnected, Error: err})
		mc.logger.Warn("disconnected: %v", err)

		// Classify and maybe reconnect
		if ClassifyError(err) == ErrTransient {
			mc.reconnector.Trigger()
		}
	}

	client, err := NewClient(mc.config)
	if err != nil {
		return err
	}

	if err := client.Connect(); err != nil {
		return err
	}

	mc.mu.Lock()
	mc.base = client
	mc.mu.Unlock()

	atomic.StoreInt32(&mc.connected, 1)
	mc.events.Emit(Event{Type: EventConnected})
	mc.logger.Info("connected to %s", mc.config.ServerAddr)

	return nil
}

// OpenStream opens a stream with timeout.
func (mc *ManagedClient) OpenStream(target string) (*mux.Stream, error) {
	if atomic.LoadInt32(&mc.connected) == 0 {
		return nil, fmt.Errorf("not connected")
	}

	mc.mu.RLock()
	base := mc.base
	mc.mu.RUnlock()

	if base == nil {
		return nil, fmt.Errorf("not connected")
	}

	type streamResult struct {
		stream *mux.Stream
		err    error
	}

	ch := make(chan streamResult, 1)
	go func() {
		PanicRecovery("open-stream", mc.logger, func() {
			s, err := base.OpenStream(target)
			ch <- streamResult{s, err}
		})
	}()

	select {
	case r := <-ch:
		return r.stream, r.err
	case <-time.After(mc.timeouts.StreamOpen):
		return nil, fmt.Errorf("stream open timeout after %v", mc.timeouts.StreamOpen)
	}
}

// IsConnected returns true if actively connected.
func (mc *ManagedClient) IsConnected() bool {
	return atomic.LoadInt32(&mc.connected) == 1
}

// Close gracefully shuts down everything.
func (mc *ManagedClient) Close() error {
	mc.cancel()

	mc.logger.Info("shutting down...")
	errs := mc.shutdown.Execute()

	if len(errs) > 0 {
		mc.logger.Warn("shutdown had %d errors", len(errs))
	}

	mc.logger.Info("shutdown complete")
	return nil
}

// Stats returns current statistics.
func (mc *ManagedClient) Stats() (bytes int64, conns int64, reconnects int) {
	return atomic.LoadInt64(&mc.totalBytes),
		atomic.LoadInt64(&mc.activeConns),
		mc.reconnector.Attempt()
}

// StartDNS starts the local DNS proxy that tunnels queries through Veil.
// This prevents DNS leaks by ensuring all DNS resolution goes through the tunnel.
func (mc *ManagedClient) StartDNS(listenAddr, dnsTarget string) error {
	opener := func(target string) (io.ReadWriteCloser, error) {
		return mc.OpenStream(target)
	}

	d := NewDNSProxy(listenAddr, dnsTarget, opener, mc.logger)
	if err := d.Start(); err != nil {
		return fmt.Errorf("dns proxy: %w", err)
	}
	mc.dnsProxy = d
	return nil
}

// DNSProxy returns the DNS proxy instance (nil if not started).
func (mc *ManagedClient) DNSProxy() *DNSProxy {
	return mc.dnsProxy
}

// StartSOCKS5 starts the SOCKS5 proxy and ties it to this client.
func (mc *ManagedClient) StartSOCKS5(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}

	mc.mu.Lock()
	mc.socksLn = ln
	mc.mu.Unlock()

	mc.logger.Info("SOCKS5 proxy on %s", addr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			if !mc.IsConnected() {
				conn.Close()
				continue
			}

			go PanicRecovery("socks5-conn", mc.logger, func() {
				mc.handleSOCKS5(conn)
			})
		}
	}()

	return nil
}

func (mc *ManagedClient) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	// Set read timeout
	conn.SetDeadline(time.Now().Add(mc.timeouts.Read))

	target, err := mc.socks5Negotiate(conn)
	if err != nil {
		return
	}

	atomic.AddInt64(&mc.activeConns, 1)
	defer atomic.AddInt64(&mc.activeConns, -1)

	mc.logger.Debug("-> %s", target)

	stream, err := mc.OpenStream(target)
	if err != nil {
		mc.logger.Debug("stream failed: %v", err)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	// SOCKS5 success
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Clear deadline for proxy phase
	conn.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				atomic.AddInt64(&mc.totalBytes, int64(n))
				if _, we := conn.Write(buf[:n]); we != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				atomic.AddInt64(&mc.totalBytes, int64(n))
				if _, we := stream.Write(buf[:n]); we != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
}

func (mc *ManagedClient) socks5Negotiate(conn net.Conn) (string, error) {
	buf := make([]byte, 2)
	if _, err := readFull(conn, buf); err != nil {
		return "", err
	}
	if buf[0] != 0x05 {
		return "", fmt.Errorf("not socks5")
	}

	methods := make([]byte, buf[1])
	if _, err := readFull(conn, methods); err != nil {
		return "", err
	}
	conn.Write([]byte{0x05, 0x00})

	header := make([]byte, 4)
	if _, err := readFull(conn, header); err != nil {
		return "", err
	}
	if header[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("not CONNECT")
	}

	var addr string
	switch header[3] {
	case 0x01:
		b := make([]byte, 4)
		readFull(conn, b)
		addr = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		readFull(conn, l)
		d := make([]byte, l[0])
		readFull(conn, d)
		addr = string(d)
	case 0x04:
		b := make([]byte, 16)
		readFull(conn, b)
		addr = net.IP(b).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("unsupported address type")
	}

	p := make([]byte, 2)
	readFull(conn, p)
	port := int(p[0])<<8 | int(p[1])

	return fmt.Sprintf("%s:%d", addr, port), nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
