package api

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockDNSStream simulates a Veil stream that speaks DNS-over-TCP.
// It reads a 2-byte length + query, then writes 2-byte length + response.
type mockDNSStream struct {
	reqBuf  bytes.Buffer
	respBuf bytes.Buffer
	mu      sync.Mutex
	closed  int32

	// For testing: what response to return
	response []byte
	// For testing: simulate error
	readErr  error
	writeErr error
}

func newMockDNSStream(response []byte) *mockDNSStream {
	s := &mockDNSStream{response: response}
	// Pre-fill response buffer with DNS-over-TCP format
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(response)))
	s.respBuf.Write(lenBuf)
	s.respBuf.Write(response)
	return s
}

func (s *mockDNSStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return 0, s.readErr
	}
	return s.respBuf.Read(p)
}

func (s *mockDNSStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return s.reqBuf.Write(p)
}

func (s *mockDNSStream) Close() error {
	atomic.StoreInt32(&s.closed, 1)
	return nil
}

// buildDNSQuery creates a minimal valid DNS query (just header + question).
func buildDNSQuery(id uint16, domain string) []byte {
	buf := make([]byte, 12) // DNS header
	binary.BigEndian.PutUint16(buf[0:2], id)
	buf[2] = 0x01 // RD (recursion desired)
	buf[5] = 1    // QDCOUNT = 1

	// Encode domain as DNS name
	for _, label := range splitDomain(domain) {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00)       // root label
	buf = append(buf, 0, 1)       // QTYPE = A
	buf = append(buf, 0, 1)       // QCLASS = IN
	return buf
}

func splitDomain(domain string) []string {
	var labels []string
	current := ""
	for _, c := range domain {
		if c == '.' {
			if current != "" {
				labels = append(labels, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		labels = append(labels, current)
	}
	return labels
}

// buildDNSResponse creates a minimal DNS response matching a query ID.
func buildDNSResponse(id uint16, ip net.IP) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], id)
	buf[2] = 0x81 // QR=1, RD=1
	buf[3] = 0x80 // RA=1
	buf[7] = 1    // ANCOUNT = 1

	// Minimal answer: pointer to name + A record
	buf = append(buf, 0xc0, 0x0c) // name pointer
	buf = append(buf, 0, 1)       // TYPE = A
	buf = append(buf, 0, 1)       // CLASS = IN
	buf = append(buf, 0, 0, 0, 60) // TTL = 60
	buf = append(buf, 0, 4)       // RDLENGTH = 4
	buf = append(buf, ip.To4()...)
	return buf
}

func TestDNSProxyNewDefaults(t *testing.T) {
	opener := func(target string) (io.ReadWriteCloser, error) {
		return nil, fmt.Errorf("not implemented")
	}
	d := NewDNSProxy("127.0.0.1:0", "", opener, nil)
	if d.dnsTarget != defaultDNSTarget {
		t.Fatalf("expected default DNS target %s, got %s", defaultDNSTarget, d.dnsTarget)
	}
	if d.logger == nil {
		t.Fatal("logger should not be nil")
	}
}

func TestDNSProxyCustomTarget(t *testing.T) {
	opener := func(target string) (io.ReadWriteCloser, error) {
		return nil, fmt.Errorf("not implemented")
	}
	d := NewDNSProxy("127.0.0.1:0", "8.8.8.8:53", opener, nil)
	if d.dnsTarget != "8.8.8.8:53" {
		t.Fatalf("expected 8.8.8.8:53, got %s", d.dnsTarget)
	}
}

func TestDNSProxyStartClose(t *testing.T) {
	opener := func(target string) (io.ReadWriteCloser, error) {
		return nil, fmt.Errorf("not implemented")
	}
	d := NewDNSProxy("127.0.0.1:0", "", opener, nil)
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	addr := d.Addr()
	if addr == nil {
		t.Fatal("addr should not be nil after start")
	}
	if err := d.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Double close should not error
	if err := d.Close(); err != nil {
		t.Fatalf("double close: %v", err)
	}
}

func TestDNSProxyAddrBeforeStart(t *testing.T) {
	opener := func(target string) (io.ReadWriteCloser, error) {
		return nil, fmt.Errorf("not implemented")
	}
	d := NewDNSProxy("127.0.0.1:0", "", opener, nil)
	if d.Addr() != nil {
		t.Fatal("addr should be nil before start")
	}
}

func TestDNSProxyRoundtrip(t *testing.T) {
	queryID := uint16(0x1234)
	responseIP := net.IPv4(93, 184, 216, 34)
	dnsResp := buildDNSResponse(queryID, responseIP)

	var capturedTarget string
	opener := func(target string) (io.ReadWriteCloser, error) {
		capturedTarget = target
		return newMockDNSStream(dnsResp), nil
	}

	logger := NewLogger("dns-test", LogDebug)
	d := NewDNSProxy("127.0.0.1:0", "1.1.1.1:53", opener, logger)
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer d.Close()

	// Send DNS query via UDP
	conn, err := net.Dial("udp", d.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	query := buildDNSQuery(queryID, "example.com")
	if _, err := conn.Write(query); err != nil {
		t.Fatalf("write query: %v", err)
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, dnsMaxSize)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp = resp[:n]

	// Verify response matches
	if !bytes.Equal(resp, dnsResp) {
		t.Fatalf("response mismatch:\n  got:  %x\n  want: %x", resp, dnsResp)
	}

	// Verify the stream was opened to the right target
	if capturedTarget != "1.1.1.1:53" {
		t.Fatalf("expected target 1.1.1.1:53, got %s", capturedTarget)
	}

	// Verify stats
	stats := d.Stats()
	if stats.Queries != 1 {
		t.Fatalf("expected 1 query, got %d", stats.Queries)
	}
	if stats.Succeeded != 1 {
		t.Fatalf("expected 1 succeeded, got %d", stats.Succeeded)
	}
	if stats.Failed != 0 {
		t.Fatalf("expected 0 failed, got %d", stats.Failed)
	}
}

func TestDNSProxyMultipleQueries(t *testing.T) {
	opener := func(target string) (io.ReadWriteCloser, error) {
		// Return a response with the same ID pattern from query
		resp := buildDNSResponse(0xAAAA, net.IPv4(10, 0, 0, 1))
		return newMockDNSStream(resp), nil
	}

	d := NewDNSProxy("127.0.0.1:0", "", opener, nil)
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer d.Close()

	conn, err := net.Dial("udp", d.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	for i := 0; i < 10; i++ {
		query := buildDNSQuery(0xAAAA, fmt.Sprintf("test%d.example.com", i))
		if _, err := conn.Write(query); err != nil {
			t.Fatalf("write query %d: %v", i, err)
		}

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp := make([]byte, dnsMaxSize)
		n, err := conn.Read(resp)
		if err != nil {
			t.Fatalf("read response %d: %v", i, err)
		}
		if n == 0 {
			t.Fatalf("empty response for query %d", i)
		}
	}

	stats := d.Stats()
	if stats.Queries != 10 {
		t.Fatalf("expected 10 queries, got %d", stats.Queries)
	}
	if stats.Succeeded != 10 {
		t.Fatalf("expected 10 succeeded, got %d", stats.Succeeded)
	}
}

func TestDNSProxyStreamOpenError(t *testing.T) {
	opener := func(target string) (io.ReadWriteCloser, error) {
		return nil, fmt.Errorf("tunnel down")
	}

	d := NewDNSProxy("127.0.0.1:0", "", opener, nil)
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer d.Close()

	conn, err := net.Dial("udp", d.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	query := buildDNSQuery(0x5678, "fail.example.com")
	conn.Write(query)

	// Should not get a response (or timeout)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	resp := make([]byte, dnsMaxSize)
	_, err = conn.Read(resp)
	if err == nil {
		t.Fatal("expected timeout, got response")
	}

	// Wait for async handler
	time.Sleep(100 * time.Millisecond)

	stats := d.Stats()
	if stats.Failed != 1 {
		t.Fatalf("expected 1 failed, got %d", stats.Failed)
	}
}

func TestDNSProxyTooShortQuery(t *testing.T) {
	opener := func(target string) (io.ReadWriteCloser, error) {
		return nil, fmt.Errorf("should not be called")
	}

	d := NewDNSProxy("127.0.0.1:0", "", opener, nil)
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer d.Close()

	conn, err := net.Dial("udp", d.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send packet shorter than DNS header (12 bytes)
	conn.Write([]byte{0x01, 0x02, 0x03})

	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	resp := make([]byte, dnsMaxSize)
	_, err = conn.Read(resp)
	if err == nil {
		t.Fatal("expected timeout for too-short query")
	}

	// Should not count as a query
	stats := d.Stats()
	if stats.Queries != 0 {
		t.Fatalf("expected 0 queries for short packet, got %d", stats.Queries)
	}
}

func TestDNSProxyConcurrent(t *testing.T) {
	var streamCount int64

	opener := func(target string) (io.ReadWriteCloser, error) {
		atomic.AddInt64(&streamCount, 1)
		resp := buildDNSResponse(0xBBBB, net.IPv4(10, 0, 0, 1))
		return newMockDNSStream(resp), nil
	}

	d := NewDNSProxy("127.0.0.1:0", "", opener, nil)
	if err := d.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer d.Close()

	const goroutines = 10
	const queriesPerGoroutine = 5

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*queriesPerGoroutine)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gID int) {
			defer wg.Done()
			conn, err := net.Dial("udp", d.Addr().String())
			if err != nil {
				errCh <- fmt.Errorf("g%d dial: %v", gID, err)
				return
			}
			defer conn.Close()

			for q := 0; q < queriesPerGoroutine; q++ {
				query := buildDNSQuery(0xBBBB, fmt.Sprintf("g%d-q%d.test.com", gID, q))
				if _, err := conn.Write(query); err != nil {
					errCh <- fmt.Errorf("g%d q%d write: %v", gID, q, err)
					return
				}

				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				resp := make([]byte, dnsMaxSize)
				n, err := conn.Read(resp)
				if err != nil {
					errCh <- fmt.Errorf("g%d q%d read: %v", gID, q, err)
					return
				}
				if n == 0 {
					errCh <- fmt.Errorf("g%d q%d: empty response", gID, q)
					return
				}
			}
		}(g)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}

	total := goroutines * queriesPerGoroutine
	stats := d.Stats()
	if stats.Queries != int64(total) {
		t.Fatalf("expected %d queries, got %d", total, stats.Queries)
	}
	if stats.Succeeded != int64(total) {
		t.Fatalf("expected %d succeeded, got %d", total, stats.Succeeded)
	}
}

func TestDNSProxyStatsInitial(t *testing.T) {
	opener := func(target string) (io.ReadWriteCloser, error) {
		return nil, fmt.Errorf("unused")
	}
	d := NewDNSProxy("127.0.0.1:0", "", opener, nil)
	stats := d.Stats()
	if stats.Queries != 0 || stats.Succeeded != 0 || stats.Failed != 0 {
		t.Fatalf("expected all zeros, got %+v", stats)
	}
}

func TestTunnelDNSInvalidResponseLength(t *testing.T) {
	// Create a stream that returns length=0
	opener := func(target string) (io.ReadWriteCloser, error) {
		s := &mockDNSStream{}
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, 0) // zero length = invalid
		s.respBuf.Write(lenBuf)
		return s, nil
	}

	d := NewDNSProxy("127.0.0.1:0", "", opener, nil)
	query := buildDNSQuery(0x1111, "test.com")
	_, err := d.tunnelDNS(query)
	if err == nil {
		t.Fatal("expected error for zero response length")
	}
}

func TestTunnelDNSWriteError(t *testing.T) {
	opener := func(target string) (io.ReadWriteCloser, error) {
		s := &mockDNSStream{writeErr: fmt.Errorf("broken pipe")}
		return s, nil
	}

	d := NewDNSProxy("127.0.0.1:0", "", opener, nil)
	query := buildDNSQuery(0x2222, "test.com")
	_, err := d.tunnelDNS(query)
	if err == nil {
		t.Fatal("expected error for write failure")
	}
}

func TestTunnelDNSReadError(t *testing.T) {
	opener := func(target string) (io.ReadWriteCloser, error) {
		s := &mockDNSStream{readErr: fmt.Errorf("connection reset")}
		return s, nil
	}

	d := NewDNSProxy("127.0.0.1:0", "", opener, nil)
	query := buildDNSQuery(0x3333, "test.com")
	_, err := d.tunnelDNS(query)
	if err == nil {
		t.Fatal("expected error for read failure")
	}
}
