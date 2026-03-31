package quic

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	vt "github.com/veil-protocol/veil-core/transport"
)

func TestQUICTransportID(t *testing.T) {
	tr := New()
	if tr.ID() != "quic" {
		t.Errorf("ID() = %q, want quic", tr.ID())
	}
}

func TestQUICDialListenRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := New()
	config := &vt.Config{InsecureSkipVerify: true}

	// Start listener.
	ln, err := tr.Listen(ctx, "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	t.Logf("listening on %s", addr)

	// Server goroutine: accept, echo, close.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer conn.Close()

		if conn.TransportID() != "quic" {
			t.Errorf("server TransportID = %q", conn.TransportID())
		}

		// Echo loop.
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	// Client: dial, send, receive, verify.
	conn, err := tr.Dial(ctx, addr, config)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if conn.TransportID() != "quic" {
		t.Errorf("client TransportID = %q", conn.TransportID())
	}
	if conn.LocalAddr() == nil {
		t.Error("LocalAddr is nil")
	}
	if conn.RemoteAddr() == nil {
		t.Error("RemoteAddr is nil")
	}

	// Send test data.
	msg := []byte("hello veil over quic")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if string(buf[:n]) != string(msg) {
		t.Errorf("echo mismatch: got %q, want %q", buf[:n], msg)
	}

	conn.Close()
	ln.Close()
	wg.Wait()
}

func TestQUICMultipleMessages(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := New()
	config := &vt.Config{InsecureSkipVerify: true}

	ln, err := tr.Listen(ctx, "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn) // echo
	}()

	conn, err := tr.Dial(ctx, ln.Addr().String(), config)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Send 100 messages.
	for i := 0; i < 100; i++ {
		msg := []byte("packet-data-for-quic-test")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("Read %d: %v", i, err)
		}
		if string(buf) != string(msg) {
			t.Fatalf("mismatch at %d: got %q", i, buf)
		}
	}

	conn.Close()
	ln.Close()
	wg.Wait()
}

func TestQUICLargePayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := New()
	config := &vt.Config{InsecureSkipVerify: true}

	ln, err := tr.Listen(ctx, "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	conn, err := tr.Dial(ctx, ln.Addr().String(), config)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Send 64KB payload.
	payload := make([]byte, 64*1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	received := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatalf("Read: %v", err)
	}

	for i := range payload {
		if payload[i] != received[i] {
			t.Fatalf("byte mismatch at offset %d: got %d want %d", i, received[i], payload[i])
		}
	}
}

func TestQUICSetDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := New()
	config := &vt.Config{InsecureSkipVerify: true}

	ln, err := tr.Listen(ctx, "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Don't write anything — let client timeout.
		time.Sleep(5 * time.Second)
		conn.Close()
	}()

	conn, err := tr.Dial(ctx, ln.Addr().String(), config)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Set a very short deadline.
	conn.SetDeadline(time.Now().Add(100 * time.Millisecond))

	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestQUICDoubleClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := New()
	config := &vt.Config{InsecureSkipVerify: true}

	ln, err := tr.Listen(ctx, "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	conn, err := tr.Dial(ctx, ln.Addr().String(), config)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Double close should not panic.
	conn.Close()
	conn.Close()
}

func TestQUICDialBadAddr(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tr := New()
	config := &vt.Config{InsecureSkipVerify: true}

	_, err := tr.Dial(ctx, "127.0.0.1:1", config)
	if err == nil {
		t.Error("expected error dialing bad address")
	}
}

func TestQUICGenerateSelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("no certificate generated")
	}
}
