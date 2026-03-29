package raw

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/veil-protocol/veil-core/transport"
)

func TestTransportID(t *testing.T) {
	tr := New()
	if tr.ID() != "raw" {
		t.Fatalf("expected 'raw', got '%s'", tr.ID())
	}
}

func TestDialAndListen(t *testing.T) {
	ctx := context.Background()
	tr := New()

	ln, err := tr.Listen(ctx, "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	// Accept in background
	accepted := make(chan transport.Connection, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	// Dial
	conn, err := tr.Dial(ctx, addr, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	// Wait for accept
	select {
	case srvConn := <-accepted:
		defer srvConn.Close()
		if srvConn.TransportID() != "raw" {
			t.Fatalf("server conn transport: expected 'raw', got '%s'", srvConn.TransportID())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("accept timed out")
	}

	if conn.TransportID() != "raw" {
		t.Fatalf("client conn transport: expected 'raw', got '%s'", conn.TransportID())
	}
}

func TestDataTransfer(t *testing.T) {
	ctx := context.Background()
	tr := New()

	ln, err := tr.Listen(ctx, "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan transport.Connection, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()

	client, err := tr.Dial(ctx, ln.Addr().String(), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()

	// Client -> Server
	testData := []byte("hello from veil client")
	if _, err := client.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 256)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(testData) {
		t.Fatalf("expected '%s', got '%s'", testData, buf[:n])
	}

	// Server -> Client
	replyData := []byte("hello from veil server")
	if _, err := server.Write(replyData); err != nil {
		t.Fatalf("write reply: %v", err)
	}

	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(buf[:n]) != string(replyData) {
		t.Fatalf("expected '%s', got '%s'", replyData, buf[:n])
	}
}

func TestConnectionClose(t *testing.T) {
	ctx := context.Background()
	tr := New()

	ln, err := tr.Listen(ctx, "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan transport.Connection, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()

	client, err := tr.Dial(ctx, ln.Addr().String(), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	server := <-accepted

	// Close client side
	client.Close()

	// Server should get EOF
	buf := make([]byte, 256)
	_, err = server.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected EOF after close, got: %v", err)
	}
	server.Close()
}

func TestDialTimeout(t *testing.T) {
	tr := New()
	cfg := &transport.Config{
		ConnectTimeout: 100 * time.Millisecond,
	}

	// Dial an address that won't respond (RFC 5737 TEST-NET)
	ctx := context.Background()
	_, err := tr.Dial(ctx, "127.0.0.1:1", cfg)
	if err == nil {
		t.Fatal("expected dial to fail with timeout")
	}
}

func TestAddresses(t *testing.T) {
	ctx := context.Background()
	tr := New()

	ln, err := tr.Listen(ctx, "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	if ln.Addr() == nil {
		t.Fatal("listener addr is nil")
	}

	accepted := make(chan transport.Connection, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()

	client, err := tr.Dial(ctx, ln.Addr().String(), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()

	if client.LocalAddr() == nil {
		t.Fatal("client LocalAddr is nil")
	}
	if client.RemoteAddr() == nil {
		t.Fatal("client RemoteAddr is nil")
	}
	if server.LocalAddr() == nil {
		t.Fatal("server LocalAddr is nil")
	}
	if server.RemoteAddr() == nil {
		t.Fatal("server RemoteAddr is nil")
	}
}

func TestSetDeadline(t *testing.T) {
	ctx := context.Background()
	tr := New()

	ln, err := tr.Listen(ctx, "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan transport.Connection, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()

	client, err := tr.Dial(ctx, ln.Addr().String(), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()

	// Set very short deadline — read should fail
	client.SetDeadline(time.Now().Add(50 * time.Millisecond))
	time.Sleep(100 * time.Millisecond)

	buf := make([]byte, 256)
	_, err = client.Read(buf)
	if err == nil {
		t.Fatal("expected read to fail after deadline")
	}
}
