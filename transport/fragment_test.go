package transport

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestFragmentedWriterSmallData(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	fw := NewFragmentedWriter(client, 2, 5, 0)

	// Data smaller than maxFrag — should send as one piece
	data := []byte("hi")

	go func() {
		fw.Write(data)
	}()

	buf := make([]byte, 256)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf[:n], data) {
		t.Fatalf("expected '%s', got '%s'", data, buf[:n])
	}
}

func TestFragmentedWriterLargeData(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	fw := NewFragmentedWriter(client, 2, 5, time.Millisecond)

	// 50 bytes — will be split into multiple fragments
	data := bytes.Repeat([]byte("A"), 50)

	go func() {
		fw.Write(data)
	}()

	// Read all fragments
	var received []byte
	buf := make([]byte, 256)
	for len(received) < len(data) {
		server.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("read error after %d bytes: %v", len(received), err)
		}
		received = append(received, buf[:n]...)
	}

	if !bytes.Equal(received, data) {
		t.Fatalf("data mismatch: got %d bytes, expected %d", len(received), len(data))
	}
}

func TestFragmentedWriterDisabled(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	fw := NewFragmentedWriter(client, 2, 5, 10*time.Millisecond)
	fw.SetEnabled(false)

	data := bytes.Repeat([]byte("B"), 50)

	go func() {
		fw.Write(data)
	}()

	// With fragmentation disabled, should come as one write
	buf := make([]byte, 256)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf[:n], data) {
		t.Fatalf("expected all %d bytes in one read, got %d", len(data), n)
	}
}

func TestFragmentedWriterToggle(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	fw := NewFragmentedWriter(client, 2, 5, 0)

	// Start enabled
	if !fw.enabled {
		t.Fatal("expected enabled by default")
	}

	// Disable
	fw.SetEnabled(false)
	if fw.enabled {
		t.Fatal("expected disabled after SetEnabled(false)")
	}

	// Re-enable
	fw.SetEnabled(true)
	if !fw.enabled {
		t.Fatal("expected enabled after SetEnabled(true)")
	}
}

func TestFragmentedWriterZeroData(t *testing.T) {
	// net.Pipe blocks on zero-length writes, so we use a real TCP connection
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	fw := NewFragmentedWriter(client, 2, 5, 0)

	n, err := fw.Write([]byte{})
	if err != nil {
		t.Fatalf("write empty: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes written, got %d", n)
	}
}

func TestFragmentedWriterBoundary(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// minFrag == maxFrag == 5 — each fragment is exactly 5 bytes
	fw := NewFragmentedWriter(client, 5, 5, 0)

	// 15 bytes — should be exactly 3 fragments of 5
	data := []byte("123456789012345")

	go func() {
		fw.Write(data)
	}()

	var received []byte
	buf := make([]byte, 256)
	for len(received) < len(data) {
		server.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		received = append(received, buf[:n]...)
	}

	if !bytes.Equal(received, data) {
		t.Fatalf("data mismatch")
	}
}
