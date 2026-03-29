package api

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/veil-protocol/veil-core/transport"
	"github.com/veil-protocol/veil-core/transport/raw"
)

// helper: creates a real TCP listener + pool factory
func setupPoolTest(t *testing.T) (*ConnPool, net.Listener) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Accept connections in background
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn
		}
	}()

	tr := raw.New()
	factory := func(ctx context.Context) (transport.Connection, error) {
		return tr.Dial(ctx, ln.Addr().String(), nil)
	}

	pool := NewConnPool(3, 30*time.Second, factory)
	return pool, ln
}

func TestConnPoolGetCreatesNew(t *testing.T) {
	pool, ln := setupPoolTest(t)
	defer ln.Close()
	defer pool.Close()

	conn, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer pool.Put(conn)

	if conn == nil {
		t.Fatal("expected non-nil connection")
	}
	if pool.Active() != 1 {
		t.Fatalf("expected 1 active, got %d", pool.Active())
	}
}

func TestConnPoolPutAndReuse(t *testing.T) {
	pool, ln := setupPoolTest(t)
	defer ln.Close()
	defer pool.Close()

	conn, _ := pool.Get(context.Background())
	pool.Put(conn)

	if pool.Pooled() != 1 {
		t.Fatalf("expected 1 pooled, got %d", pool.Pooled())
	}
	if pool.Active() != 0 {
		t.Fatalf("expected 0 active after put, got %d", pool.Active())
	}

	// Get again — should reuse
	conn2, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("get reuse: %v", err)
	}
	defer pool.Put(conn2)

	if pool.Pooled() != 0 {
		t.Fatalf("expected 0 pooled after reuse, got %d", pool.Pooled())
	}
}

func TestConnPoolMaxSize(t *testing.T) {
	pool, ln := setupPoolTest(t)
	defer ln.Close()
	defer pool.Close()

	// Get 5 connections, put all back — pool max is 3
	var conns []transport.Connection
	for i := 0; i < 5; i++ {
		conn, err := pool.Get(context.Background())
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		conns = append(conns, conn)
	}

	for _, conn := range conns {
		pool.Put(conn)
	}

	// Only 3 should be pooled (max size)
	if pool.Pooled() > 3 {
		t.Fatalf("expected max 3 pooled, got %d", pool.Pooled())
	}
}

func TestConnPoolClose(t *testing.T) {
	pool, ln := setupPoolTest(t)
	defer ln.Close()

	conn, _ := pool.Get(context.Background())
	pool.Put(conn)

	pool.Close()

	if pool.Pooled() != 0 {
		t.Fatalf("expected 0 pooled after close, got %d", pool.Pooled())
	}
}

func TestConnPoolFactoryError(t *testing.T) {
	factory := func(ctx context.Context) (transport.Connection, error) {
		return nil, errors.New("connection refused")
	}

	pool := NewConnPool(3, 30*time.Second, factory)
	defer pool.Close()

	_, err := pool.Get(context.Background())
	if err == nil {
		t.Fatal("expected error from factory")
	}
}

func TestConnPoolExpiredConnection(t *testing.T) {
	pool, ln := setupPoolTest(t)
	defer ln.Close()

	// Override maxAge to very short
	pool.maxAge = 1 * time.Millisecond

	conn, _ := pool.Get(context.Background())
	pool.Put(conn)

	// Wait for it to expire
	time.Sleep(10 * time.Millisecond)

	// Get should create new (expired one discarded)
	conn2, err := pool.Get(context.Background())
	if err != nil {
		t.Fatalf("get after expire: %v", err)
	}
	pool.Put(conn2)
}

func TestConnPoolActiveCounter(t *testing.T) {
	pool, ln := setupPoolTest(t)
	defer ln.Close()
	defer pool.Close()

	if pool.Active() != 0 {
		t.Fatalf("expected 0 active initially")
	}

	c1, _ := pool.Get(context.Background())
	c2, _ := pool.Get(context.Background())

	if pool.Active() != 2 {
		t.Fatalf("expected 2 active, got %d", pool.Active())
	}

	pool.Put(c1)
	if pool.Active() != 1 {
		t.Fatalf("expected 1 active after put, got %d", pool.Active())
	}

	pool.Put(c2)
	if pool.Active() != 0 {
		t.Fatalf("expected 0 active after all put, got %d", pool.Active())
	}
}
