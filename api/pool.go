package api

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/veil-protocol/veil-core/transport"
)

// ConnPool manages a pool of transport connections for reuse.
type ConnPool struct {
	mu       sync.Mutex
	conns    []poolEntry
	maxSize  int
	maxAge   time.Duration
	factory  func(ctx context.Context) (transport.Connection, error)
	active   int64
}

type poolEntry struct {
	conn    transport.Connection
	created time.Time
}

// NewConnPool creates a connection pool.
func NewConnPool(maxSize int, maxAge time.Duration, factory func(ctx context.Context) (transport.Connection, error)) *ConnPool {
	return &ConnPool{
		maxSize: maxSize,
		maxAge:  maxAge,
		factory: factory,
	}
}

// Get returns a connection from the pool or creates a new one.
func (cp *ConnPool) Get(ctx context.Context) (transport.Connection, error) {
	cp.mu.Lock()

	// Try to find a valid pooled connection
	for len(cp.conns) > 0 {
		entry := cp.conns[len(cp.conns)-1]
		cp.conns = cp.conns[:len(cp.conns)-1]

		if time.Since(entry.created) < cp.maxAge {
			cp.mu.Unlock()
			atomic.AddInt64(&cp.active, 1)
			return entry.conn, nil
		}
		// Too old, close it
		entry.conn.Close()
	}
	cp.mu.Unlock()

	// Create new connection
	conn, err := cp.factory(ctx)
	if err != nil {
		return nil, err
	}

	atomic.AddInt64(&cp.active, 1)
	return conn, nil
}

// Put returns a connection to the pool for reuse.
func (cp *ConnPool) Put(conn transport.Connection) {
	atomic.AddInt64(&cp.active, -1)

	cp.mu.Lock()
	defer cp.mu.Unlock()

	if len(cp.conns) >= cp.maxSize {
		conn.Close()
		return
	}

	cp.conns = append(cp.conns, poolEntry{
		conn:    conn,
		created: time.Now(),
	})
}

// Close closes all pooled connections.
func (cp *ConnPool) Close() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	for _, entry := range cp.conns {
		entry.conn.Close()
	}
	cp.conns = nil
}

// Active returns number of connections currently in use.
func (cp *ConnPool) Active() int64 {
	return atomic.LoadInt64(&cp.active)
}

// Pooled returns number of idle connections in pool.
func (cp *ConnPool) Pooled() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.conns)
}
