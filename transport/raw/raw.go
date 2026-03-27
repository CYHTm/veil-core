// Package raw implements a plain TCP transport for Veil.
// This transport provides NO obfuscation and should only be used
// for testing or in environments with no censorship.
package raw

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/veil-protocol/veil-core/transport"
)

// Transport implements the raw TCP transport.
type Transport struct{}

// New creates a new raw TCP transport.
func New() *Transport {
	return &Transport{}
}

func (t *Transport) ID() string {
	return "raw"
}

func (t *Transport) Dial(ctx context.Context, addr string, config *transport.Config) (transport.Connection, error) {
	timeout := 15 * time.Second
	if config != nil && config.ConnectTimeout > 0 {
		timeout = config.ConnectTimeout
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("raw dial: %w", err)
	}

	return &rawConnection{Conn: conn, transportID: "raw"}, nil
}

func (t *Transport) Listen(ctx context.Context, addr string, config *transport.Config) (transport.Listener, error) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("raw listen: %w", err)
	}

	return &rawListener{Listener: ln}, nil
}

// rawConnection wraps net.Conn to implement transport.Connection.
type rawConnection struct {
	net.Conn
	transportID string
}

func (c *rawConnection) TransportID() string {
	return c.transportID
}

// rawListener wraps net.Listener to implement transport.Listener.
type rawListener struct {
	net.Listener
}

func (l *rawListener) Accept() (transport.Connection, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &rawConnection{Conn: conn, transportID: "raw"}, nil
}
