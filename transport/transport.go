// Package transport defines the pluggable transport interface for Veil.
//
// Each transport provides a way to send and receive raw bytes over
// a network connection, disguised as some legitimate protocol.
// The Veil core doesn't care how bytes travel — it only works with
// the Transport interface.
//
// Built-in transports:
//   - raw: Plain TCP (for testing or low-censorship environments)
//   - tls: TLS 1.3 over TCP
//   - wss: WebSocket over TLS (looks like HTTPS)
//   - quic: QUIC/HTTP3 (future)
//   - doh: DNS-over-HTTPS steganographic channel (future)
package transport

import (
	"context"
	"io"
	"net"
	"time"
)

// Transport is the interface that all Veil transports must implement.
type Transport interface {
	// ID returns the unique identifier for this transport (e.g., "tls", "wss").
	ID() string

	// Dial connects to a remote Veil server.
	Dial(ctx context.Context, addr string, config *Config) (Connection, error)

	// Listen starts accepting connections from Veil clients.
	Listen(ctx context.Context, addr string, config *Config) (Listener, error)
}

// Connection represents a bidirectional byte stream over a transport.
type Connection interface {
	io.ReadWriteCloser

	// LocalAddr returns the local network address.
	LocalAddr() net.Addr

	// RemoteAddr returns the remote network address.
	RemoteAddr() net.Addr

	// SetDeadline sets read and write deadlines.
	SetDeadline(t time.Time) error

	// TransportID returns the transport that created this connection.
	TransportID() string
}

// Listener accepts incoming Veil connections.
type Listener interface {
	// Accept waits for and returns the next connection.
	Accept() (Connection, error)

	// Addr returns the listener's network address.
	Addr() net.Addr

	// Close stops listening.
	Close() error
}

// Config holds configuration for transports.
type Config struct {
	// TLS options
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	SNI      string `json:"sni,omitempty"` // Server Name Indication

	// WebSocket options
	Path     string            `json:"path,omitempty"`     // WebSocket path (e.g., "/ws")
	Headers  map[string]string `json:"headers,omitempty"`  // Custom HTTP headers

	// Decoy options
	DecoyHandler interface{} `json:"-"` // http.Handler for decoy website

	// General
	ConnectTimeout time.Duration `json:"connect_timeout,omitempty"`
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"` // Testing only!
}

// Registry holds all available transports.
type Registry struct {
	transports map[string]Transport
}

// NewRegistry creates a new transport registry.
func NewRegistry() *Registry {
	return &Registry{
		transports: make(map[string]Transport),
	}
}

// Register adds a transport to the registry.
func (r *Registry) Register(t Transport) {
	r.transports[t.ID()] = t
}

// Get retrieves a transport by ID.
func (r *Registry) Get(id string) (Transport, bool) {
	t, ok := r.transports[id]
	return t, ok
}

// List returns all registered transport IDs.
func (r *Registry) List() []string {
	ids := make([]string, 0, len(r.transports))
	for id := range r.transports {
		ids = append(ids, id)
	}
	return ids
}
