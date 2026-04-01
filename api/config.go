// Package api provides the public API for the Veil protocol core.
//
// External applications use this package to:
//   - Create Veil clients and servers
//   - Configure transports, morph profiles, and crypto settings
//   - Open and manage tunneled connections
//
// Example usage:
//
//   client, _ := api.NewClient(api.ClientConfig{
//       ServerAddr:   "example.com:443",
//       Secret:       "my-shared-secret",
//       Transport:    "wss",
//       MorphProfile: "http2_browsing",
//   })
//   client.Start()
//   stream, _ := client.OpenStream("target.com:80")
//   stream.Write([]byte("GET / HTTP/1.1\r\nHost: target.com\r\n\r\n"))
package api

import (
	"time"
)

// ClientConfig configures a Veil client.
type ClientConfig struct {
	// Server connection
	ServerAddr string `json:"server_addr"` // e.g., "example.com:443"
	Secret     string `json:"secret"`      // Pre-shared secret

	// Transport
	Transport    string            `json:"transport"`     // "raw", "tls", "wss"
	TransportOpts map[string]string `json:"transport_opts,omitempty"`

	// TLS
	SNI                string `json:"sni,omitempty"`         // Override SNI
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`  // Testing only

	// Morph
	MorphProfile string `json:"morph_profile,omitempty"` // "http2_browsing", "video_streaming"

	// Cipher
	Cipher string `json:"cipher,omitempty"` // "chacha20-poly1305" (default), "aes-256-gcm"

	// Mux
	MaxStreams uint16 `json:"max_streams,omitempty"` // Default: 256

	// Timeouts
	ConnectTimeout time.Duration `json:"connect_timeout,omitempty"` // Default: 15s
	KeepaliveInterval time.Duration `json:"keepalive_interval,omitempty"` // Default: 30s

	// DNS leak protection
	DNSListenAddr string `json:"dns_listen,omitempty"` // Local DNS proxy (e.g., "127.0.0.1:5353")

	// Callbacks (optional)
	OnConnect    func()       `json:"-"`
	OnDisconnect func(error)  `json:"-"`
	OnStreamOpen func(uint16) `json:"-"`
}

// ServerConfig configures a Veil server.
type ServerConfig struct {
	// Listen
	ListenAddr string `json:"listen_addr"` // e.g., ":443"
	Secret     string `json:"secret"`      // Pre-shared secret

	// Transport
	Transport     string `json:"transport"`      // "raw", "tls", "wss"
	CertFile      string `json:"cert_file,omitempty"`
	KeyFile       string `json:"key_file,omitempty"`

	// Decoy
	DecoyDir string `json:"decoy_dir,omitempty"` // Path to decoy website files
	DecoyURL string `json:"decoy_url,omitempty"` // Reverse proxy to this URL instead

	// Morph
	MorphProfiles []string `json:"morph_profiles,omitempty"`

	// Cipher
	Cipher string `json:"cipher,omitempty"` // "chacha20-poly1305" (default), "aes-256-gcm"

	// Mux
	MaxStreams uint16 `json:"max_streams,omitempty"` // Default: 256

	// DNS resolution
	DNSServer string `json:"dns_server,omitempty"` // Custom DNS for target resolution

	// Callbacks
	OnClientConnect    func(addr string) `json:"-"`
	OnClientDisconnect func(addr string) `json:"-"`
	OnStreamOpen       func(clientAddr string, target string) `json:"-"`
}

// DefaultClientConfig returns a ClientConfig with sensible defaults.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Transport:         "tls",
		Cipher:            "chacha20-poly1305",
		MorphProfile:      "http2_browsing",
		MaxStreams:         256,
		ConnectTimeout:    15 * time.Second,
		KeepaliveInterval: 30 * time.Second,
	}
}

// DefaultServerConfig returns a ServerConfig with sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		ListenAddr:    ":443",
		Transport:     "tls",
		Cipher:        "chacha20-poly1305",
		MorphProfiles: []string{"http2_browsing", "video_streaming", "grpc_api"},
		MaxStreams:     256,
	}
}
