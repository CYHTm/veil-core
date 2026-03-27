// Package tls implements a TLS 1.3 transport with browser fingerprint mimicry.
//
// Uses uTLS to make connections indistinguishable from real Chrome/Firefox/Safari.
// Standard Go TLS has a unique fingerprint that DPI systems (China GFW, Iran)
// can detect. uTLS clones the exact ClientHello of real browsers.
package tls

import (
	"context"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/veil-protocol/veil-core/transport"
)

// Supported browser fingerprints
const (
	FingerprintChrome  = "chrome"
	FingerprintFirefox = "firefox"
	FingerprintSafari  = "safari"
	FingerprintEdge    = "edge"
	FingerprintRandom  = "random" // Random fingerprint each connection
)

// Transport implements TLS 1.3 with uTLS browser mimicry.
type Transport struct {
	fingerprint string
}

// New creates a TLS transport with Chrome fingerprint (default).
func New() *Transport {
	return &Transport{fingerprint: FingerprintChrome}
}

// NewWithFingerprint creates a TLS transport with specific browser fingerprint.
func NewWithFingerprint(fp string) *Transport {
	return &Transport{fingerprint: fp}
}

func (t *Transport) ID() string {
	return "tls"
}

func (t *Transport) Dial(ctx context.Context, addr string, config *transport.Config) (transport.Connection, error) {
	timeout := 15 * time.Second
	if config != nil && config.ConnectTimeout > 0 {
		timeout = config.ConnectTimeout
	}

	// Determine SNI
	sni := ""
	if config != nil && config.SNI != "" {
		sni = config.SNI
	} else {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		sni = host
	}

	// Choose fingerprint
	fp := t.fingerprint
	if config != nil {
		if cfgFP, ok := config.Headers["fingerprint"]; ok {
			fp = cfgFP
		}
	}

	// TCP connection first
	dialer := &net.Dialer{Timeout: timeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	// uTLS with browser fingerprint
	tlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: config != nil && config.InsecureSkipVerify,
	}

	clientHelloID := getClientHelloID(fp)
	tlsConn := utls.UClient(tcpConn, tlsConfig, clientHelloID)

	// Perform handshake with timeout
	handshakeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- tlsConn.Handshake()
	}()

	select {
	case err := <-errCh:
		if err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
	case <-handshakeCtx.Done():
		tcpConn.Close()
		return nil, fmt.Errorf("tls handshake timeout")
	}

	return &tlsConnection{
		Conn:        tlsConn,
		transportID: "tls",
		fingerprint: fp,
	}, nil
}

func (t *Transport) Listen(ctx context.Context, addr string, config *transport.Config) (transport.Listener, error) {
	if config == nil || config.CertFile == "" || config.KeyFile == "" {
		return nil, fmt.Errorf("tls listen: cert_file and key_file are required")
	}

	// Server side uses standard TLS (fingerprint only matters for client)
	cert, err := utls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls load cert: %w", err)
	}

	tlsConfig := &utls.Config{
		Certificates: []utls.Certificate{cert},
		MinVersion:   utls.VersionTLS12,
		MaxVersion:   utls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	ln, err := utls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("tls listen: %w", err)
	}

	return &tlsListener{Listener: ln}, nil
}

// getClientHelloID maps fingerprint name to uTLS ClientHelloID.
func getClientHelloID(fp string) utls.ClientHelloID {
	switch fp {
	case FingerprintChrome:
		return utls.HelloChrome_Auto
	case FingerprintFirefox:
		return utls.HelloFirefox_Auto
	case FingerprintSafari:
		return utls.HelloSafari_Auto
	case FingerprintEdge:
		return utls.HelloEdge_Auto
	case FingerprintRandom:
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_Auto
	}
}

// tlsConnection wraps uTLS connection.
type tlsConnection struct {
	net.Conn
	transportID string
	fingerprint string
}

func (c *tlsConnection) TransportID() string {
	return c.transportID
}

// Fingerprint returns which browser this connection mimics.
func (c *tlsConnection) Fingerprint() string {
	return c.fingerprint
}

// tlsListener wraps a TLS listener.
type tlsListener struct {
	net.Listener
}

func (l *tlsListener) Accept() (transport.Connection, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tlsConnection{Conn: conn, transportID: "tls", fingerprint: "server"}, nil
}
