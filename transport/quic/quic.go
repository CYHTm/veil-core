// Package quic implements a QUIC/HTTP3 transport for Veil.
//
// QUIC provides several advantages for censorship circumvention:
//   - Built on UDP (harder for DPI to track than TCP)
//   - Native TLS 1.3 encryption (no separate TLS handshake)
//   - Multiplexed streams without head-of-line blocking
//   - Connection migration (survives IP changes)
//   - Looks like normal HTTP/3 traffic (Chrome, YouTube, etc.)
package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	vt "github.com/veil-protocol/veil-core/transport"
)

// Transport implements QUIC/HTTP3 transport for Veil.
type Transport struct{}

// New creates a new QUIC transport.
func New() *Transport {
	return &Transport{}
}

func (t *Transport) ID() string {
	return "quic"
}

func (t *Transport) Dial(ctx context.Context, addr string, config *vt.Config) (vt.Connection, error) {
	tlsCfg := &tls.Config{
		NextProtos:         []string{"h3", "veil"},
		InsecureSkipVerify: config != nil && config.InsecureSkipVerify,
	}

	if config != nil && config.SNI != "" {
		tlsCfg.ServerName = config.SNI
	} else {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		tlsCfg.ServerName = host
	}

	quicCfg := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	}

	conn, err := quic.DialAddr(ctx, addr, tlsCfg, quicCfg)
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(1, "stream open failed")
		return nil, fmt.Errorf("quic open stream: %w", err)
	}

	return &quicConnection{
		qconn:  conn,
		stream: stream,
	}, nil
}

func (t *Transport) Listen(ctx context.Context, addr string, config *vt.Config) (vt.Listener, error) {
	tlsCfg, err := buildServerTLS(config)
	if err != nil {
		return nil, fmt.Errorf("quic tls config: %w", err)
	}

	quicCfg := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	}

	ln, err := quic.ListenAddr(addr, tlsCfg, quicCfg)
	if err != nil {
		return nil, fmt.Errorf("quic listen: %w", err)
	}

	return &quicListener{
		listener: ln,
		ctx:      ctx,
	}, nil
}

func buildServerTLS(config *vt.Config) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		NextProtos: []string{"h3", "veil"},
	}

	if config != nil && config.CertFile != "" && config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	} else {
		cert, err := generateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("generate cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// ── Connection ──────────────────────────────────────────────

type quicConnection struct {
	qconn  *quic.Conn
	stream *quic.Stream
	closed bool
	mu     sync.Mutex
}

func (c *quicConnection) Read(b []byte) (int, error) {
	return c.stream.Read(b)
}

func (c *quicConnection) Write(b []byte) (int, error) {
	return c.stream.Write(b)
}

func (c *quicConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.stream.Close()
	return c.qconn.CloseWithError(0, "closed")
}

func (c *quicConnection) LocalAddr() net.Addr {
	return c.qconn.LocalAddr()
}

func (c *quicConnection) RemoteAddr() net.Addr {
	return c.qconn.RemoteAddr()
}

func (c *quicConnection) SetDeadline(t time.Time) error {
	c.stream.SetReadDeadline(t)
	c.stream.SetWriteDeadline(t)
	return nil
}

func (c *quicConnection) TransportID() string {
	return "quic"
}

// ── Listener ────────────────────────────────────────────────

type quicListener struct {
	listener *quic.Listener
	ctx      context.Context
}

func (l *quicListener) Accept() (vt.Connection, error) {
	conn, err := l.listener.Accept(l.ctx)
	if err != nil {
		return nil, err
	}

	stream, err := conn.AcceptStream(l.ctx)
	if err != nil {
		conn.CloseWithError(1, "stream accept failed")
		return nil, fmt.Errorf("quic accept stream: %w", err)
	}

	return &quicConnection{
		qconn:  conn,
		stream: stream,
	}, nil
}

func (l *quicListener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *quicListener) Close() error {
	return l.listener.Close()
}
