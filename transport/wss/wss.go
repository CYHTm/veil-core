// Package wss implements a WebSocket-over-TLS transport for Veil.
// Traffic appears as standard WebSocket connections (like web apps use).
package wss

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/veil-protocol/veil-core/transport"
)

// Transport implements the WebSocket-over-TLS transport.
type Transport struct{}

// New creates a new WSS transport.
func New() *Transport {
	return &Transport{}
}

func (t *Transport) ID() string {
	return "wss"
}

func (t *Transport) Dial(ctx context.Context, addr string, config *transport.Config) (transport.Connection, error) {
	timeout := 15 * time.Second
	if config != nil && config.ConnectTimeout > 0 {
		timeout = config.ConnectTimeout
	}

	path := "/ws"
	if config != nil && config.Path != "" {
		path = config.Path
	}

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

	u := url.URL{
		Scheme: "wss",
		Host:   addr,
		Path:   path,
	}

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: config != nil && config.InsecureSkipVerify,
		},
		HandshakeTimeout: timeout,
	}

	// Add custom headers if any
	headers := http.Header{}
	if config != nil {
		for k, v := range config.Headers {
			headers.Set(k, v)
		}
	}
	// Make it look like a real browser
	if headers.Get("User-Agent") == "" {
		headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}
	if headers.Get("Origin") == "" {
		headers.Set("Origin", fmt.Sprintf("https://%s", sni))
	}

	conn, _, err := dialer.DialContext(ctx, u.String(), headers)
	if err != nil {
		return nil, fmt.Errorf("wss dial: %w", err)
	}

	return newWSConnection(conn, "wss"), nil
}

func (t *Transport) Listen(ctx context.Context, addr string, config *transport.Config) (transport.Listener, error) {
	if config == nil || config.CertFile == "" || config.KeyFile == "" {
		return nil, fmt.Errorf("wss listen: cert_file and key_file are required")
	}

	path := "/ws"
	if config.Path != "" {
		path = config.Path
	}

	listener := &wssListener{
		addr:     addr,
		path:     path,
		config:   config,
		connChan: make(chan transport.Connection, 64),
		done:     make(chan struct{}),
	}

	go listener.serve()

	return listener, nil
}

// wssListener implements transport.Listener using an HTTP server with WebSocket upgrade.
type wssListener struct {
	addr     string
	path     string
	config   *transport.Config
	connChan chan transport.Connection
	done     chan struct{}
	server   *http.Server
	once     sync.Once
}

func (l *wssListener) serve() {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	mux := http.NewServeMux()

	// WebSocket endpoint for Veil
	mux.HandleFunc(l.path, func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		select {
		case l.connChan <- newWSConnection(conn, "wss"):
		default:
			conn.Close()
		}
	})

	// Decoy handler for other paths
	if l.config.DecoyHandler != nil {
		if handler, ok := l.config.DecoyHandler.(http.Handler); ok {
			mux.Handle("/", handler)
		}
	} else {
		// Default: serve a fake page
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Welcome</h1></body></html>"))
		})
	}

	cert, err := tls.LoadX509KeyPair(l.config.CertFile, l.config.KeyFile)
	if err != nil {
		return
	}

	l.server = &http.Server{
		Addr:    l.addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h2", "http/1.1"},
		},
	}

	l.server.ListenAndServeTLS("", "")
}

func (l *wssListener) Accept() (transport.Connection, error) {
	select {
	case conn := <-l.connChan:
		return conn, nil
	case <-l.done:
		return nil, fmt.Errorf("wss listener closed")
	}
}

func (l *wssListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

func (l *wssListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		if l.server != nil {
			l.server.Close()
		}
	})
	return nil
}

// wsConnection wraps a gorilla/websocket.Conn to implement transport.Connection.
type wsConnection struct {
	conn        *websocket.Conn
	transportID string
	readBuf     []byte
	mu          sync.Mutex
}

func newWSConnection(conn *websocket.Conn, tid string) *wsConnection {
	return &wsConnection{
		conn:        conn,
		transportID: tid,
	}
}

func (c *wsConnection) Read(p []byte) (int, error) {
	// If we have leftover data from a previous message, use it first
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Read next WebSocket message
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	n := copy(p, msg)
	if n < len(msg) {
		c.readBuf = msg[n:]
	}

	return n, nil
}

func (c *wsConnection) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	err := c.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConnection) Close() error {
	return c.conn.Close()
}

func (c *wsConnection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *wsConnection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *wsConnection) SetDeadline(t time.Time) error {
	if err := c.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.conn.SetWriteDeadline(t)
}

func (c *wsConnection) TransportID() string {
	return c.transportID
}
