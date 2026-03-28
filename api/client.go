package api

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"

	veilcrypto "github.com/veil-protocol/veil-core/crypto"
	"github.com/veil-protocol/veil-core/morph"
	"github.com/veil-protocol/veil-core/mux"
	"github.com/veil-protocol/veil-core/protocol"
	"github.com/veil-protocol/veil-core/transport"
	"github.com/veil-protocol/veil-core/transport/raw"
	veiltls "github.com/veil-protocol/veil-core/transport/tls"
	"github.com/veil-protocol/veil-core/transport/decoy"
	"github.com/veil-protocol/veil-core/transport/wss"
)

// Client is the main Veil client.
type Client struct {
	mu     sync.RWMutex
	config ClientConfig
	events *EventBus
	logger *log.Logger

	session   *protocol.Session
	registry  *transport.Registry
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewClient creates a new Veil client.
func NewClient(config ClientConfig) (*Client, error) {
	if config.ServerAddr == "" {
		return nil, fmt.Errorf("veil: server_addr is required")
	}
	if config.Secret == "" {
		return nil, fmt.Errorf("veil: secret is required")
	}

	defaults := DefaultClientConfig()
	if config.Transport == "" {
		config.Transport = defaults.Transport
	}
	if config.Cipher == "" {
		config.Cipher = defaults.Cipher
	}
	if config.MorphProfile == "" {
		config.MorphProfile = defaults.MorphProfile
	}
	if config.MaxStreams == 0 {
		config.MaxStreams = defaults.MaxStreams
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = defaults.ConnectTimeout
	}
	if config.KeepaliveInterval == 0 {
		config.KeepaliveInterval = defaults.KeepaliveInterval
	}

	ctx, cancel := context.WithCancel(context.Background())

	c := &Client{
		config:   config,
		events:   NewEventBus(256),
		logger:   log.New(os.Stdout, "[veil-client] ", log.LstdFlags),
		registry: transport.NewRegistry(),
		ctx:      ctx,
		cancel:   cancel,
	}

	c.registry.Register(raw.New())
	c.registry.Register(veiltls.New())
	c.registry.Register(wss.New())
	c.registry.Register(decoy.New())

	return c, nil
}

// Events returns the event bus for subscribing to events.
func (c *Client) Events() *EventBus {
	return c.events
}

// Connect establishes a Veil session with the server.
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.events.Emit(Event{Type: EventConnecting, Message: c.config.ServerAddr})

	tr, ok := c.registry.Get(c.config.Transport)
	if !ok {
		return fmt.Errorf("veil: unknown transport: %s", c.config.Transport)
	}

	tConfig := &transport.Config{
		Headers: map[string]string{"secret": c.config.Secret},
		SNI:                c.config.SNI,
		ConnectTimeout:     c.config.ConnectTimeout,
		InsecureSkipVerify: c.config.InsecureSkipVerify,
	}

	ctx, cancel := context.WithTimeout(c.ctx, c.config.ConnectTimeout)
	defer cancel()

	conn, err := tr.Dial(ctx, c.config.ServerAddr, tConfig)
	if err != nil {
		c.events.Emit(Event{Type: EventError, Error: err})
		return fmt.Errorf("transport connect: %w", err)
	}

	c.logger.Printf("transport connected (%s -> %s)", conn.LocalAddr(), conn.RemoteAddr())

	c.events.Emit(Event{Type: EventHandshakeStart})

	handshaker := protocol.NewHandshaker(
		protocol.RoleClient,
		c.config.Secret,
		c.config.Transport,
		protocol.DefaultCapabilities(),
	)

	cipherType := veilcrypto.CipherChaCha20Poly1305
	if c.config.Cipher == "aes-256-gcm" {
		cipherType = veilcrypto.CipherAES256GCM
	}
	handshaker.SetCipher(cipherType)

	clientHelloBytes, clientKP, clientNonce, _, err := handshaker.GenerateClientHello()
	if err != nil {
		conn.Close()
		c.events.Emit(Event{Type: EventHandshakeFail, Error: err})
		return fmt.Errorf("generate client hello: %w", err)
	}

	// Send length-prefixed ClientHello
	if err := writeHandshake(conn, clientHelloBytes); err != nil {
		conn.Close()
		return fmt.Errorf("send client hello: %w", err)
	}

	// Read ServerHello
	serverHelloBytes, err := readHandshake(conn, 4096)
	if err != nil {
		conn.Close()
		c.events.Emit(Event{Type: EventHandshakeFail, Error: err})
		return fmt.Errorf("read server hello: %w", err)
	}

	hsResult, err := handshaker.ProcessServerHello(serverHelloBytes, clientKP, clientNonce)
	if err != nil {
		conn.Close()
		c.events.Emit(Event{Type: EventHandshakeFail, Error: err})
		return fmt.Errorf("process server hello: %w", err)
	}

	c.events.Emit(Event{Type: EventHandshakeOK, SessionID: hsResult.SessionID})
	c.logger.Printf("handshake complete (session: %x)", hsResult.SessionID[:4])

	var morphProfile *morph.Profile
	switch c.config.MorphProfile {
	case "http2_browsing":
		morphProfile = morph.BuiltinHTTP2Profile()
	case "video_streaming":
		morphProfile = morph.BuiltinVideoProfile()
	default:
		morphProfile = morph.BuiltinHTTP2Profile()
	}

	session, err := protocol.NewSession(protocol.SessionConfig{
		Role:              protocol.RoleClient,
		Connection:        conn,
		Transport:         tr,
		HandshakeResult:   hsResult,
		MorphProfile:      morphProfile,
		KeepaliveInterval: c.config.KeepaliveInterval,
		Logger:            c.logger,
		OnStreamOpen: func(streamID uint16, targetAddr string) {
			c.events.Emit(Event{
				Type:     EventStreamOpened,
				StreamID: streamID,
				Message:  targetAddr,
			})
		},
		OnClose: func(err error) {
			c.events.Emit(Event{Type: EventDisconnected, Error: err})
			if c.config.OnDisconnect != nil {
				c.config.OnDisconnect(err)
			}
		},
	})
	if err != nil {
		conn.Close()
		return fmt.Errorf("create session: %w", err)
	}

	c.session = session
	session.Start(c.ctx)

	c.events.Emit(Event{
		Type:      EventConnected,
		SessionID: session.ID(),
	})

	if c.config.OnConnect != nil {
		go c.config.OnConnect()
	}

	return nil
}

// OpenStream opens a new multiplexed stream to the target address.
func (c *Client) OpenStream(targetAddr string) (*mux.Stream, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.session == nil {
		return nil, fmt.Errorf("veil: not connected")
	}

	return c.session.OpenStream(targetAddr)
}

// Close disconnects the client.
func (c *Client) Close() error {
	c.cancel()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil {
		c.session.Close()
		c.session = nil
	}

	c.events.Close()
	return nil
}

// IsConnected returns true if the client has an active session.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.session != nil && c.session.State() == protocol.SessionEstablished
}

// ============================================================
// Wire helpers — work with io.ReadWriter (not net.Conn)
// ============================================================


