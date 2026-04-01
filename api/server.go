// Package api provides the high-level client and server API for Veil.
//
// This file implements the Veil server that accepts client connections,
// performs handshakes, manages sessions, and proxies traffic.
package api

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	veilcrypto "github.com/veil-protocol/veil-core/crypto"
	"github.com/veil-protocol/veil-core/morph"
	"github.com/veil-protocol/veil-core/protocol"
	"github.com/veil-protocol/veil-core/transport"
	"github.com/veil-protocol/veil-core/transport/raw"
	veilquic "github.com/veil-protocol/veil-core/transport/quic"
	veiltls "github.com/veil-protocol/veil-core/transport/tls"
	"github.com/veil-protocol/veil-core/transport/wss"
)

type Server struct {
	mu       sync.RWMutex
	config   ServerConfig
	events   *EventBus
	logger   *log.Logger
	registry *transport.Registry

	sessions map[[16]byte]*protocol.Session
	listener transport.Listener

	ctx    context.Context
	cancel context.CancelFunc
	dialer *net.Dialer
}

func NewServer(config ServerConfig) (*Server, error) {
	if config.ListenAddr == "" {
		return nil, fmt.Errorf("veil: listen_addr is required")
	}
	if config.Secret == "" {
		return nil, fmt.Errorf("veil: secret is required")
	}

	defaults := DefaultServerConfig()
	if config.Transport == "" {
		config.Transport = defaults.Transport
	}
	if config.Cipher == "" {
		config.Cipher = defaults.Cipher
	}
	if config.MaxStreams == 0 {
		config.MaxStreams = defaults.MaxStreams
	}
	if len(config.MorphProfiles) == 0 {
		config.MorphProfiles = defaults.MorphProfiles
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Build dialer with optional custom DNS resolver
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if config.DNSServer != "" {
		dialer.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// Route all DNS lookups to the configured DNS server
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", config.DNSServer)
			},
		}
	}

	s := &Server{
		config:   config,
		events:   NewEventBus(256),
		logger:   log.New(os.Stdout, "[veil-server] ", log.LstdFlags),
		registry: transport.NewRegistry(),
		sessions: make(map[[16]byte]*protocol.Session),
		ctx:      ctx,
		cancel:   cancel,
		dialer:   dialer,
	}

	s.registry.Register(raw.New())
	s.registry.Register(veiltls.New())
	s.registry.Register(wss.New())
	s.registry.Register(veilquic.New())

	return s, nil
}

func (s *Server) Events() *EventBus {
	return s.events
}

func (s *Server) Start() error {
	tr, ok := s.registry.Get(s.config.Transport)
	if !ok {
		return fmt.Errorf("veil: unknown transport: %s", s.config.Transport)
	}

	tConfig := &transport.Config{
		CertFile: s.config.CertFile,
		KeyFile:  s.config.KeyFile,
	}

	listener, err := tr.Listen(s.ctx, s.config.ListenAddr, tConfig)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	s.listener = listener
	s.logger.Printf("listening on %s (transport: %s)", s.config.ListenAddr, s.config.Transport)

	go s.acceptLoop()

	return nil
}

func (s *Server) Stop() error {
	s.cancel()

	s.mu.Lock()
	defer s.mu.Unlock()

	for id, session := range s.sessions {
		session.Close()
		delete(s.sessions, id)
	}

	if s.listener != nil {
		s.listener.Close()
	}

	s.events.Close()
	s.logger.Println("server stopped")

	return nil
}

func (s *Server) ActiveSessions() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

func (s *Server) acceptLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			s.logger.Printf("accept error: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn transport.Connection) {
	remoteAddr := conn.RemoteAddr().String()
	s.logger.Printf("new connection from %s", remoteAddr)

	if s.config.OnClientConnect != nil {
		s.config.OnClientConnect(remoteAddr)
	}

	s.events.Emit(Event{Type: EventConnecting, Message: remoteAddr})
	s.events.Emit(Event{Type: EventHandshakeStart, Message: remoteAddr})

	handshaker := protocol.NewHandshaker(
		protocol.RoleServer,
		s.config.Secret,
		s.config.Transport,
		protocol.Capabilities{
			MaxStreams:    s.config.MaxStreams,
			MorphProfiles: s.config.MorphProfiles,
			Transports:    []string{s.config.Transport},
		},
	)

	cipherType := veilcrypto.CipherChaCha20Poly1305
	if s.config.Cipher == "aes-256-gcm" {
		cipherType = veilcrypto.CipherAES256GCM
	}
	handshaker.SetCipher(cipherType)

	clientHelloBytes, err := readHandshake(conn, 4096)
	if err != nil {
		s.logger.Printf("read client hello failed (%s): %v", remoteAddr, err)
		conn.Close()
		return
	}

	serverHelloBytes, hsResult, _, err := handshaker.ProcessClientHello(clientHelloBytes)
	if err != nil {
		s.logger.Printf("handshake failed (%s): %v", remoteAddr, err)
		s.events.Emit(Event{Type: EventHandshakeFail, Error: err, Message: remoteAddr})
		conn.Close()
		return
	}

	if err := writeHandshake(conn, serverHelloBytes); err != nil {
		s.logger.Printf("send server hello failed (%s): %v", remoteAddr, err)
		conn.Close()
		return
	}

	s.events.Emit(Event{Type: EventHandshakeOK, SessionID: hsResult.SessionID, Message: remoteAddr})
	s.logger.Printf("handshake complete with %s (session: %x)", remoteAddr, hsResult.SessionID[:4])

	tr, _ := s.registry.Get(s.config.Transport)
	morphProfile := morph.BuiltinHTTP2Profile()

	var session *protocol.Session

	sessionCfg := protocol.SessionConfig{
		Role:            protocol.RoleServer,
		Connection:      conn,
		Transport:       tr,
		HandshakeResult: hsResult,
		MorphProfile:    morphProfile,
		Logger:          s.logger,
		OnStreamOpen: func(streamID uint16, targetAddr string) {
			s.logger.Printf("[session:%x] stream %d -> %s",
				hsResult.SessionID[:4], streamID, targetAddr)

			if s.config.OnStreamOpen != nil {
				s.config.OnStreamOpen(remoteAddr, targetAddr)
			}

			go s.proxyStream(session, streamID, targetAddr)
		},
		OnClose: func(err error) {
			s.mu.Lock()
			delete(s.sessions, hsResult.SessionID)
			s.mu.Unlock()

			s.events.Emit(Event{
				Type:      EventDisconnected,
				SessionID: hsResult.SessionID,
				Error:     err,
			})

			if s.config.OnClientDisconnect != nil {
				s.config.OnClientDisconnect(remoteAddr)
			}
		},
	}

	var sessionErr error
	session, sessionErr = protocol.NewSession(sessionCfg)
	if sessionErr != nil {
		s.logger.Printf("create session failed (%s): %v", remoteAddr, sessionErr)
		conn.Close()
		return
	}

	s.mu.Lock()
	s.sessions[hsResult.SessionID] = session
	s.mu.Unlock()

	session.Start(s.ctx)

	s.events.Emit(Event{
		Type:      EventConnected,
		SessionID: hsResult.SessionID,
		Message:   remoteAddr,
	})
}

// proxyStream connects a Veil stream to the actual target.
func (s *Server) proxyStream(session *protocol.Session, streamID uint16, targetAddr string) {
	if session == nil {
		s.logger.Printf("proxy error: session is nil for stream %d", streamID)
		return
	}

	stream, ok := session.GetMux().GetStream(streamID)
	if !ok {
		s.logger.Printf("proxy error: stream %d not found", streamID)
		return
	}

	targetConn, err := s.dialer.DialContext(s.ctx, "tcp", targetAddr)
	if err != nil {
		s.logger.Printf("proxy connect to %s failed: %v", targetAddr, err)
		stream.Close()
		return
	}

	s.logger.Printf("proxy established: stream %d <-> %s", streamID, targetAddr)

	// Bidirectional copy with proper shutdown
	done := make(chan struct{}, 2)

	// target → stream (response data)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				if _, writeErr := stream.Write(buf[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// stream → target (request data)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				if _, writeErr := targetConn.Write(buf[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for one direction to finish, then clean up both
	<-done

	// Shut down both sides cleanly
	targetConn.Close()
	stream.Close()

	s.logger.Printf("proxy closed: stream %d <-> %s", streamID, targetAddr)
}
