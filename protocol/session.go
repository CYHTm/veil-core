package protocol

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	veilcrypto "github.com/veil-protocol/veil-core/crypto"
	"github.com/veil-protocol/veil-core/morph"
	"github.com/veil-protocol/veil-core/mux"
	"github.com/veil-protocol/veil-core/transport"
)

// Session represents a fully established Veil session.
// It ties together: transport connection, crypto, mux, morph engine, state machine.
type Session struct {
	mu sync.RWMutex

	// Identity
	id    [16]byte
	role  HandshakeRole
	state *StateMachine

	// Networking
	conn      transport.Connection
	transport transport.Transport

	// Crypto
	cipher *veilcrypto.SessionCipher

	// Multiplexing
	mux *mux.Mux

	// Traffic morphing
	morphEngine *morph.Engine

	// Keepalive
	keepaliveInterval time.Duration
	keepaliveCancel   context.CancelFunc

	// Events
	onStreamOpen func(streamID uint16, targetAddr string)
	onClose      func(error)

	// Logging
	logger *log.Logger
}

// SessionConfig holds configuration for creating a session.
type SessionConfig struct {
	Role              HandshakeRole
	Connection        transport.Connection
	Transport         transport.Transport
	HandshakeResult   *HandshakeResult
	MorphProfile      *morph.Profile
	KeepaliveInterval time.Duration
	Logger            *log.Logger
	OnStreamOpen      func(streamID uint16, targetAddr string)
	OnClose           func(error)
}

// NewSession creates a new session from a completed handshake.
func NewSession(cfg SessionConfig) (*Session, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.KeepaliveInterval == 0 {
		cfg.KeepaliveInterval = KeepaliveInterval
	}

	hr := cfg.HandshakeResult

	// Create the session cipher
	// Client encrypts with ClientWriteKey, decrypts with ServerWriteKey
	// Server encrypts with ServerWriteKey, decrypts with ClientWriteKey
	var writeKey, readKey, writeNonce, readNonce []byte
	if cfg.Role == RoleClient {
		writeKey = hr.ClientWriteKey
		readKey = hr.ServerWriteKey
		writeNonce = hr.ClientNonce
		readNonce = hr.ServerNonce
	} else {
		writeKey = hr.ServerWriteKey
		readKey = hr.ClientWriteKey
		writeNonce = hr.ServerNonce
		readNonce = hr.ClientNonce
	}

	sessionCipher, err := veilcrypto.NewSessionCipher(
		hr.SelectedCipher,
		writeKey, readKey,
		writeNonce, readNonce,
	)
	if err != nil {
		return nil, fmt.Errorf("create session cipher: %w", err)
	}

	s := &Session{
		role:              cfg.Role,
		state:             NewStateMachine(),
		conn:              cfg.Connection,
		transport:         cfg.Transport,
		cipher:            sessionCipher,
		keepaliveInterval: cfg.KeepaliveInterval,
		onStreamOpen:      cfg.OnStreamOpen,
		onClose:           cfg.OnClose,
		logger:            cfg.Logger,
	}
	copy(s.id[:], hr.SessionID[:])

	// Initialize morph engine
	if cfg.MorphProfile != nil {
		s.morphEngine = morph.NewEngine(cfg.MorphProfile)
	}

	// Initialize mux — the callback converts mux.Message → protocol.Frame
	maxStreams := hr.PeerCapabilities.MaxStreams
	if maxStreams == 0 {
		maxStreams = 256
	}
	s.mux = mux.NewMux(maxStreams, s.handleMuxMessage)

	if cfg.OnStreamOpen != nil {
		s.mux.SetStreamOpenHandler(cfg.OnStreamOpen)
	}

	// Transition to established
	s.state.Transition(SessionHandshaking, "session_create")
	s.state.Transition(SessionEstablished, "handshake_complete")

	return s, nil
}

// Start begins the session's read loop and keepalive.
func (s *Session) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.keepaliveCancel = cancel

	go s.readLoop(ctx)
	go s.keepaliveLoop(ctx)

	s.logger.Printf("[session:%x] started (role=%d, transport=%s)",
		s.id[:4], s.role, s.conn.TransportID())
}

// OpenStream opens a new multiplexed stream to the given target.
func (s *Session) OpenStream(targetAddr string) (*mux.Stream, error) {
	if !s.state.IsEstablished() {
		return nil, ErrSessionClosed
	}
	return s.mux.OpenStream(targetAddr)
}

// GetMux returns the underlying mux (for advanced server-side proxying).
func (s *Session) GetMux() *mux.Mux {
	return s.mux
}

// Close gracefully closes the session.
func (s *Session) Close() error {
	if s.state.IsClosed() {
		return nil
	}

	s.state.Transition(SessionClosing, "close_requested")

	// Send session close frame
	s.sendFrame(NewSessionCloseFrame())

	// Stop keepalive
	if s.keepaliveCancel != nil {
		s.keepaliveCancel()
	}

	// Close mux (closes all streams)
	s.mux.Close()

	// Close transport connection
	s.conn.Close()

	s.state.Transition(SessionClosed, "closed")

	s.logger.Printf("[session:%x] closed", s.id[:4])

	return nil
}

// ID returns the session ID.
func (s *Session) ID() [16]byte {
	return s.id
}

// State returns the current session state.
func (s *Session) State() SessionState {
	return s.state.Current()
}

// ActiveStreams returns the count of active streams.
func (s *Session) ActiveStreams() int {
	return s.mux.ActiveStreams()
}

// ============================================================
// Bridge: mux.Message <-> protocol.Frame
// ============================================================

// handleMuxMessage converts a mux.Message into a protocol.Frame and sends it.
// This is the bridge that avoids the import cycle.
func (s *Session) handleMuxMessage(msg *mux.Message) error {
	frame := s.muxMessageToFrame(msg)
	return s.sendFrame(frame)
}

// muxMessageToFrame converts a mux.Message into a protocol.Frame.
func (s *Session) muxMessageToFrame(msg *mux.Message) *Frame {
	f := &Frame{
		Version:  ProtocolVersion,
		StreamID: msg.StreamID,
		SeqNum:   msg.SeqNum,
		Payload:  msg.Payload,
	}

	switch msg.Type {
	case mux.MsgStreamOpen:
		f.Type = FrameStreamOpen
	case mux.MsgStreamData:
		f.Type = FrameStreamData
	case mux.MsgStreamClose:
		f.Type = FrameStreamClose
		if msg.Final {
			f.Flags = FlagFinal
		}
	case mux.MsgKeepalive:
		f.Type = FrameKeepalive
	case mux.MsgSessionClose:
		f.Type = FrameSessionClose
		f.Flags = FlagFinal
	}

	return f
}

// frameToMuxMessage converts a protocol.Frame into a mux.Message.
func (s *Session) frameToMuxMessage(f *Frame) *mux.Message {
	msg := &mux.Message{
		StreamID: f.StreamID,
		SeqNum:   f.SeqNum,
		Payload:  f.Payload,
		Final:    f.Flags&FlagFinal != 0,
	}

	switch f.Type {
	case FrameStreamOpen:
		msg.Type = mux.MsgStreamOpen
	case FrameStreamData:
		msg.Type = mux.MsgStreamData
	case FrameStreamClose:
		msg.Type = mux.MsgStreamClose
	case FrameKeepalive:
		msg.Type = mux.MsgKeepalive
	case FrameSessionClose:
		msg.Type = mux.MsgSessionClose
	}

	return msg
}

// ============================================================
// Wire I/O
// ============================================================

// sendFrame encrypts and sends a frame over the transport.
func (s *Session) sendFrame(frame *Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Apply morph padding if engine is active
	if s.morphEngine != nil && frame.Type == FrameStreamData {
		paddingSize := s.morphEngine.CalculatePadding(len(frame.Payload))
		if paddingSize > 0 {
			frame.MorphPad = s.morphEngine.GeneratePadding(paddingSize)
			frame.Flags |= FlagMorphPadded
		}

		// Apply timing delay
		delay := s.morphEngine.CalculateDelay()
		if delay > 0 {
			time.Sleep(delay)
		}
	}

	// Serialize frame
	plaintext, err := frame.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}

	// Version byte is additional data (authenticated but not encrypted)
	ad := []byte{frame.Version}
	ciphertext := s.cipher.Encrypt(plaintext[1:], ad)

	// Wire format: [version(1)][length(4)][ciphertext(variable)]
	ctLen := len(ciphertext)
	wire := make([]byte, 1+4+ctLen)
	wire[0] = frame.Version
	wire[1] = byte(ctLen >> 24)
	wire[2] = byte(ctLen >> 16)
	wire[3] = byte(ctLen >> 8)
	wire[4] = byte(ctLen)
	copy(wire[5:], ciphertext)

	_, err = s.conn.Write(wire)
	if err != nil {
		return fmt.Errorf("write frame: %w", err)
	}

	return nil
}

// readLoop continuously reads and processes incoming frames.
func (s *Session) readLoop(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf("[session:%x] readLoop panic: %v", s.id[:4], r)
		}
		s.handleDisconnect(nil)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read version byte
		versionBuf := make([]byte, 1)
		if _, err := io.ReadFull(s.conn, versionBuf); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.logger.Printf("[session:%x] read error: %v", s.id[:4], err)
			s.handleDisconnect(err)
			return
		}

		version := versionBuf[0]
		if version != ProtocolVersion {
			s.logger.Printf("[session:%x] invalid version: %d", s.id[:4], version)
			continue
		}

		// Read length prefix (4 bytes)
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(s.conn, lenBuf); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.handleDisconnect(err)
			return
		}

		frameLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
		if frameLen <= 0 || frameLen > MaxPayloadSize+AuthTagSize+FrameHeaderSize {
			s.logger.Printf("[session:%x] invalid frame length: %d", s.id[:4], frameLen)
			s.handleDisconnect(fmt.Errorf("invalid frame length: %d", frameLen))
			return
		}

		// Read encrypted frame data
		encData := make([]byte, frameLen)
		if _, err := io.ReadFull(s.conn, encData); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.handleDisconnect(err)
			return
		}

		// Decrypt
		ad := []byte{version}
		plaintext, err := s.cipher.Decrypt(encData, ad)
		if err != nil {
			s.logger.Printf("[session:%x] decryption failed: %v", s.id[:4], err)
			continue
		}

		// Reconstruct full frame bytes (version + decrypted rest)
		fullFrame := make([]byte, 1+len(plaintext))
		fullFrame[0] = version
		copy(fullFrame[1:], plaintext)

		// Parse frame
		frame := &Frame{}
		if err := frame.UnmarshalBinary(fullFrame); err != nil {
			s.logger.Printf("[session:%x] unmarshal error: %v", s.id[:4], err)
			continue
		}

		// Convert frame → mux message and route
		msg := s.frameToMuxMessage(frame)
		if err := s.mux.HandleMessage(msg); err != nil {
			s.logger.Printf("[session:%x] handle message error: %v", s.id[:4], err)
		}
	}
}

// keepaliveLoop sends periodic keepalive frames.
func (s *Session) keepaliveLoop(ctx context.Context) {
	ticker := time.NewTicker(s.keepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.state.IsEstablished() {
				if err := s.sendFrame(NewKeepaliveFrame()); err != nil {
					s.logger.Printf("[session:%x] keepalive error: %v", s.id[:4], err)
				}
			}
		}
	}
}

// handleDisconnect handles an unexpected disconnect.
func (s *Session) handleDisconnect(err error) {
	if s.state.IsClosed() {
		return
	}

	s.state.Transition(SessionClosing, "disconnect")
	s.mux.Close()
	s.conn.Close()
	s.state.Transition(SessionClosed, "disconnected")

	if s.onClose != nil {
		s.onClose(err)
	}

	s.logger.Printf("[session:%x] disconnected: %v", s.id[:4], err)
}
