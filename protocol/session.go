// Package protocol implements the Veil wire protocol.
//
// This file manages encrypted sessions including frame encryption,
// decryption, multiplexed streams, and replay protection.
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

type Session struct {
	mu sync.RWMutex

	id    [16]byte
	role  HandshakeRole
	state *StateMachine
	sendSeq uint32 // global sequence counter for replay protection

	conn      transport.Connection
	transport transport.Transport

	cipher       *veilcrypto.SessionCipher
	replayFilter *veilcrypto.ReplayFilter

	mux         *mux.Mux
	morphEngine *morph.Engine
	timing      *morph.TimingEngine

	keepaliveInterval time.Duration
	keepaliveCancel   context.CancelFunc

	onStreamOpen func(streamID uint16, targetAddr string)
	onClose      func(error)

	logger *log.Logger
}

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

func NewSession(cfg SessionConfig) (*Session, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.KeepaliveInterval == 0 {
		cfg.KeepaliveInterval = KeepaliveInterval
	}

	hr := cfg.HandshakeResult

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
		replayFilter:      veilcrypto.NewReplayFilter(),
		keepaliveInterval: cfg.KeepaliveInterval,
		onStreamOpen:      cfg.OnStreamOpen,
		onClose:           cfg.OnClose,
		logger:            cfg.Logger,
	}
	copy(s.id[:], hr.SessionID[:])

	if cfg.MorphProfile != nil {
		s.morphEngine = morph.NewEngine(cfg.MorphProfile)
		s.timing = morph.NewTimingEngine(&cfg.MorphProfile.Timing)
	}

	maxStreams := hr.PeerCapabilities.MaxStreams
	if maxStreams == 0 {
		maxStreams = 256
	}
	s.mux = mux.NewMux(maxStreams, s.handleMuxMessage)

	if cfg.OnStreamOpen != nil {
		s.mux.SetStreamOpenHandler(cfg.OnStreamOpen)
	}

	s.state.Transition(SessionHandshaking, "session_create")
	s.state.Transition(SessionEstablished, "handshake_complete")

	return s, nil
}

func (s *Session) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.keepaliveCancel = cancel

	go s.readLoop(ctx)
	go s.keepaliveLoop(ctx)

	s.logger.Printf("[session:%x] started (role=%d, transport=%s)",
		s.id[:4], s.role, s.conn.TransportID())
}

func (s *Session) OpenStream(targetAddr string) (*mux.Stream, error) {
	if !s.state.IsEstablished() {
		return nil, ErrSessionClosed
	}
	return s.mux.OpenStream(targetAddr)
}

func (s *Session) GetMux() *mux.Mux {
	return s.mux
}

func (s *Session) Close() error {
	if s.state.IsClosed() {
		return nil
	}

	s.state.Transition(SessionClosing, "close_requested")
	s.sendFrame(NewSessionCloseFrame())

	if s.keepaliveCancel != nil {
		s.keepaliveCancel()
	}

	s.mux.Close()
	s.conn.Close()
	s.state.Transition(SessionClosed, "closed")

	s.logger.Printf("[session:%x] closed", s.id[:4])
	return nil
}

func (s *Session) ID() [16]byte      { return s.id }
func (s *Session) State() SessionState { return s.state.Current() }
func (s *Session) ActiveStreams() int  { return s.mux.ActiveStreams() }

// Bridge: mux.Message <-> protocol.Frame

func (s *Session) handleMuxMessage(msg *mux.Message) error {
	frame := s.muxMessageToFrame(msg)
	return s.sendFrame(frame)
}

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

// Wire I/O

func (s *Session) sendFrame(frame *Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Global session-wide seq number prevents replay false positives across streams
	s.sendSeq++
	frame.SeqNum = s.sendSeq

	// Apply morph padding and timing
	if s.morphEngine != nil && frame.Type == FrameStreamData {
		paddingSize := s.morphEngine.CalculatePadding(len(frame.Payload))
		if paddingSize > 0 {
			frame.MorphPad = s.morphEngine.GeneratePadding(paddingSize)
			frame.Flags |= FlagMorphPadded
		}

		// Use real TimingEngine instead of basic delay
		if s.timing != nil {
			delay := s.timing.NextDelay()
			if delay > 0 {
				time.Sleep(delay)
			}
		}
	}

	plaintext, err := frame.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}

	ad := []byte{frame.Version}
	ciphertext := s.cipher.Encrypt(plaintext[1:], ad)

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
			s.handleDisconnect(err)
			return
		}

		version := versionBuf[0]
		if version != ProtocolVersion {
			s.logger.Printf("[session:%x] invalid version: %d", s.id[:4], version)
			continue
		}

		// Read length prefix
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
			s.handleDisconnect(fmt.Errorf("invalid frame length: %d", frameLen))
			return
		}

		// Read encrypted data
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
			s.logger.Printf("[session:%x] decryption failed (possible tamper/replay)", s.id[:4])
			continue
		}

		// Reconstruct frame
		fullFrame := make([]byte, 1+len(plaintext))
		fullFrame[0] = version
		copy(fullFrame[1:], plaintext)

		frame := &Frame{}
		if err := frame.UnmarshalBinary(fullFrame); err != nil {
			s.logger.Printf("[session:%x] unmarshal error: %v", s.id[:4], err)
			continue
		}

		// Replay protection: check sequence number
		if frame.SeqNum > 0 {
			if !s.replayFilter.Check(uint64(frame.SeqNum)) {
				s.logger.Printf("[session:%x] REPLAY DETECTED seq=%d — dropping frame",
					s.id[:4], frame.SeqNum)
				continue
			}
		}

		// Route to mux
		msg := s.frameToMuxMessage(frame)
		if err := s.mux.HandleMessage(msg); err != nil {
			s.logger.Printf("[session:%x] handle message error: %v", s.id[:4], err)
		}
	}
}

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
