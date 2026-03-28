// Package mux implements stream multiplexing for Veil.
//
// Multiple logical streams (each representing a proxied connection)
// are multiplexed over a single Veil session. This reduces the
// number of underlying transport connections and makes traffic
// analysis harder.
//
// IMPORTANT: This package has ZERO dependencies on protocol/ to avoid
// import cycles. The session layer translates between mux messages
// and protocol frames.
package mux

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

var (
	ErrMaxStreamsReached = errors.New("veil/mux: maximum streams reached")
	ErrStreamClosed     = errors.New("veil/mux: stream is closed")
	ErrMuxClosed        = errors.New("veil/mux: multiplexer is closed")
	ErrStreamNotFound   = errors.New("veil/mux: stream not found")
	ErrBufferFull       = errors.New("veil/mux: stream buffer full")
)

// MessageType represents internal mux message types.
type MessageType uint8

const (
	MsgStreamOpen  MessageType = 1
	MsgStreamData  MessageType = 2
	MsgStreamClose MessageType = 3
	MsgKeepalive   MessageType = 4
	MsgSessionClose MessageType = 5
)

// Message is the unit of communication between mux and the session layer.
// The session layer converts these to/from protocol frames.
type Message struct {
	Type     MessageType
	StreamID uint16
	SeqNum   uint32
	Payload  []byte
	Final    bool
}

// Mux multiplexes multiple streams over a single session.
type Mux struct {
	mu         sync.RWMutex
	streams    map[uint16]*Stream
	nextID     uint32 // Atomic
	maxStreams uint16
	closed     int32  // Atomic

	// Callback: send a message out through the session layer
	onMessage func(*Message) error

	// Callback: a remote side opened a new stream
	onStreamOpen func(streamID uint16, targetAddr string)
}

// NewMux creates a new multiplexer.
// onMessage is called when a message needs to be sent to the remote side.
func NewMux(maxStreams uint16, onMessage func(*Message) error) *Mux {
	return &Mux{
		streams:    make(map[uint16]*Stream),
		maxStreams: maxStreams,
		onMessage:  onMessage,
	}
}

// SetStreamOpenHandler sets the handler called when a remote side opens a stream.
func (m *Mux) SetStreamOpenHandler(handler func(streamID uint16, targetAddr string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onStreamOpen = handler
}

// OpenStream creates a new outgoing stream to the given target address.
func (m *Mux) OpenStream(targetAddr string) (*Stream, error) {
	if atomic.LoadInt32(&m.closed) == 1 {
		return nil, ErrMuxClosed
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if uint16(len(m.streams)) >= m.maxStreams {
		return nil, ErrMaxStreamsReached
	}

	id := uint16(atomic.AddUint32(&m.nextID, 1))
	stream := newStream(id, m)
	m.streams[id] = stream

	// Send stream open message
	msg := &Message{
		Type:     MsgStreamOpen,
		StreamID: id,
		Payload:  []byte(targetAddr),
	}
	if err := m.onMessage(msg); err != nil {
		delete(m.streams, id)
		return nil, err
	}

	return stream, nil
}

// GetStream returns a stream by ID (used by session layer for proxying).
func (m *Mux) GetStream(id uint16) (*Stream, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.streams[id]
	return s, ok
}

// HandleMessage processes an incoming message and routes it to the correct stream.
// Called by the session layer after converting a protocol frame to a Message.
func (m *Mux) HandleMessage(msg *Message) error {
	switch msg.Type {
	case MsgStreamOpen:
		return m.handleStreamOpen(msg)
	case MsgStreamData:
		return m.handleStreamData(msg)
	case MsgStreamClose:
		return m.handleStreamClose(msg)
	case MsgKeepalive:
		return nil // No-op
	case MsgSessionClose:
		return m.Close()
	default:
		return nil
	}
}

func (m *Mux) handleStreamOpen(msg *Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := msg.StreamID
	stream := newStream(id, m)
	m.streams[id] = stream

	if m.onStreamOpen != nil {
		go m.onStreamOpen(id, string(msg.Payload))
	}

	return nil
}

func (m *Mux) handleStreamData(msg *Message) error {
	m.mu.RLock()
	stream, ok := m.streams[msg.StreamID]
	m.mu.RUnlock()

	if !ok {
		return ErrStreamNotFound
	}

	return stream.receiveData(msg.Payload)
}

func (m *Mux) handleStreamClose(msg *Message) error {
	m.mu.Lock()
	stream, ok := m.streams[msg.StreamID]
	if ok {
		delete(m.streams, msg.StreamID)
	}
	m.mu.Unlock()

	if ok {
		stream.closeInternal()
	}

	return nil
}

// sendMessage sends a message through the session layer (called by streams).
func (m *Mux) sendMessage(msg *Message) error {
	if atomic.LoadInt32(&m.closed) == 1 {
		return ErrMuxClosed
	}
	return m.onMessage(msg)
}

// removeStream removes a stream from the mux.
func (m *Mux) removeStream(id uint16) {
	m.mu.Lock()
	delete(m.streams, id)
	m.mu.Unlock()
}

// Close closes the multiplexer and all streams.
func (m *Mux) Close() error {
	if !atomic.CompareAndSwapInt32(&m.closed, 0, 1) {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, stream := range m.streams {
		stream.closeInternal()
	}
	m.streams = make(map[uint16]*Stream)

	return nil
}

// ActiveStreams returns the number of active streams.
func (m *Mux) ActiveStreams() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.streams)
}

// ============================================================
// Stream
// ============================================================

// Stream represents a single multiplexed stream.
type Stream struct {
	id     uint16
	mux    *Mux
	buf    chan []byte
	closed int32
	seqNum uint32
}

func newStream(id uint16, mux *Mux) *Stream {
	return &Stream{
		id:  id,
		mux: mux,
		buf: make(chan []byte, 256), // Buffered channel
	}
}

// ID returns the stream ID.
func (s *Stream) ID() uint16 {
	return s.id
}

// Write sends data through the stream.
func (s *Stream) Write(data []byte) (int, error) {
	if atomic.LoadInt32(&s.closed) == 1 {
		return 0, ErrStreamClosed
	}

	seq := atomic.AddUint32(&s.seqNum, 1)
	msg := &Message{
		Type:     MsgStreamData,
		StreamID: s.id,
		SeqNum:   seq,
		Payload:  data,
	}

	if err := s.mux.sendMessage(msg); err != nil {
		return 0, err
	}

	return len(data), nil
}

// Read reads data from the stream.
func (s *Stream) Read(p []byte) (int, error) {
	data, ok := <-s.buf
	if !ok {
		return 0, io.EOF
	}

	n := copy(p, data)
	return n, nil
}

// Close closes the stream and notifies the remote side.
func (s *Stream) Close() error {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return nil
	}

	// Send stream close message
	msg := &Message{
		Type:     MsgStreamClose,
		StreamID: s.id,
		Final:    true,
	}

	s.mux.sendMessage(msg)
	s.mux.removeStream(s.id)
	close(s.buf)

	return nil
}

// receiveData adds incoming data to the stream buffer.
func (s *Stream) receiveData(data []byte) error {
	if atomic.LoadInt32(&s.closed) == 1 {
		return ErrStreamClosed
	}

	copied := make([]byte, len(data))
	copy(copied, data)

	select {
	case s.buf <- copied:
		return nil
	default:
		return ErrBufferFull
	}
}

// closeInternal closes the stream without sending a message (called by mux).
func (s *Stream) closeInternal() {
	if atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		close(s.buf)
	}
}

// FlowControl tracks per-stream send/receive windows.
type FlowControl struct {
	mu         sync.Mutex
	sendWindow int64
	recvWindow int64
	maxWindow  int64
	waitCh     chan struct{}
}

// NewFlowControl creates flow control with given window size.
func NewFlowControl(windowSize int64) *FlowControl {
	return &FlowControl{
		sendWindow: windowSize,
		recvWindow: windowSize,
		maxWindow:  windowSize,
		waitCh:     make(chan struct{}, 1),
	}
}

// ConsumeSend blocks until there is send window available.
func (fc *FlowControl) ConsumeSend(n int64) {
	for {
		fc.mu.Lock()
		if fc.sendWindow >= n {
			fc.sendWindow -= n
			fc.mu.Unlock()
			return
		}
		fc.mu.Unlock()
		<-fc.waitCh
	}
}

// ReleaseSend adds back to send window (when peer ACKs).
func (fc *FlowControl) ReleaseSend(n int64) {
	fc.mu.Lock()
	fc.sendWindow += n
	if fc.sendWindow > fc.maxWindow {
		fc.sendWindow = fc.maxWindow
	}
	fc.mu.Unlock()
	select {
	case fc.waitCh <- struct{}{}:
	default:
	}
}

// ConsumeRecv decrements receive window.
func (fc *FlowControl) ConsumeRecv(n int64) bool {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.recvWindow < n {
		return false
	}
	fc.recvWindow -= n
	return true
}

// ReleaseRecv adds back to receive window.
func (fc *FlowControl) ReleaseRecv(n int64) {
	fc.mu.Lock()
	fc.recvWindow += n
	if fc.recvWindow > fc.maxWindow {
		fc.recvWindow = fc.maxWindow
	}
	fc.mu.Unlock()
}

// SendWindow returns current send window.
func (fc *FlowControl) SendWindow() int64 {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.sendWindow
}
