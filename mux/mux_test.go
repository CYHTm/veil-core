package mux

import (
	"sync"
	"testing"
)

func TestOpenStream(t *testing.T) {
	sent := make([]*Message, 0)
	var mu sync.Mutex

	m := NewMux(256, func(msg *Message) error {
		mu.Lock()
		sent = append(sent, msg)
		mu.Unlock()
		return nil
	})

	stream, err := m.OpenStream("google.com:443")
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	if stream.ID() == 0 {
		t.Error("stream ID should not be 0")
	}

	if m.ActiveStreams() != 1 {
		t.Errorf("active streams: got %d, want 1", m.ActiveStreams())
	}

	// Должен быть отправлен MsgStreamOpen
	mu.Lock()
	if len(sent) != 1 || sent[0].Type != MsgStreamOpen {
		t.Error("expected StreamOpen message")
	}
	mu.Unlock()
}

func TestStreamWriteRead(t *testing.T) {
	var mu sync.Mutex
	sent := make([]*Message, 0)

	m := NewMux(256, func(msg *Message) error {
		mu.Lock()
		sent = append(sent, msg)
		mu.Unlock()
		return nil
	})

	stream, _ := m.OpenStream("test:80")

	// Пишем данные
	data := []byte("Hello from stream!")
	n, err := stream.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write: got %d, want %d", n, len(data))
	}

	// Имитируем входящие данные
	stream.receiveData([]byte("Response!"))

	buf := make([]byte, 100)
	n, err = stream.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf[:n]) != "Response!" {
		t.Errorf("Read: got %q, want 'Response!'", string(buf[:n]))
	}
}

func TestStreamClose(t *testing.T) {
	m := NewMux(256, func(msg *Message) error { return nil })

	stream, _ := m.OpenStream("test:80")
	id := stream.ID()

	stream.Close()

	if m.ActiveStreams() != 0 {
		t.Error("stream should be removed after close")
	}

	_, ok := m.GetStream(id)
	if ok {
		t.Error("closed stream should not be found")
	}
}

func TestMaxStreams(t *testing.T) {
	m := NewMux(2, func(msg *Message) error { return nil })

	_, err1 := m.OpenStream("a:80")
	_, err2 := m.OpenStream("b:80")
	_, err3 := m.OpenStream("c:80") // Должен провалиться

	if err1 != nil || err2 != nil {
		t.Error("first two streams should succeed")
	}
	if err3 == nil {
		t.Error("third stream should fail (max=2)")
	}
}

func TestMuxClose(t *testing.T) {
	m := NewMux(256, func(msg *Message) error { return nil })

	m.OpenStream("a:80")
	m.OpenStream("b:80")

	m.Close()

	if m.ActiveStreams() != 0 {
		t.Error("all streams should be closed")
	}

	_, err := m.OpenStream("c:80")
	if err == nil {
		t.Error("should not open stream on closed mux")
	}
}

func TestHandleIncomingStream(t *testing.T) {
	opened := make(chan string, 1)

	m := NewMux(256, func(msg *Message) error { return nil })
	m.SetStreamOpenHandler(func(id uint16, addr string) {
		opened <- addr
	})

	// Имитируем входящий STREAM_OPEN
	m.HandleMessage(&Message{
		Type:     MsgStreamOpen,
		StreamID: 100,
		Payload:  []byte("remote:443"),
	})

	addr := <-opened
	if addr != "remote:443" {
		t.Errorf("got %q, want 'remote:443'", addr)
	}

	if m.ActiveStreams() != 1 {
		t.Error("incoming stream should be tracked")
	}
}
