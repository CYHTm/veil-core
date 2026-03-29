package api

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEventTypeString(t *testing.T) {
	tests := []struct {
		et   EventType
		want string
	}{
		{EventConnecting, "CONNECTING"},
		{EventConnected, "CONNECTED"},
		{EventDisconnected, "DISCONNECTED"},
		{EventHandshakeOK, "HANDSHAKE_OK"},
		{EventHandshakeFail, "HANDSHAKE_FAIL"},
		{EventStreamOpened, "STREAM_OPENED"},
		{EventStreamClosed, "STREAM_CLOSED"},
		{EventError, "ERROR"},
		{EventType(0xFFFF), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.et.String(); got != tt.want {
			t.Errorf("EventType(%d).String() = %s, want %s", tt.et, got, tt.want)
		}
	}
}

func TestEventBusOn(t *testing.T) {
	eb := NewEventBus(64)
	defer eb.Close()

	var received int32
	eb.On(EventConnected, func(e Event) {
		atomic.AddInt32(&received, 1)
	})

	eb.Emit(Event{Type: EventConnected})
	time.Sleep(50 * time.Millisecond)

	if atomic.LoadInt32(&received) != 1 {
		t.Fatalf("expected 1 event, got %d", received)
	}
}

func TestEventBusOnAll(t *testing.T) {
	eb := NewEventBus(64)
	defer eb.Close()

	var received int32
	eb.OnAll(func(e Event) {
		atomic.AddInt32(&received, 1)
	})

	eb.Emit(Event{Type: EventConnected})
	eb.Emit(Event{Type: EventDisconnected})
	eb.Emit(Event{Type: EventError})
	time.Sleep(50 * time.Millisecond)

	if atomic.LoadInt32(&received) != 3 {
		t.Fatalf("expected 3 events, got %d", received)
	}
}

func TestEventBusEmitSync(t *testing.T) {
	eb := NewEventBus(64)
	defer eb.Close()

	received := false
	eb.On(EventConnected, func(e Event) {
		received = true
	})

	eb.EmitSync(Event{Type: EventConnected})
	// EmitSync is synchronous — no need to sleep
	if !received {
		t.Fatal("EmitSync did not call handler")
	}
}

func TestEventBusTimestamp(t *testing.T) {
	eb := NewEventBus(64)
	defer eb.Close()

	var got time.Time
	eb.On(EventConnected, func(e Event) {
		got = e.Timestamp
	})

	before := time.Now()
	eb.Emit(Event{Type: EventConnected})
	time.Sleep(50 * time.Millisecond)

	if got.Before(before) {
		t.Fatal("timestamp should be set by Emit")
	}
}

func TestEventBusMultipleHandlers(t *testing.T) {
	eb := NewEventBus(64)
	defer eb.Close()

	var count int32
	for i := 0; i < 5; i++ {
		eb.On(EventError, func(e Event) {
			atomic.AddInt32(&count, 1)
		})
	}

	eb.Emit(Event{Type: EventError})
	time.Sleep(50 * time.Millisecond)

	if atomic.LoadInt32(&count) != 5 {
		t.Fatalf("expected 5 handler calls, got %d", count)
	}
}

func TestEventBusNoMatchingHandler(t *testing.T) {
	eb := NewEventBus(64)
	defer eb.Close()

	var received int32
	eb.On(EventConnected, func(e Event) {
		atomic.AddInt32(&received, 1)
	})

	// Emit different event type — handler should NOT fire
	eb.Emit(Event{Type: EventDisconnected})
	time.Sleep(50 * time.Millisecond)

	if atomic.LoadInt32(&received) != 0 {
		t.Fatalf("expected 0 events, got %d", received)
	}
}

func TestEventBusConcurrent(t *testing.T) {
	eb := NewEventBus(1024)
	defer eb.Close()

	var count int32
	eb.On(EventConnected, func(e Event) {
		atomic.AddInt32(&count, 1)
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			eb.Emit(Event{Type: EventConnected})
		}()
	}
	wg.Wait()
	time.Sleep(100 * time.Millisecond)

	got := atomic.LoadInt32(&count)
	if got != 100 {
		t.Fatalf("expected 100 events, got %d", got)
	}
}

func TestEventBusBufferFull(t *testing.T) {
	eb := NewEventBus(2) // Very small buffer
	defer eb.Close()

	// Block the dispatch loop
	var mu sync.Mutex
	mu.Lock()
	eb.On(EventConnected, func(e Event) {
		mu.Lock()
		mu.Unlock()
	})

	// Fill buffer — should not panic
	for i := 0; i < 100; i++ {
		eb.Emit(Event{Type: EventConnected})
	}

	mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	// No crash = pass
}
