// Package api — events.go implements the event system for Veil.
//
// Events allow external applications to react to protocol-level
// occurrences (connection changes, stream opens, errors, etc.)
// without polling.
package api

import (
	"sync"
	"time"
)

// EventType represents a type of Veil event.
type EventType uint16

const (
	EventConnecting       EventType = 0x0001
	EventConnected        EventType = 0x0002
	EventDisconnected     EventType = 0x0003
	EventHandshakeStart   EventType = 0x0004
	EventHandshakeOK      EventType = 0x0005
	EventHandshakeFail    EventType = 0x0006
	EventStreamOpened     EventType = 0x0010
	EventStreamClosed     EventType = 0x0011
	EventStreamError      EventType = 0x0012
	EventTransportMigrate EventType = 0x0020
	EventMorphSync        EventType = 0x0021
	EventKeepalive        EventType = 0x0030
	EventError            EventType = 0x00FF
)

// String returns a human-readable event type name.
func (et EventType) String() string {
	switch et {
	case EventConnecting:
		return "CONNECTING"
	case EventConnected:
		return "CONNECTED"
	case EventDisconnected:
		return "DISCONNECTED"
	case EventHandshakeStart:
		return "HANDSHAKE_START"
	case EventHandshakeOK:
		return "HANDSHAKE_OK"
	case EventHandshakeFail:
		return "HANDSHAKE_FAIL"
	case EventStreamOpened:
		return "STREAM_OPENED"
	case EventStreamClosed:
		return "STREAM_CLOSED"
	case EventStreamError:
		return "STREAM_ERROR"
	case EventTransportMigrate:
		return "TRANSPORT_MIGRATE"
	case EventMorphSync:
		return "MORPH_SYNC"
	case EventKeepalive:
		return "KEEPALIVE"
	case EventError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Event represents a Veil protocol event.
type Event struct {
	Type      EventType
	Timestamp time.Time
	SessionID [16]byte
	StreamID  uint16
	Message   string
	Error     error
	Data      map[string]interface{}
}

// EventHandler is a function that processes an event.
type EventHandler func(Event)

// EventBus manages event subscriptions and dispatch.
type EventBus struct {
	mu       sync.RWMutex
	handlers map[EventType][]EventHandler
	global   []EventHandler // Handlers for ALL events
	buffer   chan Event     // Async event buffer
	done     chan struct{}
}

// NewEventBus creates a new event bus.
func NewEventBus(bufferSize int) *EventBus {
	if bufferSize <= 0 {
		bufferSize = 256
	}

	eb := &EventBus{
		handlers: make(map[EventType][]EventHandler),
		buffer:   make(chan Event, bufferSize),
		done:     make(chan struct{}),
	}

	// Start async dispatch loop
	go eb.dispatchLoop()

	return eb
}

// On registers a handler for a specific event type.
func (eb *EventBus) On(eventType EventType, handler EventHandler) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.handlers[eventType] = append(eb.handlers[eventType], handler)
}

// OnAll registers a handler for all events.
func (eb *EventBus) OnAll(handler EventHandler) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.global = append(eb.global, handler)
}

// Emit sends an event to all matching handlers (async).
func (eb *EventBus) Emit(event Event) {
	event.Timestamp = time.Now()

	select {
	case eb.buffer <- event:
	default:
		// Buffer full, drop event (or log warning)
	}
}

// EmitSync sends an event synchronously (blocks until processed).
func (eb *EventBus) EmitSync(event Event) {
	event.Timestamp = time.Now()
	eb.dispatch(event)
}

// Close shuts down the event bus.
func (eb *EventBus) Close() {
	eb.mu.Lock()
	select {
	case <-eb.done:
		eb.mu.Unlock()
		return // already closed
	default:
	}
	eb.mu.Unlock()
	close(eb.done)
}

func (eb *EventBus) dispatchLoop() {
	for {
		select {
		case event := <-eb.buffer:
			eb.dispatch(event)
		case <-eb.done:
			// Drain remaining events
			for {
				select {
				case event := <-eb.buffer:
					eb.dispatch(event)
				default:
					return
				}
			}
		}
	}
}

func (eb *EventBus) dispatch(event Event) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	// Type-specific handlers
	if handlers, ok := eb.handlers[event.Type]; ok {
		for _, h := range handlers {
			h(event)
		}
	}

	// Global handlers
	for _, h := range eb.global {
		h(event)
	}
}
