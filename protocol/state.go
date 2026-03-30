// Package protocol implements the Veil wire protocol.
//
// This file defines the session state machine with transitions
// between handshake, established, and teardown phases.
package protocol

import (
	"errors"
	"fmt"
	"sync"
)

var (
	ErrInvalidTransition = errors.New("veil: invalid state transition")
)

// StateMachine manages session state transitions.
type StateMachine struct {
	mu      sync.RWMutex
	current SessionState
	history []StateTransition
}

// StateTransition records a state change.
type StateTransition struct {
	From  SessionState
	To    SessionState
	Event string
}

// Valid state transitions map.
var validTransitions = map[SessionState][]SessionState{
	SessionNew:         {SessionHandshaking, SessionClosed},
	SessionHandshaking: {SessionEstablished, SessionClosed},
	SessionEstablished: {SessionMigrating, SessionClosing, SessionClosed},
	SessionMigrating:   {SessionEstablished, SessionClosing, SessionClosed},
	SessionClosing:     {SessionClosed},
	SessionClosed:      {}, // Terminal state
}

// NewStateMachine creates a new state machine in the initial state.
func NewStateMachine() *StateMachine {
	return &StateMachine{
		current: SessionNew,
		history: make([]StateTransition, 0, 16),
	}
}

// Current returns the current state.
func (sm *StateMachine) Current() SessionState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.current
}

// Transition attempts to move to a new state.
func (sm *StateMachine) Transition(to SessionState, event string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.isValidTransition(sm.current, to) {
		return fmt.Errorf("%w: %s -> %s (event: %s)",
			ErrInvalidTransition,
			sm.current.String(), to.String(), event)
	}

	transition := StateTransition{
		From:  sm.current,
		To:    to,
		Event: event,
	}

	sm.history = append(sm.history, transition)
	sm.current = to

	return nil
}

// IsEstablished returns true if the session is established.
func (sm *StateMachine) IsEstablished() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.current == SessionEstablished
}

// IsClosed returns true if the session is closed or closing.
func (sm *StateMachine) IsClosed() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.current == SessionClosed || sm.current == SessionClosing
}

// History returns all state transitions.
func (sm *StateMachine) History() []StateTransition {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]StateTransition, len(sm.history))
	copy(result, sm.history)
	return result
}

func (sm *StateMachine) isValidTransition(from, to SessionState) bool {
	allowed, ok := validTransitions[from]
	if !ok {
		return false
	}
	for _, s := range allowed {
		if s == to {
			return true
		}
	}
	return false
}

// String returns a human-readable name for the session state.
func (s SessionState) String() string {
	switch s {
	case SessionNew:
		return "NEW"
	case SessionHandshaking:
		return "HANDSHAKING"
	case SessionEstablished:
		return "ESTABLISHED"
	case SessionMigrating:
		return "MIGRATING"
	case SessionClosing:
		return "CLOSING"
	case SessionClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// String returns a human-readable name for the stream state.
func (s StreamState) String() string {
	switch s {
	case StreamIdle:
		return "IDLE"
	case StreamOpen:
		return "OPEN"
	case StreamClosing:
		return "CLOSING"
	case StreamClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}
