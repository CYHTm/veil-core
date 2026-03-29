package protocol

import (
	"testing"
)

func TestNewStateMachine(t *testing.T) {
	sm := NewStateMachine()
	if sm.Current() != SessionNew {
		t.Fatalf("expected SessionNew, got %s", sm.Current().String())
	}
}

func TestStateMachineValidTransitions(t *testing.T) {
	sm := NewStateMachine()

	steps := []struct {
		to    SessionState
		event string
	}{
		{SessionHandshaking, "start_handshake"},
		{SessionEstablished, "handshake_ok"},
		{SessionClosing, "close_requested"},
		{SessionClosed, "closed"},
	}

	for _, step := range steps {
		if err := sm.Transition(step.to, step.event); err != nil {
			t.Fatalf("transition to %s failed: %v", step.to.String(), err)
		}
		if sm.Current() != step.to {
			t.Fatalf("expected %s, got %s", step.to.String(), sm.Current().String())
		}
	}
}

func TestStateMachineInvalidTransition(t *testing.T) {
	sm := NewStateMachine()

	// Can't go from New directly to Established
	err := sm.Transition(SessionEstablished, "skip_handshake")
	if err == nil {
		t.Fatal("expected error for invalid transition New -> Established")
	}
}

func TestStateMachineClosedIsTerminal(t *testing.T) {
	sm := NewStateMachine()
	sm.Transition(SessionHandshaking, "start")
	sm.Transition(SessionClosed, "force_close")

	// Can't go anywhere from Closed
	err := sm.Transition(SessionNew, "reopen")
	if err == nil {
		t.Fatal("should not transition from Closed")
	}
	err = sm.Transition(SessionEstablished, "revive")
	if err == nil {
		t.Fatal("should not transition from Closed")
	}
}

func TestStateMachineIsEstablished(t *testing.T) {
	sm := NewStateMachine()

	if sm.IsEstablished() {
		t.Fatal("new session should not be established")
	}

	sm.Transition(SessionHandshaking, "start")
	if sm.IsEstablished() {
		t.Fatal("handshaking should not be established")
	}

	sm.Transition(SessionEstablished, "done")
	if !sm.IsEstablished() {
		t.Fatal("should be established")
	}
}

func TestStateMachineIsClosed(t *testing.T) {
	sm := NewStateMachine()

	if sm.IsClosed() {
		t.Fatal("new session should not be closed")
	}

	sm.Transition(SessionHandshaking, "start")
	sm.Transition(SessionEstablished, "done")
	sm.Transition(SessionClosing, "closing")

	if !sm.IsClosed() {
		t.Fatal("closing should count as closed")
	}

	sm.Transition(SessionClosed, "closed")
	if !sm.IsClosed() {
		t.Fatal("closed should count as closed")
	}
}

func TestStateMachineHistory(t *testing.T) {
	sm := NewStateMachine()
	sm.Transition(SessionHandshaking, "start")
	sm.Transition(SessionEstablished, "done")

	history := sm.History()
	if len(history) != 2 {
		t.Fatalf("expected 2 transitions, got %d", len(history))
	}
	if history[0].From != SessionNew || history[0].To != SessionHandshaking {
		t.Fatal("first transition wrong")
	}
	if history[1].From != SessionHandshaking || history[1].To != SessionEstablished {
		t.Fatal("second transition wrong")
	}
	if history[0].Event != "start" {
		t.Fatalf("expected event 'start', got '%s'", history[0].Event)
	}
}

func TestStateMachineMigration(t *testing.T) {
	sm := NewStateMachine()
	sm.Transition(SessionHandshaking, "start")
	sm.Transition(SessionEstablished, "done")
	sm.Transition(SessionMigrating, "migrate")

	if sm.Current() != SessionMigrating {
		t.Fatal("should be migrating")
	}

	// Can go back to established
	sm.Transition(SessionEstablished, "migrated")
	if !sm.IsEstablished() {
		t.Fatal("should be established after migration")
	}
}

func TestSessionStateString(t *testing.T) {
	tests := []struct {
		state SessionState
		want  string
	}{
		{SessionNew, "NEW"},
		{SessionHandshaking, "HANDSHAKING"},
		{SessionEstablished, "ESTABLISHED"},
		{SessionMigrating, "MIGRATING"},
		{SessionClosing, "CLOSING"},
		{SessionClosed, "CLOSED"},
		{SessionState(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("SessionState(%d).String() = %s, want %s", tt.state, got, tt.want)
		}
	}
}

func TestStreamStateString(t *testing.T) {
	tests := []struct {
		state StreamState
		want  string
	}{
		{StreamIdle, "IDLE"},
		{StreamOpen, "OPEN"},
		{StreamClosing, "CLOSING"},
		{StreamClosed, "CLOSED"},
		{StreamState(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("StreamState(%d).String() = %s, want %s", tt.state, got, tt.want)
		}
	}
}
