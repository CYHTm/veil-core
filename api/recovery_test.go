package api

import (
	"errors"
	"sync"
	"testing"
)

func TestClassifyErrorTransient(t *testing.T) {
	tests := []error{
		errors.New("connection reset"),
		errors.New("timeout"),
		errors.New("EOF"),
		nil,
	}
	for _, err := range tests {
		if ClassifyError(err) != ErrTransient {
			t.Fatalf("expected ErrTransient for: %v", err)
		}
	}
}

func TestClassifyErrorAuth(t *testing.T) {
	tests := []string{
		"handshake failed: bad key",
		"AEAD authentication failed",
		"wrong secret provided",
		"invalid key length",
		"trigger rejected by server",
	}
	for _, msg := range tests {
		if ClassifyError(errors.New(msg)) != ErrAuth {
			t.Fatalf("expected ErrAuth for: %s", msg)
		}
	}
}

func TestClassifyErrorProtocol(t *testing.T) {
	tests := []string{
		"unsupported protocol version",
		"invalid frame received",
		"unknown cipher suite",
	}
	for _, msg := range tests {
		if ClassifyError(errors.New(msg)) != ErrProtocol {
			t.Fatalf("expected ErrProtocol for: %s", msg)
		}
	}
}

func TestPanicRecovery(t *testing.T) {
	var logged string
	logger := &mockLogger{fn: func(format string, args ...interface{}) {
		logged = format
	}}

	// Should not crash
	PanicRecovery("test", logger, func() {
		panic("boom")
	})

	if logged == "" {
		t.Fatal("panic should have been logged")
	}
}

func TestPanicRecoveryNoPanic(t *testing.T) {
	executed := false
	PanicRecovery("test", nil, func() {
		executed = true
	})
	if !executed {
		t.Fatal("function should have executed")
	}
}

type mockLogger struct {
	fn func(string, ...interface{})
}

func (m *mockLogger) Printf(format string, args ...interface{}) {
	m.fn(format, args...)
}

func TestErrorAggregator(t *testing.T) {
	ea := &ErrorAggregator{}

	ea.Add(nil) // should be ignored
	ea.Add(errors.New("err1"))
	ea.Add(errors.New("err2"))

	if len(ea.Errors()) != 2 {
		t.Fatalf("expected 2 errors, got %d", len(ea.Errors()))
	}

	combined := ea.Error()
	if combined == nil {
		t.Fatal("expected combined error")
	}
}

func TestErrorAggregatorEmpty(t *testing.T) {
	ea := &ErrorAggregator{}
	if ea.Error() != nil {
		t.Fatal("expected nil error when empty")
	}
	if len(ea.Errors()) != 0 {
		t.Fatal("expected empty errors list")
	}
}

func TestErrorAggregatorConcurrent(t *testing.T) {
	ea := &ErrorAggregator{}
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ea.Add(errors.New("err"))
		}()
	}
	wg.Wait()

	if len(ea.Errors()) != 100 {
		t.Fatalf("expected 100 errors, got %d", len(ea.Errors()))
	}
}
