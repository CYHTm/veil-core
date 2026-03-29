package api

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultReconnectPolicy(t *testing.T) {
	p := DefaultReconnectPolicy()
	if !p.Enabled {
		t.Fatal("expected enabled")
	}
	if p.MaxAttempts != 0 {
		t.Fatal("expected unlimited attempts")
	}
	if p.BaseDelay != 1*time.Second {
		t.Fatalf("expected 1s base delay, got %v", p.BaseDelay)
	}
	if p.MaxDelay != 60*time.Second {
		t.Fatalf("expected 60s max delay, got %v", p.MaxDelay)
	}
	if p.BackoffFactor != 2.0 {
		t.Fatalf("expected 2.0 backoff, got %f", p.BackoffFactor)
	}
	if !p.Jitter {
		t.Fatal("expected jitter enabled")
	}
}

func TestReconnectorCalculateDelay(t *testing.T) {
	r := NewReconnector(ReconnectPolicy{
		BaseDelay:     100 * time.Millisecond,
		MaxDelay:      10 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        false, // disable jitter for predictable tests
	})

	// attempt 1: 100ms * 2^0 = 100ms
	d1 := r.calculateDelay(1)
	if d1 != 100*time.Millisecond {
		t.Fatalf("attempt 1: expected 100ms, got %v", d1)
	}

	// attempt 2: 100ms * 2^1 = 200ms
	d2 := r.calculateDelay(2)
	if d2 != 200*time.Millisecond {
		t.Fatalf("attempt 2: expected 200ms, got %v", d2)
	}

	// attempt 3: 100ms * 2^2 = 400ms
	d3 := r.calculateDelay(3)
	if d3 != 400*time.Millisecond {
		t.Fatalf("attempt 3: expected 400ms, got %v", d3)
	}
}

func TestReconnectorMaxDelay(t *testing.T) {
	r := NewReconnector(ReconnectPolicy{
		BaseDelay:     100 * time.Millisecond,
		MaxDelay:      500 * time.Millisecond,
		BackoffFactor: 2.0,
		Jitter:        false,
	})

	// attempt 10: 100ms * 2^9 = 51200ms — should be capped at 500ms
	d := r.calculateDelay(10)
	if d != 500*time.Millisecond {
		t.Fatalf("expected capped at 500ms, got %v", d)
	}
}

func TestReconnectorJitter(t *testing.T) {
	r := NewReconnector(ReconnectPolicy{
		BaseDelay:     100 * time.Millisecond,
		MaxDelay:      10 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        true,
	})

	// With jitter, delay should be >= base and < base * 1.3
	d := r.calculateDelay(1)
	if d < 100*time.Millisecond {
		t.Fatalf("delay with jitter too small: %v", d)
	}
	if d > 130*time.Millisecond {
		t.Fatalf("delay with jitter too large: %v", d)
	}
}

func TestReconnectorSuccessOnFirstRetry(t *testing.T) {
	r := NewReconnector(ReconnectPolicy{
		Enabled:       true,
		BaseDelay:     10 * time.Millisecond,
		MaxDelay:      100 * time.Millisecond,
		BackoffFactor: 2.0,
		Jitter:        false,
	})

	var attempts int32
	r.SetHandlers(
		func() error {
			atomic.AddInt32(&attempts, 1)
			return nil // success immediately
		},
		nil,
	)

	r.Trigger()
	time.Sleep(200 * time.Millisecond)

	if atomic.LoadInt32(&attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", attempts)
	}
	if r.Attempt() != 0 {
		t.Fatalf("expected attempt counter reset to 0, got %d", r.Attempt())
	}
}

func TestReconnectorMaxAttempts(t *testing.T) {
	r := NewReconnector(ReconnectPolicy{
		Enabled:       true,
		MaxAttempts:   3,
		BaseDelay:     10 * time.Millisecond,
		MaxDelay:      50 * time.Millisecond,
		BackoffFactor: 1.0,
		Jitter:        false,
	})

	var attempts int32
	r.SetHandlers(
		func() error {
			atomic.AddInt32(&attempts, 1)
			return errors.New("fail")
		},
		nil,
	)

	r.Trigger()
	time.Sleep(500 * time.Millisecond)

	got := atomic.LoadInt32(&attempts)
	if got > 3 {
		t.Fatalf("expected max 3 attempts, got %d", got)
	}
}

func TestReconnectorStop(t *testing.T) {
	r := NewReconnector(ReconnectPolicy{
		Enabled:       true,
		BaseDelay:     50 * time.Millisecond,
		MaxDelay:      1 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        false,
	})

	var attempts int32
	r.SetHandlers(
		func() error {
			atomic.AddInt32(&attempts, 1)
			return errors.New("fail")
		},
		nil,
	)

	r.Trigger()
	time.Sleep(30 * time.Millisecond)
	r.Stop()
	time.Sleep(200 * time.Millisecond)

	got := atomic.LoadInt32(&attempts)
	if got > 2 {
		t.Fatalf("expected reconnector to stop quickly, got %d attempts", got)
	}
}

func TestReconnectorDisabled(t *testing.T) {
	r := NewReconnector(ReconnectPolicy{
		Enabled: false,
	})

	var attempts int32
	r.SetHandlers(
		func() error {
			atomic.AddInt32(&attempts, 1)
			return nil
		},
		nil,
	)

	r.Trigger()
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&attempts) != 0 {
		t.Fatal("disabled reconnector should not attempt")
	}
}
