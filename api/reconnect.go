// Package api provides the high-level client and server API for Veil.
//
// This file implements automatic reconnection with exponential
// backoff and jitter for resilient client connections.
package api

import (
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// ReconnectPolicy controls automatic reconnection behavior.
type ReconnectPolicy struct {
	Enabled       bool
	MaxAttempts   int           // 0 = unlimited
	BaseDelay     time.Duration // Initial delay (default 1s)
	MaxDelay      time.Duration // Maximum delay (default 60s)
	BackoffFactor float64       // Multiplier per attempt (default 2.0)
	Jitter        bool          // Add random jitter to prevent thundering herd
}

// DefaultReconnectPolicy returns sensible defaults.
func DefaultReconnectPolicy() ReconnectPolicy {
	return ReconnectPolicy{
		Enabled:       true,
		MaxAttempts:   0, // unlimited
		BaseDelay:     1 * time.Second,
		MaxDelay:      60 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        true,
	}
}

// Reconnector manages automatic reconnection with exponential backoff.
type Reconnector struct {
	mu       sync.Mutex
	policy   ReconnectPolicy
	attempt  int32
	stopped  int32
	stopCh   chan struct{}
	onReconnect func() error
	onStatus    func(attempt int, delay time.Duration, err error)
}

// NewReconnector creates a reconnector with the given policy.
func NewReconnector(policy ReconnectPolicy) *Reconnector {
	return &Reconnector{
		policy: policy,
		stopCh: make(chan struct{}),
	}
}

// SetHandlers sets the reconnection and status callbacks.
func (r *Reconnector) SetHandlers(onReconnect func() error, onStatus func(int, time.Duration, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onReconnect = onReconnect
	r.onStatus = onStatus
}

// Trigger starts the reconnection loop (call when connection drops).
func (r *Reconnector) Trigger() {
	if !r.policy.Enabled || atomic.LoadInt32(&r.stopped) == 1 {
		return
	}
	go r.reconnectLoop()
}

// Reset resets the attempt counter (call on successful connection).
func (r *Reconnector) Reset() {
	atomic.StoreInt32(&r.attempt, 0)
}

// Stop permanently stops the reconnector.
func (r *Reconnector) Stop() {
	if atomic.CompareAndSwapInt32(&r.stopped, 0, 1) {
		close(r.stopCh)
	}
}

func (r *Reconnector) reconnectLoop() {
	for {
		if atomic.LoadInt32(&r.stopped) == 1 {
			return
		}

		attempt := int(atomic.AddInt32(&r.attempt, 1))

		if r.policy.MaxAttempts > 0 && attempt > r.policy.MaxAttempts {
			if r.onStatus != nil {
				r.onStatus(attempt, 0, nil)
			}
			return
		}

		delay := r.calculateDelay(attempt)

		if r.onStatus != nil {
			r.onStatus(attempt, delay, nil)
		}

		select {
		case <-time.After(delay):
		case <-r.stopCh:
			return
		}

		r.mu.Lock()
		handler := r.onReconnect
		r.mu.Unlock()

		if handler == nil {
			return
		}

		err := handler()
		if err == nil {
			r.Reset()
			return
		}

		if r.onStatus != nil {
			r.onStatus(attempt, delay, err)
		}
	}
}

func (r *Reconnector) calculateDelay(attempt int) time.Duration {
	delay := float64(r.policy.BaseDelay) * math.Pow(r.policy.BackoffFactor, float64(attempt-1))

	if delay > float64(r.policy.MaxDelay) {
		delay = float64(r.policy.MaxDelay)
	}

	if r.policy.Jitter {
		jitter := delay * 0.3 * rand.Float64()
		delay += jitter
	}

	return time.Duration(delay)
}

// Attempt returns current attempt number.
func (r *Reconnector) Attempt() int {
	return int(atomic.LoadInt32(&r.attempt))
}
