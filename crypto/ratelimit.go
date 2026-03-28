package crypto

import (
	"sync"
	"time"
)

// RateLimiter protects against brute-force attacks on triggers and handshakes.
// Uses token bucket algorithm per source IP.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // Tokens per second
	burst   int     // Max tokens
	cleanup time.Duration
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

// NewRateLimiter creates a limiter. Example: rate=1, burst=5 means
// 1 attempt per second, burst of 5 rapid attempts allowed.
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
		cleanup: 5 * time.Minute,
	}

	// Cleanup old entries periodically
	go func() {
		ticker := time.NewTicker(rl.cleanup)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanOld()
		}
	}()

	return rl
}

// Allow returns true if the request from this key should be allowed.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, exists := rl.buckets[key]
	now := time.Now()

	if !exists {
		rl.buckets[key] = &bucket{
			tokens:    float64(rl.burst) - 1,
			lastCheck: now,
		}
		return true
	}

	// Add tokens based on elapsed time
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastCheck = now

	if b.tokens < 1 {
		return false // Rate limited
	}

	b.tokens--
	return true
}

func (rl *RateLimiter) cleanOld() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.cleanup)
	for key, b := range rl.buckets {
		if b.lastCheck.Before(cutoff) {
			delete(rl.buckets, key)
		}
	}
}
