package crypto

import (
	"testing"
	"time"
)

func TestRateLimiterAllowFirst(t *testing.T) {
	rl := NewRateLimiter(10, 5)

	if !rl.Allow("client1") {
		t.Fatal("first request should be allowed")
	}
}

func TestRateLimiterBurst(t *testing.T) {
	rl := NewRateLimiter(1, 5)

	// Burst of 5 should all pass
	for i := 0; i < 5; i++ {
		if !rl.Allow("client1") {
			t.Fatalf("burst request %d should be allowed", i+1)
		}
	}

	// 6th should be denied (burst exceeded, no time to refill)
	if rl.Allow("client1") {
		t.Fatal("should be rate limited after burst")
	}
}

func TestRateLimiterRefill(t *testing.T) {
	rl := NewRateLimiter(100, 1) // 100 tokens/sec, burst 1

	// Use up the burst
	rl.Allow("client1")
	if rl.Allow("client1") {
		t.Fatal("should be limited immediately")
	}

	// Wait for refill
	time.Sleep(50 * time.Millisecond)

	if !rl.Allow("client1") {
		t.Fatal("should be allowed after refill")
	}
}

func TestRateLimiterDifferentKeys(t *testing.T) {
	rl := NewRateLimiter(1, 1)

	rl.Allow("client1")
	// client1 is now exhausted

	// client2 should still work (separate bucket)
	if !rl.Allow("client2") {
		t.Fatal("different client should have separate bucket")
	}
}

func TestRateLimiterMaxTokens(t *testing.T) {
	rl := NewRateLimiter(1000, 3)

	// Wait to accumulate tokens
	time.Sleep(100 * time.Millisecond)

	// Even with time passed, max is burst (3)
	count := 0
	for i := 0; i < 10; i++ {
		if rl.Allow("client1") {
			count++
		}
	}

	if count > 4 { // burst + maybe 1 refilled
		t.Fatalf("should not exceed burst + small refill, got %d", count)
	}
}

func TestRateLimiterCleanOld(t *testing.T) {
	rl := NewRateLimiter(1, 5)
	rl.cleanup = 10 * time.Millisecond

	rl.Allow("old-client")

	// Manually set old timestamp
	rl.mu.Lock()
	rl.buckets["old-client"].lastCheck = time.Now().Add(-1 * time.Hour)
	rl.mu.Unlock()

	rl.cleanOld()

	rl.mu.Lock()
	_, exists := rl.buckets["old-client"]
	rl.mu.Unlock()

	if exists {
		t.Fatal("old bucket should have been cleaned")
	}
}
