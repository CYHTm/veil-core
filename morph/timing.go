// Package morph — timing.go implements the Timing Jitter Engine.
//
// This engine adds realistic timing variations to packet transmission
// to defeat timing-based traffic analysis. It can simulate:
//   - User think time (pauses between actions)
//   - Network jitter (variable latency)
//   - Application-specific patterns (burst downloads, streaming cadence)
//   - TCP slow start behavior
package morph

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

// TimingEngine controls inter-packet delays to mimic real traffic.
type TimingEngine struct {
	mu      sync.RWMutex
	profile *TimingProfile
	rng     *rand.Rand

	// State tracking
	packetCount    uint64
	burstRemaining int
	inBurst        bool
	lastSendTime   time.Time
}

// NewTimingEngine creates a new timing engine.
func NewTimingEngine(profile *TimingProfile) *TimingEngine {
	return &TimingEngine{
		profile:      profile,
		rng:          rand.New(rand.NewSource(time.Now().UnixNano())),
		lastSendTime: time.Now(),
	}
}

// NextDelay calculates the delay before sending the next packet.
func (te *TimingEngine) NextDelay() time.Duration {
	te.mu.Lock()
	defer te.mu.Unlock()

	if te.profile == nil {
		return 0
	}

	te.packetCount++

	// Are we in a burst?
	if te.inBurst {
		te.burstRemaining--
		if te.burstRemaining <= 0 {
			te.inBurst = false
			// Inter-burst gap
			return te.jitteredDelay(float64(te.profile.BurstGapMs))
		}
		// Intra-burst: minimal delay
		return te.jitteredDelay(float64(te.profile.MinDelayMs))
	}

	// Should we start a new burst?
	if te.profile.BurstSize > 0 && te.rng.Float64() < 0.3 {
		te.inBurst = true
		te.burstRemaining = te.profile.BurstSize + te.rng.Intn(te.profile.BurstSize/2+1)
		return te.jitteredDelay(float64(te.profile.MinDelayMs))
	}

	// Normal packet: gaussian around mean
	return te.jitteredDelay(te.profile.MeanDelayMs)
}

// SimulateThinkTime returns a longer delay simulating user think time.
// Used between logical "actions" (e.g., page loads).
func (te *TimingEngine) SimulateThinkTime() time.Duration {
	te.mu.Lock()
	defer te.mu.Unlock()

	// Think time: 0.5 - 5 seconds, exponentially distributed
	lambda := 1.0 / 2000.0 // mean 2 seconds
	delay := -math.Log(1.0-te.rng.Float64()) / lambda
	if delay > 5000 {
		delay = 5000
	}
	if delay < 500 {
		delay = 500
	}

	return time.Duration(delay) * time.Millisecond
}

// SimulateSlowStart simulates TCP slow start behavior.
// Returns delays that decrease over the first N packets.
func (te *TimingEngine) SimulateSlowStart(packetIndex int) time.Duration {
	te.mu.Lock()
	defer te.mu.Unlock()

	if packetIndex > 20 {
		return 0 // Past slow start
	}

	// Exponential decrease
	baseDelay := 100.0 * math.Exp(-0.2*float64(packetIndex))
	return te.jitteredDelay(baseDelay)
}

// jitteredDelay adds gaussian jitter to a base delay.
func (te *TimingEngine) jitteredDelay(baseMs float64) time.Duration {
	jitter := te.rng.NormFloat64() * te.profile.JitterMs
	delay := baseMs + jitter

	if delay < float64(te.profile.MinDelayMs) {
		delay = float64(te.profile.MinDelayMs)
	}
	if delay > float64(te.profile.MaxDelayMs) {
		delay = float64(te.profile.MaxDelayMs)
	}

	return time.Duration(delay) * time.Millisecond
}

// UpdateProfile changes the timing profile dynamically.
func (te *TimingEngine) UpdateProfile(profile *TimingProfile) {
	te.mu.Lock()
	defer te.mu.Unlock()
	te.profile = profile
}

// Reset resets the engine state (e.g., after transport migration).
func (te *TimingEngine) Reset() {
	te.mu.Lock()
	defer te.mu.Unlock()
	te.packetCount = 0
	te.burstRemaining = 0
	te.inBurst = false
	te.lastSendTime = time.Now()
}
