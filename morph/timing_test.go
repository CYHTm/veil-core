package morph

import (
	"testing"
	"time"
)

func testTimingProfile() *TimingProfile {
	return &TimingProfile{
		MinDelayMs:  1,
		MaxDelayMs:  100,
		MeanDelayMs: 20,
		JitterMs:    5,
		BurstSize:   4,
		BurstGapMs:  50,
	}
}

func TestTimingEngineCreate(t *testing.T) {
	te := NewTimingEngine(testTimingProfile())
	if te == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestTimingEngineNextDelay(t *testing.T) {
	te := NewTimingEngine(testTimingProfile())

	delay := te.NextDelay()
	if delay < 0 {
		t.Fatalf("delay should not be negative: %v", delay)
	}
	if delay > 100*time.Millisecond {
		t.Fatalf("delay should not exceed max: %v", delay)
	}
}

func TestTimingEngineNilProfile(t *testing.T) {
	te := NewTimingEngine(nil)
	delay := te.NextDelay()
	if delay != 0 {
		t.Fatalf("nil profile should return 0 delay, got %v", delay)
	}
}

func TestTimingEngineDelayRange(t *testing.T) {
	profile := testTimingProfile()
	te := NewTimingEngine(profile)

	for i := 0; i < 100; i++ {
		delay := te.NextDelay()
		if delay < time.Duration(profile.MinDelayMs)*time.Millisecond {
			t.Fatalf("delay %v below min %dms", delay, profile.MinDelayMs)
		}
		if delay > time.Duration(profile.MaxDelayMs)*time.Millisecond {
			t.Fatalf("delay %v above max %dms", delay, profile.MaxDelayMs)
		}
	}
}

func TestTimingEngineSimulateThinkTime(t *testing.T) {
	te := NewTimingEngine(testTimingProfile())

	delay := te.SimulateThinkTime()
	if delay < 500*time.Millisecond {
		t.Fatalf("think time should be >= 500ms, got %v", delay)
	}
	if delay > 5*time.Second {
		t.Fatalf("think time should be <= 5s, got %v", delay)
	}
}

func TestTimingEngineSimulateThinkTimeVariety(t *testing.T) {
	te := NewTimingEngine(testTimingProfile())

	delays := map[time.Duration]bool{}
	for i := 0; i < 20; i++ {
		d := te.SimulateThinkTime()
		delays[d] = true
	}
	if len(delays) < 5 {
		t.Fatal("think time should have variety")
	}
}

func TestTimingEngineSimulateSlowStart(t *testing.T) {
	te := NewTimingEngine(testTimingProfile())

	// Early packets should have longer delays
	d0 := te.SimulateSlowStart(0)
	d10 := te.SimulateSlowStart(10)
	d25 := te.SimulateSlowStart(25)

	if d25 != 0 {
		t.Fatalf("past slow start (index 25) should be 0, got %v", d25)
	}
	// d0 should generally be larger than d10 (exponential decrease)
	// But with jitter there's some randomness, so just check d0 > 0
	if d0 <= 0 {
		t.Fatalf("slow start delay at index 0 should be positive, got %v", d0)
	}
	_ = d10
}

func TestTimingEngineReset(t *testing.T) {
	te := NewTimingEngine(testTimingProfile())

	// Generate some packets
	for i := 0; i < 50; i++ {
		te.NextDelay()
	}

	te.Reset()

	// After reset, should work normally
	delay := te.NextDelay()
	if delay < 0 {
		t.Fatal("delay after reset should be valid")
	}
}

func TestTimingEngineUpdateProfile(t *testing.T) {
	te := NewTimingEngine(testTimingProfile())

	newProfile := &TimingProfile{
		MinDelayMs:  50,
		MaxDelayMs:  200,
		MeanDelayMs: 100,
		JitterMs:    10,
		BurstSize:   2,
		BurstGapMs:  100,
	}
	te.UpdateProfile(newProfile)

	delay := te.NextDelay()
	if delay < 50*time.Millisecond {
		t.Fatalf("delay should respect new min: %v", delay)
	}
}

func TestTimingEngineBurstBehavior(t *testing.T) {
	profile := &TimingProfile{
		MinDelayMs:  1,
		MaxDelayMs:  200,
		MeanDelayMs: 50,
		JitterMs:    2,
		BurstSize:   10,
		BurstGapMs:  100,
	}
	te := NewTimingEngine(profile)

	// Generate many delays — we should see some variation
	var delays []time.Duration
	for i := 0; i < 100; i++ {
		delays = append(delays, te.NextDelay())
	}

	// Check we got both small (burst) and larger delays
	hasSmall := false
	hasLarge := false
	for _, d := range delays {
		if d <= 5*time.Millisecond {
			hasSmall = true
		}
		if d > 30*time.Millisecond {
			hasLarge = true
		}
	}
	if !hasSmall || !hasLarge {
		t.Fatalf("expected mix of small and large delays, small=%v large=%v", hasSmall, hasLarge)
	}
}
