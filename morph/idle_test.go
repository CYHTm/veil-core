package morph

import (
	"testing"
	"time"
)

func TestNewIdlePadderNilProfile(t *testing.T) {
	ip := NewIdlePadder(nil)
	p := ip.Profile()
	if p.MinInterval != 15*time.Second {
		t.Fatalf("expected default MinInterval 15s, got %v", p.MinInterval)
	}
	if p.MaxInterval != 45*time.Second {
		t.Fatalf("expected default MaxInterval 45s, got %v", p.MaxInterval)
	}
}

func TestNewIdlePadderFromMorphProfile(t *testing.T) {
	profiles := []struct {
		name    string
		profile *Profile
	}{
		{"http2", BuiltinHTTP2Profile()},
		{"video", BuiltinVideoProfile()},
		{"chrome", BuiltinChromeRealProfile()},
		{"youtube", BuiltinYouTubeRealProfile()},
		{"tiktok", BuiltinTikTokProfile()},
		{"discord", BuiltinDiscordProfile()},
		{"telegram", BuiltinTelegramProfile()},
		{"grpc", BuiltinGRPCProfile()},
	}

	for _, tc := range profiles {
		t.Run(tc.name, func(t *testing.T) {
			ip := NewIdlePadder(tc.profile)
			p := ip.Profile()

			if p.MinInterval < 5*time.Second {
				t.Errorf("MinInterval too small: %v", p.MinInterval)
			}
			if p.MaxInterval > 60*time.Second {
				t.Errorf("MaxInterval too large: %v", p.MaxInterval)
			}
			if p.MaxInterval <= p.MinInterval {
				t.Errorf("MaxInterval (%v) should be > MinInterval (%v)", p.MaxInterval, p.MinInterval)
			}
			if p.MinPadding < 8 {
				t.Errorf("MinPadding too small: %d", p.MinPadding)
			}
			if p.MaxPadding < p.MinPadding {
				t.Errorf("MaxPadding (%d) < MinPadding (%d)", p.MaxPadding, p.MinPadding)
			}
			if p.BurstChance < 0 || p.BurstChance > 1 {
				t.Errorf("BurstChance out of range: %f", p.BurstChance)
			}
		})
	}
}

func TestNewIdlePadderFromConfig(t *testing.T) {
	cfg := IdleProfile{
		MinInterval: 10 * time.Second,
		MaxInterval: 20 * time.Second,
		MinPadding:  16,
		MaxPadding:  128,
		BurstChance: 0.5,
		BurstMin:    2,
		BurstMax:    4,
		BurstGap:    100 * time.Millisecond,
	}
	ip := NewIdlePadderFromConfig(cfg)
	p := ip.Profile()
	if p.MinInterval != 10*time.Second {
		t.Fatalf("expected 10s, got %v", p.MinInterval)
	}
	if p.MaxPadding != 128 {
		t.Fatalf("expected 128, got %d", p.MaxPadding)
	}
}

func TestIdlePadderNextActionSingle(t *testing.T) {
	cfg := IdleProfile{
		MinInterval: 10 * time.Second,
		MaxInterval: 20 * time.Second,
		MinPadding:  16,
		MaxPadding:  32,
		BurstChance: 0, // no bursts
		BurstMin:    2,
		BurstMax:    3,
		BurstGap:    50 * time.Millisecond,
	}
	ip := NewIdlePadderFromConfig(cfg)

	for i := 0; i < 100; i++ {
		action := ip.NextAction()
		if action.Delay < 10*time.Second || action.Delay > 20*time.Second {
			t.Fatalf("delay out of range: %v", action.Delay)
		}
		if action.PaddingSize < 16 || action.PaddingSize > 32 {
			t.Fatalf("padding out of range: %d", action.PaddingSize)
		}
		if action.IsBurst {
			t.Fatal("should not be burst with BurstChance=0")
		}
	}
}

func TestIdlePadderNextActionBurst(t *testing.T) {
	cfg := IdleProfile{
		MinInterval: 10 * time.Second,
		MaxInterval: 20 * time.Second,
		MinPadding:  8,
		MaxPadding:  16,
		BurstChance: 1.0, // always burst
		BurstMin:    3,
		BurstMax:    3,
		BurstGap:    50 * time.Millisecond,
	}
	ip := NewIdlePadderFromConfig(cfg)

	action := ip.NextAction()
	if !action.IsBurst {
		t.Fatal("expected burst")
	}
	if action.BurstRemaining != 2 {
		t.Fatalf("expected 2 remaining, got %d", action.BurstRemaining)
	}

	// Drain burst queue
	for i := 1; i >= 0; i-- {
		a := ip.NextAction()
		if !a.IsBurst {
			t.Fatal("expected burst continuation")
		}
		if a.BurstRemaining != i {
			t.Fatalf("expected %d remaining, got %d", i, a.BurstRemaining)
		}
		if a.Delay > 100*time.Millisecond {
			t.Fatalf("burst gap too large: %v", a.Delay)
		}
	}

	// Next should be a new burst (BurstChance=1.0)
	action = ip.NextAction()
	if !action.IsBurst {
		t.Fatal("expected new burst after queue drained")
	}
	if action.Delay < 10*time.Second {
		t.Fatal("first packet of new burst should have full delay")
	}
}

func TestIdlePadderBurstQueueDrain(t *testing.T) {
	cfg := IdleProfile{
		MinInterval: 5 * time.Second,
		MaxInterval: 10 * time.Second,
		MinPadding:  8,
		MaxPadding:  16,
		BurstChance: 1.0,
		BurstMin:    4,
		BurstMax:    4,
		BurstGap:    10 * time.Millisecond,
	}
	ip := NewIdlePadderFromConfig(cfg)

	// First call: start burst, queue has 3
	first := ip.NextAction()
	if first.BurstRemaining != 3 {
		t.Fatalf("expected 3 remaining, got %d", first.BurstRemaining)
	}

	// Drain all 3
	for i := 0; i < 3; i++ {
		a := ip.NextAction()
		if !a.IsBurst {
			t.Fatalf("packet %d should be burst", i)
		}
	}

	// Queue empty, next call should generate new burst
	next := ip.NextAction()
	if !next.IsBurst {
		t.Fatal("should start new burst")
	}
}

func TestIdlePadderUpdateProfile(t *testing.T) {
	ip := NewIdlePadder(BuiltinHTTP2Profile())
	old := ip.Profile()

	// Use a custom profile with very different timing to guarantee change
	custom := &Profile{
		Name: "custom_slow",
		Timing: TimingProfile{
			MinDelayMs:  3000,
			MaxDelayMs:  15000,
			MeanDelayMs: 8000,
			JitterMs:    2000,
		},
		PacketSizes: SizeDistribution{
			Buckets: []SizeBucket{{Min: 100, Max: 200, Weight: 1}},
		},
	}
	ip.UpdateProfile(custom)
	updated := ip.Profile()

	// Custom profile has much larger timing → different idle intervals
	if old.MinInterval == updated.MinInterval && old.MaxPadding == updated.MaxPadding {
		t.Fatal("profile should have changed after update")
	}
}

func TestIdlePadderDelayDistribution(t *testing.T) {
	cfg := IdleProfile{
		MinInterval: 10 * time.Second,
		MaxInterval: 20 * time.Second,
		MinPadding:  8,
		MaxPadding:  64,
		BurstChance: 0,
	}
	ip := NewIdlePadderFromConfig(cfg)

	// Check that delays aren't all identical (randomness works)
	delays := make(map[time.Duration]bool)
	for i := 0; i < 50; i++ {
		action := ip.NextAction()
		delays[action.Delay] = true
	}
	if len(delays) < 5 {
		t.Fatalf("expected diverse delays, got only %d unique values", len(delays))
	}
}

func TestIdlePadderPaddingDistribution(t *testing.T) {
	cfg := IdleProfile{
		MinInterval: 5 * time.Second,
		MaxInterval: 10 * time.Second,
		MinPadding:  10,
		MaxPadding:  100,
		BurstChance: 0,
	}
	ip := NewIdlePadderFromConfig(cfg)

	sizes := make(map[int]bool)
	for i := 0; i < 100; i++ {
		action := ip.NextAction()
		sizes[action.PaddingSize] = true
	}
	if len(sizes) < 10 {
		t.Fatalf("expected diverse padding sizes, got only %d unique", len(sizes))
	}
}

func TestDeriveIdleProfileClamps(t *testing.T) {
	// Profile with very small timing → should clamp to minimums
	p := &Profile{
		Name: "tiny",
		Timing: TimingProfile{
			MinDelayMs: 1,
			MaxDelayMs: 2,
		},
	}
	ip := deriveIdleProfile(p)
	if ip.MinInterval < 5*time.Second {
		t.Fatalf("MinInterval should be clamped to 5s, got %v", ip.MinInterval)
	}
	if ip.MaxInterval > 60*time.Second {
		t.Fatalf("MaxInterval should be clamped to 60s, got %v", ip.MaxInterval)
	}
}

func TestDeriveIdleProfileLargeTiming(t *testing.T) {
	// Profile with very large timing → should clamp max to 60s
	p := &Profile{
		Name: "large",
		Timing: TimingProfile{
			MinDelayMs: 5000,
			MaxDelayMs: 30000,
		},
	}
	ip := deriveIdleProfile(p)
	if ip.MaxInterval > 60*time.Second {
		t.Fatalf("MaxInterval should clamp to 60s, got %v", ip.MaxInterval)
	}
}

func TestDefaultIdleProfile(t *testing.T) {
	p := defaultIdleProfile()
	if p.MinInterval != 15*time.Second {
		t.Fatalf("expected 15s, got %v", p.MinInterval)
	}
	if p.MaxInterval != 45*time.Second {
		t.Fatalf("expected 45s, got %v", p.MaxInterval)
	}
	if p.MinPadding != 8 {
		t.Fatalf("expected 8, got %d", p.MinPadding)
	}
	if p.MaxPadding != 64 {
		t.Fatalf("expected 64, got %d", p.MaxPadding)
	}
	if p.BurstChance != 0.15 {
		t.Fatalf("expected 0.15, got %f", p.BurstChance)
	}
}

func TestIdlePadderEqualMinMax(t *testing.T) {
	cfg := IdleProfile{
		MinInterval: 10 * time.Second,
		MaxInterval: 10 * time.Second,
		MinPadding:  32,
		MaxPadding:  32,
		BurstChance: 0,
	}
	ip := NewIdlePadderFromConfig(cfg)

	for i := 0; i < 20; i++ {
		action := ip.NextAction()
		if action.Delay != 10*time.Second {
			t.Fatalf("expected exactly 10s, got %v", action.Delay)
		}
		if action.PaddingSize != 32 {
			t.Fatalf("expected exactly 32, got %d", action.PaddingSize)
		}
	}
}
