package morph

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// TestAllProfilesLoadable verifies every JSON profile in profiles/ can be loaded and parsed.
func TestAllProfilesLoadable(t *testing.T) {
	profileDir := "profiles"
	entries, err := os.ReadDir(profileDir)
	if err != nil {
		t.Fatalf("cannot read profiles dir: %v", err)
	}

	count := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		count++
		t.Run(e.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(profileDir, e.Name()))
			if err != nil {
				t.Fatalf("read error: %v", err)
			}
			var p Profile
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatalf("JSON parse error: %v", err)
			}
			if p.Name == "" {
				t.Error("profile name is empty")
			}
			if p.Description == "" {
				t.Error("profile description is empty")
			}
		})
	}
	if count == 0 {
		t.Fatal("no JSON profiles found")
	}
	t.Logf("loaded %d profiles successfully", count)
}

// TestAllProfilesBucketsValid checks that each profile has valid buckets.
func TestAllProfilesBucketsValid(t *testing.T) {
	profileDir := "profiles"
	entries, err := os.ReadDir(profileDir)
	if err != nil {
		t.Fatalf("cannot read profiles dir: %v", err)
	}

	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(profileDir, e.Name()))
			if err != nil {
				t.Fatalf("read error: %v", err)
			}
			var p Profile
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatalf("JSON parse error: %v", err)
			}

			buckets := p.PacketSizes.Buckets
			if len(buckets) == 0 {
				t.Fatal("no size buckets defined")
			}

			totalWeight := 0.0
			for i, b := range buckets {
				if b.Min < 0 {
					t.Errorf("bucket %d: min %d < 0", i, b.Min)
				}
				if b.Max <= b.Min {
					t.Errorf("bucket %d: max %d <= min %d", i, b.Max, b.Min)
				}
				if b.Weight <= 0 {
					t.Errorf("bucket %d: weight %.2f <= 0", i, b.Weight)
				}
				totalWeight += b.Weight
			}

			if totalWeight < 1.0 {
				t.Errorf("total weight %.2f is too low (< 1.0)", totalWeight)
			}

			// Check buckets are ordered by min
			for i := 1; i < len(buckets); i++ {
				if buckets[i].Min < buckets[i-1].Min {
					t.Errorf("bucket %d min %d < previous bucket min %d (not ordered)", i, buckets[i].Min, buckets[i-1].Min)
				}
			}
		})
	}
}

// TestAllProfilesTimingValid checks timing parameters are sane.
func TestAllProfilesTimingValid(t *testing.T) {
	profileDir := "profiles"
	entries, err := os.ReadDir(profileDir)
	if err != nil {
		t.Fatalf("cannot read profiles dir: %v", err)
	}

	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(profileDir, e.Name()))
			if err != nil {
				t.Fatalf("read error: %v", err)
			}
			var p Profile
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatalf("JSON parse error: %v", err)
			}

			tm := p.Timing
			if tm.MinDelayMs < 0 {
				t.Errorf("min_delay_ms %d < 0", tm.MinDelayMs)
			}
			if tm.MaxDelayMs < tm.MinDelayMs {
				t.Errorf("max_delay_ms %d < min_delay_ms %d", tm.MaxDelayMs, tm.MinDelayMs)
			}
			if tm.MeanDelayMs < 0 {
				t.Errorf("mean_delay_ms %.2f < 0", tm.MeanDelayMs)
			}
			if tm.JitterMs < 0 {
				t.Errorf("jitter_ms %.2f < 0", tm.JitterMs)
			}
			if tm.BurstSize < 1 {
				t.Errorf("burst_size %d < 1", tm.BurstSize)
			}
			if tm.BurstGapMs < 0 {
				t.Errorf("burst_gap_ms %d < 0", tm.BurstGapMs)
			}
		})
	}
}

// TestTikTokProfile verifies TikTok-specific characteristics.
func TestTikTokProfile(t *testing.T) {
	data, err := os.ReadFile("profiles/tiktok_scrolling.json")
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	if p.Name != "tiktok_scrolling" {
		t.Errorf("expected name 'tiktok_scrolling', got %q", p.Name)
	}

	// TikTok should have high burst size (aggressive video download)
	if p.Timing.BurstSize < 15 {
		t.Errorf("TikTok burst_size %d too low for video streaming", p.Timing.BurstSize)
	}

	// Check that near-MTU packets dominate (video data)
	nearMTUWeight := 0.0
	for _, b := range p.PacketSizes.Buckets {
		if b.Min >= 1200 {
			nearMTUWeight += b.Weight
		}
	}
	if nearMTUWeight < 40.0 {
		t.Errorf("near-MTU weight %.1f%% too low for video traffic (expected > 40%%)", nearMTUWeight)
	}
}

// TestDiscordProfile verifies Discord-specific characteristics.
func TestDiscordProfile(t *testing.T) {
	data, err := os.ReadFile("profiles/discord_chat.json")
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	if p.Name != "discord_chat" {
		t.Errorf("expected name 'discord_chat', got %q", p.Name)
	}

	// Discord should have small burst size (text chat pattern)
	if p.Timing.BurstSize > 10 {
		t.Errorf("Discord burst_size %d too high for text chat", p.Timing.BurstSize)
	}

	// Discord has mostly small packets (compressed WebSocket)
	smallWeight := 0.0
	for _, b := range p.PacketSizes.Buckets {
		if b.Max <= 300 {
			smallWeight += b.Weight
		}
	}
	if smallWeight < 50.0 {
		t.Errorf("small packet weight %.1f%% too low for text chat (expected > 50%%)", smallWeight)
	}
}

// TestTelegramProfile verifies Telegram-specific characteristics.
func TestTelegramProfile(t *testing.T) {
	data, err := os.ReadFile("profiles/telegram_messaging.json")
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	if p.Name != "telegram_messaging" {
		t.Errorf("expected name 'telegram_messaging', got %q", p.Name)
	}

	// Telegram should have medium burst (msg + ack + status)
	if p.Timing.BurstSize < 3 || p.Timing.BurstSize > 12 {
		t.Errorf("Telegram burst_size %d unexpected (expected 3-12)", p.Timing.BurstSize)
	}

	// Telegram has a mix of small and medium packets
	smallMedWeight := 0.0
	for _, b := range p.PacketSizes.Buckets {
		if b.Max <= 700 {
			smallMedWeight += b.Weight
		}
	}
	if smallMedWeight < 55.0 {
		t.Errorf("small+medium packet weight %.1f%% too low for messaging (expected > 55%%)", smallMedWeight)
	}
}

// TestProfileWeightsNormalized checks total weights sum to ~100 for percentage-based profiles.
func TestProfileWeightsNormalized(t *testing.T) {
	profileDir := "profiles"
	entries, err := os.ReadDir(profileDir)
	if err != nil {
		t.Fatalf("cannot read profiles dir: %v", err)
	}

	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(profileDir, e.Name()))
			if err != nil {
				t.Fatalf("read error: %v", err)
			}
			var p Profile
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatalf("JSON parse error: %v", err)
			}

			totalWeight := 0.0
			for _, b := range p.PacketSizes.Buckets {
				totalWeight += b.Weight
			}

			// Weights should sum to approximately 100 (percentage-like)
			if math.Abs(totalWeight-100.0) > 2.0 {
				t.Errorf("total weight %.2f deviates from 100 by more than 2%%", totalWeight)
			}
		})
	}
}

// TestEngineLoadNewProfiles tests that the Engine can load each new profile and use it.
func TestEngineLoadNewProfiles(t *testing.T) {
	profiles := []string{
		"profiles/tiktok_scrolling.json",
		"profiles/discord_chat.json",
		"profiles/telegram_messaging.json",
	}

	for _, path := range profiles {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read error: %v", err)
			}
			var p Profile
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatalf("JSON parse error: %v", err)
			}

			e := NewEngine(&p)
			if e == nil {
				t.Fatal("NewEngine returned nil")
			}

			// Verify engine works: calculate padding and delay
			pad := e.CalculatePadding(100)
			if pad < 0 {
				t.Errorf("CalculatePadding returned negative: %d", pad)
			}

			delay := e.CalculateDelay()
			if delay < 0 {
				t.Errorf("CalculateDelay returned negative: %v", delay)
			}

			// Verify SetProfile works with same profile
			e.SetProfile(&p)
		})
	}
}

// TestListBuiltinProfiles verifies the profile registry returns all expected profiles.
func TestListBuiltinProfiles(t *testing.T) {
	profiles := ListBuiltinProfiles()

	expected := map[string]bool{
		"http2_browsing":      false,
		"video_streaming":     false,
		"chrome_real":         false,
		"youtube_real":        false,
		"tiktok_scrolling":    false,
		"discord_chat":        false,
		"telegram_messaging":  false,
		"grpc_api":            false,
	}

	for _, p := range profiles {
		if _, ok := expected[p.Name]; !ok {
			t.Errorf("unexpected profile in list: %q", p.Name)
		}
		expected[p.Name] = true
		if p.Description == "" {
			t.Errorf("profile %q has empty description", p.Name)
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("expected profile %q not in list", name)
		}
	}

	t.Logf("registry has %d profiles", len(profiles))
}

// TestGetBuiltinProfile verifies each profile can be retrieved by name.
func TestGetBuiltinProfile(t *testing.T) {
	names := []string{
		"http2_browsing", "video_streaming", "chrome_real", "youtube_real",
		"tiktok_scrolling", "discord_chat", "telegram_messaging", "grpc_api",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			p := GetBuiltinProfile(name)
			if p == nil {
				t.Fatalf("GetBuiltinProfile(%q) returned nil", name)
			}
			if p.Name != name {
				t.Errorf("name mismatch: got %q, want %q", p.Name, name)
			}
			if len(p.PacketSizes.Buckets) == 0 {
				t.Error("no packet size buckets")
			}
			if p.Timing.BurstSize < 1 {
				t.Error("burst_size < 1")
			}
		})
	}
}

// TestGetBuiltinProfileUnknown returns nil for unknown names.
func TestGetBuiltinProfileUnknown(t *testing.T) {
	p := GetBuiltinProfile("nonexistent_profile")
	if p != nil {
		t.Errorf("expected nil for unknown profile, got %v", p.Name)
	}
}

// TestResolveProfileBuiltin resolves built-in profiles by name.
func TestResolveProfileBuiltin(t *testing.T) {
	p, err := ResolveProfile("tiktok_scrolling")
	if err != nil {
		t.Fatalf("ResolveProfile error: %v", err)
	}
	if p.Name != "tiktok_scrolling" {
		t.Errorf("got %q, want tiktok_scrolling", p.Name)
	}
}

// TestResolveProfileFile resolves a profile from JSON file.
func TestResolveProfileFile(t *testing.T) {
	p, err := ResolveProfile("profiles/discord_chat.json")
	if err != nil {
		t.Fatalf("ResolveProfile from file error: %v", err)
	}
	if p.Name != "discord_chat" {
		t.Errorf("got %q, want discord_chat", p.Name)
	}
}

// TestResolveProfileUnknown returns error for bad name/path.
func TestResolveProfileUnknown(t *testing.T) {
	_, err := ResolveProfile("totally_fake_profile")
	if err == nil {
		t.Error("expected error for unknown profile, got nil")
	}
}
