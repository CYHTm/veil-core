package morph

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCaptureAnalyzerCreate(t *testing.T) {
	ca := NewCaptureAnalyzer()
	if ca == nil {
		t.Fatal("expected non-nil analyzer")
	}
}

func TestCaptureAnalyzerAddPacket(t *testing.T) {
	ca := NewCaptureAnalyzer()
	ca.AddPacket(100, 0.0, 0)
	ca.AddPacket(500, 0.1, 1)
	ca.AddPacket(200, 0.2, 0)

	if len(ca.packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(ca.packets))
	}
}

func TestCaptureAnalyzerBuildProfileEmpty(t *testing.T) {
	ca := NewCaptureAnalyzer()
	profile := ca.BuildProfile("empty", "no packets")

	// Should return builtin profile for empty input
	if profile == nil {
		t.Fatal("should return fallback profile for empty input")
	}
	if profile == nil {
		t.Fatal("should not return nil")
	}
}

func TestCaptureAnalyzerBuildProfile(t *testing.T) {
	ca := NewCaptureAnalyzer()

	// Simulate 100 packets
	for i := 0; i < 100; i++ {
		size := 100 + (i%10)*100 // 100-1000 bytes
		ts := float64(i) * 0.01  // 10ms apart
		dir := 0
		if i%3 == 0 {
			dir = 1
		}
		ca.AddPacket(size, ts, dir)
	}

	profile := ca.BuildProfile("test-capture", "test description")

	if profile.Name != "test-capture" {
		t.Fatalf("expected name 'test-capture', got '%s'", profile.Name)
	}
	if profile.Description != "test description" {
		t.Fatal("description mismatch")
	}
	if len(profile.PacketSizes.Buckets) == 0 {
		t.Fatal("expected non-empty size buckets")
	}
	if profile.Timing.MeanDelayMs <= 0 {
		t.Fatal("expected positive mean delay")
	}
	if len(profile.ByteFreq) != 256 {
		t.Fatalf("expected 256 byte frequencies, got %d", len(profile.ByteFreq))
	}
}

func TestCaptureAnalyzerByteFrequency(t *testing.T) {
	ca := NewCaptureAnalyzer()
	ca.AddPacket(100, 0.0, 0)

	profile := ca.BuildProfile("test", "")

	// All frequencies should be near-uniform for encrypted traffic
	total := 0.0
	for _, f := range profile.ByteFreq {
		total += f
		if f <= 0 {
			t.Fatal("byte frequency should be positive")
		}
	}
	if total < 0.99 || total > 1.01 {
		t.Fatalf("byte frequencies should sum to ~1.0, got %f", total)
	}
}

func TestCaptureAnalyzerTimingProfile(t *testing.T) {
	ca := NewCaptureAnalyzer()

	// Simulate packets with known timing
	for i := 0; i < 50; i++ {
		ca.AddPacket(500, float64(i)*0.02, 0) // 20ms apart
	}

	profile := ca.BuildProfile("timing-test", "")
	tp := profile.Timing

	if tp.MinDelayMs < 0 {
		t.Fatal("min delay should not be negative")
	}
	if tp.MeanDelayMs <= 0 {
		t.Fatal("mean delay should be positive")
	}
}

func TestSaveAndLoadProfile(t *testing.T) {
	ca := NewCaptureAnalyzer()
	for i := 0; i < 30; i++ {
		ca.AddPacket(200+i*10, float64(i)*0.01, i%2)
	}

	profile := ca.BuildProfile("save-test", "testing save")

	// Save to temp file
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "profile.json")

	if err := SaveProfile(profile, path); err != nil {
		t.Fatalf("save profile: %v", err)
	}

	// Verify file exists and is valid JSON
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("saved file is empty")
	}
}

func TestCaptureAnalyzerLoadPackets(t *testing.T) {
	// Create temp JSON file with packets
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "packets.json")

	json := `[{"size":100,"timestamp":0.0,"direction":0},{"size":500,"timestamp":0.1,"direction":1}]`
	os.WriteFile(path, []byte(json), 0644)

	ca := NewCaptureAnalyzer()
	if err := ca.LoadPackets(path); err != nil {
		t.Fatalf("load packets: %v", err)
	}

	if len(ca.packets) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(ca.packets))
	}
	if ca.packets[0].Size != 100 {
		t.Fatalf("expected size 100, got %d", ca.packets[0].Size)
	}
}

func TestCaptureAnalyzerLoadPacketsFileNotFound(t *testing.T) {
	ca := NewCaptureAnalyzer()
	err := ca.LoadPackets("/nonexistent/file.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestSaveProfileError(t *testing.T) {
	profile := BuiltinHTTP2Profile()
	err := SaveProfile(profile, "/nonexistent/dir/profile.json")
	if err == nil {
		t.Fatal("expected error saving to nonexistent dir")
	}
}
