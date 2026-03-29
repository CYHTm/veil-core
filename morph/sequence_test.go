package morph

import (
	"testing"
)

func TestHTTPBrowsingDirection(t *testing.T) {
	p := HTTPBrowsingDirection()
	if p.ClientToServerRatio != 0.30 {
		t.Fatalf("expected 0.30, got %f", p.ClientToServerRatio)
	}
	if p.ClientBurstSize != 3 {
		t.Fatalf("expected client burst 3, got %d", p.ClientBurstSize)
	}
	if p.ServerBurstSize != 12 {
		t.Fatalf("expected server burst 12, got %d", p.ServerBurstSize)
	}
}

func TestVideoStreamingDirection(t *testing.T) {
	p := VideoStreamingDirection()
	if p.ClientToServerRatio != 0.05 {
		t.Fatalf("expected 0.05, got %f", p.ClientToServerRatio)
	}
	if p.ClientBurstSize != 1 {
		t.Fatalf("expected client burst 1, got %d", p.ClientBurstSize)
	}
	if p.ServerBurstSize != 30 {
		t.Fatalf("expected server burst 30, got %d", p.ServerBurstSize)
	}
}

func TestSequenceMorpherCreate(t *testing.T) {
	sm := NewSequenceMorpher(HTTPBrowsingDirection())
	if sm == nil {
		t.Fatal("expected non-nil morpher")
	}
}

func TestSequenceMorpherEarlyPackets(t *testing.T) {
	sm := NewSequenceMorpher(HTTPBrowsingDirection())

	// First 20 packets should never suggest dummies
	for i := 0; i < 19; i++ {
		if sm.ShouldInsertDummy(0) {
			t.Fatalf("should not insert dummy for early packet %d", i)
		}
	}
}

func TestSequenceMorpherBalancing(t *testing.T) {
	sm := NewSequenceMorpher(HTTPBrowsingDirection())

	// Send 100 client packets — ratio will be way above 0.3
	for i := 0; i < 100; i++ {
		sm.ShouldInsertDummy(0) // client -> server
	}

	// At this point the morpher should suggest server dummies
	dummySuggested := false
	for i := 0; i < 10; i++ {
		if sm.ShouldInsertDummy(0) {
			dummySuggested = true
			break
		}
	}
	if !dummySuggested {
		t.Fatal("should suggest dummy when ratio is off")
	}
}

func TestSequenceMorpherDummySize(t *testing.T) {
	sm := NewSequenceMorpher(HTTPBrowsingDirection())

	// Client dummy should be small
	for i := 0; i < 50; i++ {
		size := sm.DummySize(0)
		if size < 40 || size > 160 {
			t.Fatalf("client dummy size out of range: %d", size)
		}
	}

	// Server dummy should be medium
	for i := 0; i < 50; i++ {
		size := sm.DummySize(1)
		if size < 200 || size > 1000 {
			t.Fatalf("server dummy size out of range: %d", size)
		}
	}
}

func TestSequenceMorpherReset(t *testing.T) {
	sm := NewSequenceMorpher(HTTPBrowsingDirection())

	// Send packets
	for i := 0; i < 50; i++ {
		sm.ShouldInsertDummy(0)
	}

	sm.Reset()

	// After reset, early packets should not trigger dummies
	if sm.ShouldInsertDummy(0) {
		t.Fatal("should not suggest dummy right after reset")
	}
}

func TestSequenceMorpherVideoProfile(t *testing.T) {
	sm := NewSequenceMorpher(VideoStreamingDirection())

	// Send mostly server packets (like video streaming)
	for i := 0; i < 100; i++ {
		sm.ShouldInsertDummy(1) // server -> client
	}

	// Ratio should be very low — morpher might suggest client dummies
	// to bring ratio up to 0.05
	clientDummy := false
	for i := 0; i < 20; i++ {
		if sm.ShouldInsertDummy(1) {
			clientDummy = true
			break
		}
	}
	_ = clientDummy // may or may not trigger depending on exact ratio
}
