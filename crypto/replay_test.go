package crypto

import (
	"testing"
)

func TestReplayFilterNew(t *testing.T) {
	rf := NewReplayFilter()
	if rf == nil {
		t.Fatal("expected non-nil filter")
	}
}

func TestReplayFilterRejectsZero(t *testing.T) {
	rf := NewReplayFilter()
	if rf.Check(0) {
		t.Fatal("seq 0 should always be rejected")
	}
}

func TestReplayFilterAcceptsNew(t *testing.T) {
	rf := NewReplayFilter()
	if !rf.Check(1) {
		t.Fatal("first seq should be accepted")
	}
	if !rf.Check(2) {
		t.Fatal("second seq should be accepted")
	}
	if !rf.Check(100) {
		t.Fatal("seq 100 should be accepted")
	}
}

func TestReplayFilterRejectsDuplicate(t *testing.T) {
	rf := NewReplayFilter()
	rf.Check(42)

	if rf.Check(42) {
		t.Fatal("duplicate seq should be rejected")
	}
}

func TestReplayFilterSequential(t *testing.T) {
	rf := NewReplayFilter()

	for i := uint64(1); i <= 500; i++ {
		if !rf.Check(i) {
			t.Fatalf("sequential seq %d should be accepted", i)
		}
	}

	// All should be rejected on second pass
	for i := uint64(1); i <= 500; i++ {
		if rf.Check(i) {
			t.Fatalf("repeated seq %d should be rejected", i)
		}
	}
}

func TestReplayFilterOutOfOrder(t *testing.T) {
	rf := NewReplayFilter()

	rf.Check(10)
	rf.Check(5) // Out of order but within window
	rf.Check(8)

	// All should be rejected now
	if rf.Check(10) {
		t.Fatal("10 should be rejected")
	}
	if rf.Check(5) {
		t.Fatal("5 should be rejected")
	}
	if rf.Check(8) {
		t.Fatal("8 should be rejected")
	}

	// New ones should work
	if !rf.Check(11) {
		t.Fatal("11 should be accepted")
	}
}

func TestReplayFilterWindowSlide(t *testing.T) {
	rf := NewReplayFilter()

	// Accept seq 1
	rf.Check(1)

	// Jump far ahead — past window
	rf.Check(ReplayWindowSize + 100)

	// Seq 1 is now too old
	if rf.Check(1) {
		t.Fatal("seq 1 should be too old after window slide")
	}
}

func TestReplayFilterTooOld(t *testing.T) {
	rf := NewReplayFilter()

	// Set high watermark
	rf.Check(2000)

	// Anything more than ReplayWindowSize behind should be rejected
	old := uint64(2000 - ReplayWindowSize - 1)
	if rf.Check(old) {
		t.Fatalf("seq %d should be too old (maxSeen=2000, window=%d)", old, ReplayWindowSize)
	}
}

func TestReplayFilterLargeJump(t *testing.T) {
	rf := NewReplayFilter()

	rf.Check(1)
	// Jump way past window — should clear bitmap
	rf.Check(ReplayWindowSize * 2)

	if !rf.Check(ReplayWindowSize*2 + 1) {
		t.Fatal("seq after large jump should be accepted")
	}
}

func TestReplayFilterWindowSize(t *testing.T) {
	if ReplayWindowSize != 1024 {
		t.Fatalf("expected window size 1024, got %d", ReplayWindowSize)
	}
}

func TestReplayFilterEdgeOfWindow(t *testing.T) {
	rf := NewReplayFilter()

	// Set maxSeen to exactly ReplayWindowSize
	rf.Check(uint64(ReplayWindowSize))

	// Seq 1 should still be within window
	if !rf.Check(1) {
		t.Fatal("seq 1 should be at edge of window but still valid")
	}

	// Seq 1 again should be rejected
	if rf.Check(1) {
		t.Fatal("seq 1 should be rejected on second try")
	}
}

func TestReplayFilterConcurrentSafe(t *testing.T) {
	rf := NewReplayFilter()

	done := make(chan bool, 10)
	for g := 0; g < 10; g++ {
		go func(base uint64) {
			for i := uint64(0); i < 100; i++ {
				rf.Check(base + i)
			}
			done <- true
		}(uint64(g) * 1000)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
	// No crash = pass
}
