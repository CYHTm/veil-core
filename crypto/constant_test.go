package crypto

import (
	"testing"
	"time"
)

func TestConstantTimeCompareEqual(t *testing.T) {
	a := []byte("hello world")
	b := []byte("hello world")
	if !ConstantTimeCompare(a, b) {
		t.Fatal("equal slices should return true")
	}
}

func TestConstantTimeCompareNotEqual(t *testing.T) {
	a := []byte("hello world")
	b := []byte("hello worlx")
	if ConstantTimeCompare(a, b) {
		t.Fatal("different slices should return false")
	}
}

func TestConstantTimeCompareDifferentLength(t *testing.T) {
	a := []byte("short")
	b := []byte("longer string")
	if ConstantTimeCompare(a, b) {
		t.Fatal("different length slices should return false")
	}
}

func TestConstantTimeCompareEmpty(t *testing.T) {
	if !ConstantTimeCompare([]byte{}, []byte{}) {
		t.Fatal("two empty slices should be equal")
	}
}

func TestConstantTimeHMACCompare(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x01, 0x02, 0x03}
	if !ConstantTimeHMACCompare(a, b) {
		t.Fatal("equal HMACs should return true")
	}
}

func TestConstantTimeHMACCompareNotEqual(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03}
	b := []byte{0x01, 0x02, 0x04}
	if ConstantTimeHMACCompare(a, b) {
		t.Fatal("different HMACs should return false")
	}
}

func TestPaddedSleep(t *testing.T) {
	start := time.Now()
	minDuration := 100 * time.Millisecond

	// Simulate fast operation
	time.Sleep(10 * time.Millisecond)
	PaddedSleep(start, minDuration)

	elapsed := time.Since(start)
	if elapsed < minDuration {
		t.Fatalf("padded sleep should ensure at least %v, got %v", minDuration, elapsed)
	}
}

func TestPaddedSleepAlreadySlow(t *testing.T) {
	start := time.Now()
	minDuration := 10 * time.Millisecond

	// Simulate slow operation
	time.Sleep(50 * time.Millisecond)
	PaddedSleep(start, minDuration)

	// Should not add extra delay
	elapsed := time.Since(start)
	if elapsed > 150*time.Millisecond {
		t.Fatalf("padded sleep should not add delay for slow operations, got %v", elapsed)
	}
}

func TestConstantTimeSelectOne(t *testing.T) {
	a := []byte{0xAA, 0xBB, 0xCC}
	b := []byte{0x11, 0x22, 0x33}

	result := ConstantTimeSelect(1, a, b)
	if !ConstantTimeCompare(result, a) {
		t.Fatal("selector=1 should return a")
	}
}

func TestConstantTimeSelectZero(t *testing.T) {
	a := []byte{0xAA, 0xBB, 0xCC}
	b := []byte{0x11, 0x22, 0x33}

	result := ConstantTimeSelect(0, a, b)
	if !ConstantTimeCompare(result, b) {
		t.Fatal("selector=0 should return b")
	}
}

func TestConstantTimeSelectDifferentLength(t *testing.T) {
	a := []byte{0xAA}
	b := []byte{0x11, 0x22}

	result := ConstantTimeSelect(1, a, b)
	if result != nil {
		t.Fatal("different length should return nil")
	}
}
