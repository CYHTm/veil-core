package api

import (
	"testing"
)

func TestGetBufferSmall(t *testing.T) {
	buf := GetBuffer(100)
	if len(buf) != 100 {
		t.Fatalf("expected len 100, got %d", len(buf))
	}
	if cap(buf) < 100 {
		t.Fatalf("expected cap >= 100, got %d", cap(buf))
	}
	PutBuffer(buf)
}

func TestGetBufferMedium(t *testing.T) {
	buf := GetBuffer(8 * 1024)
	if len(buf) != 8*1024 {
		t.Fatalf("expected len 8192, got %d", len(buf))
	}
	if cap(buf) < 16*1024 {
		t.Fatalf("expected cap >= 16384, got %d", cap(buf))
	}
	PutBuffer(buf)
}

func TestGetBufferLarge(t *testing.T) {
	buf := GetBuffer(32 * 1024)
	if len(buf) != 32*1024 {
		t.Fatalf("expected len 32768, got %d", len(buf))
	}
	if cap(buf) < 64*1024 {
		t.Fatalf("expected cap >= 65536, got %d", cap(buf))
	}
	PutBuffer(buf)
}

func TestGetBufferOversized(t *testing.T) {
	// Bigger than largest pool — should allocate new
	buf := GetBuffer(128 * 1024)
	if len(buf) != 128*1024 {
		t.Fatalf("expected len 131072, got %d", len(buf))
	}
	// PutBuffer should not panic on oversized
	PutBuffer(buf)
}

func TestGetBufferExactBoundaries(t *testing.T) {
	tests := []struct {
		size    int
		minCap  int
	}{
		{4 * 1024, 4 * 1024},
		{16 * 1024, 16 * 1024},
		{64 * 1024, 64 * 1024},
	}
	for _, tt := range tests {
		buf := GetBuffer(tt.size)
		if len(buf) != tt.size {
			t.Fatalf("size %d: expected len %d, got %d", tt.size, tt.size, len(buf))
		}
		if cap(buf) < tt.minCap {
			t.Fatalf("size %d: expected cap >= %d, got %d", tt.size, tt.minCap, cap(buf))
		}
		PutBuffer(buf)
	}
}

func TestPutBufferTooSmall(t *testing.T) {
	// Buffer smaller than any pool — should not panic
	tiny := make([]byte, 10)
	PutBuffer(tiny) // no crash = pass
}

func TestBufferPoolReuse(t *testing.T) {
	// Get and put back, then get again — should reuse
	buf1 := GetBuffer(100)
	buf1[0] = 0xAA
	PutBuffer(buf1)

	// Second get may or may not reuse (GC can clear pool)
	buf2 := GetBuffer(100)
	_ = buf2 // just verify no panic
	PutBuffer(buf2)
}
