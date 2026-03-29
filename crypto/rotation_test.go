package crypto

import (
	"testing"
)

func TestPSKRotatorCurrentPSK(t *testing.T) {
	r := NewPSKRotator("test-secret", 1)
	psk := r.CurrentPSK()

	if len(psk) != 32 {
		t.Fatalf("expected 32 byte PSK, got %d", len(psk))
	}

	// Should be deterministic
	psk2 := r.CurrentPSK()
	if !ConstantTimeCompare(psk, psk2) {
		t.Fatal("CurrentPSK should be deterministic within same period")
	}
}

func TestPSKRotatorValidPSKs(t *testing.T) {
	r := NewPSKRotator("test-secret", 1)
	psks := r.ValidPSKs()

	if len(psks) != 2 {
		t.Fatalf("expected 2 valid PSKs (current + grace), got %d", len(psks))
	}

	// Both should be 32 bytes
	for i, psk := range psks {
		if len(psk) != 32 {
			t.Fatalf("PSK %d: expected 32 bytes, got %d", i, len(psk))
		}
	}

	// They should be different (different periods)
	if ConstantTimeCompare(psks[0], psks[1]) {
		t.Fatal("current and previous PSK should differ")
	}
}

func TestPSKRotatorIsValid(t *testing.T) {
	r := NewPSKRotator("test-secret", 1)
	current := r.CurrentPSK()

	if !r.IsValid(current) {
		t.Fatal("current PSK should be valid")
	}
}

func TestPSKRotatorIsValidRejectsRandom(t *testing.T) {
	r := NewPSKRotator("test-secret", 1)
	random := make([]byte, 32)
	for i := range random {
		random[i] = 0xFF
	}

	if r.IsValid(random) {
		t.Fatal("random bytes should not be valid")
	}
}

func TestPSKRotatorDifferentSecrets(t *testing.T) {
	r1 := NewPSKRotator("secret-1", 1)
	r2 := NewPSKRotator("secret-2", 1)

	psk1 := r1.CurrentPSK()
	psk2 := r2.CurrentPSK()

	if ConstantTimeCompare(psk1, psk2) {
		t.Fatal("different secrets should produce different PSKs")
	}
}

func TestPSKRotatorCrossValidation(t *testing.T) {
	r1 := NewPSKRotator("same-secret", 1)
	r2 := NewPSKRotator("same-secret", 1)

	psk := r1.CurrentPSK()
	if !r2.IsValid(psk) {
		t.Fatal("same secret should cross-validate")
	}
}

func TestPSKRotatorDifferentRotationDays(t *testing.T) {
	r1 := NewPSKRotator("secret", 1)
	r7 := NewPSKRotator("secret", 7)

	// Different rotation periods should yield different PSKs (usually)
	// Unless we happen to be at a boundary where both periods align
	psk1 := r1.CurrentPSK()
	psk7 := r7.CurrentPSK()

	// They may or may not be equal depending on timing,
	// but both should be 32 bytes
	if len(psk1) != 32 || len(psk7) != 32 {
		t.Fatal("both should produce 32-byte PSKs")
	}
}
