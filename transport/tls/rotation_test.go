package tls

import (
	"testing"
)

func TestFingerprintRotatorCreate(t *testing.T) {
	fr := NewFingerprintRotator()
	if fr == nil {
		t.Fatal("expected non-nil rotator")
	}
}

func TestFingerprintRotatorNext(t *testing.T) {
	fr := NewFingerprintRotator()

	fp := fr.Next()
	if fp == "" {
		t.Fatal("expected non-empty fingerprint")
	}

	valid := map[string]bool{
		FingerprintChrome:  true,
		FingerprintFirefox: true,
		FingerprintSafari:  true,
		FingerprintEdge:    true,
	}
	if !valid[fp] {
		t.Fatalf("unexpected fingerprint: %s", fp)
	}
}

func TestFingerprintRotatorVariety(t *testing.T) {
	fr := NewFingerprintRotator()

	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		seen[fr.Next()] = true
	}

	// With weighted random and 200 draws, should see at least 3 browsers
	if len(seen) < 3 {
		t.Fatalf("expected at least 3 different fingerprints, got %d: %v", len(seen), seen)
	}
}

func TestFingerprintRotatorAvoidRepeat(t *testing.T) {
	fr := NewFingerprintRotator()

	// Check that consecutive calls usually differ
	repeatCount := 0
	prev := fr.Next()
	for i := 0; i < 100; i++ {
		curr := fr.Next()
		if curr == prev {
			repeatCount++
		}
		prev = curr
	}

	// With avoidRepeat=true, repeats should be rare
	if repeatCount > 20 {
		t.Fatalf("too many consecutive repeats: %d/100", repeatCount)
	}
}

func TestFingerprintRotatorLastUsed(t *testing.T) {
	fr := NewFingerprintRotator()

	if fr.LastUsed() != "" {
		t.Fatal("LastUsed should be empty before first call")
	}

	fp := fr.Next()
	if fr.LastUsed() != fp {
		t.Fatalf("LastUsed should be '%s', got '%s'", fp, fr.LastUsed())
	}
}

func TestFingerprintRotatorSetPool(t *testing.T) {
	fr := NewFingerprintRotator()
	fr.SetPool(
		[]string{"chrome", "firefox"},
		[]float64{0.5, 0.5},
	)

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		seen[fr.Next()] = true
	}

	if seen["safari"] || seen["edge"] {
		t.Fatal("should only use chrome and firefox after SetPool")
	}
	if !seen["chrome"] || !seen["firefox"] {
		t.Fatal("should see both chrome and firefox")
	}
}

func TestFingerprintRotatorSinglePool(t *testing.T) {
	fr := NewFingerprintRotator()
	fr.SetPool(
		[]string{"chrome"},
		[]float64{1.0},
	)

	for i := 0; i < 20; i++ {
		fp := fr.Next()
		if fp != "chrome" {
			t.Fatalf("single pool should always return chrome, got %s", fp)
		}
	}
}

func TestFingerprintRotatorWeights(t *testing.T) {
	fr := NewFingerprintRotator()

	// Default weights: Chrome 65%, Firefox 18%, Safari 10%, Edge 7%
	counts := make(map[string]int)
	total := 10000
	for i := 0; i < total; i++ {
		counts[fr.Next()]++
	}

	// Chrome should be most popular (>40% considering avoidRepeat)
	chromeRatio := float64(counts["chrome"]) / float64(total)
	if chromeRatio < 0.35 {
		t.Fatalf("chrome should be dominant, got %.2f%%", chromeRatio*100)
	}
}

func TestFingerprintConstants(t *testing.T) {
	if FingerprintChrome != "chrome" {
		t.Fatal("chrome constant wrong")
	}
	if FingerprintFirefox != "firefox" {
		t.Fatal("firefox constant wrong")
	}
	if FingerprintSafari != "safari" {
		t.Fatal("safari constant wrong")
	}
	if FingerprintEdge != "edge" {
		t.Fatal("edge constant wrong")
	}
	if FingerprintRandom != "random" {
		t.Fatal("random constant wrong")
	}
}
