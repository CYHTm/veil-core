// Package tls — rotation.go implements TLS fingerprint rotation.
//
// Instead of always using Chrome, randomly select between
// Chrome, Firefox, Safari, Edge. Each new connection gets
// a different browser fingerprint. This prevents DPI from
// saying "all connections from this IP use Chrome 120 → suspicious".
package tls

import (
	"math/rand"
	"sync"
	"time"
)

// FingerprintRotator randomly selects browser fingerprints.
type FingerprintRotator struct {
	mu          sync.Mutex
	rng         *rand.Rand
	pool        []string
	weights     []float64
	lastUsed    string
	avoidRepeat bool
}

// NewFingerprintRotator creates a rotator with default browser mix.
func NewFingerprintRotator() *FingerprintRotator {
	return &FingerprintRotator{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
		pool: []string{
			FingerprintChrome,
			FingerprintFirefox,
			FingerprintSafari,
			FingerprintEdge,
		},
		// Chrome dominant (matches real-world browser share)
		weights:     []float64{0.65, 0.18, 0.10, 0.07},
		avoidRepeat: true,
	}
}

// Next returns the next fingerprint to use.
func (fr *FingerprintRotator) Next() string {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	for attempts := 0; attempts < 10; attempts++ {
		r := fr.rng.Float64()
		cumulative := 0.0

		for i, w := range fr.weights {
			cumulative += w
			if r <= cumulative {
				fp := fr.pool[i]
				if fr.avoidRepeat && fp == fr.lastUsed && len(fr.pool) > 1 {
					continue // Try again to avoid same fingerprint twice
				}
				fr.lastUsed = fp
				return fp
			}
		}
	}

	// Fallback
	fr.lastUsed = fr.pool[0]
	return fr.pool[0]
}

// SetPool configures which fingerprints to use and their weights.
func (fr *FingerprintRotator) SetPool(fingerprints []string, weights []float64) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	fr.pool = fingerprints
	fr.weights = weights
}

// LastUsed returns the most recently selected fingerprint.
func (fr *FingerprintRotator) LastUsed() string {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	return fr.lastUsed
}
