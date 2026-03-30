// Package crypto provides cryptographic primitives for Veil.
//
// This file implements PSK (Pre-Shared Key) rotation with
// time-based key derivation for forward secrecy.
package crypto

import (
	"crypto/sha256"
	"time"
)

// PSKRotator manages automatic key rotation.
// Old keys remain valid for a grace period to handle in-flight connections.
type PSKRotator struct {
	basePSK      []byte
	rotationDays int
	gracePeriod  time.Duration
}

// NewPSKRotator creates a rotator from a base secret.
func NewPSKRotator(secret string, rotationDays int) *PSKRotator {
	return &PSKRotator{
		basePSK:      GeneratePSK(secret),
		rotationDays: rotationDays,
		gracePeriod:  24 * time.Hour, // Accept yesterday's key too
	}
}

// CurrentPSK returns the PSK for the current rotation period.
func (r *PSKRotator) CurrentPSK() []byte {
	period := r.currentPeriod()
	return r.derivePSK(period)
}

// ValidPSKs returns all currently valid PSKs (current + grace period).
func (r *PSKRotator) ValidPSKs() [][]byte {
	period := r.currentPeriod()
	return [][]byte{
		r.derivePSK(period),
		r.derivePSK(period - 1), // Previous period (grace)
	}
}

// IsValid checks if a PSK is currently valid.
func (r *PSKRotator) IsValid(psk []byte) bool {
	for _, valid := range r.ValidPSKs() {
		if ConstantTimeCompare(psk, valid) {
			return true
		}
	}
	return false
}

func (r *PSKRotator) currentPeriod() int64 {
	return time.Now().Unix() / int64(r.rotationDays*86400)
}

func (r *PSKRotator) derivePSK(period int64) []byte {
	input := append(r.basePSK, byte(period>>24), byte(period>>16), byte(period>>8), byte(period))
	hash := sha256.Sum256(input)
	return hash[:]
}
