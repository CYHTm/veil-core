package crypto

import (
	"crypto/hmac"
	"crypto/subtle"
	"time"
)

// ConstantTimeCompare compares two byte slices in constant time.
// Prevents timing attacks that measure how long comparison takes.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ConstantTimeHMACCompare compares two HMAC values in constant time.
func ConstantTimeHMACCompare(a, b []byte) bool {
	return hmac.Equal(a, b)
}

// PaddedSleep ensures operations take at least minDuration.
// Prevents timing side channels that reveal whether an operation
// succeeded or failed based on how long it took.
func PaddedSleep(start time.Time, minDuration time.Duration) {
	elapsed := time.Since(start)
	if elapsed < minDuration {
		time.Sleep(minDuration - elapsed)
	}
}

// ConstantTimeSelect returns a if selector == 1, b if selector == 0.
// Does not branch — prevents timing side channels.
func ConstantTimeSelect(selector int, a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}
	result := make([]byte, len(a))
	for i := range result {
		result[i] = byte(subtle.ConstantTimeSelect(selector, int(a[i]), int(b[i])))
	}
	return result
}
