package crypto

import "runtime"

// Zeroize overwrites a byte slice with zeros.
// Call this when secret key material is no longer needed.
// Prevents keys from lingering in memory where they could be
// extracted via memory dumps or cold boot attacks.
func Zeroize(data []byte) {
	for i := range data {
		data[i] = 0
	}
	// Prevent compiler from optimizing away the zeroing
	runtime.KeepAlive(data)
}

// SecureBuffer is a byte slice that automatically zeros itself.
type SecureBuffer struct {
	data []byte
}

// NewSecureBuffer creates a secure buffer of given size.
func NewSecureBuffer(size int) *SecureBuffer {
	return &SecureBuffer{data: make([]byte, size)}
}

// Bytes returns the underlying data. Do NOT store this reference
// after calling Destroy().
func (sb *SecureBuffer) Bytes() []byte {
	return sb.data
}

// Copy copies data into the secure buffer.
func (sb *SecureBuffer) Copy(src []byte) {
	copy(sb.data, src)
}

// Destroy zeros the buffer. Call when done with the key.
func (sb *SecureBuffer) Destroy() {
	Zeroize(sb.data)
}
