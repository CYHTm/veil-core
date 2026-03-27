// Package crypto provides cryptographic primitives for the Veil protocol.
//
// Key exchange: X25519 (Curve25519 ECDH)
// AEAD cipher: ChaCha20-Poly1305 (primary) / AES-256-GCM (alternative)
// KDF: HKDF-SHA256
// Handshake masking: HKDF-derived XOR masks with time-based epochs
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// KeySize is the size of X25519 keys.
	KeySize = 32

	// EpochWindow is the time window for handshake epoch derivation.
	EpochWindow = 30 * time.Second
)

var (
	ErrKeyGeneration = errors.New("veil/crypto: key generation failed")
	ErrKeyExchange   = errors.New("veil/crypto: key exchange failed")
)

// KeyPair holds an X25519 key pair.
type KeyPair struct {
	Private [KeySize]byte
	Public  [KeySize]byte
}

// GenerateKeyPair generates a new ephemeral X25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}

	if _, err := rand.Read(kp.Private[:]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyGeneration, err)
	}

	// Clamp the private key per X25519 spec
	kp.Private[0] &= 248
	kp.Private[31] &= 127
	kp.Private[31] |= 64

	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyGeneration, err)
	}
	copy(kp.Public[:], pub)

	return kp, nil
}

// ECDH performs X25519 key exchange.
func ECDH(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != KeySize || len(peerPublicKey) != KeySize {
		return nil, ErrKeyExchange
	}

	shared, err := curve25519.X25519(privateKey, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyExchange, err)
	}

	return shared, nil
}

// DeriveSessionKeys derives symmetric keys from the shared secret using HKDF.
// Returns: clientWriteKey, serverWriteKey, clientNonce, serverNonce
func DeriveSessionKeys(sharedSecret, psk []byte) (cWK, sWK, cN, sN []byte, err error) {
	// Combine shared secret with PSK
	ikm := append(sharedSecret, psk...)

	salt := sha256.Sum256([]byte("veil-session-salt-v1"))
	info := []byte("veil-session-keys-v1")

	hkdfReader := hkdf.New(sha256.New, ikm, salt[:], info)

	keys := make([]byte, 32+32+12+12) // 2 keys + 2 nonces
	if _, err := io.ReadFull(hkdfReader, keys); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("key derivation failed: %w", err)
	}

	cWK = keys[0:32]
	sWK = keys[32:64]
	cN = keys[64:76]
	sN = keys[76:88]

	return cWK, sWK, cN, sN, nil
}

// DeriveHandshakeMask generates a time-based mask for the polymorphic handshake.
// The mask changes every EpochWindow, making each handshake look different.
func DeriveHandshakeMask(psk []byte, transportID string, maskLen int) ([]byte, int64, error) {
	epoch := time.Now().Unix() / int64(EpochWindow.Seconds())
	mask, err := deriveHandshakeMaskForEpoch(psk, transportID, epoch, maskLen)
	return mask, epoch, err
}

// DeriveHandshakeMaskForEpoch generates a mask for a specific epoch.
// The server tries current and previous epoch to handle clock skew.
func DeriveHandshakeMaskForEpoch(psk []byte, transportID string, epoch int64, maskLen int) ([]byte, error) {
	return deriveHandshakeMaskForEpoch(psk, transportID, epoch, maskLen)
}

func deriveHandshakeMaskForEpoch(psk []byte, transportID string, epoch int64, maskLen int) ([]byte, error) {
	info := fmt.Sprintf("veil-handshake-mask-v1|%s|%d", transportID, epoch)
	salt := sha256.Sum256([]byte("veil-handshake-salt-v1"))

	hkdfReader := hkdf.New(sha256.New, psk, salt[:], []byte(info))

	mask := make([]byte, maskLen)
	if _, err := io.ReadFull(hkdfReader, mask); err != nil {
		return nil, fmt.Errorf("mask derivation failed: %w", err)
	}

	return mask, nil
}

// XORBytes XORs two byte slices of equal length.
func XORBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("veil/crypto: XOR operands must be same length")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// GenerateNonce generates a random nonce of the given size.
func GenerateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// GeneratePSK generates a pre-shared key from a human-readable secret.
func GeneratePSK(secret string) []byte {
	h := sha256.Sum256([]byte("veil-psk-v1|" + secret))
	return h[:]
}
