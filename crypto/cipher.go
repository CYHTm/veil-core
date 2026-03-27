package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrDecryptionFailed = errors.New("veil/crypto: decryption failed (invalid key or corrupted data)")
	ErrUnknownCipher    = errors.New("veil/crypto: unknown cipher type")
)

// CipherType represents the AEAD cipher algorithm.
type CipherType uint8

const (
	CipherChaCha20Poly1305 CipherType = 0x01
	CipherAES256GCM        CipherType = 0x02
)

// SessionCipher handles encryption/decryption for a Veil session.
type SessionCipher struct {
	encryptor cipher.AEAD
	decryptor cipher.AEAD
	encNonce  uint64 // Counter-based nonce for encryption
	decNonce  uint64 // Counter-based nonce for decryption
	baseEncN  []byte // Base nonce for encryption (XORed with counter)
	baseDecN  []byte // Base nonce for decryption (XORed with counter)
}

// NewSessionCipher creates a new session cipher.
// writeKey/readKey are 32 bytes, writeNonce/readNonce are 12 bytes.
func NewSessionCipher(cipherType CipherType, writeKey, readKey, writeNonce, readNonce []byte) (*SessionCipher, error) {
	enc, err := newAEAD(cipherType, writeKey)
	if err != nil {
		return nil, fmt.Errorf("create encryptor: %w", err)
	}

	dec, err := newAEAD(cipherType, readKey)
	if err != nil {
		return nil, fmt.Errorf("create decryptor: %w", err)
	}

	return &SessionCipher{
		encryptor: enc,
		decryptor: dec,
		baseEncN:  writeNonce,
		baseDecN:  readNonce,
	}, nil
}

func newAEAD(ct CipherType, key []byte) (cipher.AEAD, error) {
	switch ct {
	case CipherChaCha20Poly1305:
		return chacha20poly1305.New(key)
	case CipherAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, ErrUnknownCipher
	}
}

// Encrypt encrypts plaintext with AEAD, using a counter-based nonce.
// additionalData is authenticated but not encrypted (e.g., frame version byte).
func (sc *SessionCipher) Encrypt(plaintext, additionalData []byte) []byte {
	nonce := sc.buildNonce(sc.baseEncN, sc.encNonce)
	sc.encNonce++

	return sc.encryptor.Seal(nil, nonce, plaintext, additionalData)
}

// Decrypt decrypts ciphertext with AEAD.
func (sc *SessionCipher) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	nonce := sc.buildNonce(sc.baseDecN, sc.decNonce)
	sc.decNonce++

	plaintext, err := sc.decryptor.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// buildNonce XORs the base nonce with a counter to produce a unique nonce per message.
func (sc *SessionCipher) buildNonce(base []byte, counter uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, base)

	// XOR counter into last 8 bytes of nonce
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= counterBytes[i]
	}

	return nonce
}
