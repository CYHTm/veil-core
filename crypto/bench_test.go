package crypto

import (
	"crypto/rand"
	"testing"
)

func BenchmarkChaCha20Encrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)
	cipher, _ := NewSessionCipher(CipherChaCha20Poly1305, key, key, nonce, nonce)
	payload := make([]byte, 1400) // Typical MTU-sized packet
	rand.Read(payload)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cipher.Encrypt(payload, nil)
	}
}

func BenchmarkChaCha20Decrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)
	enc, _ := NewSessionCipher(CipherChaCha20Poly1305, key, key, nonce, nonce)
	payload := make([]byte, 1400)
	rand.Read(payload)
	ciphertext := enc.Encrypt(payload, nil)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Reset nonce counter for each iteration
		dec2, _ := NewSessionCipher(CipherChaCha20Poly1305, key, key, nonce, nonce)
		dec2.Decrypt(ciphertext, nil)
	}
}

func BenchmarkAES256GCMEncrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)
	cipher, _ := NewSessionCipher(CipherAES256GCM, key, key, nonce, nonce)
	payload := make([]byte, 1400)
	rand.Read(payload)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cipher.Encrypt(payload, nil)
	}
}

func BenchmarkECDH(b *testing.B) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ECDH(kp1.Private[:], kp2.Public[:])
	}
}

func BenchmarkHandshakeMask(b *testing.B) {
	psk := GeneratePSK("bench-secret")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveHandshakeMask(psk, "raw", 128)
	}
}

func BenchmarkReplayFilter(b *testing.B) {
	rf := NewReplayFilter()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rf.Check(uint64(i + 1))
	}
}
