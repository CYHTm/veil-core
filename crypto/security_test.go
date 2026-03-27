package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Проверяем что шифротекст не утекает информацию о plaintext
func TestCiphertextIndistinguishable(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)

	cipher, _ := NewSessionCipher(CipherChaCha20Poly1305, key, key, nonce, nonce)

	// Шифруем два разных сообщения одинаковой длины
	msg1 := bytes.Repeat([]byte("A"), 1000)
	msg2 := bytes.Repeat([]byte("B"), 1000)

	ct1 := cipher.Encrypt(msg1, nil)
	ct2 := cipher.Encrypt(msg2, nil)

	// Шифротексты должны быть разными
	if bytes.Equal(ct1, ct2) {
		t.Error("CRITICAL: same-length messages produce identical ciphertext")
	}

	// Длины шифротекстов должны быть одинаковыми (не утекает длина)
	if len(ct1) != len(ct2) {
		t.Error("ciphertext lengths differ for same-length plaintext")
	}
}

// Проверяем что нельзя подменить данные
func TestTamperDetection(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)

	cipher, _ := NewSessionCipher(CipherChaCha20Poly1305, key, key, nonce, nonce)

	ct := cipher.Encrypt([]byte("important data"), nil)

	// Меняем один байт
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[5] ^= 0xFF

	_, err := cipher.Decrypt(tampered, nil)
	if err == nil {
		t.Error("CRITICAL: tampered ciphertext was accepted")
	}
}

// Проверяем что replay attack не работает
func TestReplayProtection(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)

	encCipher, _ := NewSessionCipher(CipherChaCha20Poly1305, key, key, nonce, nonce)
	decCipher, _ := NewSessionCipher(CipherChaCha20Poly1305, key, key, nonce, nonce)

	// Нормальная последовательность
	ct1 := encCipher.Encrypt([]byte("message 1"), nil)
	ct2 := encCipher.Encrypt([]byte("message 2"), nil)

	// Расшифровываем в порядке
	_, err1 := decCipher.Decrypt(ct1, nil)
	_, err2 := decCipher.Decrypt(ct2, nil)
	if err1 != nil || err2 != nil {
		t.Fatal("normal decryption failed")
	}

	// Попытка replay: отправить ct1 ещё раз
	// Это должно провалиться потому что nonce counter уже ушёл вперёд
	decCipher2, _ := NewSessionCipher(CipherChaCha20Poly1305, key, key, nonce, nonce)
	decCipher2.Decrypt(ct1, nil) // msg 1 OK
	decCipher2.Decrypt(ct2, nil) // msg 2 OK

	// Третье сообщение с nonce=0 (replay ct1) не совпадёт с nonce=2
	_, err := decCipher2.Decrypt(ct1, nil)
	if err == nil {
		t.Error("CRITICAL: replay attack succeeded")
	}
}

// Проверяем что ключи не предсказуемы
func TestKeyRandomness(t *testing.T) {
	keys := make([][]byte, 100)
	for i := range keys {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = kp.Private[:]
	}

	// Никакие два ключа не должны совпасть
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if bytes.Equal(keys[i], keys[j]) {
				t.Errorf("CRITICAL: key collision at %d and %d", i, j)
			}
		}
	}
}

// Проверяем что PSK из разных паролей не совпадает
func TestPSKUniqueness(t *testing.T) {
	passwords := []string{
		"password1",
		"password2",
		"password1 ", // С пробелом
		"Password1",  // Другой регистр
	}

	psks := make([][]byte, len(passwords))
	for i, p := range passwords {
		psks[i] = GeneratePSK(p)
	}

	for i := 0; i < len(psks); i++ {
		for j := i + 1; j < len(psks); j++ {
			if bytes.Equal(psks[i], psks[j]) {
				t.Errorf("CRITICAL: PSK collision: %q and %q", passwords[i], passwords[j])
			}
		}
	}
}

// Проверяем что хэндшейк-маска уникальна для каждой эпохи
func TestHandshakeMaskUniqueness(t *testing.T) {
	psk := GeneratePSK("test")

	masks := make([][]byte, 10)
	for i := int64(0); i < 10; i++ {
		m, _ := DeriveHandshakeMaskForEpoch(psk, "raw", i, 48)
		masks[i] = m
	}

	for i := 0; i < len(masks); i++ {
		for j := i + 1; j < len(masks); j++ {
			if bytes.Equal(masks[i], masks[j]) {
				t.Errorf("CRITICAL: mask collision at epochs %d and %d", i, j)
			}
		}
	}
}
