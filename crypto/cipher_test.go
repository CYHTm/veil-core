package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSessionCipherEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)

	cipher, err := NewSessionCipher(CipherChaCha20Poly1305, key, key, nonce, nonce)
	if err != nil {
		t.Fatalf("NewSessionCipher failed: %v", err)
	}

	plaintext := []byte("Hello, Veil Protocol!")
	ad := []byte{0x01}

	ciphertext := cipher.Encrypt(plaintext, ad)

	// Шифротекст не должен совпадать с открытым текстом
	if bytes.Equal(plaintext, ciphertext[:len(plaintext)]) {
		t.Error("ciphertext equals plaintext")
	}

	// Шифротекст длиннее (добавлен auth tag)
	if len(ciphertext) <= len(plaintext) {
		t.Error("ciphertext should be longer than plaintext")
	}

	decrypted, err := cipher.Decrypt(ciphertext, ad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted != plaintext: got %q, want %q", decrypted, plaintext)
	}
}

func TestSessionCipherAES256GCM(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)
	rand.Read(nonce)

	cipher, err := NewSessionCipher(CipherAES256GCM, key, key, nonce, nonce)
	if err != nil {
		t.Fatalf("NewSessionCipher AES failed: %v", err)
	}

	plaintext := []byte("AES-256-GCM test data")
	ciphertext := cipher.Encrypt(plaintext, nil)
	decrypted, err := cipher.Decrypt(ciphertext, nil)
	if err != nil {
		t.Fatalf("AES Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("AES roundtrip failed")
	}
}

func TestSessionCipherWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)
	nonce := make([]byte, 12)

	encCipher, _ := NewSessionCipher(CipherChaCha20Poly1305, key1, key1, nonce, nonce)
	decCipher, _ := NewSessionCipher(CipherChaCha20Poly1305, key2, key2, nonce, nonce)

	ciphertext := encCipher.Encrypt([]byte("secret"), nil)

	_, err := decCipher.Decrypt(ciphertext, nil)
	if err == nil {
		t.Error("should fail with wrong key")
	}
}

func TestSessionCipherSequentialNonces(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	nonce := make([]byte, 12)

	cipher, _ := NewSessionCipher(CipherChaCha20Poly1305, key, key, nonce, nonce)

	// Шифруем одно и то же сообщение дважды — результат РАЗНЫЙ (разные nonce)
	ct1 := cipher.Encrypt([]byte("same message"), nil)
	ct2 := cipher.Encrypt([]byte("same message"), nil)

	if bytes.Equal(ct1, ct2) {
		t.Error("same plaintext should produce different ciphertext (nonce increment)")
	}
}

func TestSessionCipherClientServer(t *testing.T) {
	// Имитация: клиент и сервер с разными ключами
	cWK := make([]byte, 32)
	sWK := make([]byte, 32)
	cN := make([]byte, 12)
	sN := make([]byte, 12)
	rand.Read(cWK)
	rand.Read(sWK)
	rand.Read(cN)
	rand.Read(sN)

	// Client: пишет cWK, читает sWK
	clientCipher, _ := NewSessionCipher(CipherChaCha20Poly1305, cWK, sWK, cN, sN)

	// Server: пишет sWK, читает cWK
	serverCipher, _ := NewSessionCipher(CipherChaCha20Poly1305, sWK, cWK, sN, cN)

	// Client шифрует → сервер расшифровывает
	msg := []byte("client to server")
	ct := clientCipher.Encrypt(msg, nil)
	pt, err := serverCipher.Decrypt(ct, nil)
	if err != nil {
		t.Fatalf("server decrypt failed: %v", err)
	}
	if !bytes.Equal(msg, pt) {
		t.Error("client->server message corrupted")
	}

	// Server шифрует → клиент расшифровывает
	msg2 := []byte("server to client")
	ct2 := serverCipher.Encrypt(msg2, nil)
	pt2, err := clientCipher.Decrypt(ct2, nil)
	if err != nil {
		t.Fatalf("client decrypt failed: %v", err)
	}
	if !bytes.Equal(msg2, pt2) {
		t.Error("server->client message corrupted")
	}
}
