package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Два ключа должны быть разными
	if bytes.Equal(kp1.Public[:], kp2.Public[:]) {
		t.Error("two keypairs have same public key")
	}
	if bytes.Equal(kp1.Private[:], kp2.Private[:]) {
		t.Error("two keypairs have same private key")
	}

	// Ключ не должен быть нулевым
	allZero := true
	for _, b := range kp1.Public {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("public key is all zeros")
	}
}

func TestECDH(t *testing.T) {
	// Обе стороны генерируют ключи
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	// Обе стороны вычисляют общий секрет
	secret1, err := ECDH(alice.Private[:], bob.Public[:])
	if err != nil {
		t.Fatalf("ECDH alice failed: %v", err)
	}

	secret2, err := ECDH(bob.Private[:], alice.Public[:])
	if err != nil {
		t.Fatalf("ECDH bob failed: %v", err)
	}

	// Секреты должны совпасть
	if !bytes.Equal(secret1, secret2) {
		t.Error("ECDH shared secrets don't match")
	}
}

func TestDeriveSessionKeys(t *testing.T) {
	shared := make([]byte, 32)
	shared[0] = 0x42
	psk := []byte("test-psk")

	cWK, sWK, cN, sN, err := DeriveSessionKeys(shared, psk)
	if err != nil {
		t.Fatalf("DeriveSessionKeys failed: %v", err)
	}

	// Все ключи должны быть правильной длины
	if len(cWK) != 32 {
		t.Errorf("client write key: got %d bytes, want 32", len(cWK))
	}
	if len(sWK) != 32 {
		t.Errorf("server write key: got %d bytes, want 32", len(sWK))
	}
	if len(cN) != 12 {
		t.Errorf("client nonce: got %d bytes, want 12", len(cN))
	}
	if len(sN) != 12 {
		t.Errorf("server nonce: got %d bytes, want 12", len(sN))
	}

	// Ключи не должны совпадать
	if bytes.Equal(cWK, sWK) {
		t.Error("client and server write keys are the same")
	}

	// Повторный вызов с теми же данными = те же ключи
	cWK2, sWK2, _, _, _ := DeriveSessionKeys(shared, psk)
	if !bytes.Equal(cWK, cWK2) || !bytes.Equal(sWK, sWK2) {
		t.Error("deterministic key derivation failed")
	}
}

func TestHandshakeMask(t *testing.T) {
	psk := GeneratePSK("test-secret")

	mask1, epoch1, err := DeriveHandshakeMask(psk, "raw", 48)
	if err != nil {
		t.Fatalf("DeriveHandshakeMask failed: %v", err)
	}

	if len(mask1) != 48 {
		t.Errorf("mask length: got %d, want 48", len(mask1))
	}

	// Та же эпоха = та же маска
	mask2, _ := DeriveHandshakeMaskForEpoch(psk, "raw", epoch1, 48)
	if !bytes.Equal(mask1, mask2) {
		t.Error("same epoch should produce same mask")
	}

	// Другой транспорт = другая маска
	mask3, _, _ := DeriveHandshakeMask(psk, "tls", 48)
	if bytes.Equal(mask1, mask3) {
		t.Error("different transport should produce different mask")
	}

	// Другой секрет = другая маска
	psk2 := GeneratePSK("other-secret")
	mask4, _, _ := DeriveHandshakeMask(psk2, "raw", 48)
	if bytes.Equal(mask1, mask4) {
		t.Error("different PSK should produce different mask")
	}
}

func TestXORBytes(t *testing.T) {
	a := []byte{0xFF, 0x00, 0xAA}
	b := []byte{0x0F, 0xF0, 0x55}

	result := XORBytes(a, b)
	expected := []byte{0xF0, 0xF0, 0xFF}

	if !bytes.Equal(result, expected) {
		t.Errorf("XOR: got %x, want %x", result, expected)
	}

	// XOR с самим собой = нули
	zeros := XORBytes(a, a)
	for _, b := range zeros {
		if b != 0 {
			t.Error("XOR with self should be zero")
		}
	}
}

func TestGeneratePSK(t *testing.T) {
	psk1 := GeneratePSK("secret1")
	psk2 := GeneratePSK("secret2")
	psk3 := GeneratePSK("secret1") // Тот же секрет

	if bytes.Equal(psk1, psk2) {
		t.Error("different secrets produce same PSK")
	}
	if !bytes.Equal(psk1, psk3) {
		t.Error("same secret should produce same PSK")
	}
	if len(psk1) != 32 {
		t.Errorf("PSK length: got %d, want 32", len(psk1))
	}
}
