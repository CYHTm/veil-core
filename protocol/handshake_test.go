package protocol

import (
	"crypto/rand"
	"testing"

	veilcrypto "github.com/veil-protocol/veil-core/crypto"
)

func TestClientHelloMarshalUnmask(t *testing.T) {
	psk := veilcrypto.GeneratePSK("test-secret")

	ch := &ClientHello{}
	rand.Read(ch.EphemeralPublic[:])
	rand.Read(ch.Nonce[:])

	wire, _, err := ch.MarshalAndMask(psk, "raw")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	decoded, _, err := UnmaskClientHello(wire, psk, "raw")
	if err != nil {
		t.Fatalf("unmask: %v", err)
	}

	if decoded.EphemeralPublic != ch.EphemeralPublic {
		t.Fatal("ephemeral public key mismatch")
	}
	if decoded.Nonce != ch.Nonce {
		t.Fatal("nonce mismatch")
	}
}

func TestClientHelloVariableLength(t *testing.T) {
	psk := veilcrypto.GeneratePSK("test-secret")

	lengths := make(map[int]bool)
	for i := 0; i < 50; i++ {
		ch := &ClientHello{}
		rand.Read(ch.EphemeralPublic[:])
		rand.Read(ch.Nonce[:])

		wire, _, err := ch.MarshalAndMask(psk, "raw")
		if err != nil {
			t.Fatalf("marshal %d: %v", i, err)
		}
		lengths[len(wire)] = true
	}

	// Should have variety in lengths (polymorphic)
	if len(lengths) < 5 {
		t.Fatalf("expected polymorphic lengths, only got %d unique sizes", len(lengths))
	}
}

func TestClientHelloWrongPSK(t *testing.T) {
	psk1 := veilcrypto.GeneratePSK("secret-1")
	psk2 := veilcrypto.GeneratePSK("secret-2")

	ch := &ClientHello{}
	rand.Read(ch.EphemeralPublic[:])
	rand.Read(ch.Nonce[:])

	wire, _, err := ch.MarshalAndMask(psk1, "raw")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, _, err = UnmaskClientHello(wire, psk2, "raw")
	if err == nil {
		t.Fatal("should fail with wrong PSK")
	}
}


func TestClientHelloTooShort(t *testing.T) {
	psk := veilcrypto.GeneratePSK("test-secret")
	_, _, err := UnmaskClientHello([]byte{0x00, 0x01}, psk, "raw")
	if err == nil {
		t.Fatal("should reject too short data")
	}
}

func TestClientHelloAllZeroKey(t *testing.T) {
	psk := veilcrypto.GeneratePSK("test-secret")

	ch := &ClientHello{}
	// EphemeralPublic is all zeros (not initialized)
	rand.Read(ch.Nonce[:])

	wire, _, err := ch.MarshalAndMask(psk, "raw")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, _, err = UnmaskClientHello(wire, psk, "raw")
	if err == nil {
		t.Fatal("should reject all-zero public key")
	}
}

func TestServerHelloMarshalUnmarshal(t *testing.T) {
	psk := veilcrypto.GeneratePSK("test-secret")
	clientNonce := make([]byte, 16)
	rand.Read(clientNonce)

	sh := &ServerHello{
		Capabilities: DefaultCapabilities(),
		CipherType:   uint8(veilcrypto.CipherChaCha20Poly1305),
	}
	rand.Read(sh.EphemeralPublic[:])
	rand.Read(sh.SessionID[:])

	wire, err := MarshalServerHello(sh, psk, clientNonce)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	decoded, err := UnmarshalServerHello(wire, psk, clientNonce)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.EphemeralPublic != sh.EphemeralPublic {
		t.Fatal("ephemeral public mismatch")
	}
	if decoded.SessionID != sh.SessionID {
		t.Fatal("session ID mismatch")
	}
	if decoded.CipherType != sh.CipherType {
		t.Fatal("cipher type mismatch")
	}
	if decoded.Capabilities.MaxStreams != sh.Capabilities.MaxStreams {
		t.Fatal("capabilities mismatch")
	}
}

func TestServerHelloWrongPSK(t *testing.T) {
	psk1 := veilcrypto.GeneratePSK("secret-1")
	psk2 := veilcrypto.GeneratePSK("secret-2")
	clientNonce := make([]byte, 16)
	rand.Read(clientNonce)

	sh := &ServerHello{Capabilities: DefaultCapabilities()}
	rand.Read(sh.EphemeralPublic[:])
	rand.Read(sh.SessionID[:])

	wire, err := MarshalServerHello(sh, psk1, clientNonce)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, err = UnmarshalServerHello(wire, psk2, clientNonce)
	if err == nil {
		t.Fatal("should fail with wrong PSK")
	}
}

func TestServerHelloWrongNonce(t *testing.T) {
	psk := veilcrypto.GeneratePSK("test-secret")
	nonce1 := make([]byte, 16)
	nonce2 := make([]byte, 16)
	rand.Read(nonce1)
	rand.Read(nonce2)

	sh := &ServerHello{Capabilities: DefaultCapabilities()}
	rand.Read(sh.EphemeralPublic[:])
	rand.Read(sh.SessionID[:])

	wire, err := MarshalServerHello(sh, psk, nonce1)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, err = UnmarshalServerHello(wire, psk, nonce2)
	if err == nil {
		t.Fatal("should fail with wrong client nonce")
	}
}

func TestServerHelloTooShort(t *testing.T) {
	psk := veilcrypto.GeneratePSK("test-secret")
	_, err := UnmarshalServerHello([]byte{0x00}, psk, []byte("nonce"))
	if err == nil {
		t.Fatal("should reject too short data")
	}
}

func TestServerHelloBadLength(t *testing.T) {
	psk := veilcrypto.GeneratePSK("test-secret")
	// Length field says 9999 bytes but payload is tiny
	wire := []byte{0x00, 0x00, 0x27, 0x0F, 0x01, 0x02}
	_, err := UnmarshalServerHello(wire, psk, []byte("nonce"))
	if err == nil {
		t.Fatal("should reject invalid length")
	}
}

func TestFullHandshakeFlow(t *testing.T) {
	secret := "test-handshake-secret"
	transport := "raw"
	caps := DefaultCapabilities()

	// Client side
	clientHS := NewHandshaker(RoleClient, secret, transport, caps)
	clientHelloWire, clientKP, clientNonce, _, err := clientHS.GenerateClientHello()
	if err != nil {
		t.Fatalf("generate client hello: %v", err)
	}

	// Server side
	serverHS := NewHandshaker(RoleServer, secret, transport, caps)
	serverHelloWire, serverResult, _, err := serverHS.ProcessClientHello(clientHelloWire)
	if err != nil {
		t.Fatalf("process client hello: %v", err)
	}

	// Client processes server response
	clientResult, err := clientHS.ProcessServerHello(serverHelloWire, clientKP, clientNonce)
	if err != nil {
		t.Fatalf("process server hello: %v", err)
	}

	// Session IDs should match
	if clientResult.SessionID != serverResult.SessionID {
		t.Fatal("session IDs should match")
	}

	// Derived keys should match (client write key = what server expects to read)
	if !veilcrypto.ConstantTimeCompare(clientResult.ClientWriteKey, serverResult.ClientWriteKey) {
		t.Fatal("client write keys should match")
	}
	if !veilcrypto.ConstantTimeCompare(clientResult.ServerWriteKey, serverResult.ServerWriteKey) {
		t.Fatal("server write keys should match")
	}
	if !veilcrypto.ConstantTimeCompare(clientResult.ClientNonce, serverResult.ClientNonce) {
		t.Fatal("client nonces should match")
	}
	if !veilcrypto.ConstantTimeCompare(clientResult.ServerNonce, serverResult.ServerNonce) {
		t.Fatal("server nonces should match")
	}
}

func TestFullHandshakeWrongSecret(t *testing.T) {
	caps := DefaultCapabilities()

	clientHS := NewHandshaker(RoleClient, "secret-1", "raw", caps)
	clientHelloWire, _, _, _, err := clientHS.GenerateClientHello()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	serverHS := NewHandshaker(RoleServer, "secret-2", "raw", caps)
	_, _, _, err = serverHS.ProcessClientHello(clientHelloWire)
	if err == nil {
		t.Fatal("should fail with wrong secret")
	}
}

func TestHandshakerSetCipher(t *testing.T) {
	caps := DefaultCapabilities()
	hs := NewHandshaker(RoleClient, "secret", "raw", caps)

	hs.SetCipher(veilcrypto.CipherAES256GCM)

	// Do full handshake with AES
	clientHelloWire, clientKP, clientNonce, _, err := hs.GenerateClientHello()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	serverHS := NewHandshaker(RoleServer, "secret", "raw", caps)
	serverHS.SetCipher(veilcrypto.CipherAES256GCM)

	serverHelloWire, _, _, err := serverHS.ProcessClientHello(clientHelloWire)
	if err != nil {
		t.Fatalf("process client hello: %v", err)
	}

	result, err := hs.ProcessServerHello(serverHelloWire, clientKP, clientNonce)
	if err != nil {
		t.Fatalf("process server hello: %v", err)
	}

	if result.SelectedCipher != veilcrypto.CipherAES256GCM {
		t.Fatalf("expected AES-256-GCM, got %d", result.SelectedCipher)
	}
}

func TestHandshakeMultipleTimes(t *testing.T) {
	caps := DefaultCapabilities()

	// Multiple handshakes should produce different session IDs and keys
	sessionIDs := make(map[[16]byte]bool)

	for i := 0; i < 10; i++ {
		clientHS := NewHandshaker(RoleClient, "secret", "raw", caps)
		serverHS := NewHandshaker(RoleServer, "secret", "raw", caps)

		wire, kp, nonce, _, _ := clientHS.GenerateClientHello()
		shWire, _, _, _ := serverHS.ProcessClientHello(wire)
		result, _ := clientHS.ProcessServerHello(shWire, kp, nonce)

		if sessionIDs[result.SessionID] {
			t.Fatal("duplicate session ID")
		}
		sessionIDs[result.SessionID] = true
	}
}

func TestHandshakeResultKeysNonZero(t *testing.T) {
	caps := DefaultCapabilities()
	clientHS := NewHandshaker(RoleClient, "secret", "raw", caps)
	serverHS := NewHandshaker(RoleServer, "secret", "raw", caps)

	wire, kp, nonce, _, _ := clientHS.GenerateClientHello()
	shWire, _, _, _ := serverHS.ProcessClientHello(wire)
	result, err := clientHS.ProcessServerHello(shWire, kp, nonce)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// All keys should be non-zero
	allZero := func(b []byte) bool {
		for _, v := range b {
			if v != 0 {
				return false
			}
		}
		return true
	}

	if allZero(result.ClientWriteKey) {
		t.Fatal("client write key is all zeros")
	}
	if allZero(result.ServerWriteKey) {
		t.Fatal("server write key is all zeros")
	}
	if allZero(result.ClientNonce) {
		t.Fatal("client nonce is all zeros")
	}
	if allZero(result.ServerNonce) {
		t.Fatal("server nonce is all zeros")
	}
	if allZero(result.SessionID[:]) {
		t.Fatal("session ID is all zeros")
	}
}

func TestClientHelloMaskedLooksRandom(t *testing.T) {
	psk := veilcrypto.GeneratePSK("test-secret")

	ch := &ClientHello{}
	rand.Read(ch.EphemeralPublic[:])
	rand.Read(ch.Nonce[:])

	wire1, _, _ := ch.MarshalAndMask(psk, "raw")
	wire2, _, _ := ch.MarshalAndMask(psk, "raw")

	// Two marshals of same data should produce different wire bytes (random padding)
	if len(wire1) == len(wire2) {
		same := true
		for i := range wire1 {
			if wire1[i] != wire2[i] {
				same = false
				break
			}
		}
		if same {
			t.Fatal("two marshals should not produce identical wire bytes")
		}
	}
}
