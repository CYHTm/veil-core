package protocol

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	veilcrypto "github.com/veil-protocol/veil-core/crypto"
)

var (
	ErrHandshakeTimeout = errors.New("veil: handshake timed out")
	ErrHandshakeFailed  = errors.New("veil: handshake failed")
	ErrInvalidHandshake = errors.New("veil: invalid handshake data")
	ErrClockSkew        = errors.New("veil: clock skew too large")
)

const (
	ClientHelloSize     = 48
	MaxHandshakePayload = 4096
)

type HandshakeRole uint8

const (
	RoleClient HandshakeRole = 0
	RoleServer HandshakeRole = 1
)

type HandshakeResult struct {
	SessionID        [16]byte
	ClientWriteKey   []byte
	ServerWriteKey   []byte
	ClientNonce      []byte
	ServerNonce      []byte
	PeerCapabilities Capabilities
	SelectedCipher   veilcrypto.CipherType
	Epoch            int64
}

type ClientHello struct {
	EphemeralPublic [32]byte
	Nonce           [16]byte
}

func (ch *ClientHello) MarshalAndMask(psk []byte, transportID string) ([]byte, int64, error) {
	raw := make([]byte, ClientHelloSize)
	copy(raw[0:32], ch.EphemeralPublic[:])
	copy(raw[32:48], ch.Nonce[:])

	mask, epoch, err := veilcrypto.DeriveHandshakeMask(psk, transportID, ClientHelloSize)
	if err != nil {
		return nil, 0, fmt.Errorf("derive mask: %w", err)
	}

	masked := veilcrypto.XORBytes(raw, mask)
	return masked, epoch, nil
}

func UnmaskClientHello(data []byte, psk []byte, transportID string) (*ClientHello, int64, error) {
	if len(data) != ClientHelloSize {
		return nil, 0, ErrInvalidHandshake
	}

	now := time.Now().Unix()
	currentEpoch := now / int64(veilcrypto.EpochWindow.Seconds())

	for _, epoch := range []int64{currentEpoch, currentEpoch - 1} {
		mask, err := veilcrypto.DeriveHandshakeMaskForEpoch(psk, transportID, epoch, ClientHelloSize)
		if err != nil {
			continue
		}

		unmasked := veilcrypto.XORBytes(data, mask)

		ch := &ClientHello{}
		copy(ch.EphemeralPublic[:], unmasked[0:32])
		copy(ch.Nonce[:], unmasked[32:48])

		allZero := true
		for _, b := range ch.EphemeralPublic {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			continue
		}

		return ch, epoch, nil
	}

	return nil, 0, ErrHandshakeFailed
}

type ServerHello struct {
	EphemeralPublic [32]byte     `json:"ephemeral_public"`
	SessionID       [16]byte     `json:"session_id"`
	Capabilities    Capabilities `json:"capabilities"`
	CipherType      uint8        `json:"cipher_type"`
}

// deriveHelloKey derives a symmetric key from PSK + client nonce.
// Both sides can compute this WITHOUT needing ECDH.
func deriveHelloKey(psk, clientNonce []byte) (key, nonce []byte) {
	// Combine PSK and client nonce
	combined := append(psk, clientNonce...)
	hash := sha256.Sum256(combined)
	key = hash[:]

	// Derive a nonce from a different hash
	nonceInput := append([]byte("veil-hello-nonce-v1|"), clientNonce...)
	nonceHash := sha256.Sum256(nonceInput)
	nonce = nonceHash[:12]

	return key, nonce
}

func MarshalServerHello(sh *ServerHello, psk, clientNonce []byte) ([]byte, error) {
	payload, err := json.Marshal(sh)
	if err != nil {
		return nil, fmt.Errorf("marshal server hello: %w", err)
	}

	// Derive key from PSK + client nonce (no ECDH needed)
	key, nonce := deriveHelloKey(psk, clientNonce)

	cipher, err := veilcrypto.NewSessionCipher(
		veilcrypto.CipherChaCha20Poly1305,
		key, key,
		nonce, nonce,
	)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	encrypted := cipher.Encrypt(payload, nil)
	return encrypted, nil
}

func UnmarshalServerHello(data []byte, psk, clientNonce []byte) (*ServerHello, error) {
	// Derive same key from PSK + client nonce
	key, nonce := deriveHelloKey(psk, clientNonce)

	cipher, err := veilcrypto.NewSessionCipher(
		veilcrypto.CipherChaCha20Poly1305,
		key, key,
		nonce, nonce,
	)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	plaintext, err := cipher.Decrypt(data, nil)
	if err != nil {
		return nil, ErrHandshakeFailed
	}

	sh := &ServerHello{}
	if err := json.Unmarshal(plaintext, sh); err != nil {
		return nil, fmt.Errorf("unmarshal server hello: %w", err)
	}

	return sh, nil
}

type Handshaker struct {
	role         HandshakeRole
	psk          []byte
	transportID  string
	capabilities Capabilities
	cipherType   veilcrypto.CipherType
}

func NewHandshaker(role HandshakeRole, secret string, transportID string, caps Capabilities) *Handshaker {
	return &Handshaker{
		role:         role,
		psk:          veilcrypto.GeneratePSK(secret),
		transportID:  transportID,
		capabilities: caps,
		cipherType:   veilcrypto.CipherChaCha20Poly1305,
	}
}

func (h *Handshaker) SetCipher(ct veilcrypto.CipherType) {
	h.cipherType = ct
}

func (h *Handshaker) GenerateClientHello() ([]byte, *veilcrypto.KeyPair, []byte, int64, error) {
	kp, err := veilcrypto.GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("generate keypair: %w", err)
	}

	nonce, err := veilcrypto.GenerateNonce(16)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("generate nonce: %w", err)
	}

	ch := &ClientHello{}
	copy(ch.EphemeralPublic[:], kp.Public[:])
	copy(ch.Nonce[:], nonce)

	masked, epoch, err := ch.MarshalAndMask(h.psk, h.transportID)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	return masked, kp, nonce, epoch, nil
}

// ProcessClientHello — server side.
// 1. Unmask client hello → get client ephemeral pub + nonce
// 2. Generate server keypair
// 3. Encrypt ServerHello with PSK + client nonce (both sides know this)
// 4. Derive session keys from ECDH + PSK
func (h *Handshaker) ProcessClientHello(data []byte) ([]byte, *HandshakeResult, *veilcrypto.KeyPair, error) {
	ch, epoch, err := UnmaskClientHello(data, h.psk, h.transportID)
	if err != nil {
		return nil, nil, nil, err
	}

	serverKP, err := veilcrypto.GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate server keypair: %w", err)
	}

	// ECDH for session keys (NOT for ServerHello encryption)
	sharedSecret, err := veilcrypto.ECDH(serverKP.Private[:], ch.EphemeralPublic[:])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ECDH: %w", err)
	}

	sessionID, err := veilcrypto.GenerateNonce(16)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate session ID: %w", err)
	}

	sh := &ServerHello{
		Capabilities: h.capabilities,
		CipherType:   uint8(h.cipherType),
	}
	copy(sh.EphemeralPublic[:], serverKP.Public[:])
	copy(sh.SessionID[:], sessionID)

	// Encrypt ServerHello with PSK + client nonce
	shBytes, err := MarshalServerHello(sh, h.psk, ch.Nonce[:])
	if err != nil {
		return nil, nil, nil, err
	}

	// Derive session keys from ECDH shared secret + PSK
	cWK, sWK, cN, sN, err := veilcrypto.DeriveSessionKeys(sharedSecret, h.psk)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("derive session keys: %w", err)
	}

	result := &HandshakeResult{
		ClientWriteKey:   cWK,
		ServerWriteKey:   sWK,
		ClientNonce:      cN,
		ServerNonce:      sN,
		PeerCapabilities: h.capabilities,
		SelectedCipher:   h.cipherType,
		Epoch:            epoch,
	}
	copy(result.SessionID[:], sessionID)

	return shBytes, result, serverKP, nil
}

// ProcessServerHello — client side.
// 1. Decrypt ServerHello with PSK + client nonce
// 2. Extract server ephemeral public key
// 3. ECDH(client_private, server_public) → shared secret
// 4. Derive session keys from shared secret + PSK
func (h *Handshaker) ProcessServerHello(data []byte, clientKP *veilcrypto.KeyPair, clientNonce []byte) (*HandshakeResult, error) {
	// Decrypt ServerHello using PSK + client nonce (no ECDH needed)
	sh, err := UnmarshalServerHello(data, h.psk, clientNonce)
	if err != nil {
		return nil, fmt.Errorf("decrypt server hello: %w", err)
	}

	// Now we have server's ephemeral public key → do ECDH
	sharedSecret, err := veilcrypto.ECDH(clientKP.Private[:], sh.EphemeralPublic[:])
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// Derive session keys from ECDH + PSK (same as server)
	cWK, sWK, cN, sN, err := veilcrypto.DeriveSessionKeys(sharedSecret, h.psk)
	if err != nil {
		return nil, fmt.Errorf("derive session keys: %w", err)
	}

	result := &HandshakeResult{
		ClientWriteKey:   cWK,
		ServerWriteKey:   sWK,
		ClientNonce:      cN,
		ServerNonce:      sN,
		PeerCapabilities: sh.Capabilities,
		SelectedCipher:   veilcrypto.CipherType(sh.CipherType),
	}
	copy(result.SessionID[:], sh.SessionID[:])

	return result, nil
}
