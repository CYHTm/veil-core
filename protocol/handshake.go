// Package protocol implements the Veil wire protocol.
//
// This file implements the polymorphic handshake that changes
// its byte pattern every 30 seconds, preventing DPI signature matching.
package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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
	// Core payload: ephemeral_public_key(32) + nonce(16) = 48 bytes
	ClientHelloCoreSize = 48
	// Random padding range: 16..128 bytes added to core
	MinHelloPadding = 16
	MaxHelloPadding = 128
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

// MarshalAndMask serializes, pads to random length, and XOR-masks.
// Wire format: [2-byte masked length][masked core][random padding]
// Total size varies every connection — no fixed fingerprint.
func (ch *ClientHello) MarshalAndMask(psk []byte, transportID string) ([]byte, int64, error) {
	core := make([]byte, ClientHelloCoreSize)
	copy(core[0:32], ch.EphemeralPublic[:])
	copy(core[32:48], ch.Nonce[:])

	// Random padding length (different every connection)
	padLenBuf := make([]byte, 1)
	rand.Read(padLenBuf)
	padLen := MinHelloPadding + int(padLenBuf[0])%(MaxHelloPadding-MinHelloPadding+1)

	// Generate random padding
	padding := make([]byte, padLen)
	rand.Read(padding)

	// Full payload: [core 48 bytes][padding N bytes]
	payload := append(core, padding...)

	// Get mask for current epoch (mask covers entire payload)
	mask, epoch, err := veilcrypto.DeriveHandshakeMask(psk, transportID, len(payload))
	if err != nil {
		return nil, 0, fmt.Errorf("derive mask: %w", err)
	}

	masked := veilcrypto.XORBytes(payload, mask)

	// Wire format: [2-byte big-endian total length][masked payload]
	wire := make([]byte, 2+len(masked))
	binary.BigEndian.PutUint16(wire[0:2], uint16(len(masked)))
	copy(wire[2:], masked)

	// Mask the length bytes too (so even length looks random)
	lengthMask := sha256.Sum256(append(psk, byte(epoch), byte(epoch>>8)))
	wire[0] ^= lengthMask[0]
	wire[1] ^= lengthMask[1]

	return wire, epoch, nil
}

// UnmaskClientHello tries current and previous epoch to decode.
func UnmaskClientHello(wire []byte, psk []byte, transportID string) (*ClientHello, int64, error) {
	if len(wire) < 2+ClientHelloCoreSize+MinHelloPadding {
		return nil, 0, ErrInvalidHandshake
	}

	now := time.Now().Unix()
	currentEpoch := now / int64(veilcrypto.EpochWindow.Seconds())

	for _, epoch := range []int64{currentEpoch, currentEpoch - 1} {
		// Unmask length
		lengthMask := sha256.Sum256(append(psk, byte(epoch), byte(epoch>>8)))
		payloadLen := int(binary.BigEndian.Uint16([]byte{
			wire[0] ^ lengthMask[0],
			wire[1] ^ lengthMask[1],
		}))

		if payloadLen < ClientHelloCoreSize+MinHelloPadding || payloadLen > len(wire)-2 {
			continue
		}

		// Derive mask for this payload length
		mask, err := veilcrypto.DeriveHandshakeMaskForEpoch(psk, transportID, epoch, payloadLen)
		if err != nil {
			continue
		}

		unmasked := veilcrypto.XORBytes(wire[2:2+payloadLen], mask)

		ch := &ClientHello{}
		copy(ch.EphemeralPublic[:], unmasked[0:32])
		copy(ch.Nonce[:], unmasked[32:48])

		// Validate: public key should not be all zeros or low-order points
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

func deriveHelloKey(psk, clientNonce []byte) (key, nonce []byte) {
	combined := append(psk, clientNonce...)
	hash := sha256.Sum256(combined)
	key = hash[:]
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

	key, nonce := deriveHelloKey(psk, clientNonce)

	cipher, err := veilcrypto.NewSessionCipher(
		veilcrypto.CipherChaCha20Poly1305,
		key, key, nonce, nonce,
	)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	encrypted := cipher.Encrypt(payload, nil)

	// Add random padding to server hello too
	padBuf := make([]byte, 1)
	rand.Read(padBuf)
	padLen := 16 + int(padBuf[0])%64
	pad := make([]byte, padLen)
	rand.Read(pad)

	// Wire: [4-byte encrypted len][encrypted][padding]
	wire := make([]byte, 4+len(encrypted)+padLen)
	binary.BigEndian.PutUint32(wire[0:4], uint32(len(encrypted)))
	copy(wire[4:], encrypted)
	copy(wire[4+len(encrypted):], pad)

	return wire, nil
}

func UnmarshalServerHello(wire []byte, psk, clientNonce []byte) (*ServerHello, error) {
	if len(wire) < 4 {
		return nil, ErrInvalidHandshake
	}

	encLen := int(binary.BigEndian.Uint32(wire[0:4]))
	if encLen <= 0 || encLen > len(wire)-4 {
		return nil, ErrInvalidHandshake
	}

	encrypted := wire[4 : 4+encLen]

	key, nonce := deriveHelloKey(psk, clientNonce)

	cipher, err := veilcrypto.NewSessionCipher(
		veilcrypto.CipherChaCha20Poly1305,
		key, key, nonce, nonce,
	)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	plaintext, err := cipher.Decrypt(encrypted, nil)
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

	wire, epoch, err := ch.MarshalAndMask(h.psk, h.transportID)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	return wire, kp, nonce, epoch, nil
}

func (h *Handshaker) ProcessClientHello(wire []byte) ([]byte, *HandshakeResult, *veilcrypto.KeyPair, error) {
	ch, epoch, err := UnmaskClientHello(wire, h.psk, h.transportID)
	if err != nil {
		return nil, nil, nil, err
	}

	serverKP, err := veilcrypto.GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate server keypair: %w", err)
	}

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

	shBytes, err := MarshalServerHello(sh, h.psk, ch.Nonce[:])
	if err != nil {
		return nil, nil, nil, err
	}

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

func (h *Handshaker) ProcessServerHello(wire []byte, clientKP *veilcrypto.KeyPair, clientNonce []byte) (*HandshakeResult, error) {
	sh, err := UnmarshalServerHello(wire, h.psk, clientNonce)
	if err != nil {
		return nil, fmt.Errorf("decrypt server hello: %w", err)
	}

	sharedSecret, err := veilcrypto.ECDH(clientKP.Private[:], sh.EphemeralPublic[:])
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

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
