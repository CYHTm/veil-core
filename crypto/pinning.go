package crypto

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// CertPin represents a pinned certificate hash.
type CertPin struct {
	// SHA256 hash of the certificate's Subject Public Key Info (SPKI).
	SHA256 string
}

// PinFromCert generates a pin from a DER-encoded certificate.
func PinFromCert(certDER []byte) (CertPin, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return CertPin{}, fmt.Errorf("parse cert: %w", err)
	}

	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return CertPin{SHA256: hex.EncodeToString(hash[:])}, nil
}

// VerifyPin checks if a certificate matches the expected pin.
// Returns nil if the pin matches, error otherwise.
func VerifyPin(certDER []byte, expected CertPin) error {
	actual, err := PinFromCert(certDER)
	if err != nil {
		return err
	}

	if !ConstantTimeCompare([]byte(actual.SHA256), []byte(expected.SHA256)) {
		return fmt.Errorf("certificate pin mismatch: got %s, want %s",
			actual.SHA256[:16]+"...", expected.SHA256[:16]+"...")
	}

	return nil
}

// VerifyPinAny checks if a certificate matches ANY of the expected pins.
// Useful for key rotation (accept old and new certificate).
func VerifyPinAny(certDER []byte, expected []CertPin) error {
	actual, err := PinFromCert(certDER)
	if err != nil {
		return err
	}

	for _, pin := range expected {
		if ConstantTimeCompare([]byte(actual.SHA256), []byte(pin.SHA256)) {
			return nil
		}
	}

	return fmt.Errorf("certificate matches none of %d pinned certificates", len(expected))
}
