package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// helper: generates a self-signed cert for testing
func generateTestCert(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return certDER
}

func TestPinFromCert(t *testing.T) {
	certDER := generateTestCert(t)

	pin, err := PinFromCert(certDER)
	if err != nil {
		t.Fatalf("pin from cert: %v", err)
	}

	if len(pin.SHA256) != 64 { // hex-encoded SHA256
		t.Fatalf("expected 64 char hex, got %d: %s", len(pin.SHA256), pin.SHA256)
	}
}

func TestPinFromCertDeterministic(t *testing.T) {
	certDER := generateTestCert(t)

	pin1, _ := PinFromCert(certDER)
	pin2, _ := PinFromCert(certDER)

	if pin1.SHA256 != pin2.SHA256 {
		t.Fatal("same cert should produce same pin")
	}
}

func TestPinFromCertInvalid(t *testing.T) {
	_, err := PinFromCert([]byte("not a cert"))
	if err == nil {
		t.Fatal("expected error for invalid cert")
	}
}

func TestVerifyPinMatch(t *testing.T) {
	certDER := generateTestCert(t)
	pin, _ := PinFromCert(certDER)

	err := VerifyPin(certDER, pin)
	if err != nil {
		t.Fatalf("matching pin should verify: %v", err)
	}
}

func TestVerifyPinMismatch(t *testing.T) {
	certDER := generateTestCert(t)
	wrongPin := CertPin{SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}

	err := VerifyPin(certDER, wrongPin)
	if err == nil {
		t.Fatal("mismatched pin should fail")
	}
}

func TestVerifyPinInvalidCert(t *testing.T) {
	pin := CertPin{SHA256: "abcd"}
	err := VerifyPin([]byte("garbage"), pin)
	if err == nil {
		t.Fatal("invalid cert should fail")
	}
}

func TestVerifyPinAnyMatch(t *testing.T) {
	certDER := generateTestCert(t)
	pin, _ := PinFromCert(certDER)

	pins := []CertPin{
		{SHA256: "0000000000000000000000000000000000000000000000000000000000000000"},
		pin, // correct one
		{SHA256: "1111111111111111111111111111111111111111111111111111111111111111"},
	}

	err := VerifyPinAny(certDER, pins)
	if err == nil {
		// passed
	} else {
		t.Fatalf("should match one of the pins: %v", err)
	}
}

func TestVerifyPinAnyNoMatch(t *testing.T) {
	certDER := generateTestCert(t)

	pins := []CertPin{
		{SHA256: "0000000000000000000000000000000000000000000000000000000000000000"},
		{SHA256: "1111111111111111111111111111111111111111111111111111111111111111"},
	}

	err := VerifyPinAny(certDER, pins)
	if err == nil {
		t.Fatal("should fail when no pin matches")
	}
}

func TestDifferentCertsDifferentPins(t *testing.T) {
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t)

	pin1, _ := PinFromCert(cert1)
	pin2, _ := PinFromCert(cert2)

	if pin1.SHA256 == pin2.SHA256 {
		t.Fatal("different certs should have different pins")
	}
}
