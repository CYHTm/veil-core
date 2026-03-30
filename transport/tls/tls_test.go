package tls

import (
	"context"
	"testing"
	"time"

	"github.com/veil-protocol/veil-core/transport"
)

func TestTLSTransportID(t *testing.T) {
	tr := New()
	if tr.ID() != "tls" {
		t.Fatalf("expected 'tls', got '%s'", tr.ID())
	}
}

func TestTLSNewWithFingerprint(t *testing.T) {
	tr := NewWithFingerprint(FingerprintFirefox)
	if tr.fingerprint != FingerprintFirefox {
		t.Fatalf("expected firefox, got %s", tr.fingerprint)
	}
}

func TestTLSNewDefault(t *testing.T) {
	tr := New()
	if tr.fingerprint != FingerprintChrome {
		t.Fatalf("default should be chrome, got %s", tr.fingerprint)
	}
}

func TestTLSListenRequiresCert(t *testing.T) {
	tr := New()
	_, err := tr.Listen(context.Background(), "127.0.0.1:0", nil)
	if err == nil {
		t.Fatal("should require cert config")
	}

	_, err = tr.Listen(context.Background(), "127.0.0.1:0", &transport.Config{})
	if err == nil {
		t.Fatal("should require cert_file and key_file")
	}
}

func TestTLSListenBadCert(t *testing.T) {
	tr := New()
	cfg := &transport.Config{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}
	_, err := tr.Listen(context.Background(), "127.0.0.1:0", cfg)
	if err == nil {
		t.Fatal("should fail with nonexistent cert files")
	}
}

func TestGetClientHelloID(t *testing.T) {
	fps := []string{
		FingerprintChrome,
		FingerprintFirefox,
		FingerprintSafari,
		FingerprintEdge,
		FingerprintRandom,
		"unknown-fp",
	}
	for _, fp := range fps {
		id := getClientHelloID(fp)
		_ = id // no panic = pass
	}
}

func TestTLSDialBadAddress(t *testing.T) {
	tr := New()
	cfg := &transport.Config{
		ConnectTimeout: 100 * time.Millisecond,
		InsecureSkipVerify: true,
	}
	_, err := tr.Dial(context.Background(), "127.0.0.1:1", cfg)
	if err == nil {
		t.Fatal("should fail dialing closed port")
	}
}
