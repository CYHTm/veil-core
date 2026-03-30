package decoy

import (
	"context"
	"testing"
	"time"

	"github.com/veil-protocol/veil-core/transport"
)

func TestDecoyTransportID(t *testing.T) {
	tr := New()
	if tr.ID() != "decoy" {
		t.Fatalf("expected 'decoy', got '%s'", tr.ID())
	}
}

func TestDecoyListenNotSupported(t *testing.T) {
	tr := New()
	_, err := tr.Listen(context.Background(), "127.0.0.1:0", nil)
	if err == nil {
		t.Fatal("decoy Listen should return error (use DecoyServer instead)")
	}
}

func TestDecoyDialBadAddress(t *testing.T) {
	tr := New()
	cfg := &transport.Config{
		ConnectTimeout: 100 * time.Millisecond,
	}

	_, err := tr.Dial(context.Background(), "127.0.0.1:1", cfg)
	if err == nil {
		t.Fatal("should fail dialing closed port")
	}
}

func TestDecoyDialTimeout(t *testing.T) {
	tr := New()
	cfg := &transport.Config{
		ConnectTimeout: 100 * time.Millisecond,
		InsecureSkipVerify: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := tr.Dial(ctx, "127.0.0.1:1", cfg)
	if err == nil {
		t.Fatal("should fail with timeout/refused")
	}
}

func TestDecoyDialDefaultTimeout(t *testing.T) {
	tr := New()
	// nil config — should use default 15s timeout
	// We just verify it doesn't panic
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := tr.Dial(ctx, "127.0.0.1:1", nil)
	if err == nil {
		t.Fatal("should fail")
	}
}
