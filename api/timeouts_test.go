package api

import (
	"testing"
	"time"
)

func TestDefaultTimeouts(t *testing.T) {
	to := DefaultTimeouts()
	if to.Connect != 15*time.Second {
		t.Fatalf("Connect: expected 15s, got %v", to.Connect)
	}
	if to.Handshake != 15*time.Second {
		t.Fatalf("Handshake: expected 15s, got %v", to.Handshake)
	}
	if to.Read != 120*time.Second {
		t.Fatalf("Read: expected 120s, got %v", to.Read)
	}
	if to.Write != 30*time.Second {
		t.Fatalf("Write: expected 30s, got %v", to.Write)
	}
	if to.Idle != 300*time.Second {
		t.Fatalf("Idle: expected 300s, got %v", to.Idle)
	}
	if to.Keepalive != 30*time.Second {
		t.Fatalf("Keepalive: expected 30s, got %v", to.Keepalive)
	}
	if to.StreamOpen != 10*time.Second {
		t.Fatalf("StreamOpen: expected 10s, got %v", to.StreamOpen)
	}
	if to.DNS != 5*time.Second {
		t.Fatalf("DNS: expected 5s, got %v", to.DNS)
	}
}

func TestAggressiveTimeouts(t *testing.T) {
	ag := AggressiveTimeouts()
	def := DefaultTimeouts()

	// Aggressive should be faster than default
	if ag.Connect >= def.Connect {
		t.Fatal("aggressive Connect should be less than default")
	}
	if ag.Handshake >= def.Handshake {
		t.Fatal("aggressive Handshake should be less than default")
	}
	if ag.Read >= def.Read {
		t.Fatal("aggressive Read should be less than default")
	}
	if ag.Idle >= def.Idle {
		t.Fatal("aggressive Idle should be less than default")
	}
}

func TestTimeoutsAllPositive(t *testing.T) {
	for name, to := range map[string]Timeouts{
		"default":    DefaultTimeouts(),
		"aggressive": AggressiveTimeouts(),
	} {
		if to.Connect <= 0 {
			t.Fatalf("%s: Connect should be positive", name)
		}
		if to.Handshake <= 0 {
			t.Fatalf("%s: Handshake should be positive", name)
		}
		if to.Read <= 0 {
			t.Fatalf("%s: Read should be positive", name)
		}
		if to.Write <= 0 {
			t.Fatalf("%s: Write should be positive", name)
		}
		if to.Idle <= 0 {
			t.Fatalf("%s: Idle should be positive", name)
		}
		if to.Keepalive <= 0 {
			t.Fatalf("%s: Keepalive should be positive", name)
		}
		if to.StreamOpen <= 0 {
			t.Fatalf("%s: StreamOpen should be positive", name)
		}
		if to.DNS <= 0 {
			t.Fatalf("%s: DNS should be positive", name)
		}
	}
}
