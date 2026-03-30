package api

import (
	"testing"
	"time"
)

func TestDefaultManagedConfig(t *testing.T) {
	cfg := DefaultManagedConfig()

	if cfg.Transport != "tls" {
		t.Fatalf("expected transport 'tls', got '%s'", cfg.Transport)
	}
	if cfg.Cipher != "chacha20-poly1305" {
		t.Fatalf("expected chacha20, got '%s'", cfg.Cipher)
	}
	if !cfg.Reconnect.Enabled {
		t.Fatal("reconnect should be enabled by default")
	}
	if cfg.Timeouts.Connect != 15*time.Second {
		t.Fatalf("expected 15s connect timeout, got %v", cfg.Timeouts.Connect)
	}
	if cfg.LogLevel != LogInfo {
		t.Fatalf("expected LogInfo, got %d", cfg.LogLevel)
	}
}

func TestNewManagedClientRequiresFields(t *testing.T) {
	// Missing server
	_, err := NewManagedClient(ManagedClientConfig{
		ClientConfig: ClientConfig{Secret: "secret"},
	})
	if err == nil {
		t.Fatal("should require server address")
	}

	// Missing secret
	_, err = NewManagedClient(ManagedClientConfig{
		ClientConfig: ClientConfig{ServerAddr: "1.2.3.4:443"},
	})
	if err == nil {
		t.Fatal("should require secret")
	}
}

func TestNewManagedClientCreates(t *testing.T) {
	cfg := DefaultManagedConfig()
	cfg.ServerAddr = "1.2.3.4:443"
	cfg.Secret = "test-secret"

	mc, err := NewManagedClient(cfg)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer mc.Close()

	if mc == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestManagedClientIsConnectedInitial(t *testing.T) {
	cfg := DefaultManagedConfig()
	cfg.ServerAddr = "1.2.3.4:443"
	cfg.Secret = "test-secret"

	mc, _ := NewManagedClient(cfg)
	defer mc.Close()

	if mc.IsConnected() {
		t.Fatal("should not be connected initially")
	}
}

func TestManagedClientEvents(t *testing.T) {
	cfg := DefaultManagedConfig()
	cfg.ServerAddr = "1.2.3.4:443"
	cfg.Secret = "test-secret"

	mc, _ := NewManagedClient(cfg)
	defer mc.Close()

	if mc.Events() == nil {
		t.Fatal("events should not be nil")
	}
}

func TestManagedClientLogger(t *testing.T) {
	cfg := DefaultManagedConfig()
	cfg.ServerAddr = "1.2.3.4:443"
	cfg.Secret = "test-secret"

	mc, _ := NewManagedClient(cfg)
	defer mc.Close()

	if mc.Log() == nil {
		t.Fatal("logger should not be nil")
	}
}

func TestManagedClientStats(t *testing.T) {
	cfg := DefaultManagedConfig()
	cfg.ServerAddr = "1.2.3.4:443"
	cfg.Secret = "test-secret"

	mc, _ := NewManagedClient(cfg)
	defer mc.Close()

	bytes, conns, reconnects := mc.Stats()
	if bytes != 0 {
		t.Fatalf("expected 0 bytes, got %d", bytes)
	}
	if conns != 0 {
		t.Fatalf("expected 0 conns, got %d", conns)
	}
	if reconnects != 0 {
		t.Fatalf("expected 0 reconnects, got %d", reconnects)
	}
}

func TestManagedClientOpenStreamNotConnected(t *testing.T) {
	cfg := DefaultManagedConfig()
	cfg.ServerAddr = "1.2.3.4:443"
	cfg.Secret = "test-secret"

	mc, _ := NewManagedClient(cfg)
	defer mc.Close()

	_, err := mc.OpenStream("google.com:443")
	if err == nil {
		t.Fatal("should fail when not connected")
	}
}

func TestManagedClientClose(t *testing.T) {
	cfg := DefaultManagedConfig()
	cfg.ServerAddr = "1.2.3.4:443"
	cfg.Secret = "test-secret"

	mc, _ := NewManagedClient(cfg)

	err := mc.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}

	// Double close should not panic
	mc.Close()
}

func TestManagedClientStartSOCKS5(t *testing.T) {
	cfg := DefaultManagedConfig()
	cfg.ServerAddr = "1.2.3.4:443"
	cfg.Secret = "test-secret"

	mc, _ := NewManagedClient(cfg)
	defer mc.Close()

	err := mc.StartSOCKS5("127.0.0.1:0")
	if err != nil {
		t.Fatalf("start socks5: %v", err)
	}
}

func TestManagedClientStartSOCKS5BadAddr(t *testing.T) {
	cfg := DefaultManagedConfig()
	cfg.ServerAddr = "1.2.3.4:443"
	cfg.Secret = "test-secret"

	mc, _ := NewManagedClient(cfg)
	defer mc.Close()

	err := mc.StartSOCKS5("999.999.999.999:99999")
	if err == nil {
		t.Fatal("should fail with invalid address")
	}
}
