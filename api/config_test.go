package api

import (
	"testing"
	"time"
)

func TestDefaultClientConfig(t *testing.T) {
	cfg := DefaultClientConfig()

	if cfg.Transport != "tls" {
		t.Fatalf("expected transport 'tls', got '%s'", cfg.Transport)
	}
	if cfg.Cipher != "chacha20-poly1305" {
		t.Fatalf("expected cipher 'chacha20-poly1305', got '%s'", cfg.Cipher)
	}
	if cfg.MorphProfile != "http2_browsing" {
		t.Fatalf("expected morph 'http2_browsing', got '%s'", cfg.MorphProfile)
	}
	if cfg.MaxStreams != 256 {
		t.Fatalf("expected 256 max streams, got %d", cfg.MaxStreams)
	}
	if cfg.ConnectTimeout != 15*time.Second {
		t.Fatalf("expected 15s connect timeout, got %v", cfg.ConnectTimeout)
	}
	if cfg.KeepaliveInterval != 30*time.Second {
		t.Fatalf("expected 30s keepalive, got %v", cfg.KeepaliveInterval)
	}
}

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()

	if cfg.ListenAddr != ":443" {
		t.Fatalf("expected ':443', got '%s'", cfg.ListenAddr)
	}
	if cfg.Transport != "tls" {
		t.Fatalf("expected transport 'tls', got '%s'", cfg.Transport)
	}
	if cfg.Cipher != "chacha20-poly1305" {
		t.Fatalf("expected cipher 'chacha20-poly1305', got '%s'", cfg.Cipher)
	}
	if cfg.MaxStreams != 256 {
		t.Fatalf("expected 256 max streams, got %d", cfg.MaxStreams)
	}
	if len(cfg.MorphProfiles) != 3 {
		t.Fatalf("expected 3 morph profiles, got %d", len(cfg.MorphProfiles))
	}
}

func TestClientConfigCallbacksNil(t *testing.T) {
	cfg := DefaultClientConfig()

	// Callbacks should be nil by default — not panic when uncalled
	if cfg.OnConnect != nil {
		t.Fatal("OnConnect should be nil by default")
	}
	if cfg.OnDisconnect != nil {
		t.Fatal("OnDisconnect should be nil by default")
	}
	if cfg.OnStreamOpen != nil {
		t.Fatal("OnStreamOpen should be nil by default")
	}
}

func TestServerConfigCallbacksNil(t *testing.T) {
	cfg := DefaultServerConfig()

	if cfg.OnClientConnect != nil {
		t.Fatal("OnClientConnect should be nil by default")
	}
	if cfg.OnClientDisconnect != nil {
		t.Fatal("OnClientDisconnect should be nil by default")
	}
	if cfg.OnStreamOpen != nil {
		t.Fatal("OnStreamOpen should be nil by default")
	}
}

func TestClientConfigCustomValues(t *testing.T) {
	connected := false
	cfg := ClientConfig{
		ServerAddr:        "1.2.3.4:443",
		Secret:            "my-secret",
		Transport:         "wss",
		Cipher:            "aes-256-gcm",
		MorphProfile:      "video_streaming",
		MaxStreams:         128,
		ConnectTimeout:    5 * time.Second,
		KeepaliveInterval: 10 * time.Second,
		SNI:               "cdn.example.com",
		InsecureSkipVerify: true,
		OnConnect:         func() { connected = true },
	}

	if cfg.ServerAddr != "1.2.3.4:443" {
		t.Fatal("ServerAddr mismatch")
	}
	if cfg.Transport != "wss" {
		t.Fatal("Transport mismatch")
	}
	if cfg.Cipher != "aes-256-gcm" {
		t.Fatal("Cipher mismatch")
	}
	if cfg.SNI != "cdn.example.com" {
		t.Fatal("SNI mismatch")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify should be true")
	}

	cfg.OnConnect()
	if !connected {
		t.Fatal("OnConnect callback not called")
	}
}

func TestServerConfigMorphProfiles(t *testing.T) {
	cfg := DefaultServerConfig()

	expected := map[string]bool{
		"http2_browsing":  true,
		"video_streaming": true,
		"grpc_api":        true,
	}
	for _, p := range cfg.MorphProfiles {
		if !expected[p] {
			t.Fatalf("unexpected morph profile: %s", p)
		}
	}
}
