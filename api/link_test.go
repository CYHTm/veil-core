package api

import (
	"testing"
)

func TestGenerateAndParseLink(t *testing.T) {
	cfg := ClientConfig{
		ServerAddr:   "1.2.3.4:443",
		Secret:       "my-secret",
		Transport:    "tls",
		MorphProfile: "video_streaming",
		Cipher:       "aes-256-gcm",
		SNI:          "cdn.example.com",
	}

	link := GenerateLink(cfg)

	parsed, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}

	if parsed.ServerAddr != cfg.ServerAddr {
		t.Errorf("server: got %q, want %q", parsed.ServerAddr, cfg.ServerAddr)
	}
	if parsed.Secret != cfg.Secret {
		t.Errorf("secret: got %q, want %q", parsed.Secret, cfg.Secret)
	}
	if parsed.Transport != cfg.Transport {
		t.Errorf("transport: got %q, want %q", parsed.Transport, cfg.Transport)
	}
	if parsed.SNI != cfg.SNI {
		t.Errorf("sni: got %q, want %q", parsed.SNI, cfg.SNI)
	}
}

func TestParseLinkSimple(t *testing.T) {
	// Минимальная ссылка — только сервер и секрет
	cfg, err := ParseLink("veil://mysecret@10.0.0.1:8443")
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}

	if cfg.ServerAddr != "10.0.0.1:8443" {
		t.Errorf("server: %q", cfg.ServerAddr)
	}
	if cfg.Secret != "mysecret" {
		t.Errorf("secret: %q", cfg.Secret)
	}
	// Должны быть дефолты
	if cfg.Transport != "tls" {
		t.Errorf("default transport: %q", cfg.Transport)
	}
}

func TestParseLinkInvalid(t *testing.T) {
	invalids := []string{
		"",
		"https://google.com",
		"veil://",
		"veil://nohost",
		"veil://@host:443", // Пустой секрет
	}

	for _, link := range invalids {
		_, err := ParseLink(link)
		if err == nil {
			t.Errorf("should reject: %q", link)
		}
	}
}
