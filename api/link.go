// Package api — link.go implements Veil share links.
//
// Format: veil://secret@host:port?transport=tls&morph=http2_browsing&sni=example.com
//
// This allows easy sharing of server configs — just send a link.
package api

import (
	"fmt"
	"net/url"
	"strings"
)

// GenerateLink creates a shareable veil:// link from config.
func GenerateLink(cfg ClientConfig) string {
	u := url.URL{
		Scheme: "veil",
		User:   url.User(cfg.Secret),
		Host:   cfg.ServerAddr,
	}

	q := url.Values{}
	if cfg.Transport != "" && cfg.Transport != "raw" {
		q.Set("transport", cfg.Transport)
	}
	if cfg.MorphProfile != "" && cfg.MorphProfile != "http2_browsing" {
		q.Set("morph", cfg.MorphProfile)
	}
	if cfg.Cipher != "" && cfg.Cipher != "chacha20-poly1305" {
		q.Set("cipher", cfg.Cipher)
	}
	if cfg.SNI != "" {
		q.Set("sni", cfg.SNI)
	}

	u.RawQuery = q.Encode()
	return u.String()
}

// ParseLink parses a veil:// link into a ClientConfig.
func ParseLink(link string) (*ClientConfig, error) {
	// Handle both veil:// and plain paste
	link = strings.TrimSpace(link)
	if !strings.HasPrefix(link, "veil://") {
		return nil, fmt.Errorf("invalid link: must start with veil://")
	}

	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("invalid link: %w", err)
	}

	secret := ""
	if u.User != nil {
		secret = u.User.Username()
	}
	if secret == "" {
		return nil, fmt.Errorf("invalid link: missing secret")
	}

	host := u.Host
	if host == "" {
		return nil, fmt.Errorf("invalid link: missing host")
	}

	// Defaults
	cfg := DefaultClientConfig()
	cfg.ServerAddr = host
	cfg.Secret = secret

	q := u.Query()
	if v := q.Get("transport"); v != "" {
		cfg.Transport = v
	}
	if v := q.Get("morph"); v != "" {
		cfg.MorphProfile = v
	}
	if v := q.Get("cipher"); v != "" {
		cfg.Cipher = v
	}
	if v := q.Get("sni"); v != "" {
		cfg.SNI = v
	}

	return &cfg, nil
}
