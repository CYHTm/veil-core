package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestGenerateSubscriptionFile(t *testing.T) {
	servers := []ClientConfig{
		{ServerAddr: "1.2.3.4:443", Secret: "secret1", Transport: "tls"},
		{ServerAddr: "5.6.7.8:443", Secret: "secret2", Transport: "wss"},
	}

	encoded := GenerateSubscriptionFile(servers)
	if encoded == "" {
		t.Fatal("expected non-empty subscription file")
	}

	// Should be valid base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("invalid base64: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatal("decoded content is empty")
	}
}

func TestSubscriptionFetch(t *testing.T) {
	// Create test server list
	servers := []ClientConfig{
		{ServerAddr: "1.2.3.4:443", Secret: "secret1", Transport: "tls"},
		{ServerAddr: "5.6.7.8:443", Secret: "secret2", Transport: "wss"},
	}
	body := GenerateSubscriptionFile(servers)

	// Mock HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer ts.Close()

	sub := NewSubscription(ts.URL, 1*time.Hour)
	if err := sub.Fetch(); err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	got := sub.Servers()
	if len(got) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(got))
	}
	if got[0].ServerAddr != "1.2.3.4:443" {
		t.Fatalf("expected 1.2.3.4:443, got %s", got[0].ServerAddr)
	}
	if got[1].ServerAddr != "5.6.7.8:443" {
		t.Fatalf("expected 5.6.7.8:443, got %s", got[1].ServerAddr)
	}
}

func TestSubscriptionFetchBadStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	sub := NewSubscription(ts.URL, 1*time.Hour)
	err := sub.Fetch()
	if err == nil {
		t.Fatal("expected error on 500 status")
	}
}

func TestSubscriptionFetchEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(""))
	}))
	defer ts.Close()

	sub := NewSubscription(ts.URL, 1*time.Hour)
	err := sub.Fetch()
	if err == nil {
		t.Fatal("expected error on empty subscription")
	}
}

func TestSubscriptionRandom(t *testing.T) {
	servers := []ClientConfig{
		{ServerAddr: "1.2.3.4:443", Secret: "s1", Transport: "tls"},
		{ServerAddr: "5.6.7.8:443", Secret: "s2", Transport: "tls"},
	}
	body := GenerateSubscriptionFile(servers)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer ts.Close()

	sub := NewSubscription(ts.URL, 1*time.Hour)
	sub.Fetch()

	cfg, err := sub.Random()
	if err != nil {
		t.Fatalf("random: %v", err)
	}
	if cfg.ServerAddr != "1.2.3.4:443" && cfg.ServerAddr != "5.6.7.8:443" {
		t.Fatalf("unexpected server: %s", cfg.ServerAddr)
	}
}

func TestSubscriptionRandomEmpty(t *testing.T) {
	sub := NewSubscription("http://localhost", 1*time.Hour)
	_, err := sub.Random()
	if err == nil {
		t.Fatal("expected error on empty server list")
	}
}

func TestSubscriptionOnUpdate(t *testing.T) {
	servers := []ClientConfig{
		{ServerAddr: "1.2.3.4:443", Secret: "s1", Transport: "tls"},
	}
	body := GenerateSubscriptionFile(servers)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer ts.Close()

	sub := NewSubscription(ts.URL, 1*time.Hour)

	var called int32
	sub.OnUpdate(func(configs []ClientConfig) {
		atomic.AddInt32(&called, 1)
	})

	sub.Fetch()

	if atomic.LoadInt32(&called) != 1 {
		t.Fatal("OnUpdate callback not called")
	}
}

func TestSubscriptionDefaultInterval(t *testing.T) {
	sub := NewSubscription("http://localhost", 0)
	// Default should be 6 hours
	if sub.interval != 6*time.Hour {
		t.Fatalf("expected 6h default interval, got %v", sub.interval)
	}
}

func TestSubscriptionFetchWithComments(t *testing.T) {
	// Raw (non-base64) list with comments
	raw := "# Server list\nveil://secret1@1.2.3.4:443?transport=tls\n\n# backup\nveil://secret2@5.6.7.8:443?transport=wss\n"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(raw))
	}))
	defer ts.Close()

	sub := NewSubscription(ts.URL, 1*time.Hour)
	if err := sub.Fetch(); err != nil {
		t.Fatalf("fetch with comments failed: %v", err)
	}

	got := sub.Servers()
	if len(got) != 2 {
		t.Fatalf("expected 2 servers (comments filtered), got %d", len(got))
	}
}
