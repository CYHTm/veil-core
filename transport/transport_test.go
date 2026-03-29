package transport

import (
	"context"
	"testing"
)

// mockTransport implements Transport for testing.
type mockTransport struct {
	id string
}

func (m *mockTransport) ID() string { return m.id }
func (m *mockTransport) Dial(ctx context.Context, addr string, config *Config) (Connection, error) {
	return nil, nil
}
func (m *mockTransport) Listen(ctx context.Context, addr string, config *Config) (Listener, error) {
	return nil, nil
}

func TestRegistryRegisterAndGet(t *testing.T) {
	r := NewRegistry()
	mock := &mockTransport{id: "test"}
	r.Register(mock)

	got, ok := r.Get("test")
	if !ok {
		t.Fatal("expected transport to be found")
	}
	if got.ID() != "test" {
		t.Fatalf("expected ID 'test', got '%s'", got.ID())
	}
}

func TestRegistryGetNotFound(t *testing.T) {
	r := NewRegistry()
	_, ok := r.Get("nonexistent")
	if ok {
		t.Fatal("expected transport to not be found")
	}
}

func TestRegistryList(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockTransport{id: "aaa"})
	r.Register(&mockTransport{id: "bbb"})
	r.Register(&mockTransport{id: "ccc"})

	list := r.List()
	if len(list) != 3 {
		t.Fatalf("expected 3 transports, got %d", len(list))
	}

	found := map[string]bool{}
	for _, id := range list {
		found[id] = true
	}
	for _, id := range []string{"aaa", "bbb", "ccc"} {
		if !found[id] {
			t.Fatalf("transport '%s' not in list", id)
		}
	}
}

func TestRegistryOverwrite(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockTransport{id: "dup"})
	r.Register(&mockTransport{id: "dup"})

	list := r.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 transport after overwrite, got %d", len(list))
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := &Config{}
	if cfg.CertFile != "" {
		t.Fatal("expected empty CertFile")
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify to be false")
	}
	if cfg.ConnectTimeout != 0 {
		t.Fatal("expected zero ConnectTimeout")
	}
}
