package tls

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewDecoyServer(t *testing.T) {
	ds, err := NewDecoyServer("test-secret", "")
	if err != nil {
		t.Fatalf("create decoy server: %v", err)
	}
	if ds == nil {
		t.Fatal("expected non-nil decoy server")
	}
}

func TestDecoyServerGenerateTriggers(t *testing.T) {
	ds, _ := NewDecoyServer("test-secret", "")

	name, value := ds.GenerateTriggerCookie()
	if name != "_ga" {
		t.Fatalf("expected cookie name '_ga', got '%s'", name)
	}
	if value == "" {
		t.Fatal("cookie value should not be empty")
	}

	hName, hValue := ds.GenerateTriggerHeader()
	if hName != "Accept-Language" {
		t.Fatalf("expected header 'Accept-Language', got '%s'", hName)
	}
	if hValue == "" {
		t.Fatal("header value should not be empty")
	}
}

func TestDecoyServerServesHTML(t *testing.T) {
	ds, _ := NewDecoyServer("test-secret", "")
	handler := ds.GetHTTPHandler()

	// Request root — should get decoy page
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("expected HTML content type, got '%s'", w.Header().Get("Content-Type"))
	}
	if w.Body.Len() == 0 {
		t.Fatal("expected non-empty body")
	}
}

func TestDecoyServer404(t *testing.T) {
	ds, _ := NewDecoyServer("test-secret", "")
	handler := ds.GetHTTPHandler()

	req := httptest.NewRequest("GET", "/nonexistent-page", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestDecoyServerRobotsTxt(t *testing.T) {
	ds, _ := NewDecoyServer("test-secret", "")
	handler := ds.GetHTTPHandler()

	req := httptest.NewRequest("GET", "/robots.txt", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestDecoyServerFavicon(t *testing.T) {
	ds, _ := NewDecoyServer("test-secret", "")
	handler := ds.GetHTTPHandler()

	req := httptest.NewRequest("GET", "/favicon.ico", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 204 {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestDecoyServerNormalVisitorNoTrigger(t *testing.T) {
	ds, _ := NewDecoyServer("test-secret", "")
	handler := ds.GetHTTPHandler()

	// Normal request without trigger — should see decoy
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 for normal visitor, got %d", w.Code)
	}
}

func TestDecoyServerWrongCookie(t *testing.T) {
	ds, _ := NewDecoyServer("test-secret", "")
	handler := ds.GetHTTPHandler()

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "_ga", Value: "GA1.2.fake.values"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Wrong cookie should still serve decoy page
	if w.Code != 200 {
		t.Fatalf("expected 200 with wrong cookie, got %d", w.Code)
	}
}

func TestDecoyServerServerHeader(t *testing.T) {
	ds, _ := NewDecoyServer("test-secret", "")
	handler := ds.GetHTTPHandler()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	server := w.Header().Get("Server")
	if server != "nginx/1.24.0" {
		t.Fatalf("expected 'nginx/1.24.0', got '%s'", server)
	}
}
