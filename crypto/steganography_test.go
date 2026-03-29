package crypto

import (
	"strings"
	"testing"
)

func TestStegCookieTriggerGenerate(t *testing.T) {
	st := NewStegTrigger("test-secret")
	name, value := st.GenerateHTTPCookieTrigger()

	if name != "_ga" {
		t.Fatalf("expected cookie name '_ga', got '%s'", name)
	}
	if !strings.HasPrefix(value, "GA1.2.") {
		t.Fatalf("cookie should start with 'GA1.2.', got '%s'", value)
	}

	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts, got %d: %s", len(parts), value)
	}
}

func TestStegCookieTriggerValidate(t *testing.T) {
	st := NewStegTrigger("test-secret")
	_, value := st.GenerateHTTPCookieTrigger()

	if !st.ValidateHTTPCookieTrigger(value) {
		t.Fatal("generated cookie should validate")
	}
}

func TestStegCookieTriggerRejectsInvalid(t *testing.T) {
	st := NewStegTrigger("test-secret")

	invalids := []string{
		"",
		"garbage",
		"GA1.2.abc.wronghmac",
		"GA1.3.abc.def",
		"XX1.2.abc.def",
	}
	for _, v := range invalids {
		if st.ValidateHTTPCookieTrigger(v) {
			t.Fatalf("should reject invalid cookie: %s", v)
		}
	}
}

func TestStegCookieTriggerWrongSecret(t *testing.T) {
	st1 := NewStegTrigger("secret-1")
	st2 := NewStegTrigger("secret-2")

	_, value := st1.GenerateHTTPCookieTrigger()
	if st2.ValidateHTTPCookieTrigger(value) {
		t.Fatal("different secret should not validate")
	}
}

func TestStegHeaderTriggerGenerate(t *testing.T) {
	st := NewStegTrigger("test-secret")
	name, value := st.GenerateHTTPHeaderTrigger()

	if name != "Accept-Language" {
		t.Fatalf("expected 'Accept-Language', got '%s'", name)
	}
	if !strings.Contains(value, "en-US") {
		t.Fatal("header should contain en-US")
	}
	if !strings.Contains(value, "x-") {
		t.Fatal("header should contain x- trigger")
	}
}

func TestStegHeaderTriggerValidate(t *testing.T) {
	st := NewStegTrigger("test-secret")
	_, value := st.GenerateHTTPHeaderTrigger()

	if !st.ValidateHTTPHeaderTrigger(value) {
		t.Fatal("generated header should validate")
	}
}

func TestStegHeaderTriggerRejectsInvalid(t *testing.T) {
	st := NewStegTrigger("test-secret")

	if st.ValidateHTTPHeaderTrigger("en-US,en;q=0.9") {
		t.Fatal("should reject header without trigger")
	}
	if st.ValidateHTTPHeaderTrigger("") {
		t.Fatal("should reject empty header")
	}
}

func TestStegHeaderTriggerWrongSecret(t *testing.T) {
	st1 := NewStegTrigger("secret-1")
	st2 := NewStegTrigger("secret-2")

	_, value := st1.GenerateHTTPHeaderTrigger()
	if st2.ValidateHTTPHeaderTrigger(value) {
		t.Fatal("different secret should not validate header")
	}
}

func TestStegDNSTriggerGenerate(t *testing.T) {
	st := NewStegTrigger("test-secret")
	query := st.GenerateDNSTrigger("example.com")

	if !strings.HasSuffix(query, ".cdn.example.com") {
		t.Fatalf("expected suffix '.cdn.example.com', got '%s'", query)
	}

	parts := strings.Split(strings.TrimSuffix(query, ".cdn.example.com"), ".")
	if len(parts) != 2 {
		t.Fatalf("expected 2 prefix parts, got %d: %s", len(parts), query)
	}
}

func TestStegDNSTriggerValidate(t *testing.T) {
	st := NewStegTrigger("test-secret")
	query := st.GenerateDNSTrigger("example.com")

	if !st.ValidateDNSTrigger(query, "example.com") {
		t.Fatal("generated DNS trigger should validate")
	}
}

func TestStegDNSTriggerRejectsInvalid(t *testing.T) {
	st := NewStegTrigger("test-secret")

	if st.ValidateDNSTrigger("random.stuff.cdn.example.com", "example.com") {
		t.Fatal("should reject random DNS query")
	}
	if st.ValidateDNSTrigger("bad.query.com", "example.com") {
		t.Fatal("should reject wrong domain")
	}
	if st.ValidateDNSTrigger("", "example.com") {
		t.Fatal("should reject empty query")
	}
}

func TestStegDNSTriggerWrongDomain(t *testing.T) {
	st := NewStegTrigger("test-secret")
	query := st.GenerateDNSTrigger("example.com")

	if st.ValidateDNSTrigger(query, "other.com") {
		t.Fatal("should reject trigger for wrong domain")
	}
}

func TestStegSameSecretConsistent(t *testing.T) {
	st1 := NewStegTrigger("same-secret")
	st2 := NewStegTrigger("same-secret")

	_, cookie := st1.GenerateHTTPCookieTrigger()
	if !st2.ValidateHTTPCookieTrigger(cookie) {
		t.Fatal("same secret should validate across instances")
	}

	_, header := st1.GenerateHTTPHeaderTrigger()
	if !st2.ValidateHTTPHeaderTrigger(header) {
		t.Fatal("same secret should validate header across instances")
	}

	dns := st1.GenerateDNSTrigger("test.com")
	if !st2.ValidateDNSTrigger(dns, "test.com") {
		t.Fatal("same secret should validate DNS across instances")
	}
}
