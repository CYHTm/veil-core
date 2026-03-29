package api

import (
	"strings"
	"testing"
)

func TestDecoySitePoolRandom(t *testing.T) {
	pool := NewDecoySitePool()

	site := pool.Random()
	if site.Name == "" {
		t.Fatal("site name should not be empty")
	}
	if site.ServerName == "" {
		t.Fatal("server name should not be empty")
	}
	if site.HTML == "" {
		t.Fatal("HTML should not be empty")
	}
}

func TestDecoySitePoolVariety(t *testing.T) {
	pool := NewDecoySitePool()

	names := make(map[string]bool)
	for i := 0; i < 100; i++ {
		site := pool.Random()
		names[site.Name] = true
	}

	// With 3 builtin sites and 100 draws, should see at least 2
	if len(names) < 2 {
		t.Fatalf("expected variety, only got: %v", names)
	}
}

func TestDecoySitePoolAddSite(t *testing.T) {
	pool := NewDecoySitePool()

	pool.AddSite(DecoySite{
		Name:       "CustomSite",
		ServerName: "custom/1.0",
		HTML:       "<h1>Custom</h1>",
	})

	// Should have builtin + 1 custom
	found := false
	for i := 0; i < 200; i++ {
		if pool.Random().Name == "CustomSite" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("custom site should appear in random selection")
	}
}

func TestBuiltinSitesValid(t *testing.T) {
	for _, site := range builtinSites {
		if site.Name == "" {
			t.Fatal("builtin site has empty name")
		}
		if site.ServerName == "" {
			t.Fatalf("site %s has empty ServerName", site.Name)
		}
		if !strings.Contains(site.HTML, "<!DOCTYPE html>") {
			t.Fatalf("site %s HTML missing DOCTYPE", site.Name)
		}
		if !strings.Contains(site.HTML, "<title>") {
			t.Fatalf("site %s HTML missing title", site.Name)
		}
		if !strings.Contains(site.HTML, "</html>") {
			t.Fatalf("site %s HTML not closed", site.Name)
		}
	}
}

func TestBuiltinSitesCount(t *testing.T) {
	if len(builtinSites) < 3 {
		t.Fatalf("expected at least 3 builtin sites, got %d", len(builtinSites))
	}
}
