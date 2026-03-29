package api

import (
	"testing"
)

func TestSplitTunnelAllMode(t *testing.T) {
	st := NewSplitTunnel(SplitAll)

	// Everything should be proxied (except local)
	if !st.ShouldProxy("google.com:443") {
		t.Fatal("SplitAll should proxy google.com")
	}
	if !st.ShouldProxy("example.org:80") {
		t.Fatal("SplitAll should proxy example.org")
	}
}

func TestSplitTunnelLocalBypass(t *testing.T) {
	st := NewSplitTunnel(SplitAll)

	// Local networks always bypassed
	locals := []string{
		"127.0.0.1:80",
		"10.0.0.1:443",
		"172.16.0.1:8080",
		"192.168.1.1:22",
	}
	for _, addr := range locals {
		if st.ShouldProxy(addr) {
			t.Fatalf("local address %s should be direct", addr)
		}
	}
}

func TestSplitTunnelBypassMode(t *testing.T) {
	st := NewSplitTunnel(SplitBypass)
	st.AddDomain("youtube.com", ModeDirect)

	// youtube.com should be direct
	if st.ShouldProxy("youtube.com:443") {
		t.Fatal("youtube.com should be direct in bypass mode")
	}

	// Everything else should be proxied
	if !st.ShouldProxy("google.com:443") {
		t.Fatal("google.com should be proxied in bypass mode")
	}
}

func TestSplitTunnelOnlyMode(t *testing.T) {
	st := NewSplitTunnel(SplitOnly)
	st.AddDomain("blocked-site.com", ModeProxy)

	// Only blocked-site.com through tunnel
	if !st.ShouldProxy("blocked-site.com:443") {
		t.Fatal("blocked-site.com should be proxied in only mode")
	}

	// Everything else direct
	if st.ShouldProxy("youtube.com:443") {
		t.Fatal("youtube.com should be direct in only mode")
	}
}

func TestSplitTunnelWildcardDomain(t *testing.T) {
	st := NewSplitTunnel(SplitBypass)
	st.AddDomain("google.com", ModeDirect)

	// Subdomain should match parent rule
	if st.ShouldProxy("www.google.com:443") {
		t.Fatal("www.google.com should match google.com rule")
	}
	if st.ShouldProxy("mail.google.com:443") {
		t.Fatal("mail.google.com should match google.com rule")
	}
	if st.ShouldProxy("deep.sub.google.com:443") {
		t.Fatal("deep.sub.google.com should match google.com rule")
	}
}

func TestSplitTunnelCIDR(t *testing.T) {
	st := NewSplitTunnel(SplitAll)
	st.AddCIDR("8.8.8.0/24", ModeDirect)

	if st.ShouldProxy("8.8.8.8:53") {
		t.Fatal("8.8.8.8 should be direct (CIDR rule)")
	}
	if st.ShouldProxy("8.8.8.1:53") {
		t.Fatal("8.8.8.1 should be direct (CIDR rule)")
	}
	if !st.ShouldProxy("8.8.4.4:53") {
		t.Fatal("8.8.4.4 should be proxied (outside CIDR)")
	}
}

func TestSplitTunnelCaseInsensitive(t *testing.T) {
	st := NewSplitTunnel(SplitBypass)
	st.AddDomain("Google.COM", ModeDirect)

	if st.ShouldProxy("google.com:443") {
		t.Fatal("domain matching should be case insensitive")
	}
	if st.ShouldProxy("GOOGLE.COM:443") {
		t.Fatal("domain matching should be case insensitive")
	}
}

func TestSplitTunnelNoPort(t *testing.T) {
	st := NewSplitTunnel(SplitBypass)
	st.AddDomain("example.com", ModeDirect)

	// Should work without port
	if st.ShouldProxy("example.com") {
		t.Fatal("should work without port")
	}
}

func TestSplitTunnelInvalidCIDR(t *testing.T) {
	st := NewSplitTunnel(SplitAll)
	// Should not panic on invalid CIDR
	st.AddCIDR("not-a-cidr", ModeDirect)

	// Should still work normally
	if !st.ShouldProxy("google.com:443") {
		t.Fatal("should still proxy after invalid CIDR")
	}
}

func TestSplitTunnelIPv6Local(t *testing.T) {
	st := NewSplitTunnel(SplitAll)

	if st.ShouldProxy("[::1]:80") {
		t.Fatal("IPv6 localhost should be direct")
	}
}
