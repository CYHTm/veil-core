package api

import (
	"testing"
)

func TestSetSystemProxyInvalidAddr(t *testing.T) {
	// No colon — should fail validation
	err := SetSystemProxy("invalid-no-port")
	if err == nil {
		t.Fatal("expected error for invalid addr without port")
	}
}

func TestSetSystemProxyValidFormat(t *testing.T) {
	// This will try to actually set proxy via gsettings/kwriteconfig5.
	// On CI or systems without GNOME/KDE it may return an error,
	// but it should NOT panic.
	err := SetSystemProxy("127.0.0.1:1080")
	// We don't check the error because it depends on desktop environment.
	// Just ensure no panic.
	_ = err
}

func TestUnsetSystemProxyNoPanic(t *testing.T) {
	// Should not panic regardless of environment
	err := UnsetSystemProxy()
	_ = err
}

func TestSetSystemProxyEmptyHost(t *testing.T) {
	// ":1080" — technically valid split, empty host
	err := SetSystemProxy(":1080")
	// Should not panic
	_ = err
}

func TestSetSystemProxyIPv4(t *testing.T) {
	err := SetSystemProxy("192.168.1.1:9090")
	_ = err // no panic = pass
}
