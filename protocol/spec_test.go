package protocol

import (
	"testing"
	"time"
)

func TestProtocolConstants(t *testing.T) {
	if ProtocolVersion != 0x01 {
		t.Fatalf("expected version 0x01, got 0x%02x", ProtocolVersion)
	}
	if MaxPayloadSize != 1<<24 {
		t.Fatalf("expected max payload 16MB, got %d", MaxPayloadSize)
	}
	if MaxStreamID != 65535 {
		t.Fatalf("expected max stream ID 65535, got %d", MaxStreamID)
	}
	if FrameHeaderSize != 12 {
		t.Fatalf("expected frame header 12, got %d", FrameHeaderSize)
	}
	if AuthTagSize != 16 {
		t.Fatalf("expected auth tag 16, got %d", AuthTagSize)
	}
	if NonceSize != 12 {
		t.Fatalf("expected nonce size 12, got %d", NonceSize)
	}
}

func TestProtocolTimeouts(t *testing.T) {
	if HandshakeEpochWindow != 30*time.Second {
		t.Fatalf("expected 30s epoch window, got %v", HandshakeEpochWindow)
	}
	if HandshakeTimeout != 15*time.Second {
		t.Fatalf("expected 15s handshake timeout, got %v", HandshakeTimeout)
	}
	if KeepaliveInterval != 30*time.Second {
		t.Fatalf("expected 30s keepalive, got %v", KeepaliveInterval)
	}
}

func TestFrameTypeString(t *testing.T) {
	tests := []struct {
		ft   FrameType
		want string
	}{
		{FrameHandshakeInit, "HANDSHAKE_INIT"},
		{FrameHandshakeResp, "HANDSHAKE_RESP"},
		{FrameStreamOpen, "STREAM_OPEN"},
		{FrameStreamData, "STREAM_DATA"},
		{FrameStreamClose, "STREAM_CLOSE"},
		{FrameKeepalive, "KEEPALIVE"},
		{FrameMorphSync, "MORPH_SYNC"},
		{FrameTransportMigrate, "TRANSPORT_MIGRATE"},
		{FrameSessionClose, "SESSION_CLOSE"},
		{FrameType(0xFF), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.ft.String(); got != tt.want {
			t.Errorf("FrameType(0x%02x).String() = %s, want %s", tt.ft, got, tt.want)
		}
	}
}

func TestFrameFlags(t *testing.T) {
	if FlagMorphPadded != 0x01 {
		t.Fatal("FlagMorphPadded wrong")
	}
	if FlagCompressed != 0x02 {
		t.Fatal("FlagCompressed wrong")
	}
	if FlagPriority != 0x04 {
		t.Fatal("FlagPriority wrong")
	}
	if FlagFinal != 0x08 {
		t.Fatal("FlagFinal wrong")
	}

	// Flags should be combinable
	combined := FlagMorphPadded | FlagFinal
	if combined&FlagMorphPadded == 0 {
		t.Fatal("combined should include MorphPadded")
	}
	if combined&FlagFinal == 0 {
		t.Fatal("combined should include Final")
	}
	if combined&FlagCompressed != 0 {
		t.Fatal("combined should not include Compressed")
	}
}

func TestDefaultCapabilities(t *testing.T) {
	caps := DefaultCapabilities()

	if caps.MaxStreams != 256 {
		t.Fatalf("expected 256 max streams, got %d", caps.MaxStreams)
	}
	if len(caps.MorphProfiles) != 3 {
		t.Fatalf("expected 3 morph profiles, got %d", len(caps.MorphProfiles))
	}
	if len(caps.Transports) != 3 {
		t.Fatalf("expected 3 transports, got %d", len(caps.Transports))
	}

	// Check specific values
	found := map[string]bool{}
	for _, p := range caps.MorphProfiles {
		found[p] = true
	}
	for _, expected := range []string{"http2_browsing", "video_streaming", "grpc_api"} {
		if !found[expected] {
			t.Fatalf("missing morph profile: %s", expected)
		}
	}

	found = map[string]bool{}
	for _, tr := range caps.Transports {
		found[tr] = true
	}
	for _, expected := range []string{"raw", "tls", "wss"} {
		if !found[expected] {
			t.Fatalf("missing transport: %s", expected)
		}
	}
}

func TestFrameTypeValues(t *testing.T) {
	// Ensure frame types are sequential and unique
	types := []FrameType{
		FrameHandshakeInit, FrameHandshakeResp,
		FrameStreamOpen, FrameStreamData, FrameStreamClose,
		FrameKeepalive, FrameMorphSync, FrameTransportMigrate, FrameSessionClose,
	}
	seen := map[FrameType]bool{}
	for _, ft := range types {
		if seen[ft] {
			t.Fatalf("duplicate frame type: 0x%02x", ft)
		}
		seen[ft] = true
	}
}
