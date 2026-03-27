package protocol

import (
	"bytes"
	"testing"
)

func TestFrameRoundtrip(t *testing.T) {
	frame := &Frame{
		Version:  ProtocolVersion,
		Type:     FrameStreamData,
		StreamID: 42,
		Flags:    FlagCompressed,
		SeqNum:   12345,
		Payload:  []byte("Hello Veil!"),
	}

	data, err := frame.MarshalBinary()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	frame2 := &Frame{}
	if err := frame2.UnmarshalBinary(data); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if frame2.Version != frame.Version {
		t.Errorf("Version: got %d, want %d", frame2.Version, frame.Version)
	}
	if frame2.Type != frame.Type {
		t.Errorf("Type: got %d, want %d", frame2.Type, frame.Type)
	}
	if frame2.StreamID != frame.StreamID {
		t.Errorf("StreamID: got %d, want %d", frame2.StreamID, frame.StreamID)
	}
	if frame2.SeqNum != frame.SeqNum {
		t.Errorf("SeqNum: got %d, want %d", frame2.SeqNum, frame.SeqNum)
	}
	if !bytes.Equal(frame2.Payload, frame.Payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestFrameWithMorphPadding(t *testing.T) {
	frame := &Frame{
		Version:  ProtocolVersion,
		Type:     FrameStreamData,
		StreamID: 1,
		Flags:    FlagMorphPadded,
		SeqNum:   1,
		Payload:  []byte("real data here"),
		MorphPad: []byte("this is padding that should be stripped"),
	}

	data, err := frame.MarshalBinary()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	frame2 := &Frame{}
	if err := frame2.UnmarshalBinary(data); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Payload должен быть ТОЛЬКО реальные данные, без паддинга
	if !bytes.Equal(frame2.Payload, []byte("real data here")) {
		t.Errorf("Payload after unmarshal: got %q, want %q", frame2.Payload, "real data here")
	}
}

func TestFrameEmptyPayload(t *testing.T) {
	frame := NewKeepaliveFrame()

	data, err := frame.MarshalBinary()
	if err != nil {
		t.Fatalf("Marshal keepalive failed: %v", err)
	}

	frame2 := &Frame{}
	if err := frame2.UnmarshalBinary(data); err != nil {
		t.Fatalf("Unmarshal keepalive failed: %v", err)
	}

	if frame2.Type != FrameKeepalive {
		t.Errorf("Type: got %v, want KEEPALIVE", frame2.Type)
	}
}

func TestFrameTooLarge(t *testing.T) {
	frame := &Frame{
		Version: ProtocolVersion,
		Type:    FrameStreamData,
		Payload: make([]byte, MaxPayloadSize+1),
	}

	_, err := frame.MarshalBinary()
	if err == nil {
		t.Error("should reject oversized payload")
	}
}

func TestFrameTypes(t *testing.T) {
	types := []struct {
		ft   FrameType
		name string
	}{
		{FrameHandshakeInit, "HANDSHAKE_INIT"},
		{FrameHandshakeResp, "HANDSHAKE_RESP"},
		{FrameStreamOpen, "STREAM_OPEN"},
		{FrameStreamData, "STREAM_DATA"},
		{FrameStreamClose, "STREAM_CLOSE"},
		{FrameKeepalive, "KEEPALIVE"},
		{FrameSessionClose, "SESSION_CLOSE"},
	}

	for _, tt := range types {
		if tt.ft.String() != tt.name {
			t.Errorf("FrameType %d: got %q, want %q", tt.ft, tt.ft.String(), tt.name)
		}
	}
}

func TestNewDataFrame(t *testing.T) {
	f := NewDataFrame(5, 100, []byte("test"))
	if f.StreamID != 5 || f.SeqNum != 100 || f.Type != FrameStreamData {
		t.Error("NewDataFrame fields incorrect")
	}
}

func TestNewStreamOpenFrame(t *testing.T) {
	f := NewStreamOpenFrame(7, "google.com:443")
	if f.StreamID != 7 || string(f.Payload) != "google.com:443" {
		t.Error("NewStreamOpenFrame fields incorrect")
	}
}
