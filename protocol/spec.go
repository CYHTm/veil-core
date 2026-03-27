// Package protocol defines the Veil protocol specification.
//
// Veil is a polymorphic, traffic-morphing tunneling protocol designed
// to be undetectable by deep packet inspection (DPI) and statistical
// traffic analysis. It serves as a core library that other applications
// can build upon.
//
// Key design principles:
//   - No fixed protocol fingerprint (polymorphic handshake)
//   - Traffic morphing to mimic real application profiles
//   - Multi-transport support with live migration
//   - Multiplexed streams over a single session
//   - Steganographic session initiation
package protocol

import "time"

const (
	// ProtocolVersion is the current version of the Veil protocol.
	ProtocolVersion uint8 = 0x01

	// MaxPayloadSize is the maximum payload per frame (16 MB).
	MaxPayloadSize = 1 << 24 // 16,777,216 bytes

	// MaxStreamID is the maximum concurrent stream ID.
	MaxStreamID = 1<<16 - 1 // 65535

	// HandshakeEpochWindow is the time window for handshake mask derivation.
	HandshakeEpochWindow = 30 * time.Second

	// HandshakeTimeout is the maximum time to complete a handshake.
	HandshakeTimeout = 15 * time.Second

	// KeepaliveInterval is the default keepalive interval.
	KeepaliveInterval = 30 * time.Second

	// FrameHeaderSize is the fixed size of a frame header in bytes.
	// Version(1) + Type(1) + StreamID(2) + PayloadLen(3) + Flags(1) + SeqNum(4) = 12
	FrameHeaderSize = 12

	// AuthTagSize is the AEAD authentication tag size.
	AuthTagSize = 16

	// NonceSize is the nonce size for AEAD.
	NonceSize = 12
)

// FrameType represents the type of a Veil protocol frame.
type FrameType uint8

const (
	FrameHandshakeInit    FrameType = 0x01
	FrameHandshakeResp    FrameType = 0x02
	FrameStreamOpen       FrameType = 0x03
	FrameStreamData       FrameType = 0x04
	FrameStreamClose      FrameType = 0x05
	FrameKeepalive        FrameType = 0x06
	FrameMorphSync        FrameType = 0x07
	FrameTransportMigrate FrameType = 0x08
	FrameSessionClose     FrameType = 0x09
)

// String returns a human-readable name for the frame type.
func (ft FrameType) String() string {
	switch ft {
	case FrameHandshakeInit:
		return "HANDSHAKE_INIT"
	case FrameHandshakeResp:
		return "HANDSHAKE_RESP"
	case FrameStreamOpen:
		return "STREAM_OPEN"
	case FrameStreamData:
		return "STREAM_DATA"
	case FrameStreamClose:
		return "STREAM_CLOSE"
	case FrameKeepalive:
		return "KEEPALIVE"
	case FrameMorphSync:
		return "MORPH_SYNC"
	case FrameTransportMigrate:
		return "TRANSPORT_MIGRATE"
	case FrameSessionClose:
		return "SESSION_CLOSE"
	default:
		return "UNKNOWN"
	}
}

// FrameFlags represents per-frame flags.
type FrameFlags uint8

const (
	FlagMorphPadded  FrameFlags = 0x01 // Frame contains morph padding
	FlagCompressed   FrameFlags = 0x02 // Payload is compressed
	FlagPriority     FrameFlags = 0x04 // High-priority frame
	FlagFinal        FrameFlags = 0x08 // Final frame in a sequence
)

// StreamState represents the state of a multiplexed stream.
type StreamState uint8

const (
	StreamIdle    StreamState = 0
	StreamOpen    StreamState = 1
	StreamClosing StreamState = 2
	StreamClosed  StreamState = 3
)

// SessionState represents the state of a Veil session.
type SessionState uint8

const (
	SessionNew          SessionState = 0
	SessionHandshaking  SessionState = 1
	SessionEstablished  SessionState = 2
	SessionMigrating    SessionState = 3
	SessionClosing      SessionState = 4
	SessionClosed       SessionState = 5
)

// Capabilities advertised during handshake.
type Capabilities struct {
	MaxStreams       uint16   `json:"max_streams"`
	MorphProfiles    []string `json:"morph_profiles"`
	Transports       []string `json:"transports"`
	CompressionAlgos []string `json:"compression,omitempty"`
}

// DefaultCapabilities returns reasonable defaults.
func DefaultCapabilities() Capabilities {
	return Capabilities{
		MaxStreams:    256,
		MorphProfiles: []string{"http2_browsing", "video_streaming", "grpc_api"},
		Transports:    []string{"raw", "tls", "wss"},
	}
}
