// Package morph — sequence.go implements sequence-level morphing.
//
// DPI can detect tunnels not just by packet sizes, but by the
// SEQUENCE pattern:
//   Real HTTP/2:  client sends small → server sends large → client ACKs → ...
//   VPN tunnel:   both sides send similar sizes alternately
//
// SequenceMorpher injects fake directional patterns to match
// the expected client/server ratio of a real protocol.
package morph

import (
	"math/rand"
	"sync"
	"time"
)

// DirectionProfile describes expected traffic ratios.
type DirectionProfile struct {
	// ClientToServerRatio: what fraction of packets go client→server
	// HTTP browsing: ~0.3 (mostly downloading)
	// Video streaming: ~0.05 (almost all download)
	// gRPC bidirectional: ~0.5
	ClientToServerRatio float64

	// Expected burst patterns
	// HTTP: client sends 2-3, server responds 8-15
	// Video: client sends 1, server responds 20-40
	ClientBurstSize int
	ServerBurstSize int
}

// HTTPBrowsingDirection returns direction profile for web browsing.
func HTTPBrowsingDirection() DirectionProfile {
	return DirectionProfile{
		ClientToServerRatio: 0.30,
		ClientBurstSize:     3,
		ServerBurstSize:     12,
	}
}

// VideoStreamingDirection returns direction profile for video.
func VideoStreamingDirection() DirectionProfile {
	return DirectionProfile{
		ClientToServerRatio: 0.05,
		ClientBurstSize:     1,
		ServerBurstSize:     30,
	}
}

// SequenceMorpher controls packet emission order to match profiles.
type SequenceMorpher struct {
	mu      sync.Mutex
	profile DirectionProfile
	rng     *rand.Rand

	// Counters to track current ratio
	clientPackets int64
	serverPackets int64
	totalPackets  int64
}

// NewSequenceMorpher creates a sequence morpher.
func NewSequenceMorpher(profile DirectionProfile) *SequenceMorpher {
	return &SequenceMorpher{
		profile: profile,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// ShouldInsertDummy returns true if a dummy packet should be inserted
// in the given direction to maintain the expected ratio.
// direction: 0 = client→server, 1 = server→client
func (sm *SequenceMorpher) ShouldInsertDummy(direction int) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.totalPackets++
	if direction == 0 {
		sm.clientPackets++
	} else {
		sm.serverPackets++
	}

	if sm.totalPackets < 20 {
		return false // Too early to judge
	}

	currentRatio := float64(sm.clientPackets) / float64(sm.totalPackets)
	targetRatio := sm.profile.ClientToServerRatio

	// If client is sending too much relative to target, insert server dummy
	if direction == 0 && currentRatio > targetRatio+0.1 {
		return true
	}

	// If server is sending too much, insert client dummy
	if direction == 1 && currentRatio < targetRatio-0.1 {
		return true
	}

	return false
}

// DummySize returns appropriate size for a dummy packet.
func (sm *SequenceMorpher) DummySize(direction int) int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if direction == 0 {
		// Client dummy: small (like ACK or small request)
		return 40 + sm.rng.Intn(120)
	}
	// Server dummy: medium (like partial response)
	return 200 + sm.rng.Intn(800)
}

// Reset resets counters (call on new session/stream).
func (sm *SequenceMorpher) Reset() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.clientPackets = 0
	sm.serverPackets = 0
	sm.totalPackets = 0
}
