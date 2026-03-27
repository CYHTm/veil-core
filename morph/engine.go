// Package morph implements the traffic morphing engine for Veil.
//
// The morph engine transforms Veil traffic to statistically resemble
// a target application profile. This defeats DPI systems that use
// statistical analysis (packet size distribution, timing patterns,
// byte frequency analysis) to identify tunnel traffic.
//
// How it works:
//   1. A "profile" defines the statistical characteristics of a real app
//      (e.g., HTTP/2 web browsing, video streaming, gRPC API calls).
//   2. The engine adjusts packet sizes (via padding) and timing (via delays)
//      to match the target profile's distribution.
//   3. Profiles are exchanged during handshake via MORPH_SYNC frames.
package morph

import (
	"encoding/json"
	"math/rand"
	"os"
	"sync"
	"time"
)

// Profile defines statistical characteristics of a target traffic pattern.
type Profile struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	PacketSizes SizeDistribution `json:"packet_sizes"`
	Timing      TimingProfile    `json:"timing"`
	ByteFreq    []float64        `json:"byte_frequency,omitempty"` // 256 values
}

// SizeDistribution defines the packet size distribution to mimic.
type SizeDistribution struct {
	// Buckets defines ranges and their probability weights.
	// Example: [{Min: 40, Max: 100, Weight: 30}, {Min: 100, Max: 500, Weight: 50}, ...]
	Buckets []SizeBucket `json:"buckets"`
}

// SizeBucket is a range of packet sizes with a probability weight.
type SizeBucket struct {
	Min    int     `json:"min"`
	Max    int     `json:"max"`
	Weight float64 `json:"weight"` // Relative probability
}

// TimingProfile defines inter-packet timing characteristics.
type TimingProfile struct {
	MinDelayMs  int     `json:"min_delay_ms"`
	MaxDelayMs  int     `json:"max_delay_ms"`
	MeanDelayMs float64 `json:"mean_delay_ms"`
	JitterMs    float64 `json:"jitter_ms"` // Standard deviation
	BurstSize   int     `json:"burst_size"` // Packets per burst
	BurstGapMs  int     `json:"burst_gap_ms"` // Gap between bursts
}

// Engine is the traffic morphing engine.
type Engine struct {
	mu       sync.RWMutex
	profile  *Profile
	rng      *rand.Rand
}

// NewEngine creates a new morph engine with the given profile.
func NewEngine(profile *Profile) *Engine {
	return &Engine{
		profile: profile,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// SetProfile changes the active morph profile.
func (e *Engine) SetProfile(p *Profile) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.profile = p
}

// PadToTarget takes real payload and returns the padded version
// that matches the target size distribution.
// Returns: (padding bytes to append, target total size)
func (e *Engine) CalculatePadding(payloadSize int) int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.profile == nil {
		return 0
	}

	targetSize := e.sampleTargetSize()

	if targetSize <= payloadSize {
		// Payload already larger than sampled target.
		// Find next larger bucket.
		targetSize = e.findNextBucket(payloadSize)
	}

	return targetSize - payloadSize
}

// CalculateDelay returns how long to wait before sending the next packet,
// based on the timing profile.
func (e *Engine) CalculateDelay() time.Duration {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.profile == nil {
		return 0
	}

	tp := &e.profile.Timing

	// Gaussian jitter around mean
	delay := tp.MeanDelayMs + e.rng.NormFloat64()*tp.JitterMs

	// Clamp to min/max
	if delay < float64(tp.MinDelayMs) {
		delay = float64(tp.MinDelayMs)
	}
	if delay > float64(tp.MaxDelayMs) {
		delay = float64(tp.MaxDelayMs)
	}

	return time.Duration(delay) * time.Millisecond
}

// GeneratePadding creates padding bytes that match the target byte frequency.
func (e *Engine) GeneratePadding(size int) []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()

	padding := make([]byte, size)

	if e.profile != nil && len(e.profile.ByteFreq) == 256 {
		// Generate bytes matching the target frequency distribution
		for i := range padding {
			padding[i] = e.sampleByte()
		}
	} else {
		// Random padding if no byte frequency profile
		e.rng.Read(padding)
	}

	return padding
}

// sampleTargetSize picks a target packet size from the distribution.
func (e *Engine) sampleTargetSize() int {
	buckets := e.profile.PacketSizes.Buckets
	if len(buckets) == 0 {
		return 0
	}

	// Weighted random selection
	totalWeight := 0.0
	for _, b := range buckets {
		totalWeight += b.Weight
	}

	r := e.rng.Float64() * totalWeight
	cumulative := 0.0

	for _, b := range buckets {
		cumulative += b.Weight
		if r <= cumulative {
			// Uniform random within bucket
			return b.Min + e.rng.Intn(b.Max-b.Min+1)
		}
	}

	return buckets[len(buckets)-1].Max
}

// findNextBucket finds the smallest bucket that fits the payload.
func (e *Engine) findNextBucket(payloadSize int) int {
	for _, b := range e.profile.PacketSizes.Buckets {
		if b.Max > payloadSize {
			if b.Min > payloadSize {
				return b.Min + e.rng.Intn(b.Max-b.Min+1)
			}
			return payloadSize + e.rng.Intn(b.Max-payloadSize)
		}
	}
	// If payload is larger than all buckets, add small random padding
	return payloadSize + e.rng.Intn(64)
}

// sampleByte generates a single byte matching the target frequency distribution.
func (e *Engine) sampleByte() byte {
	r := e.rng.Float64()
	cumulative := 0.0
	for i, freq := range e.profile.ByteFreq {
		cumulative += freq
		if r <= cumulative {
			return byte(i)
		}
	}
	return 0xFF
}

// LoadProfile loads a morph profile from a JSON file.
func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var profile Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, err
	}

	return &profile, nil
}

// BuiltinHTTP2Profile returns a built-in profile mimicking HTTP/2 browsing.
func BuiltinHTTP2Profile() *Profile {
	return &Profile{
		Name:        "http2_browsing",
		Description: "Mimics HTTP/2 web browsing traffic patterns",
		PacketSizes: SizeDistribution{
			Buckets: []SizeBucket{
				{Min: 40, Max: 100, Weight: 15},    // TCP ACKs, small requests
				{Min: 100, Max: 300, Weight: 20},    // HTTP headers, small responses
				{Min: 300, Max: 800, Weight: 25},    // Medium responses, JS chunks
				{Min: 800, Max: 1460, Weight: 30},   // Full MTU segments
				{Min: 1460, Max: 4096, Weight: 8},   // Large frames (H2 DATA)
				{Min: 4096, Max: 16384, Weight: 2},  // Max H2 frame size
			},
		},
		Timing: TimingProfile{
			MinDelayMs:  0,
			MaxDelayMs:  200,
			MeanDelayMs: 15,
			JitterMs:    25,
			BurstSize:   8,
			BurstGapMs:  100,
		},
	}
}

// BuiltinVideoProfile returns a built-in profile mimicking video streaming.
func BuiltinVideoProfile() *Profile {
	return &Profile{
		Name:        "video_streaming",
		Description: "Mimics video streaming traffic (e.g., YouTube, Netflix)",
		PacketSizes: SizeDistribution{
			Buckets: []SizeBucket{
				{Min: 40, Max: 100, Weight: 5},      // ACKs
				{Min: 100, Max: 300, Weight: 5},      // Control messages
				{Min: 1200, Max: 1460, Weight: 70},   // Video data segments
				{Min: 1460, Max: 8192, Weight: 15},   // Large segments
				{Min: 8192, Max: 16384, Weight: 5},   // Burst segments
			},
		},
		Timing: TimingProfile{
			MinDelayMs:  0,
			MaxDelayMs:  50,
			MeanDelayMs: 5,
			JitterMs:    8,
			BurstSize:   20,
			BurstGapMs:  30,
		},
	}
}
