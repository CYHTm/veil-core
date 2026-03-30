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

// ProfileInfo describes an available morph profile.
type ProfileInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ListBuiltinProfiles returns all available built-in profile names and descriptions.
func ListBuiltinProfiles() []ProfileInfo {
	return []ProfileInfo{
		{Name: "http2_browsing", Description: "Chrome HTTP/2 web browsing"},
		{Name: "video_streaming", Description: "YouTube/Netflix video streaming"},
		{Name: "chrome_real", Description: "Real Chrome 120 captured traffic"},
		{Name: "youtube_real", Description: "Real YouTube captured traffic"},
		{Name: "tiktok_scrolling", Description: "TikTok short video feed scrolling"},
		{Name: "discord_chat", Description: "Discord text chat (WebSocket gateway)"},
		{Name: "telegram_messaging", Description: "Telegram MTProto messaging"},
		{Name: "grpc_api", Description: "gRPC API call pattern"},
	}
}

// GetBuiltinProfile returns a built-in profile by name, or nil if not found.
func GetBuiltinProfile(name string) *Profile {
	switch name {
	case "http2_browsing":
		return BuiltinHTTP2Profile()
	case "video_streaming":
		return BuiltinVideoProfile()
	case "tiktok_scrolling":
		return BuiltinTikTokProfile()
	case "discord_chat":
		return BuiltinDiscordProfile()
	case "telegram_messaging":
		return BuiltinTelegramProfile()
	case "chrome_real":
		return BuiltinChromeRealProfile()
	case "youtube_real":
		return BuiltinYouTubeRealProfile()
	case "grpc_api":
		return BuiltinGRPCProfile()
	default:
		return nil
	}
}

// ResolveProfile tries built-in profiles first, then loads from file path.
func ResolveProfile(nameOrPath string) (*Profile, error) {
	if p := GetBuiltinProfile(nameOrPath); p != nil {
		return p, nil
	}
	// Try loading as file path
	return LoadProfile(nameOrPath)
}

// BuiltinTikTokProfile returns a built-in profile mimicking TikTok feed scrolling.
func BuiltinTikTokProfile() *Profile {
	return &Profile{
		Name:        "tiktok_scrolling",
		Description: "Mimics TikTok short video feed scrolling (QUIC/HTTPS bursts)",
		PacketSizes: SizeDistribution{
			Buckets: []SizeBucket{
				{Min: 40, Max: 100, Weight: 8.5},
				{Min: 100, Max: 250, Weight: 6.2},
				{Min: 250, Max: 500, Weight: 4.8},
				{Min: 500, Max: 900, Weight: 3.5},
				{Min: 900, Max: 1200, Weight: 7.8},
				{Min: 1200, Max: 1380, Weight: 12.4},
				{Min: 1380, Max: 1460, Weight: 42.3},
				{Min: 1460, Max: 4096, Weight: 9.8},
				{Min: 4096, Max: 8192, Weight: 3.2},
				{Min: 8192, Max: 16384, Weight: 1.5},
			},
		},
		Timing: TimingProfile{
			MinDelayMs: 0, MaxDelayMs: 2000,
			MeanDelayMs: 8, JitterMs: 45,
			BurstSize: 30, BurstGapMs: 800,
		},
	}
}

// BuiltinDiscordProfile returns a built-in profile mimicking Discord text chat.
func BuiltinDiscordProfile() *Profile {
	return &Profile{
		Name:        "discord_chat",
		Description: "Mimics Discord text chat with WebSocket gateway",
		PacketSizes: SizeDistribution{
			Buckets: []SizeBucket{
				{Min: 24, Max: 60, Weight: 22.5},
				{Min: 60, Max: 130, Weight: 18.3},
				{Min: 130, Max: 300, Weight: 24.7},
				{Min: 300, Max: 600, Weight: 15.8},
				{Min: 600, Max: 1100, Weight: 9.4},
				{Min: 1100, Max: 1460, Weight: 5.2},
				{Min: 1460, Max: 4096, Weight: 3.1},
				{Min: 4096, Max: 16384, Weight: 1.0},
			},
		},
		Timing: TimingProfile{
			MinDelayMs: 0, MaxDelayMs: 41500,
			MeanDelayMs: 250, JitterMs: 800,
			BurstSize: 4, BurstGapMs: 2500,
		},
	}
}

// BuiltinTelegramProfile returns a built-in profile mimicking Telegram messaging.
func BuiltinTelegramProfile() *Profile {
	return &Profile{
		Name:        "telegram_messaging",
		Description: "Mimics Telegram MTProto encrypted messaging",
		PacketSizes: SizeDistribution{
			Buckets: []SizeBucket{
				{Min: 28, Max: 72, Weight: 16.8},
				{Min: 72, Max: 176, Weight: 21.4},
				{Min: 176, Max: 400, Weight: 19.6},
				{Min: 400, Max: 700, Weight: 12.3},
				{Min: 700, Max: 1100, Weight: 8.7},
				{Min: 1100, Max: 1380, Weight: 6.9},
				{Min: 1380, Max: 1460, Weight: 10.1},
				{Min: 1460, Max: 4096, Weight: 2.8},
				{Min: 4096, Max: 16384, Weight: 1.4},
			},
		},
		Timing: TimingProfile{
			MinDelayMs: 0, MaxDelayMs: 15000,
			MeanDelayMs: 180, JitterMs: 450,
			BurstSize: 5, BurstGapMs: 3000,
		},
	}
}

// BuiltinChromeRealProfile returns a profile based on real Chrome 120 capture.
func BuiltinChromeRealProfile() *Profile {
	return &Profile{
		Name:        "chrome_real",
		Description: "Real Chrome 120 HTTP/2 traffic profile captured via tcpdump",
		PacketSizes: SizeDistribution{
			Buckets: []SizeBucket{
				{Min: 24, Max: 66, Weight: 18.2},
				{Min: 66, Max: 150, Weight: 12.4},
				{Min: 150, Max: 350, Weight: 14.8},
				{Min: 350, Max: 700, Weight: 11.2},
				{Min: 700, Max: 1100, Weight: 8.6},
				{Min: 1100, Max: 1380, Weight: 6.3},
				{Min: 1380, Max: 1460, Weight: 22.1},
				{Min: 1460, Max: 2920, Weight: 4.2},
				{Min: 2920, Max: 8960, Weight: 1.5},
				{Min: 8960, Max: 16384, Weight: 0.7},
			},
		},
		Timing: TimingProfile{
			MinDelayMs: 0, MaxDelayMs: 500,
			MeanDelayMs: 12, JitterMs: 35,
			BurstSize: 6, BurstGapMs: 85,
		},
	}
}

// BuiltinYouTubeRealProfile returns a profile based on real YouTube capture.
func BuiltinYouTubeRealProfile() *Profile {
	return &Profile{
		Name:        "youtube_real",
		Description: "Real YouTube streaming traffic captured via tcpdump",
		PacketSizes: SizeDistribution{
			Buckets: []SizeBucket{
				{Min: 24, Max: 66, Weight: 8.5},
				{Min: 66, Max: 150, Weight: 4.2},
				{Min: 150, Max: 350, Weight: 3.8},
				{Min: 350, Max: 700, Weight: 2.1},
				{Min: 700, Max: 1100, Weight: 3.4},
				{Min: 1100, Max: 1380, Weight: 8.7},
				{Min: 1380, Max: 1460, Weight: 58.3},
				{Min: 1460, Max: 2920, Weight: 7.2},
				{Min: 2920, Max: 8960, Weight: 2.6},
				{Min: 8960, Max: 16384, Weight: 1.2},
			},
		},
		Timing: TimingProfile{
			MinDelayMs: 0, MaxDelayMs: 100,
			MeanDelayMs: 4, JitterMs: 12,
			BurstSize: 25, BurstGapMs: 50,
		},
	}
}

// BuiltinGRPCProfile returns a built-in profile mimicking gRPC API traffic.
func BuiltinGRPCProfile() *Profile {
	return &Profile{
		Name:        "grpc_api",
		Description: "Mimics gRPC API call pattern (HTTP/2 + protobuf)",
		PacketSizes: SizeDistribution{
			Buckets: []SizeBucket{
				{Min: 24, Max: 60, Weight: 20},
				{Min: 60, Max: 200, Weight: 30},
				{Min: 200, Max: 500, Weight: 25},
				{Min: 500, Max: 1000, Weight: 15},
				{Min: 1000, Max: 1460, Weight: 7},
				{Min: 1460, Max: 16384, Weight: 3},
			},
		},
		Timing: TimingProfile{
			MinDelayMs: 0, MaxDelayMs: 300,
			MeanDelayMs: 20, JitterMs: 30,
			BurstSize: 3, BurstGapMs: 150,
		},
	}
}
