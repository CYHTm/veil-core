// Package morph — idle.go implements the Idle Padding Engine.
//
// When the tunnel has no real traffic, it generates fake keepalive
// packets that mimic real application idle behavior (e.g., Chrome
// HTTP/2 PING frames, WebSocket heartbeats, periodic telemetry).
//
// This defeats DPI that detects tunnels by observing "dead" connections
// with no traffic for extended periods.
package morph

import (
	"math/rand"
	"sync"
	"time"
)

// IdleProfile configures the idle padding behavior.
type IdleProfile struct {
	// MinInterval is the minimum time between idle packets.
	MinInterval time.Duration

	// MaxInterval is the maximum time between idle packets.
	MaxInterval time.Duration

	// MinPadding is the minimum padding size (bytes) for idle packets.
	MinPadding int

	// MaxPadding is the maximum padding size (bytes) for idle packets.
	MaxPadding int

	// BurstChance is the probability (0.0-1.0) of sending a burst of
	// 2-4 packets instead of a single packet (mimics HTTP/2 PING + SETTINGS).
	BurstChance float64

	// BurstMin is the minimum number of packets in a burst.
	BurstMin int

	// BurstMax is the maximum number of packets in a burst.
	BurstMax int

	// BurstGap is the delay between packets within a burst.
	BurstGap time.Duration
}

// IdleAction describes what the keepalive loop should do next.
type IdleAction struct {
	// Delay is how long to wait before sending this packet.
	Delay time.Duration

	// PaddingSize is how many bytes of padding to add to the keepalive frame.
	PaddingSize int

	// IsBurst indicates this is part of a multi-packet burst.
	IsBurst bool

	// BurstRemaining is how many more packets follow in this burst.
	BurstRemaining int
}

// IdlePadder generates realistic idle traffic patterns based on a profile.
type IdlePadder struct {
	mu      sync.RWMutex
	profile IdleProfile
	rng     *rand.Rand

	// Internal state for burst tracking
	burstQueue []IdleAction
}

// NewIdlePadder creates an idle padder from a morph profile.
// If the profile has no explicit idle settings, sensible defaults
// based on the timing profile are derived.
func NewIdlePadder(profile *Profile) *IdlePadder {
	ip := deriveIdleProfile(profile)
	return &IdlePadder{
		profile: ip,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// NewIdlePadderFromConfig creates an idle padder from explicit config.
func NewIdlePadderFromConfig(profile IdleProfile) *IdlePadder {
	return &IdlePadder{
		profile: profile,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// NextAction returns the next idle action (delay + padding size).
// The caller should wait for Delay, then send a keepalive with PaddingSize bytes.
func (ip *IdlePadder) NextAction() IdleAction {
	ip.mu.Lock()
	defer ip.mu.Unlock()

	// If we're in the middle of a burst, return next burst packet
	if len(ip.burstQueue) > 0 {
		action := ip.burstQueue[0]
		ip.burstQueue = ip.burstQueue[1:]
		return action
	}

	// Decide: single packet or burst?
	if ip.profile.BurstChance > 0 && ip.rng.Float64() < ip.profile.BurstChance {
		return ip.generateBurst()
	}

	return ip.generateSingle()
}

// Profile returns the current idle profile.
func (ip *IdlePadder) Profile() IdleProfile {
	ip.mu.RLock()
	defer ip.mu.RUnlock()
	return ip.profile
}

// UpdateProfile changes the idle profile at runtime.
func (ip *IdlePadder) UpdateProfile(profile *Profile) {
	ip.mu.Lock()
	defer ip.mu.Unlock()
	ip.profile = deriveIdleProfile(profile)
	ip.burstQueue = nil
}

func (ip *IdlePadder) generateSingle() IdleAction {
	delay := ip.randomDuration(ip.profile.MinInterval, ip.profile.MaxInterval)
	padding := ip.randomInt(ip.profile.MinPadding, ip.profile.MaxPadding)
	return IdleAction{
		Delay:       delay,
		PaddingSize: padding,
	}
}

func (ip *IdlePadder) generateBurst() IdleAction {
	// First packet has the full inter-idle delay
	delay := ip.randomDuration(ip.profile.MinInterval, ip.profile.MaxInterval)
	padding := ip.randomInt(ip.profile.MinPadding, ip.profile.MaxPadding)

	burstSize := ip.randomInt(ip.profile.BurstMin, ip.profile.BurstMax)
	if burstSize < 2 {
		burstSize = 2
	}

	// Queue remaining burst packets
	ip.burstQueue = make([]IdleAction, burstSize-1)
	for i := range ip.burstQueue {
		ip.burstQueue[i] = IdleAction{
			Delay:          ip.profile.BurstGap + ip.randomDuration(0, ip.profile.BurstGap/2),
			PaddingSize:    ip.randomInt(ip.profile.MinPadding, ip.profile.MaxPadding),
			IsBurst:        true,
			BurstRemaining: len(ip.burstQueue) - 1 - i,
		}
	}

	return IdleAction{
		Delay:          delay,
		PaddingSize:    padding,
		IsBurst:        true,
		BurstRemaining: len(ip.burstQueue),
	}
}

func (ip *IdlePadder) randomDuration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(ip.rng.Int63n(int64(max-min)))
}

func (ip *IdlePadder) randomInt(min, max int) int {
	if max <= min {
		return min
	}
	return min + ip.rng.Intn(max-min+1)
}

// deriveIdleProfile creates an IdleProfile from a morph Profile.
// It maps traffic characteristics to realistic idle behavior:
//   - Chrome HTTP/2: PINGs every 15-45s, small frames (8-64 bytes)
//   - Video streaming: larger keepalives, longer intervals
//   - Chat apps: frequent small heartbeats
func deriveIdleProfile(p *Profile) IdleProfile {
	if p == nil {
		return defaultIdleProfile()
	}

	tp := &p.Timing

	// Base interval from timing profile, scaled for idle (2-4x normal delay)
	baseMin := time.Duration(tp.MinDelayMs*3) * time.Millisecond
	baseMax := time.Duration(tp.MaxDelayMs*4) * time.Millisecond

	// Clamp to reasonable idle range
	if baseMin < 5*time.Second {
		baseMin = 5 * time.Second
	}
	if baseMax < baseMin+5*time.Second {
		baseMax = baseMin + 5*time.Second
	}
	if baseMax > 60*time.Second {
		baseMax = 60 * time.Second
	}

	// Padding based on smallest bucket (idle = small packets)
	minPad := 8
	maxPad := 64
	if len(p.PacketSizes.Buckets) > 0 {
		smallest := p.PacketSizes.Buckets[0]
		minPad = smallest.Min
		if minPad < 8 {
			minPad = 8
		}
		maxPad = smallest.Max
		if maxPad < minPad+8 {
			maxPad = minPad + 8
		}
		if maxPad > 256 {
			maxPad = 256
		}
	}

	// Burst characteristics from timing profile
	burstChance := 0.15 // 15% chance of burst by default
	burstMin := 2
	burstMax := 3
	burstGap := 50 * time.Millisecond

	if tp.BurstSize > 0 {
		burstChance = 0.20
		burstMax = tp.BurstSize
		if burstMax > 5 {
			burstMax = 5
		}
		if tp.BurstGapMs > 0 {
			burstGap = time.Duration(tp.BurstGapMs) * time.Millisecond
		}
	}

	return IdleProfile{
		MinInterval: baseMin,
		MaxInterval: baseMax,
		MinPadding:  minPad,
		MaxPadding:  maxPad,
		BurstChance: burstChance,
		BurstMin:    burstMin,
		BurstMax:    burstMax,
		BurstGap:    burstGap,
	}
}

// defaultIdleProfile returns Chrome-like idle defaults.
func defaultIdleProfile() IdleProfile {
	return IdleProfile{
		MinInterval: 15 * time.Second,
		MaxInterval: 45 * time.Second,
		MinPadding:  8,
		MaxPadding:  64,
		BurstChance: 0.15,
		BurstMin:    2,
		BurstMax:    3,
		BurstGap:    50 * time.Millisecond,
	}
}
