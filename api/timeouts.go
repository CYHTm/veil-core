package api

import "time"

// Timeouts defines all timeout values for the protocol.
type Timeouts struct {
	Connect    time.Duration // TCP connection timeout
	Handshake  time.Duration // Veil handshake timeout
	Read       time.Duration // Read deadline per operation
	Write      time.Duration // Write deadline per operation
	Idle       time.Duration // Close session after no activity
	Keepalive  time.Duration // Keepalive interval
	StreamOpen time.Duration // Timeout for opening a new stream
	DNS        time.Duration // DNS resolution timeout
}

// DefaultTimeouts returns production-ready timeout values.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		Connect:    15 * time.Second,
		Handshake:  15 * time.Second,
		Read:       120 * time.Second,
		Write:      30 * time.Second,
		Idle:       300 * time.Second,
		Keepalive:  30 * time.Second,
		StreamOpen: 10 * time.Second,
		DNS:        5 * time.Second,
	}
}

// AggressiveTimeouts for unstable networks (faster failure detection).
func AggressiveTimeouts() Timeouts {
	return Timeouts{
		Connect:    5 * time.Second,
		Handshake:  5 * time.Second,
		Read:       30 * time.Second,
		Write:      10 * time.Second,
		Idle:       60 * time.Second,
		Keepalive:  10 * time.Second,
		StreamOpen: 5 * time.Second,
		DNS:        3 * time.Second,
	}
}
