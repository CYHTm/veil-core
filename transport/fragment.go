// Package transport — fragment.go implements TCP-level fragmentation.
//
// Some DPI systems reassemble TCP streams and look at the first N bytes.
// By splitting the handshake across multiple small TCP segments,
// we force DPI to do full reassembly which many implementations skip.
package transport

import (
	"math/rand"
	"net"
	"time"
)

// FragmentedWriter splits writes into small random-sized TCP segments.
type FragmentedWriter struct {
	conn     net.Conn
	minFrag  int
	maxFrag  int
	delay    time.Duration
	rng      *rand.Rand
	enabled  bool
}

// NewFragmentedWriter wraps a connection with write fragmentation.
func NewFragmentedWriter(conn net.Conn, minFrag, maxFrag int, delay time.Duration) *FragmentedWriter {
	return &FragmentedWriter{
		conn:    conn,
		minFrag: minFrag,
		maxFrag: maxFrag,
		delay:   delay,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
		enabled: true,
	}
}

// Write splits data into small fragments and sends with delays.
func (fw *FragmentedWriter) Write(data []byte) (int, error) {
	if !fw.enabled || len(data) <= fw.maxFrag {
		return fw.conn.Write(data)
	}

	total := 0
	remaining := data

	for len(remaining) > 0 {
		// Random fragment size
		fragSize := fw.minFrag + fw.rng.Intn(fw.maxFrag-fw.minFrag+1)
		if fragSize > len(remaining) {
			fragSize = len(remaining)
		}

		n, err := fw.conn.Write(remaining[:fragSize])
		total += n
		if err != nil {
			return total, err
		}

		remaining = remaining[fragSize:]

		// Small delay between fragments
		if len(remaining) > 0 && fw.delay > 0 {
			jitter := time.Duration(fw.rng.Int63n(int64(fw.delay)))
			time.Sleep(fw.delay/2 + jitter)
		}
	}

	return total, nil
}

// SetEnabled enables or disables fragmentation.
func (fw *FragmentedWriter) SetEnabled(enabled bool) {
	fw.enabled = enabled
}
