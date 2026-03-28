// Package crypto — replay.go implements replay attack protection.
//
// Tracks seen sequence numbers using a sliding window bitmap.
// Rejects any packet with a previously seen or too-old sequence number.
package crypto

import "sync"

const (
	// ReplayWindowSize is the number of sequence numbers to track.
	ReplayWindowSize = 1024
)

// ReplayFilter rejects replayed packets using a sliding window.
type ReplayFilter struct {
	mu       sync.Mutex
	maxSeen  uint64
	bitmap   [ReplayWindowSize / 64]uint64
}

// NewReplayFilter creates a new replay filter.
func NewReplayFilter() *ReplayFilter {
	return &ReplayFilter{}
}

// Check returns true if this sequence number is NEW (not replayed).
// Returns false if it was already seen or is too old.
func (rf *ReplayFilter) Check(seq uint64) bool {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	if seq == 0 {
		return false
	}

	// If sequence is ahead of window — advance window
	if seq > rf.maxSeen {
		diff := seq - rf.maxSeen
		if diff >= ReplayWindowSize {
			// Clear entire bitmap
			for i := range rf.bitmap {
				rf.bitmap[i] = 0
			}
		} else {
			// Shift bitmap forward
			for i := rf.maxSeen + 1; i <= seq; i++ {
				idx := i % ReplayWindowSize
				rf.bitmap[idx/64] &^= 1 << (idx % 64)
			}
		}
		rf.maxSeen = seq
	}

	// If sequence is too old — reject
	if rf.maxSeen-seq >= ReplayWindowSize {
		return false
	}

	// Check if already seen
	idx := seq % ReplayWindowSize
	bit := uint64(1) << (idx % 64)
	word := &rf.bitmap[idx/64]

	if *word&bit != 0 {
		return false // Already seen — replay!
	}

	// Mark as seen
	*word |= bit
	return true
}
