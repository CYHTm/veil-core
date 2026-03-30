// Package api provides the high-level client and server API for Veil.
//
// This file implements panic recovery middleware to prevent
// individual goroutine crashes from taking down the process.
package api

import (
	"fmt"
	"runtime"
	"sync"
)

// ErrorClass categorizes errors for recovery decisions.
type ErrorClass int

const (
	ErrTransient  ErrorClass = iota // Retry (network glitch)
	ErrAuth                         // Don't retry (wrong secret)
	ErrProtocol                     // Don't retry (incompatible version)
	ErrFatal                        // Stop everything
)

// ClassifyError determines if an error is retryable.
func ClassifyError(err error) ErrorClass {
	if err == nil {
		return ErrTransient
	}

	msg := err.Error()

	// Authentication errors — don't retry
	for _, pattern := range []string{
		"handshake failed",
		"AEAD authentication",
		"wrong secret",
		"invalid key",
		"trigger rejected",
	} {
		if contains(msg, pattern) {
			return ErrAuth
		}
	}

	// Protocol errors — don't retry
	for _, pattern := range []string{
		"unsupported protocol version",
		"invalid frame",
		"unknown cipher",
	} {
		if contains(msg, pattern) {
			return ErrProtocol
		}
	}

	// Everything else is transient (network issues)
	return ErrTransient
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// PanicRecovery wraps a goroutine with panic recovery.
func PanicRecovery(name string, logger interface{ Printf(string, ...interface{}) }, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			if logger != nil {
				logger.Printf("[PANIC] %s: %v\n%s", name, r, buf[:n])
			}
		}
	}()
	fn()
}

// ErrorAggregator collects errors from multiple goroutines.
type ErrorAggregator struct {
	mu   sync.Mutex
	errs []error
}

// Add records an error (thread-safe).
func (ea *ErrorAggregator) Add(err error) {
	if err == nil {
		return
	}
	ea.mu.Lock()
	ea.errs = append(ea.errs, err)
	ea.mu.Unlock()
}

// Errors returns all collected errors.
func (ea *ErrorAggregator) Errors() []error {
	ea.mu.Lock()
	defer ea.mu.Unlock()
	result := make([]error, len(ea.errs))
	copy(result, ea.errs)
	return result
}

// Error returns combined error or nil.
func (ea *ErrorAggregator) Error() error {
	ea.mu.Lock()
	defer ea.mu.Unlock()
	if len(ea.errs) == 0 {
		return nil
	}
	return fmt.Errorf("%d errors occurred, first: %w", len(ea.errs), ea.errs[0])
}
