// Package crypto - steganography.go implements steganographic triggers.
//
// The idea: a Veil server runs a fully legitimate service (web server,
// gRPC API, etc.). The tunnel is activated by a steganographic trigger
// hidden inside otherwise valid requests.
//
// Trigger types:
//   - HTTP header value with embedded signal
//   - Cookie with HMAC-based trigger
//   - TLS session ticket with encoded data
//   - DNS query name pattern
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	// TriggerHMACSize is the truncated HMAC size for triggers.
	TriggerHMACSize = 8
)

// StegTrigger generates and validates steganographic triggers.
type StegTrigger struct {
	psk []byte
}

// NewStegTrigger creates a new steganographic trigger generator.
func NewStegTrigger(secret string) *StegTrigger {
	return &StegTrigger{
		psk: GeneratePSK(secret + "|steg-trigger"),
	}
}

// GenerateHTTPCookieTrigger generates a cookie value that serves as a Veil trigger.
// It looks like a normal analytics/tracking cookie but contains a valid HMAC.
//
// Format: "GA1.2.<epoch_hex>.<hmac_hex>"
// This mimics a Google Analytics cookie pattern.
func (st *StegTrigger) GenerateHTTPCookieTrigger() (name, value string) {
	epoch := time.Now().Unix() / int64(EpochWindow.Seconds())
	epochHex := fmt.Sprintf("%x", epoch)

	// HMAC of epoch with PSK
	mac := st.computeHMAC([]byte(epochHex))
	macHex := hex.EncodeToString(mac[:TriggerHMACSize])

	name = "_ga"
	value = fmt.Sprintf("GA1.2.%s.%s", epochHex, macHex)
	return
}

// ValidateHTTPCookieTrigger checks if a cookie value is a valid Veil trigger.
func (st *StegTrigger) ValidateHTTPCookieTrigger(value string) bool {
	// Parse the cookie format "GA1.2.<epoch_hex>.<hmac_hex>"
	parts := strings.Split(value, ".")
	if len(parts) != 4 || parts[0] != "GA1" || parts[1] != "2" {
		return false
	}

	epochHex := parts[2]
	macHex := parts[3]

	expectedMAC := st.computeHMAC([]byte(epochHex))
	expectedHex := hex.EncodeToString(expectedMAC[:TriggerHMACSize])

	// Constant-time comparison
	return hmac.Equal([]byte(macHex), []byte(expectedHex))
}

// GenerateHTTPHeaderTrigger generates an HTTP header value that acts as a trigger.
// Uses the "Accept-Language" header with encoded data.
//
// Format: "en-US,en;q=0.9,<trigger>;q=0.8"
func (st *StegTrigger) GenerateHTTPHeaderTrigger() (headerName, headerValue string) {
	epoch := time.Now().Unix() / int64(EpochWindow.Seconds())
	epochBytes := fmt.Sprintf("%x", epoch)

	mac := st.computeHMAC([]byte(epochBytes))
	// Encode as a fake language tag
	langTrigger := fmt.Sprintf("x-%s", hex.EncodeToString(mac[:4]))

	headerName = "Accept-Language"
	headerValue = fmt.Sprintf("en-US,en;q=0.9,%s;q=0.8", langTrigger)
	return
}

// ValidateHTTPHeaderTrigger validates an Accept-Language header trigger.
func (st *StegTrigger) ValidateHTTPHeaderTrigger(value string) bool {
	// Look for "x-<hex>" pattern in the Accept-Language value
	parts := strings.Split(value, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		langParts := strings.Split(part, ";")
		lang := strings.TrimSpace(langParts[0])

		if strings.HasPrefix(lang, "x-") {
			macHex := strings.TrimPrefix(lang, "x-")
			epoch := time.Now().Unix() / int64(EpochWindow.Seconds())
			epochBytes := fmt.Sprintf("%x", epoch)

			expectedMAC := st.computeHMAC([]byte(epochBytes))
			expectedHex := hex.EncodeToString(expectedMAC[:4])

			if hmac.Equal([]byte(macHex), []byte(expectedHex)) {
				return true
			}

			// Try previous epoch
			prevEpochBytes := fmt.Sprintf("%x", epoch-1)
			prevMAC := st.computeHMAC([]byte(prevEpochBytes))
			prevHex := hex.EncodeToString(prevMAC[:4])

			if hmac.Equal([]byte(macHex), []byte(prevHex)) {
				return true
			}
		}
	}
	return false
}

// GenerateDNSTrigger generates a DNS query name that contains a trigger.
// Format: "<random>.<hmac_prefix>.cdn.example.com"
func (st *StegTrigger) GenerateDNSTrigger(domain string) string {
	epoch := time.Now().Unix() / int64(EpochWindow.Seconds())
	epochBytes := fmt.Sprintf("%x", epoch)

	mac := st.computeHMAC([]byte(epochBytes))
	prefix := hex.EncodeToString(mac[:4])

	// Generate random-looking subdomain
	randPart, _ := GenerateNonce(4)
	randHex := hex.EncodeToString(randPart)

	return fmt.Sprintf("%s.%s.cdn.%s", randHex, prefix, domain)
}

// ValidateDNSTrigger validates a DNS query name trigger.
func (st *StegTrigger) ValidateDNSTrigger(query, domain string) bool {
	suffix := ".cdn." + domain
	if !strings.HasSuffix(query, suffix) {
		return false
	}

	// Extract parts before the suffix
	prefix := strings.TrimSuffix(query, suffix)
	parts := strings.Split(prefix, ".")
	if len(parts) != 2 {
		return false
	}

	triggerHex := parts[1]

	epoch := time.Now().Unix() / int64(EpochWindow.Seconds())
	for _, e := range []int64{epoch, epoch - 1} {
		epochBytes := fmt.Sprintf("%x", e)
		mac := st.computeHMAC([]byte(epochBytes))
		expectedHex := hex.EncodeToString(mac[:4])

		if hmac.Equal([]byte(triggerHex), []byte(expectedHex)) {
			return true
		}
	}

	return false
}

// computeHMAC computes HMAC-SHA256.
func (st *StegTrigger) computeHMAC(data []byte) []byte {
	h := hmac.New(sha256.New, st.psk)
	h.Write(data)
	return h.Sum(nil)
}
