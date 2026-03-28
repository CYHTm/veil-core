// Package api — subscription.go implements server list subscriptions.
//
// Like Shadowsocks/V2Ray subscriptions: a URL that returns a list
// of servers. The client periodically fetches the list and auto-switches
// if the current server goes down.
//
// Format: Base64-encoded list of veil:// links, one per line.
// Served over HTTPS by the subscription provider.
package api

import (
	"net"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Subscription manages a list of servers from a remote URL.
type Subscription struct {
	mu        sync.RWMutex
	url       string
	servers   []ClientConfig
	lastFetch time.Time
	interval  time.Duration
	stopCh    chan struct{}
	onUpdate  func([]ClientConfig)
}

// NewSubscription creates a subscription from a URL.
func NewSubscription(url string, interval time.Duration) *Subscription {
	if interval == 0 {
		interval = 6 * time.Hour
	}
	return &Subscription{
		url:      url,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// OnUpdate sets callback when server list changes.
func (s *Subscription) OnUpdate(fn func([]ClientConfig)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onUpdate = fn
}

// Fetch downloads and parses the server list.
func (s *Subscription) Fetch() error {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(s.url)
	if err != nil {
		return fmt.Errorf("fetch subscription: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("subscription returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return fmt.Errorf("read subscription: %w", err)
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		// Try raw (not base64)
		decoded = body
	}

	// Parse veil:// links
	lines := strings.Split(strings.TrimSpace(string(decoded)), "\n")
	var servers []ClientConfig

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		cfg, err := ParseLink(line)
		if err != nil {
			continue
		}
		servers = append(servers, *cfg)
	}

	if len(servers) == 0 {
		return fmt.Errorf("subscription contains no valid servers")
	}

	s.mu.Lock()
	s.servers = servers
	s.lastFetch = time.Now()
	callback := s.onUpdate
	s.mu.Unlock()

	if callback != nil {
		callback(servers)
	}

	return nil
}

// Start begins periodic fetching.
func (s *Subscription) Start() {
	go func() {
		s.Fetch()
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.Fetch()
			case <-s.stopCh:
				return
			}
		}
	}()
}

// Stop stops periodic fetching.
func (s *Subscription) Stop() {
	close(s.stopCh)
}

// Servers returns the current server list.
func (s *Subscription) Servers() []ClientConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]ClientConfig, len(s.servers))
	copy(result, s.servers)
	return result
}

// Random returns a random server from the list.
func (s *Subscription) Random() (*ClientConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.servers) == 0 {
		return nil, fmt.Errorf("no servers available")
	}
	cfg := s.servers[rand.Intn(len(s.servers))]
	return &cfg, nil
}

// Best returns the server with lowest latency (ping test).
func (s *Subscription) Best() (*ClientConfig, error) {
	servers := s.Servers()
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers available")
	}

	type result struct {
		cfg     ClientConfig
		latency time.Duration
	}

	results := make(chan result, len(servers))

	for _, cfg := range servers {
		go func(c ClientConfig) {
			start := time.Now()
			conn, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", c.ServerAddr)
			if err != nil {
				results <- result{c, time.Hour}
				return
			}
			conn.Close()
			results <- result{c, time.Since(start)}
		}(cfg)
	}

	var best result
	best.latency = time.Hour

	for i := 0; i < len(servers); i++ {
		r := <-results
		if r.latency < best.latency {
			best = r
		}
	}

	return &best.cfg, nil
}

// GenerateSubscriptionFile creates a subscription file from server configs.
func GenerateSubscriptionFile(servers []ClientConfig) string {
	var links []string
	for _, cfg := range servers {
		links = append(links, GenerateLink(cfg))
	}
	raw := strings.Join(links, "\n")
	return base64.StdEncoding.EncodeToString([]byte(raw))
}
