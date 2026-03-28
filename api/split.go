// Package api — split.go implements split tunneling.
//
// Not all traffic needs to go through the tunnel.
// Local network, trusted sites, and high-bandwidth services
// can go direct while only blocked/sensitive traffic uses Veil.
package api

import (
	"net"
	"strings"
	"sync"
)

// SplitRule defines whether traffic to a destination goes through tunnel or direct.
type SplitMode int

const (
	ModeProxy  SplitMode = iota // Through Veil tunnel
	ModeDirect                   // Direct connection (bypass tunnel)
)

// SplitTunnel decides which traffic goes through the tunnel.
type SplitTunnel struct {
	mu          sync.RWMutex
	mode        SplitTunnelMode
	domains     map[string]SplitMode
	cidrs       []cidrRule
	defaultMode SplitMode
}

type SplitTunnelMode int

const (
	// SplitAll: everything through tunnel (default)
	SplitAll SplitTunnelMode = iota
	// SplitBypass: everything through tunnel except bypass list
	SplitBypass
	// SplitOnly: only listed domains/IPs through tunnel, rest direct
	SplitOnly
)

type cidrRule struct {
	network *net.IPNet
	mode    SplitMode
}

// NewSplitTunnel creates a split tunnel controller.
func NewSplitTunnel(mode SplitTunnelMode) *SplitTunnel {
	st := &SplitTunnel{
		mode:    mode,
		domains: make(map[string]SplitMode),
	}

	switch mode {
	case SplitAll:
		st.defaultMode = ModeProxy
	case SplitBypass:
		st.defaultMode = ModeProxy
	case SplitOnly:
		st.defaultMode = ModeDirect
	}

	// Always bypass local networks
	st.AddCIDR("127.0.0.0/8", ModeDirect)
	st.AddCIDR("10.0.0.0/8", ModeDirect)
	st.AddCIDR("172.16.0.0/12", ModeDirect)
	st.AddCIDR("192.168.0.0/16", ModeDirect)
	st.AddCIDR("::1/128", ModeDirect)

	return st
}

// AddDomain adds a domain rule.
func (st *SplitTunnel) AddDomain(domain string, mode SplitMode) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.domains[strings.ToLower(domain)] = mode
}

// AddCIDR adds an IP range rule.
func (st *SplitTunnel) AddCIDR(cidr string, mode SplitMode) {
	st.mu.Lock()
	defer st.mu.Unlock()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	st.cidrs = append(st.cidrs, cidrRule{network: network, mode: mode})
}

// ShouldProxy returns true if traffic to this target should use the tunnel.
func (st *SplitTunnel) ShouldProxy(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}

	st.mu.RLock()
	defer st.mu.RUnlock()

	// Check exact domain match
	if mode, ok := st.domains[strings.ToLower(host)]; ok {
		return mode == ModeProxy
	}

	// Check wildcard domain (e.g., rule for "google.com" matches "www.google.com")
	parts := strings.Split(strings.ToLower(host), ".")
	for i := 0; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i+1:], ".")
		if mode, ok := st.domains[parent]; ok {
			return mode == ModeProxy
		}
	}

	// Check IP ranges
	ip := net.ParseIP(host)
	if ip != nil {
		for _, rule := range st.cidrs {
			if rule.network.Contains(ip) {
				return rule.mode == ModeProxy
			}
		}
	}

	return st.defaultMode == ModeProxy
}

// BypassDomains is a convenience list of commonly bypassed domains.
var BypassDomains = []string{
	"localhost",
	"local",
	"lan",
}
