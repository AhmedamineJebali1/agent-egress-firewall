// Package policy holds the egress policy shared by the HTTP proxy and the DNS
// guard, plus the three canonical enforcement levels the lab compares.
package policy

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
)

// Enforcement levels. These are the three columns of the research matrix.
const (
	// ModeOff is the control group: nothing is enforced.
	ModeOff = "off"
	// ModeAllowlist does domain allowlisting only. TLS is tunnelled blind,
	// so request bodies are never inspected.
	ModeAllowlist = "allowlist"
	// ModeFull adds TLS interception, data-loss prevention and strict DNS.
	ModeFull = "full"
)

// DLPConfig tunes the data-loss-prevention engine.
type DLPConfig struct {
	MinFragment       int     `json:"min_fragment_len"`
	CoverageThreshold float64 `json:"coverage_threshold"`
	WindowSeconds     int     `json:"window_seconds"`
	WindowBytes       int     `json:"window_bytes"`
	MaxDecodeDepth    int     `json:"max_decode_depth"`
	Patterns          []string `json:"patterns"`
}

// DNSConfig tunes the DNS guard heuristics used in full mode.
type DNSConfig struct {
	MaxLabelLen      int     `json:"max_label_len"`
	MaxNameLen       int     `json:"max_name_len"`
	MaxLabels        int     `json:"max_labels"`
	EntropyThreshold float64 `json:"entropy_threshold"`
	MaxQPSPerDomain  int     `json:"max_queries_per_domain"`
}

// File is the on-disk policy document.
type File struct {
	Mode            string    `json:"mode"`
	Allowlist       []string  `json:"allowlist"`
	AllowIPLiterals bool      `json:"allow_ip_literals"`
	UpstreamDNS     []string  `json:"upstream_dns"`
	LabZoneDNS      string    `json:"lab_zone_dns"`
	LabZoneSuffix   string    `json:"lab_zone_suffix"`
	DLP             DLPConfig `json:"dlp"`
	DNS             DNSConfig `json:"dns"`
}

// Policy is a concurrency-safe wrapper the services hold onto. The admin API
// flips Mode at runtime so a single running stack can be measured three times.
type Policy struct {
	mu   sync.RWMutex
	f    File
	path string
}

// Defaults returns a policy that is safe if the config file is missing.
func Defaults() File {
	return File{
		Mode:            ModeFull,
		Allowlist:       []string{},
		AllowIPLiterals: false,
		UpstreamDNS:     []string{"127.0.0.11:53"},
		LabZoneSuffix:   "lab",
		DLP: DLPConfig{
			MinFragment:       3,
			CoverageThreshold: 0.5,
			WindowSeconds:     900,
			WindowBytes:       262144,
			MaxDecodeDepth:    3,
		},
		DNS: DNSConfig{
			MaxLabelLen:      30,
			MaxNameLen:       100,
			MaxLabels:        8,
			EntropyThreshold: 3.6,
			MaxQPSPerDomain:  0,
		},
	}
}

// Load reads a policy file, falling back to defaults for absent fields.
func Load(path string) (*Policy, error) {
	p := &Policy{f: Defaults(), path: path}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return p, nil
		}
		return nil, err
	}
	f := Defaults()
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.DLP.MinFragment == 0 {
		f.DLP.MinFragment = 3
	}
	if f.DLP.WindowBytes == 0 {
		f.DLP.WindowBytes = 262144
	}
	if f.DLP.MaxDecodeDepth == 0 {
		f.DLP.MaxDecodeDepth = 3
	}
	if f.LabZoneSuffix == "" {
		f.LabZoneSuffix = "lab"
	}
	p.f = f
	return p, nil
}

// Snapshot returns a copy of the current policy document.
func (p *Policy) Snapshot() File {
	p.mu.RLock()
	defer p.mu.RUnlock()
	cp := p.f
	cp.Allowlist = append([]string(nil), p.f.Allowlist...)
	return cp
}

// Mode returns the active enforcement level.
func (p *Policy) Mode() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.f.Mode
}

// SetMode switches enforcement level at runtime.
func (p *Policy) SetMode(m string) bool {
	switch m {
	case ModeOff, ModeAllowlist, ModeFull:
	default:
		return false
	}
	p.mu.Lock()
	p.f.Mode = m
	p.mu.Unlock()
	return true
}

// TLSIntercept reports whether HTTPS should be terminated and inspected.
func (p *Policy) TLSIntercept() bool { return p.Mode() == ModeFull }

// DLPEnabled reports whether payload inspection runs.
func (p *Policy) DLPEnabled() bool { return p.Mode() == ModeFull }

// AllowlistEnforced reports whether destinations are restricted.
func (p *Policy) AllowlistEnforced() bool { return p.Mode() != ModeOff }

// StrictDNS reports whether DNS heuristics run on top of the allowlist.
func (p *Policy) StrictDNS() bool { return p.Mode() == ModeFull }

// HostAllowed matches a hostname against the allowlist.
//
// Patterns:
//
//	example.com    matches exactly that host
//	*.example.com  matches any subdomain AND the apex
//
// A bare IP address is refused unless allow_ip_literals is set: connecting by
// address is the simplest way to sidestep a name-based allowlist.
func (p *Policy) HostAllowed(host string) (bool, string) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false, "empty-host"
	}
	if ip := net.ParseIP(h); ip != nil {
		if !p.f.AllowIPLiterals {
			return false, "ip-literal-denied"
		}
		return true, "ip-literal-allowed"
	}
	for _, pat := range p.f.Allowlist {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if pat == "" {
			continue
		}
		if strings.HasPrefix(pat, "*.") {
			base := pat[2:]
			if h == base || strings.HasSuffix(h, "."+base) {
				return true, "allowlist:" + pat
			}
			continue
		}
		if h == pat {
			return true, "allowlist:" + pat
		}
	}
	return false, "allowlist-miss"
}

// MatchedPattern returns the allowlist entry a host matched, if any.
func (p *Policy) MatchedPattern(host string) string {
	ok, reason := p.HostAllowed(host)
	if !ok {
		return ""
	}
	return strings.TrimPrefix(reason, "allowlist:")
}
