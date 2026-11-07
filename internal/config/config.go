// Package config loads and validates the YAML configuration file.
package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/Serraniel/SweetCaptcha/internal/edition"
	"github.com/Serraniel/SweetCaptcha/internal/pow"
)

// Mode selects what a site's widget does.
type Mode string

// Site modes.
const (
	// ModeStandard scores device, network and interaction signals on the server.
	ModeStandard Mode = "standard"
	// ModeStrict runs proof of work only. See docs/PRIVACY.md for its guarantees.
	ModeStrict Mode = "strict"
)

// Config is the root of the configuration file.
type Config struct {
	Server Server `yaml:"server"`
	Store  Store  `yaml:"store"`
	Secret Secret `yaml:"secret"`
	Admin  Admin  `yaml:"admin"`
	IPData IPData `yaml:"ipdata"`
	Sites  []Site `yaml:"sites"`
}

// Server configures listeners.
type Server struct {
	Listen         string   `yaml:"listen"`
	TrustedProxies []string `yaml:"trusted_proxies"`
	Demo           bool     `yaml:"demo"`
	TLS            TLS      `yaml:"tls"`
	// JA4Header names a header carrying a JA4 value from a trusted TLS terminator.
	JA4Header string `yaml:"ja4_header"`

	Proxies []netip.Prefix `yaml:"-"`
}

// TLS enables native TLS termination, which is what makes JA4 capture possible.
type TLS struct {
	Listen   string `yaml:"listen"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Store selects the state backend.
type Store struct {
	Type string `yaml:"type"` // valkey or memory
	URL  string `yaml:"url"`
}

// Secret holds the master key.
type Secret struct {
	MasterKey string `yaml:"master_key"`
	Decoded   []byte `yaml:"-"`
}

// Admin configures the read-only admin API.
type Admin struct {
	Token string `yaml:"token"`
}

// IPData points at local IP context files. Nothing is queried remotely.
type IPData struct {
	Dir string `yaml:"dir"`
}

// PoWLevel is one difficulty level.
type PoWLevel struct {
	Algo  string `yaml:"algo"`
	Bits  int    `yaml:"bits"`
	Count int    `yaml:"count"`
}

// PoW configures the difficulty ladder.
type PoW struct {
	Base   PoWLevel `yaml:"base"`
	StepUp PoWLevel `yaml:"step_up"`
	// Wait is the heavy puzzle offered as the no-cognitive-task alternative.
	Wait PoWLevel `yaml:"wait"`
}

// Policy sets score bands. All are probabilities that the client is automated.
type Policy struct {
	// StepUpAbove and PuzzleAbove delimit the escalation bands.
	StepUpAbove float64 `yaml:"step_up_above"`
	PuzzleAbove float64 `yaml:"puzzle_above"`
	// DenyAbove denies only when hard evidence is combined with rate or network
	// evidence, never on behaviour alone.
	DenyAbove float64 `yaml:"deny_above"`
	// OnDefinitive is "deny" or "puzzle", for explicit automation markers.
	OnDefinitive string `yaml:"on_definitive"`
	// Shadow records decisions without enforcing them.
	Shadow bool `yaml:"shadow"`
}

// Limits rate-limits challenge issuance per pseudonymised client address.
type Limits struct {
	SoftPerMinute int64 `yaml:"soft_per_minute"`
	HardPerMinute int64 `yaml:"hard_per_minute"`
}

// Site is one integration.
type Site struct {
	Name      string   `yaml:"name"`
	SiteKey   string   `yaml:"sitekey"`
	Secret    string   `yaml:"secret"`
	Mode      Mode     `yaml:"mode"`
	Hostnames []string `yaml:"hostnames"`
	// Actions restricts accepted action names; empty allows any valid name.
	Actions  []string      `yaml:"actions"`
	TokenTTL time.Duration `yaml:"token_ttl"`
	PoW      PoW           `yaml:"pow"`
	Policy   Policy        `yaml:"policy"`
	Limits   Limits        `yaml:"limits"`
	Puzzles  []string      `yaml:"puzzles"`
	// WaitFallback offers a slower compute path instead of a puzzle.
	WaitFallback *bool `yaml:"wait_fallback"`
	// SupportURL is shown to anyone denied, as a route for human review.
	SupportURL string `yaml:"support_url"`
	// TestMode is "", "pass" or "fail": skip everything, for integrator tests.
	TestMode string `yaml:"test_mode"`
}

// WaitAllowed reports whether the wait fallback is offered.
func (s *Site) WaitAllowed() bool { return s.WaitFallback == nil || *s.WaitFallback }

var (
	envRef  = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	keyName = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
)

// Load reads and validates path, expanding ${VAR} references.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // The operator chooses the config path.
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Parse validates a configuration document.
func Parse(raw []byte) (*Config, error) {
	expanded, err := expandEnv(string(raw))
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &c, c.finish()
}

// expandEnv replaces ${VAR} references. Comment lines are left alone, so that
// documentation in the file cannot break startup.
func expandEnv(doc string) (string, error) {
	var missing []string
	lines := strings.Split(doc, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		lines[i] = envRef.ReplaceAllStringFunc(line, func(m string) string {
			name := envRef.FindStringSubmatch(m)[1]
			v, ok := os.LookupEnv(name)
			if !ok {
				missing = append(missing, name)
			}
			return v
		})
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("unset environment variables: %s", strings.Join(missing, ", "))
	}
	return strings.Join(lines, "\n"), nil
}

func (c *Config) finish() error {
	if c.Server.Listen == "" {
		c.Server.Listen = ":8080"
	}
	if c.Store.Type == "" {
		c.Store.Type = "memory"
	}
	if c.Store.Type != "memory" && c.Store.Type != "valkey" {
		return fmt.Errorf("store.type must be memory or valkey, got %q", c.Store.Type)
	}
	if c.Store.Type == "valkey" && c.Store.URL == "" {
		return errors.New("store.url is required for valkey")
	}
	for _, s := range c.Server.TrustedProxies {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			addr, addrErr := netip.ParseAddr(s)
			if addrErr != nil {
				return fmt.Errorf("server.trusted_proxies: %w", err)
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		c.Server.Proxies = append(c.Server.Proxies, p)
	}
	key, err := decodeKey(c.Secret.MasterKey)
	if err != nil {
		return err
	}
	c.Secret.Decoded = key
	if len(c.Sites) == 0 {
		return errors.New("at least one site is required")
	}
	seenKey, seenSecret := map[string]bool{}, map[string]bool{}
	for i := range c.Sites {
		s := &c.Sites[i]
		if err := s.finish(); err != nil {
			return fmt.Errorf("site %q: %w", s.Name, err)
		}
		if seenKey[s.SiteKey] || seenSecret[s.Secret] {
			return fmt.Errorf("site %q: sitekey and secret must be unique", s.Name)
		}
		seenKey[s.SiteKey], seenSecret[s.Secret] = true, true
	}
	return nil
}

func decodeKey(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("secret.master_key is required; generate one with: sweetcaptcha keygen")
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) >= 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) >= 32 {
		return b, nil
	}
	return nil, errors.New("secret.master_key must be at least 32 bytes, hex or base64 encoded")
}

func (s *Site) finish() error {
	if s.Name == "" {
		return errors.New("name is required")
	}
	if !keyName.MatchString(s.SiteKey) {
		return errors.New("sitekey must be 8-128 characters of [A-Za-z0-9_-]")
	}
	if len(s.Secret) < 16 {
		return errors.New("secret must be at least 16 characters")
	}
	if s.Mode == "" {
		s.Mode = ModeStandard
		if edition.StrictOnly {
			s.Mode = ModeStrict
		}
	}
	if s.Mode != ModeStandard && s.Mode != ModeStrict {
		return fmt.Errorf("mode must be standard or strict, got %q", s.Mode)
	}
	if edition.StrictOnly && s.Mode != ModeStrict {
		return errors.New("this strict-only build does not contain the standard mode")
	}
	if len(s.Hostnames) == 0 {
		return errors.New("hostnames must list at least one host")
	}
	if s.TestMode != "" && s.TestMode != "pass" && s.TestMode != "fail" {
		return fmt.Errorf("test_mode must be pass or fail, got %q", s.TestMode)
	}
	if s.TokenTTL == 0 {
		s.TokenTTL = 5 * time.Minute
	}
	if s.TokenTTL < 30*time.Second || s.TokenTTL > 30*time.Minute {
		return errors.New("token_ttl must be between 30s and 30m")
	}
	s.PoW.Base = withDefault(s.PoW.Base, PoWLevel{pow.SHA256, 15, 10})
	s.PoW.StepUp = withDefault(s.PoW.StepUp, PoWLevel{pow.SHA256, 18, 16})
	s.PoW.Wait = withDefault(s.PoW.Wait, PoWLevel{pow.SHA256, 21, 24})
	for _, l := range []PoWLevel{s.PoW.Base, s.PoW.StepUp, s.PoW.Wait} {
		if _, err := pow.New(l.Algo, l.Bits, l.Count); err != nil {
			return fmt.Errorf("pow: %w", err)
		}
	}
	if s.Policy.StepUpAbove == 0 {
		s.Policy.StepUpAbove = 0.5
	}
	if s.Policy.PuzzleAbove == 0 {
		s.Policy.PuzzleAbove = 0.8
	}
	if s.Policy.DenyAbove == 0 {
		s.Policy.DenyAbove = 0.995
	}
	if !(s.Policy.StepUpAbove < s.Policy.PuzzleAbove && s.Policy.PuzzleAbove < s.Policy.DenyAbove && s.Policy.DenyAbove <= 1) {
		return errors.New("policy thresholds must satisfy step_up_above < puzzle_above < deny_above <= 1")
	}
	if s.Policy.OnDefinitive == "" {
		s.Policy.OnDefinitive = "deny"
	}
	if s.Policy.OnDefinitive != "deny" && s.Policy.OnDefinitive != "puzzle" {
		return errors.New("policy.on_definitive must be deny or puzzle")
	}
	if s.Limits.SoftPerMinute == 0 {
		s.Limits.SoftPerMinute = 30
	}
	if s.Limits.HardPerMinute == 0 {
		s.Limits.HardPerMinute = 300
	}
	if len(s.Puzzles) == 0 {
		s.Puzzles = []string{"line-trace", "gap-rings", "rotate-match"}
	}
	return nil
}

func withDefault(l, d PoWLevel) PoWLevel {
	if l.Algo == "" {
		l.Algo = d.Algo
	}
	if l.Bits == 0 {
		l.Bits = d.Bits
	}
	if l.Count == 0 {
		l.Count = d.Count
	}
	return l
}

// HostAllowed reports whether host matches the site's allow list. A leading
// "*." matches subdomains but not the apex.
func (s *Site) HostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range s.Hostnames {
		h = strings.ToLower(h)
		if suffix, ok := strings.CutPrefix(h, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
		} else if h == host {
			return true
		}
	}
	return false
}

// ActionAllowed reports whether action is acceptable.
func (s *Site) ActionAllowed(action string) bool {
	if len(s.Actions) == 0 {
		return true
	}
	for _, a := range s.Actions {
		if a == action {
			return true
		}
	}
	return false
}
