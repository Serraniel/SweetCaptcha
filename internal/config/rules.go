package config

import (
	"errors"
	"fmt"
	"regexp"
)

// MaxRuleAdjust bounds each rule's effect, and the sum of all rules on one
// request, in log-odds. It keeps a single mistaken rule from deciding everything.
const MaxRuleAdjust = 4.0

// Rule is an operator-defined adjustment, evaluated after the built-in engine.
type Rule struct {
	Name   string    `yaml:"name" json:"name"`
	Match  RuleMatch `yaml:"match" json:"match"`
	Adjust float64   `yaml:"adjust" json:"adjust,omitempty"`
	// Force sets the outcome for a match: pass, checkbox, task or deny.
	Force string `yaml:"force" json:"force,omitempty"`
}

// RuleMatch lists conditions that must all hold. Unset fields are ignored.
type RuleMatch struct {
	UserAgent string       `yaml:"user_agent" json:"user_agent,omitempty"`
	Header    *HeaderMatch `yaml:"header" json:"header,omitempty"`
	Address   string       `yaml:"address" json:"address,omitempty"` // datacenter or tor
	Action    *string      `yaml:"action" json:"action,omitempty"`
	Hostname  string       `yaml:"hostname" json:"hostname,omitempty"`

	UserAgentRe *regexp.Regexp `yaml:"-" json:"-"`
}

// HeaderMatch tests whether a request header is present.
type HeaderMatch struct {
	Name    string `yaml:"name" json:"name"`
	Present bool   `yaml:"present" json:"present"`
}

var ruleName = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)

func (s *Site) finishRules() error {
	if len(s.Rules) > 0 && s.Mode == ModeStrict {
		return errors.New("rules need the standard mode, which scores requests")
	}
	seen := map[string]bool{}
	for i := range s.Rules {
		r := &s.Rules[i]
		if !ruleName.MatchString(r.Name) || seen[r.Name] {
			return fmt.Errorf("rule %q: names must be unique and use a-z, 0-9, _ or -", r.Name)
		}
		seen[r.Name] = true
		m := &r.Match
		if m.UserAgent == "" && m.Header == nil && m.Address == "" && m.Action == nil && m.Hostname == "" {
			return fmt.Errorf("rule %q: match needs at least one condition", r.Name)
		}
		if m.UserAgent != "" {
			re, err := regexp.Compile(m.UserAgent)
			if err != nil {
				return fmt.Errorf("rule %q: user_agent: %w", r.Name, err)
			}
			m.UserAgentRe = re
		}
		if m.Header != nil && m.Header.Name == "" {
			return fmt.Errorf("rule %q: header needs a name", r.Name)
		}
		if m.Address != "" && m.Address != "datacenter" && m.Address != "tor" {
			return fmt.Errorf("rule %q: address must be datacenter or tor", r.Name)
		}
		switch r.Force {
		case "", "pass", "checkbox", "task", "deny":
		default:
			return fmt.Errorf("rule %q: force must be pass, checkbox, task or deny", r.Name)
		}
		if (r.Force == "") == (r.Adjust == 0) {
			return fmt.Errorf("rule %q: set exactly one of adjust or force", r.Name)
		}
		if r.Adjust < -MaxRuleAdjust || r.Adjust > MaxRuleAdjust {
			return fmt.Errorf("rule %q: adjust must be between %v and %v", r.Name, -MaxRuleAdjust, MaxRuleAdjust)
		}
	}
	return nil
}
