//go:build !strictonly

package server

import (
	"net/http"

	"github.com/Serraniel/SweetCaptcha/internal/config"
	"github.com/Serraniel/SweetCaptcha/internal/risk"
)

// ruleFacts are the request facts operator rules can match on.
type ruleFacts struct {
	header     http.Header
	datacenter bool
	tor        bool
	action     string
	hostname   string
}

func ruleMatches(m config.RuleMatch, f ruleFacts) bool {
	if m.UserAgentRe != nil && !m.UserAgentRe.MatchString(f.header.Get("User-Agent")) {
		return false
	}
	if m.Header != nil && (f.header.Get(m.Header.Name) != "") != m.Header.Present {
		return false
	}
	switch m.Address {
	case "datacenter":
		if !f.datacenter {
			return false
		}
	case "tor":
		if !f.tor {
			return false
		}
	}
	if m.Action != nil && *m.Action != f.action {
		return false
	}
	if m.Hostname != "" && m.Hostname != f.hostname {
		return false
	}
	return true
}

// applyRules adds the site's rule adjustments to a result, capped in total, and
// returns the first forced outcome, if any. Each matching rule is listed in the
// reasons as rule_custom:<name>.
func applyRules(site *config.Site, f ruleFacts, res *risk.Result) string {
	total, forced := 0.0, ""
	for _, r := range site.Rules {
		if !ruleMatches(r.Match, f) {
			continue
		}
		res.Hits = append(res.Hits, "rule_custom:"+r.Name)
		if r.Force != "" {
			if forced == "" {
				forced = r.Force
			}
			continue
		}
		total += r.Adjust
	}
	total = max(-config.MaxRuleAdjust, min(config.MaxRuleAdjust, total))
	res.LogOdds += total
	switch forced {
	case "checkbox":
		return "interact"
	case "task":
		return "puzzle"
	}
	return forced
}
