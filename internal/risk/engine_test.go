//go:build !strictonly

package risk

import (
	"net/http"
	"slices"
	"testing"
)

const (
	chromeUA  = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
	firefoxUA = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
	safariUA  = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
)

func header(ua string) http.Header {
	h := http.Header{}
	h.Set("User-Agent", ua)
	h.Set("Accept-Language", "en")
	h.Set("Sec-Fetch-Site", "same-origin")
	return h
}

func human(ua, nonce string) *Signals {
	hashes := Hashes{UA: KeyedHash(nonce, ua), Platform: "p", Langs: "l", Cores: "c", TZ: "t"}
	worker, iframe := hashes, hashes
	s := &Signals{
		V: 1, Secure: true, Hash: hashes, Worker: &worker, Iframe: &iframe,
		Device: Device{Platform: "Linux x86_64", Langs: 2, Pointer: "fine", GPU: "intel", GPUAPI: "opengl"},
		Engine: Engine{Family: "v8"},
		UACH:   &UACH{ChromiumMajor: 150, Platform: "Linux"},
		Beh:    &Behaviour{Mode: "mouse", Moves: 60, Clicks: 1, Straightness: 0.9, SpeedCV: 0.8, DirChanges: 5},
	}
	return s
}

func TestHumanPassesSilently(t *testing.T) {
	r := Evaluate(Input{Signals: human(chromeUA, "n"), Nonce: "n", Header: header(chromeUA)})
	if P(r.LogOdds) > 0.2 || r.Definitive || r.Hard {
		t.Fatalf("human scored too high: p=%.2f hits=%v", P(r.LogOdds), r.Hits)
	}
}

func TestPrivacyBrowsersAreNotPenalised(t *testing.T) {
	// Canvas noise and Tor are never evidence: both are ordinary privacy choices.
	s := human(firefoxUA, "n")
	s.Engine.Family = "spidermonkey"
	s.UACH = nil
	s.Device.CanvasStable = false
	r := Evaluate(Input{Signals: s, Nonce: "n", Header: header(firefoxUA), Tor: true})
	if P(r.LogOdds) >= 0.5 {
		t.Fatalf("privacy browser escalated: p=%.2f hits=%v", P(r.LogOdds), r.Hits)
	}
	if !slices.Contains(r.Hits, "obs_tor") {
		t.Error("expected obs_tor to be recorded")
	}
}

func TestSafariHasNoSecFetchPenalty(t *testing.T) {
	s := human(safariUA, "n")
	s.Engine.Family, s.UACH, s.Device.Touch = "jsc", nil, 5
	s.Beh = nil
	h := header(safariUA)
	h.Del("Sec-Fetch-Site")
	r := Evaluate(Input{Signals: s, Nonce: "n", Header: h})
	if slices.Contains(r.Hits, "net_no_sec_fetch") {
		t.Errorf("unexpected hits: %v", r.Hits)
	}
}

func TestKeyboardActivationIsNotTeleport(t *testing.T) {
	s := human(chromeUA, "n")
	s.Beh = &Behaviour{Mode: "keyboard", Clicks: 2, KbClicks: 2}
	r := Evaluate(Input{Signals: s, Nonce: "n", Header: header(chromeUA)})
	if slices.Contains(r.Hits, "beh_click_no_approach") {
		t.Error("keyboard activation flagged as a teleporting click")
	}
}

func TestMissingSignalsEscalate(t *testing.T) {
	r := Evaluate(Input{Nonce: "n", Header: header(chromeUA)})
	if !r.Hard || P(r.LogOdds) < 0.8 {
		t.Fatalf("no-signal client not escalated: p=%.2f hits=%v", P(r.LogOdds), r.Hits)
	}
}

func TestDefinitiveAutomation(t *testing.T) {
	s := human(chromeUA, "n")
	s.Auto.Webdriver = true
	r := Evaluate(Input{Signals: s, Nonce: "n", Header: header(chromeUA)})
	if !r.Definitive {
		t.Fatal("webdriver not definitive")
	}
	if r := Evaluate(Input{Header: header("curl/8.0")}); !r.Definitive {
		t.Fatal("curl not definitive")
	}
}

func TestConsistencyRules(t *testing.T) {
	cases := map[string]func(*Signals){
		"worker_mismatch":      func(s *Signals) { s.Worker.Platform = "x" },
		"worker_soft_mismatch": func(s *Signals) { s.Worker.Cores = "x" },
		"iframe_mismatch":      func(s *Signals) { s.Iframe.UA = "x" },
		"engine_mismatch":      func(s *Signals) { s.Engine.Family = "spidermonkey" },
		"uach_mismatch":        func(s *Signals) { s.UACH.ChromiumMajor = 99 },
		"uach_missing":         func(s *Signals) { s.UACH = nil },
		"header_ua_mismatch":   func(s *Signals) { s.Hash.UA = "x" },
		"gpu_api_mismatch":     func(s *Signals) { s.Device.GPUAPI = "d3d" },
		"tamper_native":        func(s *Signals) { s.Tamper = []string{"native:query"} },
		"tamper_webdriver":     func(s *Signals) { s.Tamper = []string{"webdriver"} },
		"tamper_proxy":         func(s *Signals) { s.Tamper = []string{"proxy:query"} },
		"trap_hit":             func(s *Signals) { s.Trap = true },
	}
	for id, mutate := range cases {
		s := human(chromeUA, "n")
		mutate(s)
		r := Evaluate(Input{Signals: s, Nonce: "n", Header: header(chromeUA)})
		if !slices.Contains(r.Hits, id) || !r.Hard {
			t.Errorf("%s: not fired or not hard, hits=%v", id, r.Hits)
		}
	}
}

func TestBehaviourAloneNeverHard(t *testing.T) {
	s := human(chromeUA, "n")
	s.Beh = &Behaviour{Mode: "mouse", Moves: 30, Clicks: 3, NoApproach: 3, Keys: 20, KeyMedianMS: 2, Straightness: 1, SpeedCV: 0, Programmatic: 3}
	r := Evaluate(Input{Signals: s, Nonce: "n", Header: header(chromeUA), Replay: true})
	if r.Hard || r.Definitive {
		t.Fatalf("behaviour counted as hard evidence: %+v", r)
	}
	// The group cap limits the sum of correlated behaviour rules.
	if want := Prior + groupCap[GroupBehaviour]; r.LogOdds > want+1e-9 {
		t.Errorf("log-odds %.2f exceeds behaviour cap %.2f", r.LogOdds, want)
	}
}

func TestTLSRules(t *testing.T) {
	s := human(chromeUA, "n")
	r := Evaluate(Input{Signals: s, Nonce: "n", Header: header(chromeUA), TLS: &TLSFacts{GREASEKnown: true, HasH2: true, HasTLS13: true}})
	if !slices.Contains(r.Hits, "net_tls_no_grease") {
		t.Errorf("hits=%v", r.Hits)
	}
	// TLS facts are absent behind a proxy, and absence must not count.
	r = Evaluate(Input{Signals: s, Nonce: "n", Header: header(chromeUA)})
	if slices.ContainsFunc(r.Hits, func(h string) bool { return h == "net_tls_no_grease" || h == "net_tls_browser_mismatch" }) {
		t.Errorf("absent TLS facts counted: %v", r.Hits)
	}
}

func TestEveryRuleHasValidGroup(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules {
		if seen[r.ID] {
			t.Errorf("duplicate rule %s", r.ID)
		}
		seen[r.ID] = true
		if _, ok := groupCap[r.Group]; !ok {
			t.Errorf("rule %s has unknown group %s", r.ID, r.Group)
		}
		if r.Doc == "" {
			t.Errorf("rule %s has no documentation", r.ID)
		}
	}
}

func TestParseUA(t *testing.T) {
	if c := ParseUA(safariUA); c.Engine != "jsc" || !c.Mobile || c.Platform != "iOS" {
		t.Errorf("safari: %+v", c)
	}
	crios := "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0.0.0 Mobile/15E148 Safari/604.1"
	if c := ParseUA(crios); c.Engine != "jsc" {
		t.Errorf("Chrome on iOS must be WebKit: %+v", c)
	}
	if c := ParseUA(chromeUA); c.Engine != "v8" || c.ChromiumMajor != 150 || c.Mobile {
		t.Errorf("chrome: %+v", c)
	}
	if c := ParseUA("python-requests/2.32"); !c.NonBrowser {
		t.Errorf("python: %+v", c)
	}
	if got := SecCHUAMajor(`"Chromium";v="150", "Not.A/Brand";v="24"`); got != 150 {
		t.Errorf("SecCHUAMajor = %d", got)
	}
}
