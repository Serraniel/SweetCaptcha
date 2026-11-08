package server

// One named case per known bypass class. Several of these also exist next to the
// feature they protect; they are collected here so that a refactor which reopens
// any of them fails in one obvious place. See docs/THREAT_MODEL.md.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBypassForgedSealedValues(t *testing.T) {
	_, ts := newTest(t, strictSite)
	_, ch := postJSON(t, ts.URL+"/v1/challenge", map[string]string{"sitekey": strictKey, "hostname": "example.com"})
	nonces := solvePow(t, ch["pow"].(map[string]any))
	c := ch["c"].(string)
	token := strictToken(t, ts, "")

	cases := map[string]string{
		"garbage":            "not-a-sealed-value",
		"truncated":          c[:len(c)-4],
		"one byte changed":   c[:10] + string(rune(c[10]^1)) + c[11:],
		"token as challenge": token,
	}
	for name, forged := range cases {
		t.Run(name, func(t *testing.T) {
			if _, r := postJSON(t, ts.URL+"/v1/submit", map[string]any{"c": forged, "nonces": nonces}); r["status"] == "pass" {
				t.Fatalf("forged challenge passed: %v", r)
			}
		})
	}
	t.Run("challenge as token", func(t *testing.T) {
		if m := verifyForm(t, ts.URL+"/v1/siteverify", url.Values{"secret": {strictPass}, "response": {c}}); m["success"] != false {
			t.Fatalf("a challenge redeemed as a token: %v", m)
		}
	})
	t.Run("truncated token", func(t *testing.T) {
		if m := verifyForm(t, ts.URL+"/v1/siteverify", url.Values{"secret": {strictPass}, "response": {token[:len(token)-3]}}); m["success"] != false {
			t.Fatalf("truncated token accepted: %v", m)
		}
	})
}

// The proof-of-work parameters are sealed in the challenge, so a client cannot
// lower them. Work done for another challenge must not count either.
func TestBypassWorkFromAnotherChallenge(t *testing.T) {
	_, ts := newTest(t, strictSite)
	body := map[string]string{"sitekey": strictKey, "hostname": "example.com"}
	_, a := postJSON(t, ts.URL+"/v1/challenge", body)
	_, b := postJSON(t, ts.URL+"/v1/challenge", body)
	if _, r := postJSON(t, ts.URL+"/v1/submit", map[string]any{"c": b["c"], "nonces": solvePow(t, a["pow"].(map[string]any))}); r["status"] == "pass" {
		t.Fatalf("work for one challenge redeemed another: %v", r)
	}
	if _, r := postJSON(t, ts.URL+"/v1/submit", map[string]any{"c": b["c"], "nonces": []uint32{}}); r["status"] == "pass" {
		t.Fatalf("empty work accepted: %v", r)
	}
}

func TestBypassConcurrentDoubleSubmit(t *testing.T) {
	_, ts := newTest(t, strictSite)
	_, ch := postJSON(t, ts.URL+"/v1/challenge", map[string]string{"sitekey": strictKey, "hostname": "example.com"})
	body := map[string]any{"c": ch["c"], "nonces": solvePow(t, ch["pow"].(map[string]any))}
	var passes atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, r := postJSON(t, ts.URL+"/v1/submit", body); r["status"] == "pass" {
				passes.Add(1)
			}
		})
	}
	wg.Wait()
	if passes.Load() != 1 {
		t.Fatalf("one challenge produced %d tokens", passes.Load())
	}
}

func TestBypassConcurrentDoubleRedeem(t *testing.T) {
	_, ts := newTest(t, strictSite)
	token := strictToken(t, ts, "")
	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if m := verifyForm(t, ts.URL+"/v1/siteverify", url.Values{"secret": {strictPass}, "response": {token}}); m["success"] == true {
				ok.Add(1)
			}
		})
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("one token redeemed %d times", ok.Load())
	}
}

func TestBypassExpiryBoundaries(t *testing.T) {
	s, ts := newTest(t, strictSite)
	_, ch := postJSON(t, ts.URL+"/v1/challenge", map[string]string{"sitekey": strictKey, "hostname": "example.com"})
	nonces := solvePow(t, ch["pow"].(map[string]any))
	token := strictToken(t, ts, "")

	s.now = func() time.Time { return time.Now().Add(challengeTTL + time.Second) }
	if _, r := postJSON(t, ts.URL+"/v1/submit", map[string]any{"c": ch["c"], "nonces": nonces}); r["status"] == "pass" {
		t.Errorf("expired challenge accepted: %v", r)
	}
	s.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	if m := verifyForm(t, ts.URL+"/v1/siteverify", url.Values{"secret": {strictPass}, "response": {token}}); m["success"] != false {
		t.Errorf("expired token accepted: %v", m)
	}
}

func TestBypassTokenOutsideItsScope(t *testing.T) {
	s, ts := newTest(t, strictSite+`
  - name: other
    sitekey: sitekey_other
    secret: secret_other_secret_
    mode: strict
    hostnames: [example.org]
`)
	t.Run("other site's secret", func(t *testing.T) {
		token := strictToken(t, ts, "login")
		if m := verifyForm(t, ts.URL+"/v1/siteverify", url.Values{"secret": {"secret_other_secret_"}, "response": {token}}); m["success"] != false {
			t.Fatalf("token redeemed by another site: %v", m)
		}
	})
	t.Run("hostname removed after issue", func(t *testing.T) {
		token := strictToken(t, ts, "login")
		saved := s.sites[strictKey].Hostnames
		s.sites[strictKey].Hostnames = []string{"other.example"}
		defer func() { s.sites[strictKey].Hostnames = saved }()
		if m := verifyForm(t, ts.URL+"/v1/siteverify", url.Values{"secret": {strictPass}, "response": {token}}); m["success"] != false {
			t.Fatalf("token for a removed host accepted: %v", m)
		}
	})
	t.Run("action removed after issue", func(t *testing.T) {
		token := strictToken(t, ts, "login")
		saved := s.sites[strictKey].Actions
		s.sites[strictKey].Actions = []string{"signup"}
		defer func() { s.sites[strictKey].Actions = saved }()
		if m := verifyForm(t, ts.URL+"/v1/siteverify", url.Values{"secret": {strictPass}, "response": {token}}); m["success"] != false {
			t.Fatalf("token for a removed action accepted: %v", m)
		}
	})
}

func TestBypassSpoofedForwardedFor(t *testing.T) {
	_, ts := newTest(t, `
  - name: limited
    sitekey: sitekey_limited
    secret: secret_limited_secret
    mode: strict
    hostnames: [example.com]
    limits: {soft_per_minute: 1, hard_per_minute: 3}
    pow: {base: {algo: sha256, bits: 4, count: 8}}
`)
	// With no trusted proxy, a fresh X-Forwarded-For on every request must not
	// reset the per-address limit.
	limited := false
	for i := range 8 {
		resp, _ := postJSON(t, ts.URL+"/v1/challenge", map[string]string{"sitekey": "sitekey_limited", "hostname": "example.com"},
			"X-Forwarded-For", "203.0.113."+string(rune('1'+i)))
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
		}
	}
	if !limited {
		t.Fatal("spoofed X-Forwarded-For escaped the rate limit")
	}
}

func TestBypassDemoPagesEscapeInput(t *testing.T) {
	cfg := testConfig(t, strictSite)
	cfg.Server.Demo = true
	s, err := New(cfg, testStore(t))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	payload := `"><script>alert(1)</script>`
	for _, path := range []string{
		"/demo/?provider=" + url.QueryEscape(payload) + "&k=" + url.QueryEscape(payload) + "&theme=" + url.QueryEscape(payload),
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(raw), "<script>alert(1)") {
			t.Fatalf("unescaped input in %s", path)
		}
	}
	resp, err := http.PostForm(ts.URL+"/demo/verify", url.Values{"k": {strictKey}, "provider": {"native"}, "theme": {payload}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(raw), "<script>alert(1)") {
		t.Fatal("unescaped theme on the result page")
	}
}
