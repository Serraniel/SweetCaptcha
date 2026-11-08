//go:build !strictonly

package server

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Serraniel/SweetCaptcha/internal/puzzle"
	"github.com/Serraniel/SweetCaptcha/internal/risk"
)

const stdUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"

const stdSite = `
  - name: std
    sitekey: sitekey_std
    secret: secret_std_secret_std
    mode: standard
    hostnames: [example.com]
    wait_fallback: true
    pow:
      base: {algo: sha256, bits: 4, count: 2}
      step_up: {algo: scrypt, bits: 1, count: 1}
      wait: {algo: sha256, bits: 5, count: 2}
      wait_min_duration: 1ms
`

var browserHeaders = []string{"User-Agent", stdUA, "Accept-Language", "en", "Sec-Fetch-Site", "same-origin"}

func goodSignals(nonce string) map[string]any {
	h := map[string]string{"ua": risk.KeyedHash(nonce, stdUA), "platform": "p", "langs": "l", "cores": "c", "tz": "t"}
	return map[string]any{
		"v": 1, "secure": true, "hash": h, "worker": h, "iframe": h,
		"engine": map[string]any{"family": "v8"},
		"uach":   map[string]any{"chromiumMajor": 150, "platform": "Linux"},
		"device": map[string]any{"platform": "Linux", "langs": 2, "gpu": "intel", "gpuApi": "opengl"},
		"beh":    map[string]any{"mode": "mouse", "moves": 50, "clicks": 1, "straightness": 0.8, "speedCv": 0.7, "dirChanges": 4},
	}
}

// softSite challenges every visitor, so tests can reach a puzzle with a coherent
// browser and no hard evidence.
const softSite = `
  - name: std
    sitekey: sitekey_std
    secret: secret_std_secret_std
    mode: standard
    hostnames: [example.com]
    policy: {step_up_above: 0.001, puzzle_above: 0.002}
    limits: {wait_per_hour: 2}
    pow:
      base: {algo: sha256, bits: 4, count: 2}
      wait: {algo: sha256, bits: 5, count: 2}
      wait_min_duration: 1ms
`

func softPuzzle(t *testing.T, ts *httptest.Server) map[string]any {
	t.Helper()
	ch, nonce := stdChallenge(t, ts)
	r := submit(t, ts, ch, goodSignals(nonce), browserHeaders...)
	if r["status"] != "puzzle" {
		t.Fatalf("expected a puzzle: %v", r)
	}
	return r
}

func stdChallenge(t *testing.T, ts *httptest.Server) (map[string]any, string) {
	t.Helper()
	_, ch := postJSON(t, ts.URL+"/v1/challenge", map[string]string{"sitekey": "sitekey_std", "hostname": "example.com"}, browserHeaders...)
	col, ok := ch["collect"].(map[string]any)
	if !ok {
		t.Fatalf("standard challenge without collect: %v", ch)
	}
	return ch, col["nonce"].(string)
}

func submit(t *testing.T, ts *httptest.Server, ch map[string]any, signals any, headers ...string) map[string]any {
	t.Helper()
	body := map[string]any{"c": ch["c"], "nonces": solvePow(t, ch["pow"].(map[string]any))}
	if signals != nil {
		body["signals"] = signals
	}
	for {
		_, r := postJSON(t, ts.URL+"/v1/submit", body, headers...)
		if r["status"] != "hold" || r["retry"].(float64) > 1000 {
			return r
		}
		time.Sleep(time.Duration(r["retry"].(float64)) * time.Millisecond)
	}
}

func TestCoherentBrowserPassesSilently(t *testing.T) {
	_, ts := newTest(t, stdSite)
	ch, nonce := stdChallenge(t, ts)
	r := submit(t, ts, ch, goodSignals(nonce), browserHeaders...)
	if r["status"] != "pass" {
		t.Fatalf("%v", r)
	}
	m := verifyForm(t, ts.URL+"/v1/siteverify", url.Values{"secret": {"secret_std_secret_std"}, "response": {r["token"].(string)}})
	if m["success"] != true || m["via"] != "silent" || m["score"].(float64) < 0.8 {
		t.Errorf("%v", m)
	}
}

func TestWebdriverIsDenied(t *testing.T) {
	_, ts := newTest(t, stdSite)
	ch, nonce := stdChallenge(t, ts)
	sig := goodSignals(nonce)
	sig["auto"] = map[string]any{"webdriver": true}
	r := submit(t, ts, ch, sig, browserHeaders...)
	if r["status"] != "deny" {
		t.Fatalf("%v", r)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "webdriver") {
		t.Errorf("deny response leaks a reason: %s", raw)
	}
}

func TestHTTPClientWithBrowserUAGetsPuzzleNotToken(t *testing.T) {
	_, ts := newTest(t, stdSite)
	ch, _ := stdChallenge(t, ts)
	r := submit(t, ts, ch, nil, browserHeaders...)
	if r["status"] != "puzzle" || r["token"] != nil {
		t.Fatalf("%v", r)
	}
}

func TestToolUserAgentIsDenied(t *testing.T) {
	_, ts := newTest(t, stdSite)
	ch, _ := stdChallenge(t, ts)
	if r := submit(t, ts, ch, nil, "User-Agent", "python-requests/2.32"); r["status"] != "deny" {
		t.Fatalf("%v", r)
	}
}

func submitClick(t *testing.T, ts *httptest.Server, r map[string]any, click any) map[string]any {
	t.Helper()
	body := map[string]any{"c": r["c"], "nonces": solvePow(t, r["pow"].(map[string]any))}
	if click != nil {
		body["click"] = click
	}
	_, out := postJSON(t, ts.URL+"/v1/submit", body, browserHeaders...)
	return out
}

func TestSoftEvidenceAsksForCheckbox(t *testing.T) {
	_, ts := newTest(t, stdSite)
	ch, nonce := stdChallenge(t, ts)
	sig := goodSignals(nonce)
	// Teleporting clicks alone reach the checkbox band but not a puzzle or a deny.
	sig["beh"] = map[string]any{"mode": "mouse", "clicks": 2, "noApproach": 2, "moves": 1}
	r := submit(t, ts, ch, sig, browserHeaders...)
	if r["status"] != "interact" {
		t.Fatalf("%v", r)
	}
	r = submitClick(t, ts, r, map[string]any{"pointer": "mouse", "approach": true, "trusted": true, "shownMs": 900})
	if r["status"] != "pass" {
		t.Fatalf("after a normal click: %v", r)
	}
	m := verifyForm(t, ts.URL+"/v1/siteverify", url.Values{"secret": {"secret_std_secret_std"}, "response": {r["token"].(string)}})
	if m["via"] != "checkbox" {
		t.Errorf("%v", m)
	}
}

func TestNoInteractionAsksForCheckbox(t *testing.T) {
	_, ts := newTest(t, stdSite)
	ch, nonce := stdChallenge(t, ts)
	sig := goodSignals(nonce)
	sig["beh"] = map[string]any{"mode": "none"}
	if r := submit(t, ts, ch, sig, browserHeaders...); r["status"] != "interact" {
		t.Fatalf("%v", r)
	}
}

func TestBadCheckboxClicksEscalate(t *testing.T) {
	for name, click := range map[string]any{
		"script click":  map[string]any{"pointer": "mouse", "approach": true, "trusted": false, "shownMs": 900},
		"no click data": nil,
		"teleport":      map[string]any{"pointer": "mouse", "approach": false, "trusted": true, "shownMs": 900},
	} {
		_, ts := newTest(t, stdSite)
		ch, nonce := stdChallenge(t, ts)
		sig := goodSignals(nonce)
		sig["beh"] = map[string]any{"mode": "mouse", "clicks": 2, "noApproach": 2, "moves": 1}
		r := submit(t, ts, ch, sig, browserHeaders...)
		if r = submitClick(t, ts, r, click); r["status"] != "puzzle" {
			t.Errorf("%s: %v", name, r)
		}
	}
}

func TestKeyboardCheckboxIsFine(t *testing.T) {
	_, ts := newTest(t, stdSite)
	ch, nonce := stdChallenge(t, ts)
	sig := goodSignals(nonce)
	sig["beh"] = map[string]any{"mode": "none"}
	r := submit(t, ts, ch, sig, browserHeaders...)
	if r = submitClick(t, ts, r, map[string]any{"pointer": "keyboard", "approach": false, "trusted": true, "shownMs": 1500}); r["status"] != "pass" {
		t.Fatalf("%v", r)
	}
}

func puzzleFor(t *testing.T, s *Server, ref string) []int {
	t.Helper()
	var pr puzzleRef
	if err := s.puzBox.Open(ref, &pr); err != nil {
		t.Fatal(err)
	}
	raw, ok, err := s.store.Get(t.Context(), "pz:"+pr.ID)
	if err != nil || !ok {
		t.Fatalf("no stored answer: %v", err)
	}
	a, err := puzzle.DecodeAnswer(raw)
	if err != nil {
		t.Fatal(err)
	}
	return a.Values
}

// wrongAnswer returns a value no puzzle family accepts.
func wrongAnswer([]int) []int { return []int{-99} }

func TestPuzzleFlow(t *testing.T) {
	s, ts := newTest(t, stdSite)
	ch, _ := stdChallenge(t, ts)
	r := submit(t, ts, ch, nil, browserHeaders...)
	if r["status"] != "puzzle" {
		t.Fatalf("%v", r)
	}
	raw, _ := json.Marshal(r["puzzle"])
	if strings.Contains(string(raw), "values") {
		t.Errorf("puzzle leaks its answer: %s", raw)
	}
	ref := r["p"].(string)

	// A wrong answer yields a new puzzle, and the old one cannot be retried.
	right := puzzleFor(t, s, ref)
	_, next := postJSON(t, ts.URL+"/v1/answer", map[string]any{"p": ref, "values": wrongAnswer(right)})
	if next["status"] != "puzzle" {
		t.Fatalf("after wrong answer: %v", next)
	}
	if _, again := postJSON(t, ts.URL+"/v1/answer", map[string]any{"p": ref, "values": right}); again["status"] != "retry" {
		t.Errorf("puzzle answered twice: %v", again)
	}

	ref = next["p"].(string)
	_, done := postJSON(t, ts.URL+"/v1/answer", map[string]any{"p": ref, "values": puzzleFor(t, s, ref)})
	if done["status"] != "pass" {
		t.Fatalf("right answer: %v", done)
	}
	m := verifyForm(t, ts.URL+"/v1/siteverify", url.Values{"secret": {"secret_std_secret_std"}, "response": {done["token"].(string)}})
	if m["via"] != "puzzle" {
		t.Errorf("%v", m)
	}
	reasons, _ := m["reasons"].([]any)
	if len(reasons) == 0 {
		t.Errorf("site owner should see reason codes: %v", m)
	}
}

func TestRepeatedPuzzleFailureFallsBackToWait(t *testing.T) {
	s, ts := newTest(t, softSite)
	r := softPuzzle(t, ts)
	for range maxAttempts {
		ref := r["p"].(string)
		_, r = postJSON(t, ts.URL+"/v1/answer", map[string]any{"p": ref, "values": wrongAnswer(puzzleFor(t, s, ref))})
	}
	if r["status"] != "stepup" {
		t.Fatalf("expected the wait path after repeated failures: %v", r)
	}
	r = submit(t, ts, r, nil, browserHeaders...)
	if r["status"] != "pass" {
		t.Fatalf("%v", r)
	}
	m := verifyForm(t, ts.URL+"/v1/siteverify", url.Values{"secret": {"secret_std_secret_std"}, "response": {r["token"].(string)}})
	if m["via"] != "wait" {
		t.Errorf("%v", m)
	}
}

func TestWaitPathConsumesPuzzle(t *testing.T) {
	s, ts := newTest(t, softSite)
	r := softPuzzle(t, ts)
	if r["wait"] != true {
		t.Fatalf("a coherent browser should be offered the wait path: %v", r)
	}
	ref := r["p"].(string)
	right := puzzleFor(t, s, ref)
	_, w := postJSON(t, ts.URL+"/v1/wait", map[string]any{"p": ref})
	if w["status"] != "stepup" {
		t.Fatalf("%v", w)
	}
	if _, a := postJSON(t, ts.URL+"/v1/answer", map[string]any{"p": ref, "values": right}); a["status"] != "retry" {
		t.Errorf("puzzle usable after trading it in: %v", a)
	}
}

// Clients with contradictions must solve the task. CPU time must not buy a way past it.
func TestHardEvidenceCannotUseWait(t *testing.T) {
	s, ts := newTest(t, stdSite)
	ch, _ := stdChallenge(t, ts)
	r := submit(t, ts, ch, nil, browserHeaders...)
	if r["status"] != "puzzle" || r["wait"] == true {
		t.Fatalf("%v", r)
	}
	ref := r["p"].(string)
	if _, w := postJSON(t, ts.URL+"/v1/wait", map[string]any{"p": ref}); w["status"] != "deny" {
		t.Errorf("forged request reached the wait path: %v", w)
	}
	// The same applies after repeated failures: the result is a denial.
	for range maxAttempts {
		ref = r["p"].(string)
		_, r = postJSON(t, ts.URL+"/v1/answer", map[string]any{"p": ref, "values": wrongAnswer(puzzleFor(t, s, ref))})
	}
	if r["status"] != "deny" {
		t.Errorf("expected a denial after repeated failures: %v", r)
	}
}

func TestWaitPathHasAQuota(t *testing.T) {
	_, ts := newTest(t, softSite)
	for i, want := range []string{"stepup", "stepup", "deny"} {
		r := softPuzzle(t, ts)
		if _, w := postJSON(t, ts.URL+"/v1/wait", map[string]any{"p": r["p"]}); w["status"] != want {
			t.Errorf("use %d: %v", i, w["status"])
		}
	}
}

func TestDefinitiveCannotUseWait(t *testing.T) {
	_, ts := newTest(t, strings.ReplaceAll(stdSite, "wait_fallback: true", "wait_fallback: true\n    policy: {on_definitive: puzzle}"))
	ch, nonce := stdChallenge(t, ts)
	sig := goodSignals(nonce)
	sig["auto"] = map[string]any{"webdriver": true}
	r := submit(t, ts, ch, sig, browserHeaders...)
	if r["status"] != "puzzle" || r["wait"] == true {
		t.Fatalf("%v", r)
	}
	_, w := postJSON(t, ts.URL+"/v1/wait", map[string]any{"p": r["p"]})
	if w["status"] != "deny" {
		t.Errorf("wait path open to a definitive marker: %v", w)
	}
}

func TestShadowModeIssuesButRecords(t *testing.T) {
	s, ts := newTest(t, strings.ReplaceAll(stdSite, "wait_fallback: true", "policy: {shadow: true}"))
	ch, _ := stdChallenge(t, ts)
	r := submit(t, ts, ch, nil, browserHeaders...)
	if r["status"] != "pass" {
		t.Fatalf("%v", r)
	}
	m := verifyForm(t, ts.URL+"/v1/siteverify", url.Values{"secret": {"secret_std_secret_std"}, "response": {r["token"].(string)}})
	if m["via"] != "shadow" || m["score"].(float64) > 0.2 {
		t.Errorf("%v", m)
	}
	sum, err := s.stats.Summarise(t.Context(), "std", []string{"would_challenge"}, 1, 0.02)
	if err != nil || sum.Counters["would_challenge"] != 1 {
		t.Errorf("%+v, %v", sum, err)
	}
}

func TestReplayedPointerPathIsFlagged(t *testing.T) {
	_, ts := newTest(t, stdSite)
	beh := map[string]any{"mode": "mouse", "moves": 50, "clicks": 1, "straightness": 0.8, "speedCv": 0.7, "dirChanges": 4, "sketch": "abcd"}
	run := func() map[string]any {
		ch, nonce := stdChallenge(t, ts)
		sig := goodSignals(nonce)
		sig["beh"] = beh
		return submit(t, ts, ch, sig, browserHeaders...)
	}
	if r := run(); r["status"] != "pass" {
		t.Fatalf("first use of a path: %v", r)
	}
	// The same path on a new challenge is evidence of replay and must escalate.
	if r := run(); r["status"] != "interact" {
		t.Fatalf("replayed path: %v", r)
	}
}

func TestTestModeSkipsWork(t *testing.T) {
	_, ts := newTest(t, `
  - name: test
    sitekey: sitekey_test
    secret: secret_test_secret_x
    mode: strict
    hostnames: [example.com]
    test_mode: pass
`)
	_, ch := postJSON(t, ts.URL+"/v1/challenge", map[string]string{"sitekey": "sitekey_test", "hostname": "example.com"})
	token := ch["token"].(string)
	for range 2 {
		m := verifyForm(t, ts.URL+"/v1/siteverify", url.Values{"secret": {"secret_test_secret_x"}, "response": {token}})
		if m["success"] != true || m["via"] != "test" {
			t.Errorf("%v", m)
		}
	}
}

func TestStandardTransparencyListsReads(t *testing.T) {
	s, _ := newTest(t, stdSite)
	reads, rules := s.std.register()
	if len(reads) == 0 || rules == nil {
		t.Error("register is empty")
	}
}

func TestScoreOnlyNeverAsksForInteraction(t *testing.T) {
	_, ts := newTest(t, strings.ReplaceAll(stdSite, "wait_fallback: true", "policy: {score_only: true}"))
	ch, _ := stdChallenge(t, ts)
	r := submit(t, ts, ch, nil, browserHeaders...)
	if r["status"] != "pass" {
		t.Fatalf("%v", r)
	}
	m := verifyForm(t, ts.URL+"/recaptcha/api/siteverify", url.Values{"secret": {"secret_std_secret_std"}, "response": {r["token"].(string)}})
	if m["success"] != true || m["score"].(float64) > 0.2 {
		t.Errorf("score-only token must carry the low score: %v", m)
	}
}

func TestWaitPathHoldsUntilMinimumDuration(t *testing.T) {
	s, ts := newTest(t, strings.ReplaceAll(softSite, "wait_min_duration: 1ms", "wait_min_duration: 4m"))
	r := softPuzzle(t, ts)
	_, w := postJSON(t, ts.URL+"/v1/wait", map[string]any{"p": r["p"]})
	held := submit(t, ts, w, nil, browserHeaders...)
	if held["status"] != "hold" || held["retry"].(float64) < 1000 {
		t.Fatalf("expected a hold: %v", held)
	}
	// After the minimum duration, the same challenge, still unconsumed, passes.
	s.now = func() time.Time { return time.Now().Add(5 * time.Minute) }
	_, done := postJSON(t, ts.URL+"/v1/submit", map[string]any{"c": w["c"], "nonces": solvePow(t, w["pow"].(map[string]any))}, browserHeaders...)
	if done["status"] != "pass" {
		t.Fatalf("after the hold: %v", done)
	}
}
