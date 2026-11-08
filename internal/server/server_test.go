package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Serraniel/SweetCaptcha/internal/config"
	"github.com/Serraniel/SweetCaptcha/internal/pow"
	"github.com/Serraniel/SweetCaptcha/internal/store"
)

const (
	testKey    = "0000000000000000000000000000000000000000000000000000000000000000"
	strictKey  = "sitekey_strict"
	strictPass = "secret_strict_secret"
)

func testConfig(t *testing.T, sites string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte("secret:\n  master_key: " + testKey + "\nsites:\n" + sites))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

const strictSite = `
  - name: strict
    sitekey: sitekey_strict
    secret: secret_strict_secret
    mode: strict
    hostnames: [example.com]
    actions: [login, ""]
    pow: {base: {algo: sha256, bits: 4, count: 2}}
`

// testStore returns Valkey when SC_TEST_VALKEY names one, so that atomicity is
// tested against the real store in CI, and the in-memory store otherwise.
func testStore(t *testing.T) store.Store {
	t.Helper()
	url := os.Getenv("SC_TEST_VALKEY")
	if url == "" {
		return store.NewMemory()
	}
	// Each test starts from an empty database. Use a database reserved for tests.
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	c := redis.NewClient(opts)
	if err := c.FlushDB(t.Context()).Err(); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	v, err := store.NewValkey(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

func newTest(t *testing.T, sites string) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(testConfig(t, sites), testStore(t))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func postJSON(t *testing.T, url string, body any, headers ...string) (*http.Response, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return resp, out
}

func solvePow(t *testing.T, view map[string]any) []uint32 {
	t.Helper()
	salt, err := base64.StdEncoding.DecodeString(view["salt"].(string))
	if err != nil {
		t.Fatal(err)
	}
	p := pow.Params{Algo: view["algo"].(string), Bits: int(view["bits"].(float64)), Count: int(view["count"].(float64)), Salt: salt}
	nonces, err := p.Solve()
	if err != nil {
		t.Fatal(err)
	}
	return nonces
}

func strictToken(t *testing.T, ts *httptest.Server, action string) string {
	t.Helper()
	_, ch := postJSON(t, ts.URL+"/v1/challenge", map[string]string{"sitekey": strictKey, "hostname": "example.com", "action": action})
	if ch["c"] == nil {
		t.Fatalf("no challenge: %v", ch)
	}
	_, res := postJSON(t, ts.URL+"/v1/submit", map[string]any{"c": ch["c"], "nonces": solvePow(t, ch["pow"].(map[string]any))})
	if res["status"] != "pass" {
		t.Fatalf("not passed: %v", res)
	}
	return res["token"].(string)
}

func verifyForm(t *testing.T, endpoint string, form url.Values) map[string]any {
	t.Helper()
	resp, err := http.PostForm(endpoint, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func codes(m map[string]any) []string {
	raw, _ := m["error-codes"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, v.(string))
	}
	return out
}

func TestStrictFlowAndCompatResponses(t *testing.T) {
	_, ts := newTest(t, strictSite)
	cases := []struct {
		path  string
		check func(map[string]any) string
	}{
		{"/v1/siteverify", func(m map[string]any) string {
			if m["mode"] != "strict" || m["score"] != 0.9 {
				return "native fields"
			}
			return ""
		}},
		{"/recaptcha/api/siteverify", func(m map[string]any) string {
			if m["score"] != 0.9 || m["action"] != "login" {
				return "recaptcha score should be 1.0=human"
			}
			return ""
		}},
		{"/siteverify", func(m map[string]any) string {
			if m["score"] != 0.1 {
				return "hcaptcha score must be inverted"
			}
			return ""
		}},
		{"/turnstile/v0/siteverify", func(m map[string]any) string {
			if _, ok := m["score"]; ok {
				return "turnstile has no top-level score"
			}
			if e, ok := m["error-codes"].([]any); !ok || len(e) != 0 {
				return "turnstile always has an error-codes array"
			}
			if m["action"] != "login" {
				return "turnstile action"
			}
			return ""
		}},
	}
	for _, tc := range cases {
		token := strictToken(t, ts, "login")
		m := verifyForm(t, ts.URL+tc.path, url.Values{"secret": {strictPass}, "response": {token}})
		if m["success"] != true {
			t.Fatalf("%s: %v", tc.path, m)
		}
		if m["hostname"] != "example.com" || m["challenge_ts"] == nil {
			t.Errorf("%s: missing common fields: %v", tc.path, m)
		}
		if msg := tc.check(m); msg != "" {
			t.Errorf("%s: %s: %v", tc.path, msg, m)
		}
	}
}

func TestTokenIsSingleUseWithProviderErrorCodes(t *testing.T) {
	_, ts := newTest(t, strictSite)
	for path, want := range map[string]string{
		"/recaptcha/api/siteverify": "timeout-or-duplicate",
		"/siteverify":               "already-seen-response",
		"/turnstile/v0/siteverify":  "timeout-or-duplicate",
	} {
		token := strictToken(t, ts, "")
		form := url.Values{"secret": {strictPass}, "response": {token}}
		if m := verifyForm(t, ts.URL+path, form); m["success"] != true {
			t.Fatalf("%s first: %v", path, m)
		}
		m := verifyForm(t, ts.URL+path, form)
		if m["success"] != false || codes(m)[0] != want {
			t.Errorf("%s replay: %v", path, m)
		}
	}
}

func TestVerifyInputErrors(t *testing.T) {
	_, ts := newTest(t, strictSite)
	path := ts.URL + "/recaptcha/api/siteverify"
	for name, tc := range map[string]struct {
		form url.Values
		want string
	}{
		"no secret":   {url.Values{"response": {"x"}}, "missing-input-secret"},
		"no response": {url.Values{"secret": {strictPass}}, "missing-input-response"},
		"bad secret":  {url.Values{"secret": {"nope"}, "response": {"x"}}, "invalid-input-secret"},
		"bad token":   {url.Values{"secret": {strictPass}, "response": {"not-a-token"}}, "invalid-input-response"},
		"long token":  {url.Values{"secret": {strictPass}, "response": {strings.Repeat("a", 3000)}}, "invalid-input-response"},
	} {
		if got := codes(verifyForm(t, path, tc.form)); len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestRecaptchaAcceptsGET(t *testing.T) {
	_, ts := newTest(t, strictSite)
	token := strictToken(t, ts, "")
	resp, err := http.Get(ts.URL + "/recaptcha/api/siteverify?" + url.Values{"secret": {strictPass}, "response": {token}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	if m["success"] != true {
		t.Errorf("%v", m)
	}
}

func TestTurnstileJSONAndIdempotency(t *testing.T) {
	_, ts := newTest(t, strictSite)
	token := strictToken(t, ts, "")
	body := map[string]string{"secret": strictPass, "response": token, "idempotency_key": "2f1a"}
	_, first := postJSON(t, ts.URL+"/turnstile/v0/siteverify", body)
	_, second := postJSON(t, ts.URL+"/turnstile/v0/siteverify", body)
	if first["success"] != true || second["success"] != true {
		t.Fatalf("retry with the same key should repeat success: %v, %v", first, second)
	}
	body["idempotency_key"] = "other"
	_, third := postJSON(t, ts.URL+"/turnstile/v0/siteverify", body)
	if third["success"] != false {
		t.Errorf("a new key must not redeem the token twice: %v", third)
	}
}

func TestChallengeValidation(t *testing.T) {
	_, ts := newTest(t, strictSite)
	path := ts.URL + "/v1/challenge"
	for name, tc := range map[string]struct {
		body map[string]string
		code int
	}{
		"unknown key":    {map[string]string{"sitekey": "nope_nope", "hostname": "example.com"}, 403},
		"wrong host":     {map[string]string{"sitekey": strictKey, "hostname": "evil.example"}, 403},
		"action denied":  {map[string]string{"sitekey": strictKey, "hostname": "example.com", "action": "other"}, 400},
		"action invalid": {map[string]string{"sitekey": strictKey, "hostname": "example.com", "action": "a b"}, 400},
	} {
		resp, _ := postJSON(t, path, tc.body)
		if resp.StatusCode != tc.code {
			t.Errorf("%s: status %d, want %d", name, resp.StatusCode, tc.code)
		}
	}
	// A plain form post is what a cross-origin page could send without preflight.
	resp, err := http.Post(path, "text/plain", strings.NewReader(`{"sitekey":"sitekey_strict","hostname":"example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("non-JSON content type: %d", resp.StatusCode)
	}
}

func TestChallengeReplayAndBadWork(t *testing.T) {
	_, ts := newTest(t, strictSite)
	_, ch := postJSON(t, ts.URL+"/v1/challenge", map[string]string{"sitekey": strictKey, "hostname": "example.com"})
	nonces := solvePow(t, ch["pow"].(map[string]any))
	// Solutions with the wrong length fail without consuming the challenge.
	if _, r := postJSON(t, ts.URL+"/v1/submit", map[string]any{"c": ch["c"], "nonces": nonces[:1]}); r["status"] != "retry" {
		t.Errorf("bad work: %v", r)
	}
	if _, r := postJSON(t, ts.URL+"/v1/submit", map[string]any{"c": ch["c"], "nonces": nonces}); r["status"] != "pass" {
		t.Errorf("valid work: %v", r)
	}
	if _, r := postJSON(t, ts.URL+"/v1/submit", map[string]any{"c": ch["c"], "nonces": nonces}); r["status"] != "retry" {
		t.Errorf("replayed challenge: %v", r)
	}
	if _, r := postJSON(t, ts.URL+"/v1/submit", map[string]any{"c": "garbage", "nonces": nonces}); r["status"] != "retry" {
		t.Errorf("forged challenge: %v", r)
	}
}

func TestTokenExpiry(t *testing.T) {
	s, ts := newTest(t, strictSite)
	token := strictToken(t, ts, "")
	s.now = func() time.Time { return time.Now().Add(time.Hour) }
	m := verifyForm(t, ts.URL+"/siteverify", url.Values{"secret": {strictPass}, "response": {token}})
	if codes(m)[0] != "expired-input-response" {
		t.Errorf("%v", m)
	}
}

func TestHostnameRecheckedAtVerify(t *testing.T) {
	s, ts := newTest(t, strictSite)
	token := strictToken(t, ts, "")
	s.sites[strictKey].Hostnames = []string{"other.example"}
	m := verifyForm(t, ts.URL+"/siteverify", url.Values{"secret": {strictPass}, "response": {token}})
	if m["success"] != false {
		t.Errorf("token for a removed host accepted: %v", m)
	}
}

func TestTokenFromAnotherSiteRejected(t *testing.T) {
	_, ts := newTest(t, strictSite+`
  - name: other
    sitekey: sitekey_other
    secret: secret_other_secret_
    mode: strict
    hostnames: [example.org]
`)
	token := strictToken(t, ts, "")
	m := verifyForm(t, ts.URL+"/siteverify", url.Values{"secret": {"secret_other_secret_"}, "response": {token}})
	if m["success"] != false || codes(m)[0] != "invalid-input-response" {
		t.Errorf("%v", m)
	}
}

func TestRateLimitAndAdaptiveDifficulty(t *testing.T) {
	_, ts := newTest(t, `
  - name: limited
    sitekey: sitekey_limited
    secret: secret_limited_secret
    mode: strict
    hostnames: [example.com]
    limits: {soft_per_minute: 1, hard_per_minute: 20}
    pow: {base: {algo: sha256, bits: 4, count: 8}}
`)
	body := map[string]string{"sitekey": "sitekey_limited", "hostname": "example.com"}
	work := func(m map[string]any) float64 {
		p := m["pow"].(map[string]any)
		return p["count"].(float64) * float64(uint64(1)<<uint(p["bits"].(float64)))
	}
	_, first := postJSON(t, ts.URL+"/v1/challenge", body)
	var last map[string]any
	for range 18 {
		_, last = postJSON(t, ts.URL+"/v1/challenge", body)
	}
	if ratio := work(last) / work(first); ratio < 3 || ratio > 16.5 {
		t.Errorf("work should rise on a log scale and stay capped: ratio %.2f", ratio)
	}
	resp, _ := postJSON(t, ts.URL+"/v1/challenge", body)
	resp2, _ := postJSON(t, ts.URL+"/v1/challenge", body)
	if resp.StatusCode != http.StatusOK || resp2.StatusCode != http.StatusTooManyRequests {
		t.Errorf("hard limit: %d then %d", resp.StatusCode, resp2.StatusCode)
	}
}

func TestStrictResponsesNameNoCollector(t *testing.T) {
	_, ts := newTest(t, strictSite)
	_, ch := postJSON(t, ts.URL+"/v1/challenge", map[string]string{"sitekey": strictKey, "hostname": "example.com"})
	if ch["collect"] != nil || ch["mode"] != "strict" {
		t.Errorf("strict challenge must not request collection: %v", ch)
	}
	resp, err := http.Get(ts.URL + "/v1/transparency?sitekey=" + strictKey)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tr map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatal(err)
	}
	if reads := tr["client_reads"].([]any); len(reads) != 0 {
		t.Errorf("strict site lists client reads: %v", reads)
	}
	if !strings.Contains(tr["statement"].(string), "does not detect") {
		t.Errorf("strict statement must state its limits: %v", tr["statement"])
	}
}

func TestClientAddrTrustsOnlyConfiguredProxies(t *testing.T) {
	cfg, err := config.Parse([]byte("secret:\n  master_key: " + testKey + "\nserver:\n  trusted_proxies: [10.0.0.0/8]\nsites:\n" + strictSite))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, store.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.1, 10.0.0.2")
	r.RemoteAddr = "10.0.0.1:1234"
	if got := s.clientAddr(r).String(); got != "198.51.100.1" {
		t.Errorf("behind proxy: %s", got)
	}
	r.RemoteAddr = "192.0.2.1:1234"
	if got := s.clientAddr(r).String(); got != "192.0.2.1" {
		t.Errorf("forged header believed: %s", got)
	}
}

func TestFrameHeaders(t *testing.T) {
	_, ts := newTest(t, strictSite)
	resp, err := http.Get(ts.URL + "/v1/frame?k=" + strictKey)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// Bundles may be unbuilt in unit tests, so only assert when the frame rendered.
	if resp.StatusCode == http.StatusOK {
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors https://example.com") {
			t.Errorf("csp: %s", csp)
		}
	}
	resp, err = http.Get(ts.URL + "/v1/frame?k=unknown_key")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unknown key status: %d", resp.StatusCode)
	}
}

func TestAdminRequiresToken(t *testing.T) {
	cfg, err := config.Parse([]byte("secret:\n  master_key: " + testKey + "\nadmin:\n  token: admintokenadmintoken\nsites:\n" + strictSite))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, store.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/admin/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/admin/api/stats", nil)
	req.Header.Set("Authorization", "Bearer admintokenadmintoken")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("with token: %d", resp.StatusCode)
	}
}

func TestInvalidSecretsAreThrottled(t *testing.T) {
	_, ts := newTest(t, strictSite)
	for range failureLimit {
		verifyForm(t, ts.URL+"/siteverify", url.Values{"secret": {"wrong-secret-value"}, "response": {"x"}})
	}
	resp, err := http.PostForm(ts.URL+"/siteverify", url.Values{"secret": {strictPass}, "response": {"x"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status %d after repeated invalid secrets", resp.StatusCode)
	}
}

func TestInvalidTokensAreNotThrottled(t *testing.T) {
	_, ts := newTest(t, strictSite)
	for range failureLimit + 5 {
		verifyForm(t, ts.URL+"/siteverify", url.Values{"secret": {strictPass}, "response": {"bogus"}})
	}
	token := strictToken(t, ts, "")
	if m := verifyForm(t, ts.URL+"/siteverify", url.Values{"secret": {strictPass}, "response": {token}}); m["success"] != true {
		t.Errorf("a site relaying bad tokens was locked out: %v", m)
	}
}

func TestHelpPage(t *testing.T) {
	_, ts := newTest(t, strictSite)
	get := func(q string, lang string) string {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/help?"+q, nil)
		if lang != "" {
			req.Header.Set("Accept-Language", lang)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return string(raw)
	}
	if body := get("k="+strictKey, "de-DE"); !strings.Contains(body, "Hilfe zur Überprüfung") {
		t.Error("German help not served")
	}
	if body := get("k="+strictKey, "ja"); !strings.Contains(body, "Verification help") {
		t.Error("untranslated language should fall back to English")
	}
	if body := get("k=%3Cscript%3E&l=%3Cscript%3E", ""); strings.Contains(body, "<script>") {
		t.Error("unescaped input on the help page")
	}
}

func TestFrameCarriesLegalLinksAndNoindex(t *testing.T) {
	_, ts := newTest(t, strings.Replace(strictSite, "    mode: strict\n", "    mode: strict\n    privacy_url: https://example.com/privacy?a=1&b=\"x\"\n", 1))
	resp, err := http.Get(ts.URL + "/v1/frame?k=" + strictKey)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skip("widget assets are not built")
	}
	if resp.Header.Get("X-Robots-Tag") != "noindex, nofollow" {
		t.Error("frame may be indexed")
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), `data-privacy="https://example.com/privacy?a=1&amp;b=&#34;x&#34;"`) {
		t.Errorf("privacy link missing or unescaped: %s", raw)
	}
}
