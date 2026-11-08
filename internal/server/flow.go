package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/Serraniel/SweetCaptcha/internal/config"
	"github.com/Serraniel/SweetCaptcha/internal/pow"
	"github.com/Serraniel/SweetCaptcha/internal/stats"
)

const (
	challengeTTL = 2 * time.Minute
	waitTTL      = 10 * time.Minute
	// StrictScore is returned for strict-mode tokens. It carries no information
	// about humanity. It exists so integrations written for reCAPTCHA v3
	// thresholds keep working, and the response also names the mode.
	StrictScore = 0.9
)

var (
	actionRe = regexp.MustCompile(`^[A-Za-z0-9_/-]{0,64}$`)
	cdataRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{0,255}$`)
)

// Stages of a verification.
const (
	stageBase     = "base"
	stageInteract = "interact"
	stageWait     = "wait"
)

// claims is sealed into each challenge.
type claims struct {
	ID       string     `json:"i"`
	SiteKey  string     `json:"s"`
	Host     string     `json:"h"`
	Action   string     `json:"a,omitempty"`
	CData    string     `json:"d,omitempty"`
	Stage    string     `json:"t"`
	Session  string     `json:"e,omitempty"`
	Nonce    string     `json:"n,omitempty"`
	Velocity int64      `json:"v,omitempty"`
	Pow      pow.Params `json:"p"`
	Issued   int64      `json:"ia"`
	Expires  int64      `json:"x"`
}

// tokenClaims is sealed into pass tokens.
type tokenClaims struct {
	ID      string   `json:"i"`
	SiteKey string   `json:"s"`
	Host    string   `json:"h"`
	Action  string   `json:"a,omitempty"`
	CData   string   `json:"d,omitempty"`
	Score   float64  `json:"c"`
	Mode    string   `json:"m"`
	Via     string   `json:"w"`
	Reasons []string `json:"r,omitempty"`
	Issued  int64    `json:"ia"`
	Expires int64    `json:"x"`
	Test    string   `json:"z,omitempty"`
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing means the system cannot be trusted at all.
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type challengeRequest struct {
	SiteKey  string `json:"sitekey"`
	Action   string `json:"action"`
	Hostname string `json:"hostname"`
	CData    string `json:"cdata"`
}

type powView struct {
	Algo  string `json:"algo"`
	Bits  int    `json:"bits"`
	Count int    `json:"count"`
	Salt  string `json:"salt"`
}

func viewOf(p pow.Params) powView {
	return powView{p.Algo, p.Bits, p.Count, base64.StdEncoding.EncodeToString(p.Salt)}
}

type collectView struct {
	Nonce   string `json:"nonce"`
	Worker  string `json:"worker"`
	Frame   string `json:"frame"`
	FrameI  string `json:"frameSri"`
	Page    string `json:"page"`
	PageSRI string `json:"pageSri"`
}

type challengeResponse struct {
	Challenge string       `json:"c,omitempty"`
	Pow       *powView     `json:"pow,omitempty"`
	Mode      config.Mode  `json:"mode"`
	Collect   *collectView `json:"collect,omitempty"`
	Token     string       `json:"token,omitempty"`
	TTL       int          `json:"ttl,omitempty"`
	Status    string       `json:"status,omitempty"`
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req challengeRequest
	if !readJSON(w, r, &req) {
		return
	}
	site, ok := s.sites[req.SiteKey]
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid-sitekey"})
		return
	}
	if !site.HostAllowed(req.Hostname) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid-domain"})
		return
	}
	if !actionRe.MatchString(req.Action) || !site.ActionAllowed(req.Action) || !cdataRe.MatchString(req.CData) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid-action"})
		return
	}
	ctx := r.Context()
	if site.TestMode != "" {
		s.issueTestToken(w, r, site, req)
		return
	}
	velocity, limited := s.rateCheck(ctx, r, site)
	if limited {
		s.stats.Add(ctx, site.Name, stats.RateLimit)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate-limited"})
		return
	}
	level := site.PoW.Base
	if velocity > site.Limits.SoftPerMinute {
		// Rate-based difficulty is available in both modes. It uses only the
		// transient per-address counter.
		level.Bits = min(level.Bits+2, pow.MaxBits)
	}
	c := &claims{
		SiteKey: site.SiteKey, Host: req.Hostname, Action: req.Action, CData: req.CData,
		Stage: stageBase, Velocity: velocity,
	}
	var collect *collectView
	if site.Mode == config.ModeStandard {
		c.Nonce = randomID()
		collect = s.collectFor(c.Nonce)
	}
	sealed, view, err := s.sealChallenge(c, level, challengeTTL)
	if err != nil {
		slog.Error("issue challenge", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal-error"})
		return
	}
	s.stats.Add(ctx, site.Name, stats.Issued)
	writeJSON(w, http.StatusOK, challengeResponse{Challenge: sealed, Pow: view, Mode: site.Mode, Collect: collect})
}

func (s *Server) sealChallenge(c *claims, level config.PoWLevel, ttl time.Duration) (string, *powView, error) {
	p, err := pow.New(level.Algo, level.Bits, level.Count)
	if err != nil {
		return "", nil, err
	}
	now := s.now()
	c.ID, c.Pow, c.Issued, c.Expires = randomID(), p, now.UnixMilli(), now.Add(ttl).Unix()
	sealed, err := s.chalBox.Seal(c)
	if err != nil {
		return "", nil, err
	}
	v := viewOf(p)
	return sealed, &v, nil
}

func (s *Server) collectFor(nonce string) *collectView {
	frame, okF := s.signals["signals-frame.js"]
	page, okP := s.signals["signals-page.js"]
	if !okF || !okP {
		return &collectView{Nonce: nonce}
	}
	return &collectView{nonce, "/v1/assets/" + s.signals["signals-worker.js"].Path, "/v1/assets/" + frame.Path, frame.SRI, "/v1/assets/" + page.Path, page.SRI}
}

// rateCheck counts challenges per pseudonymised address in a one-minute window.
// The counter key rotates daily and expires in two minutes, and the address is
// never stored. Store failures do not block visitors, since proof of work and
// single-use tokens still apply.
func (s *Server) rateCheck(ctx context.Context, r *http.Request, site *config.Site) (int64, bool) {
	addr := s.clientAddr(r)
	if !addr.IsValid() {
		return 0, false
	}
	now := s.now()
	key := "rl:" + site.SiteKey + ":" + now.UTC().Format("200601021504") + ":" + s.ring.DailyPseudonym(addr.String(), now)
	n, err := s.store.Incr(ctx, key, 1, 2*time.Minute)
	if err != nil {
		slog.Warn("rate limit counter unavailable", "error", err)
		return 0, false
	}
	return n, n > site.Limits.HardPerMinute
}

type submitRequest struct {
	Challenge string          `json:"c"`
	Nonces    []uint32        `json:"nonces"`
	Signals   json.RawMessage `json:"signals"`
	Click     json.RawMessage `json:"click"`
}

// submitResponse tells the widget what to do next. A deny carries no reasons, so
// that responses do not work as a detection oracle for attackers.
type submitResponse struct {
	Status     string          `json:"status"`
	Token      string          `json:"token,omitempty"`
	TTL        int             `json:"ttl,omitempty"`
	Challenge  string          `json:"c,omitempty"`
	Pow        *powView        `json:"pow,omitempty"`
	Puzzle     json.RawMessage `json:"puzzle,omitempty"`
	PuzzleRef  string          `json:"p,omitempty"`
	WaitOption bool            `json:"wait,omitempty"`
	SupportURL string          `json:"support,omitempty"`
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	var req submitRequest
	if !readJSON(w, r, &req) {
		return
	}
	var c claims
	if err := s.chalBox.Open(req.Challenge, &c); err != nil {
		writeJSON(w, http.StatusBadRequest, submitResponse{Status: "retry"})
		return
	}
	site, ok := s.sites[c.SiteKey]
	if !ok || s.now().Unix() > c.Expires {
		writeJSON(w, http.StatusBadRequest, submitResponse{Status: "retry"})
		return
	}
	ctx := r.Context()
	// Verify the work before consuming, so that a wrong guess costs the attacker
	// the attempt without letting a stranger burn someone else's challenge.
	if !c.Pow.Verify(req.Nonces) {
		s.stats.Add(ctx, site.Name, stats.PowFailed)
		writeJSON(w, http.StatusBadRequest, submitResponse{Status: "retry"})
		return
	}
	fresh, err := s.store.SetNX(ctx, "used:"+c.ID, "1", time.Until(time.Unix(c.Expires, 0))+time.Minute)
	if err != nil {
		slog.Error("consume challenge", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, submitResponse{Status: "retry"})
		return
	}
	if !fresh {
		s.stats.Add(ctx, site.Name, stats.Replayed)
		writeJSON(w, http.StatusConflict, submitResponse{Status: "retry"})
		return
	}
	if site.Mode == config.ModeStrict {
		s.issue(w, r, site, &c, StrictScore, "pow", nil)
		return
	}
	s.std.submit(w, r, s, site, &c, req)
}

// issue mints a pass token. No evidence survives in it other than coarse reason
// codes, which only the holder of the site secret can read.
func (s *Server) issue(w http.ResponseWriter, r *http.Request, site *config.Site, c *claims, score float64, via string, reasons []string) {
	now := s.now()
	t := tokenClaims{
		ID: randomID(), SiteKey: site.SiteKey, Host: c.Host, Action: c.Action, CData: c.CData,
		Score: score, Mode: string(site.Mode), Via: via, Reasons: reasons,
		Issued: now.Unix(), Expires: now.Add(site.TokenTTL).Unix(),
	}
	sealed, err := s.tokBox.Seal(t)
	if err != nil {
		slog.Error("issue token", "error", err)
		writeJSON(w, http.StatusInternalServerError, submitResponse{Status: "retry"})
		return
	}
	s.stats.Add(r.Context(), site.Name, stats.Passed)
	writeJSON(w, http.StatusOK, submitResponse{Status: "pass", Token: sealed, TTL: int(site.TokenTTL.Seconds())})
}

func (s *Server) issueTestToken(w http.ResponseWriter, _ *http.Request, site *config.Site, req challengeRequest) {
	now := s.now()
	sealed, err := s.tokBox.Seal(tokenClaims{
		ID: randomID(), SiteKey: site.SiteKey, Host: req.Hostname, Action: req.Action, CData: req.CData,
		Score: 0.9, Mode: string(site.Mode), Via: "test", Test: site.TestMode,
		Issued: now.Unix(), Expires: now.Add(site.TokenTTL).Unix(),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal-error"})
		return
	}
	writeJSON(w, http.StatusOK, challengeResponse{Status: "pass", Mode: site.Mode, Token: sealed, TTL: int(site.TokenTTL.Seconds())})
}
