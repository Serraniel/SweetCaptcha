//go:build !strictonly

package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Serraniel/SweetCaptcha/internal/config"
	"github.com/Serraniel/SweetCaptcha/internal/ipdata"
	"github.com/Serraniel/SweetCaptcha/internal/puzzle"
	"github.com/Serraniel/SweetCaptcha/internal/risk"
	"github.com/Serraniel/SweetCaptcha/internal/stats"
	"github.com/Serraniel/SweetCaptcha/internal/tlsfp"
)

// Escalation credits, in log-odds. Passing a step reduces suspicion, but a client
// that needed a puzzle still reports a lower score than one that passed silently.
const (
	creditStepUp = 0.5
	creditPuzzle = 2.5
	creditWait   = 1.0
)

const (
	evidenceTTL = 11 * time.Minute
	puzzleTTL   = 5 * time.Minute
	maxAttempts = 3
)

type standard struct {
	ip        *ipdata.DB
	capture   *tlsfp.Capture
	ja4Header string
}

func newStandard(cfg *config.Config) *standard {
	return &standard{ip: ipdata.Open(cfg.IPData.Dir), capture: &tlsfp.Capture{}, ja4Header: cfg.Server.JA4Header}
}

func (d *standard) start(ctx context.Context) { d.ip.Watch(ctx, 10*time.Minute) }

func (d *standard) routes(mux *http.ServeMux, s *Server) {
	mux.HandleFunc("POST /v1/answer", func(w http.ResponseWriter, r *http.Request) { d.answer(w, r, s) })
	mux.HandleFunc("POST /v1/wait", func(w http.ResponseWriter, r *http.Request) { d.wait(w, r, s) })
}

func (d *standard) wrapListener(srv *http.Server, _ *config.Config) {
	srv.TLSConfig = d.capture.Wrap(srv.TLSConfig)
	srv.ConnContext = d.capture.ConnContext
	srv.ConnState = d.capture.ConnState
}

func (d *standard) tlsFacts(r *http.Request, s *Server) *risk.TLSFacts {
	if f, ok := d.capture.FromContext(r.Context()); ok {
		return &risk.TLSFacts{GREASEKnown: true, HasGREASE: f.HasGREASE, HasH2: f.HasH2, HasTLS13: f.HasTLS13}
	}
	// A JA4 header is only believed from a trusted proxy. It has no GREASE data.
	if d.ja4Header != "" {
		if v := r.Header.Get(d.ja4Header); len(v) >= 10 && s.directPeerTrusted(r) {
			return &risk.TLSFacts{HasTLS13: strings.HasPrefix(v[1:], "13"), HasH2: v[8:10] == "h2"}
		}
	}
	return nil
}

// evidence is the only per-session state, and it expires with the session. It
// holds rule identifiers and a number, not the signals behind them.
type evidence struct {
	LogOdds    float64  `json:"l"`
	Hits       []string `json:"h"`
	Definitive bool     `json:"d"`
	Attempts   int      `json:"a"`
}

func saveEvidence(ctx context.Context, s *Server, id string, e evidence) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return s.store.Set(ctx, "ev:"+id, string(raw), evidenceTTL)
}

func loadEvidence(ctx context.Context, s *Server, id string) (evidence, bool) {
	var e evidence
	raw, ok, err := s.store.Get(ctx, "ev:"+id)
	if err != nil || !ok || json.Unmarshal([]byte(raw), &e) != nil {
		return e, false
	}
	return e, true
}

func parseSignals(raw json.RawMessage) *risk.Signals {
	if len(raw) == 0 {
		return nil
	}
	var sig risk.Signals
	if json.Unmarshal(raw, &sig) != nil {
		return nil
	}
	return &sig
}

func (d *standard) submit(w http.ResponseWriter, r *http.Request, s *Server, site *config.Site, c *claims, raw json.RawMessage) {
	ctx := r.Context()
	if c.Stage != stageBase {
		d.finishStage(w, r, s, site, c)
		return
	}
	in := d.buildInput(r, s, site, c, raw)
	res := risk.Evaluate(in)
	ev := evidence{LogOdds: res.LogOdds, Hits: res.Hits, Definitive: res.Definitive}
	for _, h := range res.Hits {
		s.stats.Add(ctx, site.Name, "rule_"+h)
	}
	if !res.Hard {
		s.stats.Add(ctx, site.Name, stats.HistName(risk.P(res.LogOdds)))
	}
	decision := decide(site, res)
	if site.Policy.Shadow {
		if decision != "pass" {
			s.stats.Add(ctx, site.Name, stats.ShadowDiff)
		}
		slog.Info("shadow decision", "site", site.Name, "decision", decision, "rules", res.Hits)
		s.issue(w, r, site, c, 1-risk.P(res.LogOdds), "shadow", res.Hits)
		return
	}
	switch decision {
	case "pass":
		s.issue(w, r, site, c, 1-risk.P(res.LogOdds), "silent", res.Hits)
	case "stepup":
		d.startStepUp(w, r, s, site, c, ev)
	case "puzzle":
		c.Session = randomID()
		d.startPuzzle(w, r, s, site, c, ev)
	default:
		s.stats.Add(ctx, site.Name, stats.Deny)
		writeJSON(w, http.StatusOK, submitResponse{Status: "deny", SupportURL: site.SupportURL})
	}
}

func (d *standard) buildInput(r *http.Request, s *Server, site *config.Site, c *claims, raw json.RawMessage) risk.Input {
	ctx := r.Context()
	in := risk.Input{
		Signals: parseSignals(raw), Nonce: c.Nonce, Header: r.Header, TLS: d.tlsFacts(r, s),
		Velocity: c.Velocity, SoftLimit: site.Limits.SoftPerMinute,
		ElapsedMS: s.now().UnixMilli() - c.Issued, ExpectedHash: c.Pow.ExpectedHashes(),
		BrowserScript: c.Pow.Algo == "sha256",
	}
	if addr := s.clientAddr(r); addr.IsValid() {
		in.Datacenter, in.Tor = d.ip.Datacenter(addr), d.ip.Tor(addr)
	}
	// Replay detection compares a sketch of the pointer path across challenges. It
	// is keyed per site and day and expires in ten minutes, so it links nothing
	// beyond that window.
	if in.Signals != nil && in.Signals.Beh != nil && in.Signals.Beh.Sketch != "" {
		key := "rp:" + site.SiteKey + ":" + s.ring.DailyPseudonym(in.Signals.Beh.Sketch, s.now())
		fresh, err := s.store.SetNX(ctx, key, "1", 10*time.Minute)
		in.Replay = err == nil && !fresh
	}
	return in
}

// decide maps a result to the response ladder. Behaviour alone can escalate but
// never deny: at realistic base rates it cannot be precise enough for that.
func decide(site *config.Site, res risk.Result) string {
	p := risk.P(res.LogOdds)
	switch {
	case res.Definitive && site.Policy.OnDefinitive == "deny":
		return "deny"
	case res.Definitive:
		return "puzzle"
	case p >= site.Policy.DenyAbove && res.Hard && res.RateOrNet:
		return "deny"
	case p >= site.Policy.PuzzleAbove:
		return "puzzle"
	case p >= site.Policy.StepUpAbove:
		return "stepup"
	}
	return "pass"
}

func (d *standard) startStepUp(w http.ResponseWriter, r *http.Request, s *Server, site *config.Site, c *claims, ev evidence) {
	ctx := r.Context()
	next := *c
	next.Session, next.Stage = randomID(), stageStepUp
	if err := saveEvidence(ctx, s, next.Session, ev); err != nil {
		slog.Error("save evidence", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, submitResponse{Status: "retry"})
		return
	}
	sealed, view, err := s.sealChallenge(&next, site.PoW.StepUp, challengeTTL)
	if err != nil {
		slog.Error("seal step-up", "error", err)
		writeJSON(w, http.StatusInternalServerError, submitResponse{Status: "retry"})
		return
	}
	s.stats.Add(ctx, site.Name, stats.StepUp)
	writeJSON(w, http.StatusOK, submitResponse{Status: "stepup", Challenge: sealed, Pow: view})
}

// puzzleRef is sealed and identifies a puzzle attempt.
type puzzleRef struct {
	ID      string `json:"i"`
	SiteKey string `json:"s"`
	Host    string `json:"h"`
	Action  string `json:"a,omitempty"`
	CData   string `json:"d,omitempty"`
	Session string `json:"e"`
	Expires int64  `json:"x"`
}

func (d *standard) startPuzzle(w http.ResponseWriter, r *http.Request, s *Server, site *config.Site, c *claims, ev evidence) {
	ctx := r.Context()
	if err := saveEvidence(ctx, s, c.Session, ev); err != nil {
		slog.Error("save evidence", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, submitResponse{Status: "retry"})
		return
	}
	family, err := puzzle.Pick(site.Puzzles)
	if err != nil {
		slog.Error("pick puzzle", "site", site.Name, "error", err)
		writeJSON(w, http.StatusInternalServerError, submitResponse{Status: "retry"})
		return
	}
	pub, ans, err := puzzle.Generate(family)
	if err != nil {
		slog.Error("generate puzzle", "site", site.Name, "error", err)
		writeJSON(w, http.StatusInternalServerError, submitResponse{Status: "retry"})
		return
	}
	ref := puzzleRef{ID: randomID(), SiteKey: site.SiteKey, Host: c.Host, Action: c.Action, CData: c.CData, Session: c.Session, Expires: s.now().Add(puzzleTTL).Unix()}
	encoded, err := puzzle.EncodeAnswer(ans)
	if err == nil {
		err = s.store.Set(ctx, "pz:"+ref.ID, encoded, puzzleTTL)
	}
	sealed := ""
	if err == nil {
		sealed, err = s.puzBox.Seal(ref)
	}
	pubRaw, jsonErr := json.Marshal(pub)
	if err != nil || jsonErr != nil {
		slog.Error("store puzzle", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, submitResponse{Status: "retry"})
		return
	}
	s.stats.Add(ctx, site.Name, stats.Puzzle)
	// A definitive automation marker does not get the wait option: compute alone
	// must not clear an explicit marker.
	writeJSON(w, http.StatusOK, submitResponse{
		Status: "puzzle", PuzzleRef: sealed, Puzzle: pubRaw,
		WaitOption: site.WaitAllowed() && !ev.Definitive, SupportURL: site.SupportURL,
	})
}

type answerRequest struct {
	Ref    string `json:"p"`
	Values []int  `json:"values"`
}

func (d *standard) answer(w http.ResponseWriter, r *http.Request, s *Server) {
	var req answerRequest
	if !readJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	var ref puzzleRef
	if s.puzBox.Open(req.Ref, &ref) != nil || s.now().Unix() > ref.Expires {
		writeJSON(w, http.StatusBadRequest, submitResponse{Status: "retry"})
		return
	}
	site, ok := s.sites[ref.SiteKey]
	if !ok {
		writeJSON(w, http.StatusBadRequest, submitResponse{Status: "retry"})
		return
	}
	stored, found, err := s.store.Get(ctx, "pz:"+ref.ID)
	if err != nil || !found {
		writeJSON(w, http.StatusBadRequest, submitResponse{Status: "retry"})
		return
	}
	// Each puzzle gets exactly one answer. Deleting first stops parallel guessing.
	if err := s.store.Del(ctx, "pz:"+ref.ID); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, submitResponse{Status: "retry"})
		return
	}
	first, err := s.store.SetNX(ctx, "pa:"+ref.ID, "1", puzzleTTL+time.Minute)
	if err != nil || !first {
		writeJSON(w, http.StatusBadRequest, submitResponse{Status: "retry"})
		return
	}
	ans, err := puzzle.DecodeAnswer(stored)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, submitResponse{Status: "retry"})
		return
	}
	ev, ok := loadEvidence(ctx, s, ref.Session)
	if !ok {
		writeJSON(w, http.StatusBadRequest, submitResponse{Status: "retry"})
		return
	}
	c := &claims{SiteKey: ref.SiteKey, Host: ref.Host, Action: ref.Action, CData: ref.CData, Session: ref.Session}
	if puzzle.Check(ans, req.Values) {
		s.stats.Add(ctx, site.Name, stats.PuzzleOK)
		s.issue(w, r, site, c, 1-risk.P(ev.LogOdds-creditPuzzle), "puzzle", ev.Hits)
		return
	}
	s.stats.Add(ctx, site.Name, stats.PuzzleFail)
	ev.Attempts++
	if ev.Attempts >= maxAttempts {
		// Without a definitive marker, the wait path stays open for people who
		// could not solve the puzzles.
		if site.WaitAllowed() && !ev.Definitive {
			if err := saveEvidence(ctx, s, ref.Session, ev); err == nil {
				d.issueWait(w, r, s, site, c)
				return
			}
		}
		s.stats.Add(ctx, site.Name, stats.Deny)
		writeJSON(w, http.StatusOK, submitResponse{Status: "deny", SupportURL: site.SupportURL})
		return
	}
	d.startPuzzle(w, r, s, site, c, ev)
}

type waitRequest struct {
	Ref string `json:"p"`
}

// wait exchanges a puzzle for a slow compute task with no cognitive content. It
// exists for people who cannot use the puzzles. It still costs an attacker time
// and CPU per action, and the resulting token reports a lower score.
func (d *standard) wait(w http.ResponseWriter, r *http.Request, s *Server) {
	var req waitRequest
	if !readJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	var ref puzzleRef
	if s.puzBox.Open(req.Ref, &ref) != nil || s.now().Unix() > ref.Expires {
		writeJSON(w, http.StatusBadRequest, submitResponse{Status: "retry"})
		return
	}
	site, ok := s.sites[ref.SiteKey]
	if !ok || !site.WaitAllowed() {
		writeJSON(w, http.StatusBadRequest, submitResponse{Status: "retry"})
		return
	}
	ev, ok := loadEvidence(ctx, s, ref.Session)
	if !ok || ev.Definitive {
		writeJSON(w, http.StatusOK, submitResponse{Status: "deny", SupportURL: site.SupportURL})
		return
	}
	// The puzzle cannot be answered after it has been traded in.
	first, err := s.store.SetNX(ctx, "pa:"+ref.ID, "1", puzzleTTL+time.Minute)
	if err != nil || !first {
		writeJSON(w, http.StatusBadRequest, submitResponse{Status: "retry"})
		return
	}
	if err := s.store.Del(ctx, "pz:"+ref.ID); err != nil {
		slog.Warn("delete puzzle", "error", err)
	}
	d.issueWait(w, r, s, site, &claims{SiteKey: ref.SiteKey, Host: ref.Host, Action: ref.Action, CData: ref.CData, Session: ref.Session})
}

func (d *standard) issueWait(w http.ResponseWriter, r *http.Request, s *Server, site *config.Site, c *claims) {
	next := *c
	next.Stage = stageWait
	sealed, view, err := s.sealChallenge(&next, site.PoW.Wait, waitTTL)
	if err != nil {
		slog.Error("seal wait", "error", err)
		writeJSON(w, http.StatusInternalServerError, submitResponse{Status: "retry"})
		return
	}
	s.stats.Add(r.Context(), site.Name, stats.Wait)
	writeJSON(w, http.StatusOK, submitResponse{Status: "stepup", Challenge: sealed, Pow: view})
}

func (d *standard) finishStage(w http.ResponseWriter, r *http.Request, s *Server, site *config.Site, c *claims) {
	ev, ok := loadEvidence(r.Context(), s, c.Session)
	if !ok {
		writeJSON(w, http.StatusBadRequest, submitResponse{Status: "retry"})
		return
	}
	credit, via := creditStepUp, "stepup"
	if c.Stage == stageWait {
		credit, via = creditWait, "wait"
	}
	s.issue(w, r, site, c, 1-risk.P(ev.LogOdds-credit), via, ev.Hits)
}

func (d *standard) register() ([]string, any) {
	type rule struct {
		ID    string  `json:"id"`
		Group string  `json:"group"`
		LLR   float64 `json:"llr"`
		Doc   string  `json:"doc"`
	}
	out := make([]rule, len(risk.Rules))
	for i, r := range risk.Rules {
		out[i] = rule{r.ID, r.Group, r.LLR, r.Doc}
	}
	return risk.ClientReads, out
}

func (d *standard) counterNames() []string {
	names := make([]string, len(risk.Rules))
	for i, r := range risk.Rules {
		names[i] = "rule_" + r.ID
	}
	return names
}
