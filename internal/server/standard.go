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
	creditInteract = 0.5
	creditPuzzle   = 2.5
	creditWait     = 1.0
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
	Hard       bool     `json:"k"`
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

func (d *standard) submit(w http.ResponseWriter, r *http.Request, s *Server, site *config.Site, c *claims, req submitRequest) {
	ctx := r.Context()
	switch c.Stage {
	case stageInteract:
		d.finishInteract(w, r, s, site, c, req.Click)
		return
	case stageWait:
		d.finishWait(w, r, s, site, c)
		return
	}
	in := d.buildInput(r, s, site, c, req.Signals)
	res := risk.Evaluate(in)
	forced := applyRules(site, ruleFacts{header: r.Header, datacenter: in.Datacenter, tor: in.Tor, action: c.Action, hostname: c.Host}, &res)
	ev := evidence{LogOdds: res.LogOdds, Hits: res.Hits, Definitive: res.Definitive, Hard: res.Hard}
	for _, h := range res.Hits {
		s.stats.Add(ctx, site.Name, "rule_"+h)
	}
	if !res.Hard {
		s.stats.Add(ctx, site.Name, stats.HistName(risk.P(res.LogOdds)))
	}
	decision := decide(site, res)
	if forced != "" {
		decision = forced
	}
	if site.Policy.Shadow {
		if decision != "pass" {
			s.stats.Add(ctx, site.Name, stats.ShadowDiff)
		}
		slog.Info("shadow decision", "site", site.Name, "decision", decision, "rules", res.Hits)
		s.issue(w, r, site, c, 1-risk.P(res.LogOdds), "shadow", res.Hits)
		return
	}
	if site.Policy.ScoreOnly {
		if decision != "pass" {
			s.stats.Add(ctx, site.Name, stats.ShadowDiff)
		}
		s.issue(w, r, site, c, 1-risk.P(res.LogOdds), "score", res.Hits)
		return
	}
	switch decision {
	case "pass":
		s.issue(w, r, site, c, 1-risk.P(res.LogOdds), "silent", res.Hits)
	case "interact":
		d.startInteract(w, r, s, site, c, ev)
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
// never deny: at realistic base rates it cannot be precise enough for that. A page
// with no input at all gets the checkbox, so that there is an interaction to judge.
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
	case p >= site.Policy.StepUpAbove, res.NoInteraction:
		return "interact"
	}
	return "pass"
}

// startInteract asks for the checkbox. A harder proof of work is solved in the
// background while it is shown, so the click is what the visitor notices.
func (d *standard) startInteract(w http.ResponseWriter, r *http.Request, s *Server, site *config.Site, c *claims, ev evidence) {
	ctx := r.Context()
	next := *c
	next.Session, next.Stage = randomID(), stageInteract
	if err := saveEvidence(ctx, s, next.Session, ev); err != nil {
		slog.Error("save evidence", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, submitResponse{Status: "retry"})
		return
	}
	sealed, view, err := s.sealChallenge(&next, site.PoW.StepUp, challengeTTL)
	if err != nil {
		slog.Error("seal interaction step", "error", err)
		writeJSON(w, http.StatusInternalServerError, submitResponse{Status: "retry"})
		return
	}
	s.stats.Add(ctx, site.Name, stats.Interact)
	writeJSON(w, http.StatusOK, submitResponse{Status: "interact", Challenge: sealed, Pow: view})
}

// puzzleRef is sealed and identifies a puzzle attempt.
type puzzleRef struct {
	ID      string `json:"i"`
	SiteKey string `json:"s"`
	Host    string `json:"h"`
	Action  string `json:"a,omitempty"`
	CData   string `json:"d,omitempty"`
	Session string `json:"e"`
	Issued  int64  `json:"ia"`
	Expires int64  `json:"x"`
}

// minAnswerTime is the least time a person needs to read and answer a task.
// Faster answers count as wrong, with no reason given.
const minAnswerTime = 1200 * time.Millisecond

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
	ref := puzzleRef{ID: randomID(), SiteKey: site.SiteKey, Host: c.Host, Action: c.Action, CData: c.CData, Session: c.Session, Issued: s.now().UnixMilli(), Expires: s.now().Add(puzzleTTL).Unix()}
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
	writeJSON(w, http.StatusOK, submitResponse{
		Status: "puzzle", PuzzleRef: sealed, Puzzle: pubRaw,
		WaitOption: waitOpen(site, ev), SupportURL: site.SupportURL,
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
	humanPaced := s.now().Sub(time.UnixMilli(ref.Issued)) >= minAnswerTime
	if !humanPaced {
		s.stats.Add(ctx, site.Name, "answer_too_fast")
	}
	if humanPaced && puzzle.Check(ans, req.Values) {
		s.stats.Add(ctx, site.Name, stats.PuzzleOK)
		s.issue(w, r, site, c, 1-risk.P(ev.LogOdds-creditPuzzle), "puzzle", ev.Hits)
		return
	}
	s.stats.Add(ctx, site.Name, stats.PuzzleFail)
	ev.Attempts++
	if ev.Attempts >= maxAttempts {
		if waitOpen(site, ev) && withinWaitQuota(r, s, site) {
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

// waitOpen decides who may leave a puzzle for the compute path. It exists for people
// who cannot do the puzzles. Their browsers are coherent, whereas contradictions and
// automation markers come from tampered or automated environments. Those clients
// must not be able to buy their way past the task with CPU time.
func waitOpen(site *config.Site, ev evidence) bool {
	return site.WaitAllowed() && !ev.Definitive && !ev.Hard
}

// withinWaitQuota limits the path per pseudonymised address, so that it cannot be
// run at volume from one place. The counter expires after an hour.
func withinWaitQuota(r *http.Request, s *Server, site *config.Site) bool {
	addr := s.clientAddr(r)
	if !addr.IsValid() {
		return true
	}
	key := "wt:" + site.SiteKey + ":" + s.ring.DailyPseudonym(addr.String(), s.now())
	n, err := s.store.Incr(r.Context(), key, 1, time.Hour)
	if err != nil {
		slog.Warn("wait quota counter unavailable", "error", err)
		return false
	}
	return n <= site.Limits.WaitPerHour
}

// wait exchanges a puzzle for a slow compute task. See waitOpen for who may use it.
// It costs time and CPU per action, and the resulting token reports a lower score.
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
	if !ok || !waitOpen(site, ev) || !withinWaitQuota(r, s, site) {
		s.stats.Add(ctx, site.Name, stats.Deny)
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

func (d *standard) finishInteract(w http.ResponseWriter, r *http.Request, s *Server, site *config.Site, c *claims, raw json.RawMessage) {
	ctx := r.Context()
	ev, ok := loadEvidence(ctx, s, c.Session)
	if !ok {
		writeJSON(w, http.StatusBadRequest, submitResponse{Status: "retry"})
		return
	}
	var click *risk.Click
	if len(raw) > 0 {
		var parsed risk.Click
		if json.Unmarshal(raw, &parsed) == nil {
			click = &parsed
		}
	}
	res := risk.EvaluateClick(click)
	for _, h := range res.Hits {
		s.stats.Add(ctx, site.Name, "rule_"+h)
	}
	ev.LogOdds += res.LogOdds - creditInteract
	ev.Hits = append(ev.Hits, res.Hits...)
	ev.Hard = ev.Hard || res.Hard
	if risk.P(ev.LogOdds) >= site.Policy.PuzzleAbove || res.Hard {
		d.startPuzzle(w, r, s, site, c, ev)
		return
	}
	s.issue(w, r, site, c, 1-risk.P(ev.LogOdds), "checkbox", ev.Hits)
}

func (d *standard) finishWait(w http.ResponseWriter, r *http.Request, s *Server, site *config.Site, c *claims) {
	ev, ok := loadEvidence(r.Context(), s, c.Session)
	if !ok {
		writeJSON(w, http.StatusBadRequest, submitResponse{Status: "retry"})
		return
	}
	s.issue(w, r, site, c, 1-risk.P(ev.LogOdds-creditWait), "wait", ev.Hits)
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

func (d *standard) counterNames(cfg *config.Config) []string {
	names := make([]string, 0, len(risk.Rules))
	for _, r := range risk.Rules {
		names = append(names, "rule_"+r.ID)
	}
	for _, site := range cfg.Sites {
		for _, r := range site.Rules {
			names = append(names, "rule_rule_custom:"+r.Name)
		}
	}
	return names
}
