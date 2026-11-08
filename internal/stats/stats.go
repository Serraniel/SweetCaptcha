// Package stats keeps daily aggregate counters. It stores counts only, with no
// addresses, identifiers or per-visitor records.
package stats

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/Serraniel/SweetCaptcha/internal/store"
)

const retention = 35 * 24 * time.Hour

// HistBuckets is the resolution of the score histogram.
const HistBuckets = 20

// Counter names shared by all editions.
const (
	Issued     = "issued"
	Passed     = "pass"
	PowFailed  = "pow_failed"
	Replayed   = "replayed"
	RateLimit  = "rate_limited"
	Verified   = "verified"
	VerifyFail = "verify_failed"
	Interact   = "interact"
	Puzzle     = "puzzle"
	PuzzleOK   = "puzzle_ok"
	PuzzleFail = "puzzle_fail"
	Wait       = "wait"
	Deny       = "deny"
	ShadowDiff = "would_challenge"
	// BindSkippedFamily counts bind_client checks skipped because the token was
	// earned over another IP family than the one the site reported.
	BindSkippedFamily = "bind_skipped_family"
)

// Base lists counters every edition records.
var Base = []string{Issued, Passed, PowFailed, Replayed, RateLimit, Verified, VerifyFail, Interact, Puzzle, PuzzleOK, PuzzleFail, Wait, Deny, ShadowDiff, BindSkippedFamily}

// Recorder writes counters to a store. Failures are logged and never affect a
// verification decision.
type Recorder struct {
	s   store.Store
	now func() time.Time
	// Mirror, when set, also receives every event, for the metrics endpoint.
	Mirror func(site, name string)
}

// New returns a Recorder.
func New(s store.Store) *Recorder { return &Recorder{s: s, now: time.Now} }

func key(site, day, name string) string { return "st:" + site + ":" + day + ":" + name }

// Add increments a counter for today.
func (r *Recorder) Add(ctx context.Context, site, name string) {
	if r.Mirror != nil {
		r.Mirror(site, name)
	}
	if _, err := r.s.Incr(ctx, key(site, r.now().UTC().Format("20060102"), name), 1, retention); err != nil {
		slog.Warn("stats: increment failed", "error", err)
	}
}

// HistName returns the counter for a probability bucket, for sessions without
// hard evidence. Only those form the human baseline used for calibration.
func HistName(p float64) string {
	b := int(p * HistBuckets)
	if b >= HistBuckets {
		b = HistBuckets - 1
	}
	if b < 0 {
		b = 0
	}
	return fmt.Sprintf("hist_%02d", b)
}

// Summary is an aggregate over a period.
type Summary struct {
	Days     int              `json:"days"`
	Counters map[string]int64 `json:"counters"`
	// SuggestedStepUpAbove is the threshold that would challenge about
	// TargetChallengeRate of sessions without hard evidence. It is advisory and
	// is never applied automatically, since self-tuning could be poisoned.
	SuggestedStepUpAbove *float64 `json:"suggested_step_up_above,omitempty"`
	TargetChallengeRate  float64  `json:"target_challenge_rate"`
	BaselineSessions     int64    `json:"baseline_sessions"`
}

const minBaseline = 500

// Summarise aggregates names over the last days.
func (r *Recorder) Summarise(ctx context.Context, site string, names []string, days int, target float64) (Summary, error) {
	all := append([]string{}, names...)
	for b := range HistBuckets {
		all = append(all, fmt.Sprintf("hist_%02d", b))
	}
	out := Summary{Days: days, Counters: map[string]int64{}, TargetChallengeRate: target}
	var keys []string
	var labels []string
	today := r.now().UTC()
	for d := range days {
		day := today.AddDate(0, 0, -d).Format("20060102")
		for _, n := range all {
			keys = append(keys, key(site, day, n))
			labels = append(labels, n)
		}
	}
	vals, err := r.s.MGet(ctx, keys)
	if err != nil {
		return out, err
	}
	for i, v := range vals {
		if v == "" {
			continue
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			out.Counters[labels[i]] += n
		}
	}
	hist := make([]int64, HistBuckets)
	for b := range HistBuckets {
		name := fmt.Sprintf("hist_%02d", b)
		hist[b] = out.Counters[name]
		out.BaselineSessions += hist[b]
	}
	if s := Suggest(hist, target, minBaseline); s != nil {
		out.SuggestedStepUpAbove = s
	}
	return out, nil
}

// Suggest returns the threshold above which about target of the baseline falls,
// or nil when there are fewer than minimum sessions.
func Suggest(hist []int64, target float64, minimum int64) *float64 {
	var total int64
	for _, h := range hist {
		total += h
	}
	if total < minimum {
		return nil
	}
	var above int64
	for b := len(hist) - 1; b >= 0; b-- {
		if float64(above+hist[b])/float64(total) > target {
			v := float64(b+1) / float64(len(hist))
			return &v
		}
		above += hist[b]
	}
	v := 1.0 / float64(len(hist))
	return &v
}
