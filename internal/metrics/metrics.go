// Package metrics keeps process-local counters and histograms and writes them in
// the Prometheus text format. Labels are limited to low-cardinality, non-personal
// values: site, event, API flavour, result and stage. Never an address, network,
// user agent or token.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var solveBuckets = []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60}

type histogram struct {
	counts []uint64
	sum    float64
	n      uint64
}

// Registry is safe for concurrent use. The zero value is not usable; use New.
type Registry struct {
	mu       sync.Mutex
	counters map[string]map[string]float64
	hists    map[string]*histogram
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{counters: map[string]map[string]float64{}, hists: map[string]*histogram{}}
}

func labels(pairs ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(pairs); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(pairs[i] + "=" + strconv.Quote(pairs[i+1]))
	}
	return b.String()
}

// Event counts a named event for a site, mirroring the admin page counters.
func (r *Registry) Event(site, event string) {
	r.inc("sweetcaptcha_events_total", labels("site", site, "event", event))
}

// Verification counts a siteverify call by API flavour and result.
func (r *Registry) Verification(site, flavor, result string) {
	r.inc("sweetcaptcha_siteverify_total", labels("site", site, "flavor", flavor, "result", result))
}

// Solve records how long a proof-of-work stage took, measured on the server from
// issue to submission.
func (r *Registry) Solve(site, stage string, seconds float64) {
	key := labels("site", site, "stage", stage)
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.hists[key]
	if !ok {
		h = &histogram{counts: make([]uint64, len(solveBuckets))}
		r.hists[key] = h
	}
	for i, le := range solveBuckets {
		if seconds <= le {
			h.counts[i]++
		}
	}
	h.sum += seconds
	h.n++
}

func (r *Registry) inc(name, lbl string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.counters[name]
	if !ok {
		m = map[string]float64{}
		r.counters[name] = m
	}
	m[lbl]++
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var help = map[string]string{
	"sweetcaptcha_events_total":     "Verification events per site, as on the admin page.",
	"sweetcaptcha_siteverify_total": "Siteverify calls per site, API flavour and result.",
	"sweetcaptcha_solve_seconds":    "Time from challenge issue to submission, per proof-of-work stage.",
}

// WriteTo writes all metrics in the Prometheus text exposition format.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	for _, name := range sortedKeys(r.counters) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", name, help[name], name)
		for _, l := range sortedKeys(r.counters[name]) {
			fmt.Fprintf(&b, "%s{%s} %g\n", name, l, r.counters[name][l])
		}
	}
	if len(r.hists) > 0 {
		name := "sweetcaptcha_solve_seconds"
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s histogram\n", name, help[name], name)
		for _, l := range sortedKeys(r.hists) {
			h := r.hists[l]
			for i, le := range solveBuckets {
				fmt.Fprintf(&b, "%s_bucket{%s,le=%q} %d\n", name, l, strconv.FormatFloat(le, 'g', -1, 64), h.counts[i])
			}
			fmt.Fprintf(&b, "%s_bucket{%s,le=\"+Inf\"} %d\n", name, l, h.n)
			fmt.Fprintf(&b, "%s_sum{%s} %g\n%s_count{%s} %d\n", name, l, math.Round(h.sum*1000)/1000, name, l, h.n)
		}
	}
	n, err := io.WriteString(w, b.String())
	return int64(n), err
}
