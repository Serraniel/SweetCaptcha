package metrics

import (
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	r := New()
	r.Event("shop", "pass")
	r.Event("shop", "pass")
	r.Verification("shop", "turnstile", "success")
	r.Solve("shop", "base", 0.3)
	r.Solve("shop", "base", 7)
	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`sweetcaptcha_events_total{site="shop",event="pass"} 2`,
		`sweetcaptcha_siteverify_total{site="shop",flavor="turnstile",result="success"} 1`,
		`sweetcaptcha_solve_seconds_bucket{site="shop",stage="base",le="0.5"} 1`,
		`sweetcaptcha_solve_seconds_bucket{site="shop",stage="base",le="10"} 2`,
		`sweetcaptcha_solve_seconds_bucket{site="shop",stage="base",le="+Inf"} 2`,
		`sweetcaptcha_solve_seconds_count{site="shop",stage="base"} 2`,
		"# TYPE sweetcaptcha_solve_seconds histogram",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestLabelsAreQuoted(t *testing.T) {
	r := New()
	r.Event(`we"ird`, "x")
	var b strings.Builder
	_, _ = r.WriteTo(&b)
	if !strings.Contains(b.String(), `site="we\"ird"`) {
		t.Errorf("label not escaped: %s", b.String())
	}
}
