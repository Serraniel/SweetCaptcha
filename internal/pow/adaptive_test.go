package pow

import (
	"math"
	"testing"
)

func TestBoost(t *testing.T) {
	if b := Boost(0, 10, 100, 1); b != 0 {
		t.Errorf("no load: %v", b)
	}
	if b := Boost(8, 0, 0, 1); math.Abs(b-1) > 1e-9 {
		t.Errorf("8 over the allowance should double the work: %v", b)
	}
	if b := Boost(1_000_000, 1_000_000, 10, 1); b != MaxBoost {
		t.Errorf("not capped: %v", b)
	}
	if b := Boost(8, 0, 0, 0); b != 0 {
		t.Errorf("growth 0 must turn it off: %v", b)
	}
	if b := Boost(0, 100, 20, 1); math.Abs(b-1) > 1e-9 {
		t.Errorf("site at 5x its baseline should double the work: %v", b)
	}
}

func TestScaleKeepsWorkProportional(t *testing.T) {
	work := func(bits, count int) float64 { return float64(count) * math.Pow(2, float64(bits)) }
	base := work(14, 48)
	for _, boost := range []float64{0, 0.5, 1, 2.3, 4} {
		b, c := Scale(14, 48, boost)
		ratio := work(b, c) / base
		if want := math.Pow(2, boost); math.Abs(ratio-want)/want > 0.03 {
			t.Errorf("boost %v: ratio %.3f, want %.3f", boost, ratio, want)
		}
		if c > MaxCount || b > MaxBits {
			t.Errorf("boost %v: out of bounds %d x %d", boost, b, c)
		}
	}
}
