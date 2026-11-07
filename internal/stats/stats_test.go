package stats

import (
	"context"
	"testing"

	"github.com/Serraniel/SweetCaptcha/internal/store"
)

func TestAddAndSummarise(t *testing.T) {
	ctx := context.Background()
	r := New(store.NewMemory())
	r.Add(ctx, "s", Passed)
	r.Add(ctx, "s", Passed)
	r.Add(ctx, "other", Passed)
	r.Add(ctx, "s", HistName(0.12))
	sum, err := r.Summarise(ctx, "s", Base, 7, 0.02)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Counters[Passed] != 2 || sum.BaselineSessions != 1 {
		t.Errorf("%+v", sum)
	}
	if sum.SuggestedStepUpAbove != nil {
		t.Error("suggested a threshold from too little data")
	}
}

func TestHistNameBounds(t *testing.T) {
	if HistName(-1) != "hist_00" || HistName(1) != "hist_19" || HistName(0.5) != "hist_10" {
		t.Error("bucket bounds wrong")
	}
}

func TestSuggest(t *testing.T) {
	hist := make([]int64, 20)
	hist[2], hist[10], hist[15] = 900, 80, 20 // 2% of sessions are in bucket 15.
	got := Suggest(hist, 0.02, 500)
	if got == nil || *got != 0.55 {
		t.Fatalf("got %v", got)
	}
	if Suggest(hist, 0.02, 5000) != nil {
		t.Error("expected nil below the minimum")
	}
}
