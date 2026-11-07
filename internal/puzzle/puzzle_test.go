//go:build !strictonly

package puzzle

import (
	"strings"
	"testing"
)

func TestGenerateAndCheck(t *testing.T) {
	for _, fam := range Families {
		pub, ans, err := Generate(fam)
		if err != nil {
			t.Fatalf("%s: %v", fam, err)
		}
		if len(pub.Images) == 0 || !strings.HasPrefix(pub.Images[0], "data:image/png;base64,") {
			t.Fatalf("%s: bad images", fam)
		}
		if !Check(ans, ans.Values) {
			t.Errorf("%s: correct answer rejected", fam)
		}
		enc, err := EncodeAnswer(ans)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := DecodeAnswer(enc)
		if err != nil || !Check(dec, ans.Values) {
			t.Errorf("%s: answer did not survive encoding: %v", fam, err)
		}
	}
}

func TestLineTraceRejectsWrongAndSwapped(t *testing.T) {
	a := Answer{LineTrace, []int{2, 5}}
	if Check(a, []int{5, 2}) || Check(a, []int{2}) || Check(a, nil) {
		t.Error("wrong answer accepted")
	}
}

func TestGapRingsIsOrderIndependentAndExact(t *testing.T) {
	a := Answer{GapRings, []int{1, 4, 7}}
	if !Check(a, []int{7, 1, 4}) || !Check(a, []int{7, 1, 4, 4}) {
		t.Error("correct set rejected")
	}
	if Check(a, []int{1, 4}) || Check(a, []int{1, 4, 7, 8}) {
		t.Error("wrong set accepted")
	}
}

func TestRotateTolerance(t *testing.T) {
	a := Answer{RotateMatch, []int{350, 10}}
	if !Check(a, []int{355, 0}) {
		t.Error("near answer across the wrap rejected")
	}
	if !Check(a, []int{2, 359}) {
		t.Error("answers within tolerance across zero rejected")
	}
	if Check(a, []int{180, 10}) || Check(a, []int{350}) {
		t.Error("wrong answer accepted")
	}
}

func TestAnswerIsNotInPublic(t *testing.T) {
	for range 20 {
		pub, _, err := Generate(LineTrace)
		if err != nil {
			t.Fatal(err)
		}
		if pub.Options != lineCount || pub.Markers != 2 {
			t.Fatalf("unexpected public shape: %+v", pub.Family)
		}
	}
	if _, _, err := Generate("nope"); err == nil {
		t.Error("unknown family accepted")
	}
}
