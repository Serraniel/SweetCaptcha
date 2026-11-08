package pow

import "testing"

func TestSolveVerify(t *testing.T) {
	for _, tc := range []struct {
		algo        string
		bits, count int
	}{{SHA256, 8, 4}, {Scrypt, 2, 2}} {
		p, err := New(tc.algo, tc.bits, tc.count)
		if err != nil {
			t.Fatal(err)
		}
		nonces, err := p.Solve()
		if err != nil {
			t.Fatal(err)
		}
		if !p.Verify(nonces) {
			t.Errorf("%s: valid solution rejected", tc.algo)
		}
		if p.Verify(nonces[:1]) {
			t.Errorf("%s: short solution accepted", tc.algo)
		}
	}
}

func TestVerifyRejectsWrongSalt(t *testing.T) {
	p, _ := New(SHA256, 16, 2)
	q, _ := New(SHA256, 16, 2)
	nonces, err := p.Solve()
	if err != nil {
		t.Fatal(err)
	}
	if q.Verify(nonces) {
		t.Error("solution for another salt accepted")
	}
}

func TestNewBounds(t *testing.T) {
	if _, err := New("md5", 1, 1); err == nil {
		t.Error("unknown algorithm accepted")
	}
	if _, err := New(SHA256, MaxBits+1, 1); err == nil {
		t.Error("excess bits accepted")
	}
	if _, err := New(SHA256, 1, 0); err == nil {
		t.Error("zero count accepted")
	}
}

func TestLeadingZeroBits(t *testing.T) {
	for _, tc := range []struct {
		in   []byte
		want int
	}{{[]byte{0xff}, 0}, {[]byte{0x00, 0x80}, 8}, {[]byte{0x00, 0x01}, 15}, {[]byte{0, 0}, 16}} {
		if got := leadingZeroBits(tc.in); got != tc.want {
			t.Errorf("%x: got %d, want %d", tc.in, got, tc.want)
		}
	}
}

// Native single-thread solve times per default level. lab/bench.mjs compares them
// with the browser widget.
func BenchmarkSolveNative(b *testing.B) {
	for _, l := range []struct {
		name        string
		algo        string
		bits, count int
	}{
		{"base", SHA256, 14, 48},
		{"checkbox", SHA256, 16, 48},
		{"wait", SHA256, 18, 48},
		{"scrypt", Scrypt, 4, 16},
	} {
		b.Run(l.name, func(b *testing.B) {
			for b.Loop() {
				p, err := New(l.algo, l.bits, l.count)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := p.Solve(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkVerify measures what the server pays per submission.
func BenchmarkVerify(b *testing.B) {
	for _, l := range []struct {
		name        string
		algo        string
		bits, count int
	}{{"sha256-48", SHA256, 14, 48}, {"scrypt-16", Scrypt, 4, 16}} {
		p, _ := New(l.algo, l.bits, l.count)
		nonces, _ := p.Solve()
		b.Run(l.name, func(b *testing.B) {
			for b.Loop() {
				if !p.Verify(nonces) {
					b.Fatal("rejected")
				}
			}
		})
	}
}
