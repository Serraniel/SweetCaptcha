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
