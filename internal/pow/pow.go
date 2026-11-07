// Package pow implements the proof-of-work puzzles solved in the widget.
//
// A challenge has Count independent sub-puzzles, each needing a nonce whose hash
// starts with Bits zero bits. Many small puzzles keep solve time predictable,
// which a single large puzzle would not: its time is geometrically distributed.
package pow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/bits"

	"golang.org/x/crypto/scrypt"
)

// Supported algorithms.
const (
	SHA256 = "sha256"
	Scrypt = "scrypt"
)

// Scrypt cost parameters. They are fixed so the client and server cannot
// disagree, and low enough for low-memory phones: about 1 MiB per evaluation.
const (
	scryptN = 1024
	scryptR = 8
	scryptP = 1
)

// MaxBits and MaxCount bound server configuration and verification work.
const (
	MaxBits  = 32
	MaxCount = 256
)

// Params describes one challenge.
type Params struct {
	Algo  string `json:"algo"`
	Bits  int    `json:"bits"`
	Count int    `json:"count"`
	Salt  []byte `json:"salt"`
}

// New returns Params with a fresh random salt.
func New(algo string, bitCount, count int) (Params, error) {
	if algo != SHA256 && algo != Scrypt {
		return Params{}, fmt.Errorf("unknown algorithm %q", algo)
	}
	if bitCount < 0 || bitCount > MaxBits || count < 1 || count > MaxCount {
		return Params{}, fmt.Errorf("difficulty out of range: bits=%d count=%d", bitCount, count)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return Params{}, err
	}
	return Params{Algo: algo, Bits: bitCount, Count: count, Salt: salt}, nil
}

// ExpectedHashes returns the mean number of evaluations a solver performs.
func (p Params) ExpectedHashes() float64 {
	return float64(p.Count) * float64(uint64(1)<<uint(p.Bits))
}

func (p Params) hash(index, nonce uint32) ([]byte, error) {
	buf := make([]byte, len(p.Salt)+8)
	copy(buf, p.Salt)
	binary.BigEndian.PutUint32(buf[len(p.Salt):], index)
	binary.BigEndian.PutUint32(buf[len(p.Salt)+4:], nonce)
	switch p.Algo {
	case SHA256:
		sum := sha256.Sum256(buf)
		return sum[:], nil
	case Scrypt:
		return scrypt.Key(buf, p.Salt, scryptN, scryptR, scryptP, 32)
	}
	return nil, fmt.Errorf("unknown algorithm %q", p.Algo)
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, v := range b {
		if v == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(v)
	}
	return n
}

// Verify reports whether nonces solve every sub-puzzle.
func (p Params) Verify(nonces []uint32) bool {
	if len(nonces) != p.Count {
		return false
	}
	for i, n := range nonces {
		h, err := p.hash(uint32(i), n)
		if err != nil || leadingZeroBits(h) < p.Bits {
			return false
		}
	}
	return true
}

// Solve finds a solution. The widget has its own TypeScript solver; this one
// exists for tests and for the attacker lab's native-solver bot.
func (p Params) Solve() ([]uint32, error) {
	out := make([]uint32, p.Count)
	for i := range out {
		for n := uint32(0); ; n++ {
			h, err := p.hash(uint32(i), n)
			if err != nil {
				return nil, err
			}
			if leadingZeroBits(h) >= p.Bits {
				out[i] = n
				break
			}
			if n == ^uint32(0) {
				return nil, fmt.Errorf("no solution for sub-puzzle %d", i)
			}
		}
	}
	return out, nil
}
