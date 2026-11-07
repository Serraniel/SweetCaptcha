// Package keys derives purpose-separated keys from the master key.
package keys

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Ring derives independent keys from one master secret, so that a value sealed
// for one purpose can never be accepted for another (RFC 8725 §3.12).
type Ring struct{ master []byte }

// New returns a Ring. The master key must be at least 32 bytes.
func New(master []byte) (*Ring, error) {
	if len(master) < 32 {
		return nil, fmt.Errorf("master key must be at least 32 bytes, got %d", len(master))
	}
	return &Ring{master: master}, nil
}

// Derive returns a 32-byte key bound to purpose and scope.
func (r *Ring) Derive(purpose, scope string) []byte {
	k, err := hkdf.Key(sha256.New, r.master, nil, "sweetcaptcha/"+purpose+"/"+scope, 32)
	if err != nil {
		panic(err) // Only possible for an invalid length, which is constant here.
	}
	return k
}

// DailyPseudonym maps a value such as an IP address to a pseudonym that changes
// every UTC day, so stored counters cannot link a visitor across days.
func (r *Ring) DailyPseudonym(value string, now time.Time) string {
	m := hmac.New(sha256.New, r.Derive("pseudonym", now.UTC().Format("20060102")))
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil)[:12])
}
