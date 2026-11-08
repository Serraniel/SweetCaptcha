package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Serraniel/SweetCaptcha/internal/config"
	"github.com/Serraniel/SweetCaptcha/internal/stats"
)

type flavor int

const (
	flavorNative flavor = iota
	flavorRecaptcha
	flavorHCaptcha
	flavorTurnstile
)

type verifyError string

const (
	errMissingSecret   verifyError = "missing-input-secret"
	errInvalidSecret   verifyError = "invalid-input-secret"
	errMissingResponse verifyError = "missing-input-response"
	errInvalidResponse verifyError = "invalid-input-response"
	errExpired         verifyError = "expired"
	errDuplicate       verifyError = "duplicate"
	errBadRequest      verifyError = "bad-request"
	errInternal        verifyError = "internal-error"
	errSiteMismatch    verifyError = "sitekey-secret-mismatch"
)

const maxTokenLen = 2048

type verifyParams struct {
	Secret      string `json:"secret"`
	Response    string `json:"response"`
	RemoteIP    string `json:"remoteip"`
	SiteKey     string `json:"sitekey"`
	Idempotency string `json:"idempotency_key"`
}

func parseVerify(r *http.Request) (verifyParams, bool) {
	var p verifyParams
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return p, json.NewDecoder(r.Body).Decode(&p) == nil
	}
	if err := r.ParseForm(); err != nil {
		return p, false
	}
	p.Secret, p.Response = r.Form.Get("secret"), r.Form.Get("response")
	p.RemoteIP, p.SiteKey = r.Form.Get("remoteip"), r.Form.Get("sitekey")
	p.Idempotency = r.Form.Get("idempotency_key")
	return p, true
}

// lookupSecret compares in constant time across all sites, so timing reveals
// neither which secret matched nor how much of it did.
func (s *Server) lookupSecret(secret string) *config.Site {
	sum := sha256.Sum256([]byte(secret))
	var found *config.Site
	for candidate, site := range s.secrets {
		other := sha256.Sum256([]byte(candidate))
		if subtle.ConstantTimeCompare(sum[:], other[:]) == 1 {
			found = site
		}
	}
	return found
}

type verifyOutcome struct {
	err   verifyError
	token tokenClaims
}

// verify enforces, regardless of API flavour: the secret owns the token, the
// host and action are still allowed for the site, the token is unexpired, and it
// has not been redeemed. Hosted providers leave host and action checks to the
// integrator, and many skip them.
func (s *Server) verify(ctx context.Context, p verifyParams) verifyOutcome {
	if p.Secret == "" {
		return verifyOutcome{err: errMissingSecret}
	}
	if p.Response == "" {
		return verifyOutcome{err: errMissingResponse}
	}
	site := s.lookupSecret(p.Secret)
	if site == nil {
		return verifyOutcome{err: errInvalidSecret}
	}
	if len(p.Response) > maxTokenLen {
		return verifyOutcome{err: errInvalidResponse}
	}
	var t tokenClaims
	if err := s.tokBox.Open(p.Response, &t); err != nil {
		return verifyOutcome{err: errInvalidResponse}
	}
	if t.SiteKey != site.SiteKey {
		return verifyOutcome{err: errInvalidResponse}
	}
	if p.SiteKey != "" && p.SiteKey != site.SiteKey {
		return verifyOutcome{err: errSiteMismatch}
	}
	if !site.HostAllowed(t.Host) || !site.ActionAllowed(t.Action) {
		return verifyOutcome{err: errInvalidResponse}
	}
	// With bind_client, a token only redeems for the network that earned it. The
	// check needs remoteip; without it, sites get the unbound behaviour.
	if site.Policy.BindClient && t.Net != "" && p.RemoteIP != "" {
		addr, err := netip.ParseAddr(strings.TrimSpace(p.RemoteIP))
		if err != nil || s.networkPseudonym(addr.Unmap()) != t.Net {
			return verifyOutcome{err: errInvalidResponse}
		}
	}
	if t.Test == "fail" {
		return verifyOutcome{err: errInvalidResponse}
	}
	remaining := time.Until(time.Unix(t.Expires, 0))
	if s.now().Unix() > t.Expires {
		return verifyOutcome{err: errExpired}
	}
	if t.Test == "pass" {
		return verifyOutcome{token: t}
	}
	fresh, err := s.store.SetNX(ctx, "red:"+t.ID, "1", remaining+time.Minute)
	if err != nil {
		// Fail closed: without the redemption store, replay cannot be excluded.
		slog.Error("redeem token", "error", err)
		return verifyOutcome{err: errInternal}
	}
	if !fresh {
		return verifyOutcome{err: errDuplicate}
	}
	return verifyOutcome{token: t}
}

func (s *Server) siteverify(f flavor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// Only invalid secrets are throttled. Invalid tokens are normal: a site's
		// backend relays whatever bots send, and must never be locked out for it.
		if s.throttled(r, "secret") {
			writeJSON(w, http.StatusTooManyRequests, format(f, verifyOutcome{err: errBadRequest}))
			return
		}
		p, ok := parseVerify(r)
		if !ok {
			writeJSON(w, http.StatusOK, format(f, verifyOutcome{err: errBadRequest}))
			return
		}
		// A retried call with the same idempotency key gets the first answer
		// rather than a spurious duplicate error.
		var idemKey string
		if f == flavorTurnstile && p.Idempotency != "" && len(p.Idempotency) <= 64 {
			idemSum := sha256.Sum256([]byte(p.Secret + "\x00" + p.Response + "\x00" + p.Idempotency))
			idemKey = "idem:" + string(hexEncode(idemSum[:16]))
			if cached, found, err := s.store.Get(ctx, idemKey); err == nil && found {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				_, _ = w.Write([]byte(cached))
				return
			}
		}
		out := s.verify(ctx, p)
		if out.err == errInvalidSecret {
			s.noteFailure(r, "secret")
		}
		if site := s.lookupSecret(p.Secret); site != nil {
			if out.err == "" {
				s.stats.Add(ctx, site.Name, stats.Verified)
			} else {
				s.stats.Add(ctx, site.Name, stats.VerifyFail)
			}
		}
		body := format(f, out)
		if idemKey != "" {
			if raw, err := json.Marshal(body); err == nil {
				if err := s.store.Set(ctx, idemKey, string(raw), 5*time.Minute); err != nil {
					slog.Warn("store idempotent result", "error", err)
				}
			}
		}
		writeJSON(w, http.StatusOK, body)
	}
}

func hexEncode(b []byte) []byte {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i], out[2*i+1] = digits[v>>4], digits[v&15]
	}
	return out
}

func errorCode(f flavor, e verifyError) string {
	switch e {
	case errExpired:
		if f == flavorHCaptcha {
			return "expired-input-response"
		}
		return "timeout-or-duplicate"
	case errDuplicate:
		if f == flavorHCaptcha {
			return "already-seen-response"
		}
		return "timeout-or-duplicate"
	case errSiteMismatch:
		if f != flavorHCaptcha {
			return string(errInvalidResponse)
		}
	case errInternal:
		if f == flavorRecaptcha || f == flavorHCaptcha {
			return string(errBadRequest)
		}
	}
	return string(e)
}

// extension is added under its own key, so strict parsers can ignore it. Its
// mode field states that a strict-mode score carries no humanity information.
type extension struct {
	Mode    string   `json:"mode"`
	Via     string   `json:"via"`
	Score   float64  `json:"score"`
	Reasons []string `json:"reasons"`
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

func format(f flavor, o verifyOutcome) map[string]any {
	out := map[string]any{"success": o.err == ""}
	if o.err != "" {
		code := errorCode(f, o.err)
		out["error-codes"] = []string{code}
		if f == flavorTurnstile {
			out["messages"] = []string{}
		}
		return out
	}
	t := o.token
	issued := time.Unix(t.Issued, 0).UTC()
	out["challenge_ts"] = issued.Format(time.RFC3339)
	out["hostname"] = t.Host
	ext := extension{Mode: t.Mode, Via: t.Via, Score: round2(t.Score), Reasons: t.Reasons}
	if ext.Reasons == nil {
		ext.Reasons = []string{}
	}
	switch f {
	case flavorNative:
		out["score"], out["action"], out["cdata"] = ext.Score, t.Action, t.CData
		out["mode"], out["via"], out["reasons"] = ext.Mode, ext.Via, ext.Reasons
	case flavorRecaptcha:
		out["score"], out["action"] = ext.Score, t.Action
		out["sweetcaptcha"] = ext
	case flavorHCaptcha:
		// hCaptcha's score runs the other way: 1.0 means a confirmed threat.
		out["score"] = round2(1 - t.Score)
		out["score_reason"] = ext.Reasons
		out["sweetcaptcha"] = ext
	case flavorTurnstile:
		out["action"], out["cdata"] = t.Action, t.CData
		out["error-codes"] = []string{}
		out["metadata"] = map[string]any{}
		out["messages"] = []string{}
		out["sweetcaptcha"] = ext
	}
	return out
}
