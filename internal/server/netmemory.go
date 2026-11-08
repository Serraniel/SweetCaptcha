package server

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Serraniel/SweetCaptcha/internal/config"
)

// networkFailureWindow is how long hard failures from a network are remembered.
const networkFailureWindow = 30 * time.Minute

// networkKey returns the counter key for the client's /24 (IPv4) or /48 (IPv6),
// under a pseudonym that rotates daily. Nothing in it identifies an address.
func (s *Server) networkKey(r *http.Request, site *config.Site) string {
	if !site.NetworkMemoryOn() {
		return ""
	}
	addr := s.clientAddr(r)
	if !addr.IsValid() {
		return ""
	}
	bits := 48
	if addr.Is4() {
		bits = 24
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}
	return "nf:" + site.SiteKey + ":" + s.ring.DailyPseudonym(prefix.String(), s.now())
}

// noteNetworkFailure records a hard failure: a denial, hard evidence, or a wrong
// task answer.
func (s *Server) noteNetworkFailure(r *http.Request, site *config.Site) {
	key := s.networkKey(r, site)
	if key == "" {
		return
	}
	if _, err := s.store.Incr(r.Context(), key, 1, networkFailureWindow); err != nil {
		slog.Warn("network failure counter unavailable", "error", err)
	}
}

// networkFailures returns the remembered count, or 0 when unavailable.
func (s *Server) networkFailures(r *http.Request, site *config.Site) int64 {
	key := s.networkKey(r, site)
	if key == "" {
		return 0
	}
	v, ok, err := s.store.Get(r.Context(), key)
	if err != nil || !ok {
		return 0
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}
