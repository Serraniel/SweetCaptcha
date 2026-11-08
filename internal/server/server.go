// Package server implements the HTTP API, compatibility routes and frame host.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Serraniel/SweetCaptcha/internal/assets"
	"github.com/Serraniel/SweetCaptcha/internal/config"
	"github.com/Serraniel/SweetCaptcha/internal/keys"
	"github.com/Serraniel/SweetCaptcha/internal/seal"
	"github.com/Serraniel/SweetCaptcha/internal/stats"
	"github.com/Serraniel/SweetCaptcha/internal/store"
)

const maxBody = 64 << 10

// Server holds request-independent state.
type Server struct {
	cfg      *config.Config
	store    store.Store
	ring     *keys.Ring
	stats    *stats.Recorder
	sites    map[string]*config.Site
	secrets  map[string]*config.Site
	chalBox  *seal.Box
	tokBox   *seal.Box
	puzBox   *seal.Box
	core     assets.Manifest
	coreFS   fs.FS
	signals  assets.Manifest
	sigFS    fs.FS
	std      *standard
	now      func() time.Time
	handler  http.Handler
	frameCSP map[string]string
}

// New builds a Server.
func New(cfg *config.Config, st store.Store) (*Server, error) {
	ring, err := keys.New(cfg.Secret.Decoded)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, store: st, ring: ring, stats: stats.New(st), now: time.Now,
		sites: map[string]*config.Site{}, secrets: map[string]*config.Site{}, frameCSP: map[string]string{},
	}
	if s.chalBox, err = seal.New(ring.Derive("challenge", "")); err != nil {
		return nil, err
	}
	if s.tokBox, err = seal.New(ring.Derive("token", "")); err != nil {
		return nil, err
	}
	if s.puzBox, err = seal.New(ring.Derive("puzzle", "")); err != nil {
		return nil, err
	}
	for i := range cfg.Sites {
		site := &cfg.Sites[i]
		s.sites[site.SiteKey] = site
		s.secrets[site.Secret] = site
		s.frameCSP[site.SiteKey] = frameCSP(site)
	}
	s.core, s.coreFS = assets.Core()
	s.signals, s.sigFS = assets.Signals()
	s.std = newStandard(cfg)
	s.handler = s.routes()
	return s, nil
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", s.handleReady)

	mux.HandleFunc("POST /v1/challenge", s.handleChallenge)
	mux.HandleFunc("POST /v1/submit", s.handleSubmit)
	s.std.routes(mux, s)
	mux.HandleFunc("GET /v1/frame", s.handleFrame)
	mux.HandleFunc("GET /v1/assets/{name}", s.handleAsset)
	mux.HandleFunc("GET /v1/transparency", s.handleTransparency)
	mux.HandleFunc("GET /v1/help", s.handleHelp)

	// The same loader serves every provider path. It inspects its own URL to
	// decide which global to expose.
	for _, p := range []string{"/v1/api.js", "/recaptcha/api.js", "/1/api.js", "/turnstile/v0/api.js"} {
		mux.HandleFunc("GET "+p, s.handleLoader)
	}
	mux.HandleFunc("POST /v1/siteverify", s.siteverify(flavorNative))
	mux.HandleFunc("POST /recaptcha/api/siteverify", s.siteverify(flavorRecaptcha))
	mux.HandleFunc("GET /recaptcha/api/siteverify", s.siteverify(flavorRecaptcha))
	mux.HandleFunc("POST /siteverify", s.siteverify(flavorHCaptcha))
	mux.HandleFunc("POST /turnstile/v0/siteverify", s.siteverify(flavorTurnstile))

	if s.cfg.Admin.Token != "" {
		mux.HandleFunc("GET /admin/{$}", s.handleAdminPage)
		mux.HandleFunc("GET /admin/api/stats", s.requireAdmin(s.handleAdminStats))
	}
	if s.cfg.Server.Demo {
		s.demoRoutes(mux)
	}
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		slog.Warn("readiness check failed", "error", err)
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clientAddr returns the peer address, honouring X-Forwarded-For only when the
// direct peer is a configured trusted proxy.
func (s *Server) clientAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	addr = addr.Unmap()
	if !s.trusted(addr) {
		return addr
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		hop = hop.Unmap()
		if !s.trusted(hop) {
			return hop
		}
		addr = hop
	}
	return addr
}

func (s *Server) trusted(addr netip.Addr) bool {
	for _, p := range s.cfg.Server.Proxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		slog.Debug("write response", "error", err)
	}
}

// readJSON requires application/json. That forces a CORS preflight, which this
// API never grants, so other origins cannot post to it from a browser.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "json-required"})
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad-request"})
		return false
	}
	return true
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	want := []byte("Bearer " + s.cfg.Admin.Token)
	return func(w http.ResponseWriter, r *http.Request) {
		if s.throttled(r, "admin") {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate-limited"})
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			s.noteFailure(r, "admin")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

// failureLimit is how many failed authentications an address may make in
// failureWindow before it is refused.
const (
	failureLimit  = 20
	failureWindow = 10 * time.Minute
)

func (s *Server) failureKey(r *http.Request, scope string) string {
	addr := s.clientAddr(r)
	if !addr.IsValid() {
		return ""
	}
	return "fl:" + scope + ":" + s.ring.DailyPseudonym(addr.String(), s.now())
}

// throttled reports whether this address has failed too often. It fails open
// when the store is unavailable, since the secret comparison still applies.
func (s *Server) throttled(r *http.Request, scope string) bool {
	key := s.failureKey(r, scope)
	if key == "" {
		return false
	}
	v, ok, err := s.store.Get(r.Context(), key)
	if err != nil || !ok {
		return false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return err == nil && n >= failureLimit
}

func (s *Server) noteFailure(r *http.Request, scope string) {
	if key := s.failureKey(r, scope); key != "" {
		if _, err := s.store.Incr(r.Context(), key, 1, failureWindow); err != nil {
			slog.Warn("failure counter unavailable", "error", err)
		}
	}
}
