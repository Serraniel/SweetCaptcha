package server

import (
	_ "embed"
	"log/slog"
	"net/http"
	"slices"
	"strconv"

	"github.com/Serraniel/SweetCaptcha/internal/stats"
)

//go:embed admin.html
var adminHTML []byte

func (s *Server) handleAdminPage(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	if _, err := w.Write(adminHTML); err != nil {
		slog.Debug("write admin page", "error", err)
	}
}

func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	days, err := strconv.Atoi(r.URL.Query().Get("days"))
	if err != nil || days < 1 || days > 35 {
		days = 7
	}
	target := 0.02
	names := slices.Concat(stats.Base, s.std.counterNames())
	type siteStats struct {
		Name    string        `json:"name"`
		SiteKey string        `json:"sitekey"`
		Mode    string        `json:"mode"`
		Shadow  bool          `json:"shadow"`
		Summary stats.Summary `json:"summary"`
	}
	out := make([]siteStats, 0, len(s.cfg.Sites))
	for i := range s.cfg.Sites {
		site := &s.cfg.Sites[i]
		sum, err := s.stats.Summarise(r.Context(), site.Name, names, days, target)
		if err != nil {
			slog.Error("summarise stats", "site", site.Name, "error", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "store-unavailable"})
			return
		}
		out = append(out, siteStats{site.Name, site.SiteKey, string(site.Mode), site.Policy.Shadow, sum})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sites": out})
}
