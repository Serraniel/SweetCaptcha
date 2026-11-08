package server

import (
	"errors"
	"html"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Serraniel/SweetCaptcha/internal/assets"
	"github.com/Serraniel/SweetCaptcha/internal/config"
	"github.com/Serraniel/SweetCaptcha/internal/edition"
)

// frameCSP limits the widget frame to its own origin, and frame-ancestors makes
// browsers refuse to embed it on hosts the site has not listed.
func frameCSP(site *config.Site) string {
	var ancestors []string
	for _, h := range site.Hostnames {
		if h == "localhost" || h == "127.0.0.1" {
			ancestors = append(ancestors, "http://"+h+":*", "https://"+h+":*")
			continue
		}
		ancestors = append(ancestors, "https://"+h)
	}
	return "default-src 'none'; script-src 'self'; style-src 'self'; img-src data:; connect-src 'self'; " +
		"worker-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors " + strings.Join(ancestors, " ")
}

func (s *Server) handleFrame(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("k")
	csp, ok := s.frameCSP[key]
	if !ok {
		http.Error(w, "unknown sitekey", http.StatusForbidden)
		return
	}
	script, css, worker := s.core["frame.js"], s.core["frame.css"], s.core["worker.js"]
	if script.Path == "" {
		http.Error(w, "widget assets are not built", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	site := s.sites[key]
	lang := pickLanguage(r.URL.Query().Get("l"), r.Header.Get("Accept-Language"), r.URL.Query().Get("p"))
	dir := "ltr"
	if rtlLanguages[lang] {
		dir = "rtl"
	}
	h.Set("Vary", "Accept-Language")
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="` + lang + `" dir="` + dir + `" data-worker="/v1/assets/`)
	b.WriteString(html.EscapeString(worker.Path))
	b.WriteString(`" data-version="`)
	b.WriteString(html.EscapeString(edition.Version))
	b.WriteString(`" data-privacy="`)
	b.WriteString(html.EscapeString(site.PrivacyURL))
	b.WriteString(`" data-imprint="`)
	b.WriteString(html.EscapeString(site.ImprintURL))
	b.WriteString(`"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Verification</title><link rel="stylesheet" href="/v1/assets/`)
	b.WriteString(html.EscapeString(css.Path))
	b.WriteString(`" integrity="`)
	b.WriteString(html.EscapeString(css.SRI))
	b.WriteString(`"></head><body>`)
	// A link no person or assistive technology meets: off-screen, aria-hidden and
	// out of the tab order. Scrapers that parse the raw HTML and follow every link
	// fetch it. Standard mode only.
	if site.Mode == config.ModeStandard {
		if trap := s.newTrap(); trap != "" {
			b.WriteString(`<a class="t" href="/v1/t/` + html.EscapeString(trap) + `" data-trap="` + html.EscapeString(trap) +
				`" tabindex="-1" aria-hidden="true" rel="nofollow">Continue without verification</a>`)
		}
	}
	b.WriteString(`<main id="root"></main><script src="/v1/assets/`)
	b.WriteString(html.EscapeString(script.Path))
	b.WriteString(`" integrity="`)
	b.WriteString(html.EscapeString(script.SRI))
	b.WriteString(`"></script></body></html>`)
	if _, err := w.Write([]byte(b.String())); err != nil {
		slog.Debug("write frame", "error", err)
	}
}

// handleLoader serves the one script host pages include.
func (s *Server) handleLoader(w http.ResponseWriter, _ *http.Request) {
	loader, ok := s.core["api.js"]
	if !ok {
		http.Error(w, "widget assets are not built", http.StatusInternalServerError)
		return
	}
	raw, err := fs.ReadFile(s.coreFS, loader.Path)
	if err != nil {
		http.Error(w, "widget assets are not built", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/javascript; charset=utf-8")
	h.Set("Cache-Control", "public, max-age=3600")
	h.Set("Cross-Origin-Resource-Policy", "cross-origin")
	if _, err := w.Write(raw); err != nil {
		slog.Debug("write loader", "error", err)
	}
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	for _, src := range []struct {
		m assets.Manifest
		f fs.FS
	}{{s.core, s.coreFS}, {s.signals, s.sigFS}} {
		for _, file := range src.m {
			if file.Path != name {
				continue
			}
			raw, err := fs.ReadFile(src.f, name)
			if errors.Is(err, fs.ErrNotExist) {
				break
			}
			if err != nil {
				http.Error(w, "read error", http.StatusInternalServerError)
				return
			}
			h := w.Header()
			if strings.HasSuffix(name, ".css") {
				h.Set("Content-Type", "text/css; charset=utf-8")
			} else {
				h.Set("Content-Type", "text/javascript; charset=utf-8")
			}
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
			h.Set("Access-Control-Allow-Origin", "*") // Required for cross-origin SRI.
			h.Set("Cross-Origin-Resource-Policy", "cross-origin")
			if _, err := w.Write(raw); err != nil {
				slog.Debug("write asset", "error", err)
			}
			return
		}
	}
	http.NotFound(w, r)
}

// transparency is a machine-readable statement of what a site's configuration
// does. It is generated from the running code and config, so operators can base
// a privacy notice on it and test it against network captures.
type transparency struct {
	SiteKey     string   `json:"sitekey"`
	Mode        string   `json:"mode"`
	StrictBuild bool     `json:"strict_only_build"`
	ClientReads []string `json:"client_reads"`
	Rules       any      `json:"rules"`
	CustomRules any      `json:"custom_rules"`
	Storage     []string `json:"browser_storage"`
	ThirdParty  []string `json:"third_party_requests"`
	Retention   any      `json:"server_retention"`
	Statement   string   `json:"statement"`
}

func (s *Server) handleTransparency(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	site, ok := s.sites[r.URL.Query().Get("sitekey")]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invalid-sitekey"})
		return
	}
	t := transparency{
		SiteKey: site.SiteKey, Mode: string(site.Mode), StrictBuild: edition.StrictOnly,
		ClientReads: []string{}, Storage: []string{}, ThirdParty: []string{}, Rules: []any{}, CustomRules: []any{},
		Retention: map[string]string{ //nolint:gosec // These are descriptions, not credentials.
			"challenge_state":    "until expiry, at most 11 minutes",
			"token_redemption":   "until token expiry plus 1 minute",
			"wait_path_counter":  "1 hour, keyed by a daily-rotating pseudonym of the address",
			"network_failures":   "30 minutes, standard mode only, keyed by a daily-rotating pseudonym of the /24 or /48 network",
			"rate_counter":       "2 minutes, keyed by a daily-rotating pseudonym of the address",
			"aggregate_counters": "35 days, counts only",
			"ip_address_stored":  "never",
			"raw_signals_stored": "never",
		},
	}
	if site.Mode == config.ModeStrict {
		t.Statement = "Proof of work only. This mode raises the cost of automated requests; it does not detect sophisticated bots or distinguish humans. The returned score is a fixed value and carries no information about humanity."
	} else {
		t.ClientReads, t.Rules = s.std.register()
		t.CustomRules = site.Rules
		t.Statement = "Device, network and interaction signals are evaluated on this server only. Signals are not shared with third parties, not stored after evaluation, and not used for any other purpose by the software as shipped."
	}
	writeJSON(w, http.StatusOK, t)
}
