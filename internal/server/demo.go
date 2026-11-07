package server

import (
	_ "embed"
	"encoding/json"
	"html"
	"log/slog"
	"net/http"
	"strings"
)

//go:embed demo.html
var demoHTML string

var demoProviders = map[string]struct{ script, class, field string }{
	"native":    {"/v1/api.js", "sweetcaptcha", "sc-response"},
	"recaptcha": {"/recaptcha/api.js", "g-recaptcha", "g-recaptcha-response"},
	"hcaptcha":  {"/1/api.js", "h-captcha", "h-captcha-response"},
	"turnstile": {"/turnstile/v0/api.js", "cf-turnstile", "cf-turnstile-response"},
}

// demoRoutes mounts test pages. They use each site's real secret on the server
// side, exactly as an integrator's backend would.
func (s *Server) demoRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /demo/{$}", func(w http.ResponseWriter, r *http.Request) {
		provider := r.URL.Query().Get("provider")
		p, ok := demoProviders[provider]
		if !ok {
			provider, p = "native", demoProviders["native"]
		}
		key := r.URL.Query().Get("k")
		if _, ok := s.sites[key]; !ok {
			key = s.cfg.Sites[0].SiteKey
		}
		var links strings.Builder
		for i := range s.cfg.Sites {
			site := &s.cfg.Sites[i]
			for _, name := range []string{"native", "recaptcha", "hcaptcha", "turnstile"} {
				links.WriteString(`<a href="/demo/?provider=` + name + `&k=` + html.EscapeString(site.SiteKey) + `">` + html.EscapeString(site.Name) + ` · ` + name + `</a> `)
			}
		}
		page := strings.NewReplacer(
			"{{SCRIPT}}", p.script, "{{CLASS}}", p.class, "{{KEY}}", html.EscapeString(key),
			"{{PROVIDER}}", provider, "{{LINKS}}", links.String(),
		).Replace(demoHTML)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if _, err := w.Write([]byte(page)); err != nil { //nolint:gosec // Every substituted value is a constant or is HTML-escaped.
			slog.Debug("write demo", "error", err)
		}
	})
	mux.HandleFunc("POST /demo/verify", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		site, ok := s.sites[r.Form.Get("k")]
		if !ok {
			http.Error(w, "unknown site", http.StatusBadRequest)
			return
		}
		provider := r.Form.Get("provider")
		p, ok := demoProviders[provider]
		if !ok {
			http.Error(w, "unknown provider", http.StatusBadRequest)
			return
		}
		f := map[string]flavor{"native": flavorNative, "recaptcha": flavorRecaptcha, "hcaptcha": flavorHCaptcha, "turnstile": flavorTurnstile}[provider]
		out := s.verify(r.Context(), verifyParams{Secret: site.Secret, Response: r.Form.Get(p.field)})
		body, err := json.MarshalIndent(format(f, out), "", "  ")
		if err != nil {
			http.Error(w, "encode", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page := `<!doctype html><meta charset="utf-8"><title>Result</title><style>:root{color-scheme:light dark}body{font:15px system-ui;margin:24px}</style><h1>Server-side result</h1><pre id="result">` +
			html.EscapeString(string(body)) + `</pre><a href="/demo/?provider=` + html.EscapeString(provider) + `&k=` + html.EscapeString(site.SiteKey) + `">Back</a>`
		if _, err := w.Write([]byte(page)); err != nil {
			slog.Debug("write demo result", "error", err)
		}
	})
}
