package server

import (
	_ "embed"
	"encoding/json"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/Serraniel/SweetCaptcha/internal/edition"
)

//go:embed demo.html
var demoHTML string

//go:embed demo.css
var demoCSS string

// demoTheme accepts only known values, because the result is written into pages.
func demoTheme(v string) string {
	if v == "light" || v == "dark" {
		return v
	}
	return "auto"
}

func demoThemeAttr(theme string) string {
	if theme == "auto" {
		return ""
	}
	return ` data-theme="` + theme + `"`
}

func demoURL(provider, key, theme string) string {
	return "/demo/?" + url.Values{"provider": {provider}, "k": {key}, "theme": {theme}}.Encode()
}

// demoFields explains the result page. Which fields appear depends on the API.
var demoFields = [][2]string{
	{"success", "Whether the token was valid. This is the only field a form must check."},
	{"score", "Native and reCAPTCHA: 1.0 is most human. hCaptcha is reversed: 1.0 is a threat. Fixed at 0.9 in strict mode, where it means nothing."},
	{"via", "How the visitor got through: silent, stepup, puzzle, wait, or pow in strict mode."},
	{"mode", "standard or strict."},
	{"reasons", "Which rules fired. See docs/SIGNALS.md. Only your server sees these."},
	{"action, cdata", "Values set by the page when the widget was rendered."},
	{"hostname, challenge_ts", "Where and when the token was issued."},
	{"sweetcaptcha", "The same details on the provider APIs, whose own formats have no field for them."},
	{"error-codes", "Why verification failed."},
}

var demoProviders = map[string]struct{ script, class, field string }{
	"native":    {"/v1/api.js", "sweetcaptcha", "sc-response"},
	"recaptcha": {"/recaptcha/api.js", "g-recaptcha", "g-recaptcha-response"},
	"hcaptcha":  {"/1/api.js", "h-captcha", "h-captcha-response"},
	"turnstile": {"/turnstile/v0/api.js", "cf-turnstile", "cf-turnstile-response"},
}

var demoAPILabels = map[string]string{
	"native": "SweetCaptcha API", "recaptcha": "reCAPTCHA API", "hcaptcha": "hCaptcha API", "turnstile": "Turnstile API",
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
		theme := demoTheme(r.URL.Query().Get("theme"))
		var themes strings.Builder
		for _, name := range []string{"auto", "light", "dark"} {
			current := ""
			if name == theme {
				current = ` aria-current="true"`
			}
			themes.WriteString(`<a href="` + html.EscapeString(demoURL(provider, key, name)) + `"` + current + `>` + name + `</a>`)
		}
		var links strings.Builder
		for i := range s.cfg.Sites {
			site := &s.cfg.Sites[i]
			links.WriteString(`<p><strong>` + html.EscapeString(site.Name) + `</strong> (` + string(site.Mode) + ` mode): `)
			for _, name := range []string{"native", "recaptcha", "hcaptcha", "turnstile"} {
				links.WriteString(`<a href="` + html.EscapeString(demoURL(name, site.SiteKey, theme)) + `">` + demoAPILabels[name] + `</a> `)
			}
			links.WriteString(`</p>`)
		}
		siteName := s.sites[key].Name
		page := strings.NewReplacer(
			"{{CSS}}", demoCSS, "{{THEME_ATTR}}", demoThemeAttr(theme), "{{THEME}}", theme, "{{THEMES}}", themes.String(),
			"{{VERSION}}", html.EscapeString(edition.Version), "{{SCRIPT}}", p.script, "{{CLASS}}", p.class, "{{KEY}}", html.EscapeString(key),
			"{{PROVIDER}}", provider, "{{API}}", demoAPILabels[provider], "{{SITE}}", html.EscapeString(siteName),
			"{{MODE}}", string(s.sites[key].Mode), "{{LINKS}}", links.String(),
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
		theme := demoTheme(r.Form.Get("theme"))
		var rows strings.Builder
		for _, f := range demoFields {
			rows.WriteString(`<tr><td>` + html.EscapeString(f[0]) + `</td><td>` + html.EscapeString(f[1]) + `</td></tr>`)
		}
		page := `<!doctype html><html lang="en"` + demoThemeAttr(theme) + `><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Result</title><style>` + demoCSS + `</style><main><h1>Server-side result</h1><p>This is the complete response your backend would receive from <code>siteverify</code>.</p><pre id="result">` +
			html.EscapeString(string(body)) + `</pre><p><a href="` + html.EscapeString(demoURL(provider, site.SiteKey, theme)) + `">Back</a></p><h2>What the fields mean</h2><table>` + rows.String() + `</table></main>`
		if _, err := w.Write([]byte(page)); err != nil {
			slog.Debug("write demo result", "error", err)
		}
	})
}
