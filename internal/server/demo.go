package server

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/Serraniel/SweetCaptcha/internal/edition"
)

//go:embed demo.html
var demoPageSource string

//go:embed demo_result.html
var demoResultSource string

//go:embed demo.css
var demoCSS string

// The demo pages use html/template, which escapes every value for its context.
// Only the stylesheet is passed as trusted CSS: it is a constant embedded at build
// time and never contains request data.
var demoStyle = template.CSS(demoCSS) //nolint:gosec // A build-time constant.

var (
	demoPage   = template.Must(template.New("demo").Parse(demoPageSource))
	demoResult = template.Must(template.New("result").Parse(demoResultSource))
)

type demoLink struct {
	Name, URL string
	Current   bool
}

type demoSite struct {
	Name, Mode string
	Links      []demoLink
}

// demoTheme accepts only known values, because the result is written into pages.
func demoTheme(v string) string {
	if v == "light" || v == "dark" {
		return v
	}
	return "auto"
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
		var themes []demoLink
		for _, name := range []string{"auto", "light", "dark"} {
			themes = append(themes, demoLink{Name: name, URL: demoURL(provider, key, name), Current: name == theme})
		}
		var sites []demoSite
		for i := range s.cfg.Sites {
			site := &s.cfg.Sites[i]
			ds := demoSite{Name: site.Name, Mode: string(site.Mode)}
			for _, name := range []string{"native", "recaptcha", "hcaptcha", "turnstile"} {
				ds.Links = append(ds.Links, demoLink{Name: demoAPILabels[name], URL: demoURL(name, site.SiteKey, theme)})
			}
			sites = append(sites, ds)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		err := demoPage.Execute(w, map[string]any{
			"CSS": demoStyle, "Theme": theme, "Themes": themes, "Version": edition.Version,
			"Script": p.script, "Class": p.class, "Key": key, "Provider": provider, "API": demoAPILabels[provider],
			"Site": s.sites[key].Name, "Mode": string(s.sites[key].Mode), "Sites": sites,
		})
		if err != nil {
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
		err = demoResult.Execute(w, map[string]any{
			"CSS": demoStyle, "Theme": theme, "Body": string(body),
			"Back": demoURL(provider, site.SiteKey, theme), "Fields": demoFields,
		})
		if err != nil {
			slog.Debug("write demo result", "error", err)
		}
	})
}
