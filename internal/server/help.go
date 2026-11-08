package server

import (
	"html"
	"log/slog"
	"net/http"
	"strings"
)

// helpText is the page linked from the widget's error states. It gives practical
// advice without describing what the detection looks at. Other languages fall
// back to English.
var helpText = map[string]struct {
	title, intro, back string
	tips               []string
}{
	"en": {
		title: "Verification help",
		intro: "If the verification on this site fails or keeps asking for more, these steps usually help:",
		tips: []string{
			"Allow JavaScript for this site and for the verification frame.",
			"If you use an extension that changes how your browser identifies itself, such as a user-agent switcher, turn it off for this site.",
			"With a VPN, Tor or a shared network, an extra step is expected. Complete it, or choose “I can't do this task” for a longer calculation instead.",
			"Reload the page and try again, or try another browser.",
			"If none of this works, contact the site.",
		},
		back: "Contact the site",
	},
	"de": {
		title: "Hilfe zur Überprüfung",
		intro: "Wenn die Überprüfung auf dieser Seite fehlschlägt oder immer weitere Schritte verlangt, helfen meist diese Schritte:",
		tips: []string{
			"Erlaube JavaScript für diese Seite und für den Überprüfungsrahmen.",
			"Wenn du eine Erweiterung nutzt, die verändert, wie sich dein Browser ausgibt, etwa einen User-Agent-Wechsler, schalte sie für diese Seite aus.",
			"Mit VPN, Tor oder einem geteilten Netzwerk ist ein zusätzlicher Schritt normal. Löse ihn, oder wähle „Ich kann diese Aufgabe nicht lösen“ für eine längere Berechnung.",
			"Lade die Seite neu und versuche es erneut, oder nutze einen anderen Browser.",
			"Wenn nichts davon hilft, kontaktiere die Seite.",
		},
		back: "Seite kontaktieren",
	},
}

func (s *Server) handleHelp(w http.ResponseWriter, r *http.Request) {
	lang := pickLanguage(r.URL.Query().Get("l"), r.Header.Get("Accept-Language"), "")
	t, ok := helpText[lang]
	if !ok {
		lang, t = "en", helpText["en"]
	}
	support := ""
	if site, ok := s.sites[r.URL.Query().Get("k")]; ok && site.SupportURL != "" {
		support = site.SupportURL
	}
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="` + lang + `"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` +
		html.EscapeString(t.title) + `</title><style>` + demoCSS + `</style><main><h1>` + html.EscapeString(t.title) + `</h1><p>` +
		html.EscapeString(t.intro) + `</p><ol>`)
	for _, tip := range t.tips {
		b.WriteString(`<li>` + html.EscapeString(tip) + `</li>`)
	}
	b.WriteString(`</ol>`)
	if support != "" {
		b.WriteString(`<p><a href="` + html.EscapeString(support) + `" rel="noopener">` + html.EscapeString(t.back) + `</a></p>`)
	}
	b.WriteString(`</main>`)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Cache-Control", "public, max-age=3600")
	h.Set("Vary", "Accept-Language")
	if _, err := w.Write([]byte(b.String())); err != nil { //nolint:gosec // Every value is HTML-escaped.
		slog.Debug("write help", "error", err)
	}
}
