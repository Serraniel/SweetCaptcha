package server

import (
	"sort"
	"strconv"
	"strings"
)

// SupportedLanguages must match the locales in web/src/frame/i18n.ts. A test checks
// this.
var SupportedLanguages = []string{
	"en", "de", "fr", "es", "pt", "it", "nl", "pl", "cs", "sv", "ru", "uk", "tr",
	"ar", "hi", "id", "vi", "zh", "zh-TW", "ja", "ko",
}

var rtlLanguages = map[string]bool{"ar": true}

// supported normalises a language tag to a supported code, or returns "".
func supported(tag string) string {
	tag = strings.TrimSpace(strings.ReplaceAll(tag, "_", "-"))
	if tag == "" {
		return ""
	}
	parts := strings.Split(tag, "-")
	primary := strings.ToLower(parts[0])
	if primary == "zh" {
		// Traditional script for Taiwan, Hong Kong, Macau and explicit Hant tags.
		for _, p := range parts[1:] {
			switch strings.ToLower(p) {
			case "tw", "hk", "mo", "hant":
				return "zh-TW"
			}
		}
		return "zh"
	}
	for _, l := range SupportedLanguages {
		if l == primary {
			return l
		}
	}
	return ""
}

// pickLanguage chooses the widget language: the site's explicit hl or
// data-language first, then the visitor's Accept-Language header, then the host
// page's <html lang>. The header arrives with every request; nothing is read from
// the device.
func pickLanguage(explicit, acceptLanguage, page string) string {
	if l := supported(explicit); l != "" {
		return l
	}
	type choice struct {
		tag string
		q   float64
	}
	var choices []choice
	for _, part := range strings.Split(acceptLanguage, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		q := 1.0
		for _, f := range fields[1:] {
			if v, ok := strings.CutPrefix(strings.TrimSpace(f), "q="); ok {
				if parsed, err := strconv.ParseFloat(v, 64); err == nil {
					q = parsed
				}
			}
		}
		if fields[0] != "" && q > 0 {
			choices = append(choices, choice{fields[0], q})
		}
	}
	sort.SliceStable(choices, func(i, j int) bool { return choices[i].q > choices[j].q })
	for _, c := range choices {
		if l := supported(c.tag); l != "" {
			return l
		}
	}
	if l := supported(page); l != "" {
		return l
	}
	return "en"
}
