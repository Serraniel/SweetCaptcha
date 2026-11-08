package server

import (
	"os"
	"regexp"
	"slices"
	"testing"
)

func TestPickLanguage(t *testing.T) {
	for _, tc := range []struct{ explicit, header, page, want string }{
		{"", "", "", "en"},
		{"", "de-DE,de;q=0.9,en;q=0.8", "", "de"},
		{"", "xx,fr;q=0.5", "", "fr"},
		{"", "en;q=0.2,ja;q=0.9", "", "ja"},
		{"", "zh-HK,zh;q=0.9", "", "zh-TW"},
		{"", "zh-Hans-CN", "", "zh"},
		{"", "zh-Hant", "", "zh-TW"},
		{"pt_BR", "de", "", "pt"},
		{"es-419", "", "", "es"},
		{"xx", "it", "", "it"},
		{"", "*", "", "en"},
		{"", "fr;q=0", "", "en"},
		{"", "xx", "nl-BE", "nl"},
		{"", "de", "nl", "de"},
	} {
		if got := pickLanguage(tc.explicit, tc.header, tc.page); got != tc.want {
			t.Errorf("pickLanguage(%q, %q, %q) = %q, want %q", tc.explicit, tc.header, tc.page, got, tc.want)
		}
	}
}

// The language list here and the locales in the widget must not drift apart.
func TestLanguagesMatchWidgetLocales(t *testing.T) {
	src, err := os.ReadFile("../../web/src/frame/i18n.ts")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^  '?([a-z]{2}(?:-[A-Z]{2})?)'?: \{$`)
	var found []string
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		found = append(found, m[1])
	}
	want := slices.Clone(SupportedLanguages)
	slices.Sort(found)
	slices.Sort(want)
	if !slices.Equal(found, want) {
		t.Errorf("widget locales %v, server list %v", found, want)
	}
}
