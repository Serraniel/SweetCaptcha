//go:build !strictonly

package risk

import (
	"regexp"
	"strconv"
	"strings"
)

// UAClaim is what a User-Agent header claims about the browser.
type UAClaim struct {
	Family        string // chromium, firefox, safari or other
	Engine        string // v8, spidermonkey, jsc or empty
	ChromiumMajor int
	Mobile        bool
	Platform      string // Windows, macOS, Linux, Android, iOS or empty
	Headless      bool
	NonBrowser    bool
}

var (
	reChromium = regexp.MustCompile(`(?:Chrome|Chromium)/(\d+)`)
	reTools    = regexp.MustCompile(`(?i)\b(curl|wget|python|go-http|httpx|axios|node-fetch|okhttp|java/|libwww|scrapy|aiohttp|phantomjs|bot\b|spider|crawler)`)
)

// ParseUA extracts claims from a User-Agent string.
func ParseUA(ua string) UAClaim {
	c := UAClaim{Family: "other"}
	switch {
	case strings.Contains(ua, "Windows"):
		c.Platform = "Windows"
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"):
		c.Platform = "iOS"
	case strings.Contains(ua, "Android"):
		c.Platform = "Android"
	case strings.Contains(ua, "Macintosh"):
		c.Platform = "macOS"
	case strings.Contains(ua, "Linux"), strings.Contains(ua, "X11"):
		c.Platform = "Linux"
	}
	c.Mobile = strings.Contains(ua, "Mobile") || c.Platform == "iOS"
	c.Headless = strings.Contains(ua, "HeadlessChrome")
	c.NonBrowser = !strings.HasPrefix(ua, "Mozilla/5.0") || reTools.MatchString(ua)
	switch {
	case c.Platform == "iOS":
		// Every iOS browser has been a WebKit shell regardless of its name.
		c.Family, c.Engine = "safari", "jsc"
	case strings.Contains(ua, "Firefox/"):
		c.Family, c.Engine = "firefox", "spidermonkey"
	case reChromium.MatchString(ua):
		c.Family, c.Engine = "chromium", "v8"
		c.ChromiumMajor, _ = strconv.Atoi(reChromium.FindStringSubmatch(ua)[1])
	case strings.Contains(ua, "Safari/"):
		c.Family, c.Engine = "safari", "jsc"
	}
	return c
}

var reSecCHUA = regexp.MustCompile(`"(?:Chromium|Google Chrome|Microsoft Edge)";\s*v="(\d+)"`)

// SecCHUAMajor returns the Chromium major version from a Sec-CH-UA header.
func SecCHUAMajor(header string) int {
	m := reSecCHUA.FindStringSubmatch(header)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}
