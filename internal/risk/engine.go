//go:build !strictonly

package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"sort"
	"strings"
)

// Rule describes one piece of evidence. LLR is a log-likelihood ratio: positive
// values favour automation, negative values favour a human.
type Rule struct {
	ID    string
	Group string
	LLR   float64
	Doc   string
}

// Group names. A group's contribution is capped, so that one root cause showing
// up in several correlated rules counts only once.
const (
	GroupAutomation  = "automation"
	GroupTamper      = "tamper"
	GroupConsistency = "consistency"
	GroupEnvironment = "environment"
	GroupNetwork     = "network"
	GroupBehaviour   = "behaviour"
	GroupProtocol    = "protocol"
)

var groupCap = map[string]float64{
	GroupAutomation:  8,
	GroupTamper:      4,
	GroupConsistency: 5,
	GroupEnvironment: 2,
	GroupNetwork:     3.5,
	GroupBehaviour:   3.5,
	GroupProtocol:    6,
}

// HardGroups contain evidence that a real, unmodified browser should not produce.
var hardGroups = map[string]bool{GroupAutomation: true, GroupTamper: true, GroupConsistency: true, GroupProtocol: true}

// Prior is the starting log-odds of automation, about 12%.
const Prior = -2.0

// Rules is the register of all evidence the engine can use. docs/SIGNALS.md is
// generated from it, and a test fails when the two drift apart.
var Rules = []Rule{
	{"auto_webdriver", GroupAutomation, 8, "`navigator.webdriver` is true. Only a positive value counts."},
	{"auto_artefact", GroupAutomation, 8, "Globals left behind by a browser driver (Playwright, Selenium, PhantomJS and others)."},
	{"auto_headless_ua", GroupAutomation, 8, "The User-Agent says HeadlessChrome."},
	{"auto_tool_ua", GroupAutomation, 8, "The User-Agent names an HTTP library or a crawler."},
	{"tamper_native", GroupTamper, 3, "A browser function does not look native: patched by script."},
	{"tamper_webdriver", GroupTamper, 3, "`navigator.webdriver` was deleted or redefined."},
	{"tamper_proxy", GroupTamper, 3, "A browser API behaves like a JavaScript Proxy."},
	{"worker_mismatch", GroupConsistency, 3, "User-Agent or platform differs between the page and a Web Worker."},
	{"worker_soft_mismatch", GroupConsistency, 1, "Languages, core count or timezone differ between the page and a Worker."},
	{"iframe_mismatch", GroupConsistency, 2.5, "User-Agent or platform differs between the page and an iframe."},
	{"engine_mismatch", GroupConsistency, 3.5, "The JavaScript engine observed is not the one the User-Agent claims."},
	{"header_ua_mismatch", GroupConsistency, 3.5, "`navigator.userAgent` differs from the User-Agent HTTP header."},
	{"uach_mismatch", GroupConsistency, 2.5, "Client Hints contradict the User-Agent (version, mobile or platform)."},
	{"uach_missing", GroupConsistency, 1.5, "A recent Chromium claim has no Client Hints in a secure context."},
	{"gpu_api_mismatch", GroupConsistency, 2, "The graphics API cannot exist on the claimed OS, such as Direct3D on Linux."},
	{"mobile_no_touch", GroupConsistency, 1.5, "A mobile User-Agent with no touch points."},
	{"notification_lie", GroupConsistency, 1, "The Notification and Permissions APIs disagree."},
	{"env_software_gpu", GroupEnvironment, 1.2, "Software rendering. Weak alone, since VMs and remote desktops also do this."},
	{"env_zero_screen", GroupEnvironment, 1.5, "Zero-sized screen or window."},
	{"env_no_languages", GroupEnvironment, 1, "`navigator.languages` is empty."},
	{"net_tls_no_grease", GroupNetwork, 2.5, "A Chromium claim whose TLS handshake lacks GREASE values."},
	{"net_tls_browser_mismatch", GroupNetwork, 2.5, "The TLS handshake does not fit any browser (no HTTP/2 or no TLS 1.3)."},
	{"net_datacenter", GroupNetwork, 1, "The address is in a cloud or hosting range. VPN users also match this."},
	{"net_velocity", GroupNetwork, 1.5, "Many challenges from one address in a short time."},
	{"net_velocity_high", GroupNetwork, 3, "Far too many challenges from one address."},
	{"net_recent_failures", GroupNetwork, 1.5, "This network (/24 or /48) failed hard checks or tasks at least 3 times in the last 30 minutes."},
	{"net_no_sec_fetch", GroupNetwork, 1.5, "A browser claim with no Sec-Fetch headers."},
	{"net_no_accept_language", GroupNetwork, 1, "A browser claim with no Accept-Language header."},
	{"beh_click_no_approach", GroupBehaviour, 2.5, "Mouse clicks with no pointer movement leading to them. Keyboard and assistive-technology activations are excluded."},
	{"beh_burst_typing", GroupBehaviour, 2, "Keystrokes faster than human typing allows."},
	{"beh_programmatic_input", GroupBehaviour, 1, "Field values changed with no key, paste or autofill event."},
	{"beh_linear_path", GroupBehaviour, 1.5, "Pointer movement that is straight with constant speed."},
	{"beh_replay", GroupBehaviour, 3, "The same pointer path was seen in an earlier challenge."},
	{"beh_no_interaction", GroupBehaviour, 0.4, "No interaction was seen before verification timed out. Weak, because users may simply not have reached the form."},
	{"beh_rich_motion", GroupBehaviour, -1, "Curved, variable-speed pointer movement. Lowers suspicion a little, and can be imitated."},
	{"beh_natural_typing", GroupBehaviour, -0.5, "Typing rhythm with natural variation. Lowers suspicion a little, and can be imitated."},
	{"beh_checkbox_no_approach", GroupBehaviour, 2.5, "The checkbox was clicked with a mouse that did not move to it."},
	{"beh_checkbox_instant", GroupBehaviour, 1.5, "The checkbox was clicked within 200 ms of appearing."},
	{"proto_checkbox_untrusted", GroupProtocol, 4, "The checkbox click was generated by script."},
	{"proto_checkbox_missing", GroupProtocol, 5, "The checkbox step was answered without any click evidence."},
	{"trap_hit", GroupProtocol, 4, "A control invisible to people and to assistive technology was activated."},
	{"proto_no_signals", GroupProtocol, 5, "The collector did not run or returned an invalid document."},
	{"proto_too_fast", GroupProtocol, 1.5, "Proof of work finished faster than JavaScript can run it."},
	{"obs_tor", GroupNetwork, 0, "Observed only, with no score effect: a Tor exit. Tor is not treated as evidence of a bot."},
}

var ruleIndex = func() map[string]Rule {
	m := make(map[string]Rule, len(Rules))
	for _, r := range Rules {
		m[r.ID] = r
	}
	return m
}()

// TLSFacts summarises a ClientHello. It is nil when TLS is terminated elsewhere,
// which is reported as unavailable rather than as suspicious.
type TLSFacts struct {
	// GREASEKnown is false when only a JA4 value is available, since JA4 omits GREASE.
	GREASEKnown bool
	HasGREASE   bool
	HasH2       bool
	HasTLS13    bool
}

// Input is everything the engine evaluates for one submission.
type Input struct {
	Signals      *Signals
	Nonce        string
	Header       http.Header
	TLS          *TLSFacts
	Datacenter   bool
	Tor          bool
	Velocity     int64
	SoftLimit    int64
	ElapsedMS    int64
	ExpectedHash float64
	Replay       bool
	// NetFailures counts hard failures from the same network in the last 30 minutes.
	NetFailures   int64
	BrowserScript bool // True when the algorithm's JS speed bound applies.
}

// Result is the engine's verdict.
type Result struct {
	LogOdds    float64
	Hits       []string
	Definitive bool
	Hard       bool
	RateOrNet  bool
	// NoInteraction is set when the page saw no input at all before verification.
	NoInteraction bool
}

// P converts log-odds to a probability of automation.
func P(logOdds float64) float64 { return 1 / (1 + math.Exp(-logOdds)) }

// KeyedHash is the hash the collector applies to comparable values.
func KeyedHash(nonce, value string) string {
	s := sha256.Sum256([]byte(nonce + ":" + value))
	return hex.EncodeToString(s[:8])
}

// maxJSHashRate is a generous upper bound for SHA-256 in browser JavaScript.
const maxJSHashRate = 40e6

// minTooFastMS is the smallest time bound the too-fast rule will act on.
const minTooFastMS = 5.0

// Evaluate scores an input. It is pure and safe for concurrent use.
func Evaluate(in Input) Result {
	hits := map[string]bool{}
	fire := func(id string) { hits[id] = true }

	ua := in.Header.Get("User-Agent")
	claim := ParseUA(ua)
	if claim.Headless {
		fire("auto_headless_ua")
	}
	if claim.NonBrowser {
		fire("auto_tool_ua")
	}
	evalNetwork(in, claim, fire)

	if in.Signals == nil || in.Signals.V != 1 {
		fire("proto_no_signals")
	} else {
		evalClient(in, claim, fire)
	}
	// Below the minimum, clock resolution and network jitter would decide the result.
	if floorMS := in.ExpectedHash / maxJSHashRate * 1000 / 2; in.BrowserScript && floorMS >= minTooFastMS && float64(in.ElapsedMS) < floorMS {
		fire("proto_too_fast")
	}
	r := summarise(hits)
	r.NoInteraction = hits["beh_no_interaction"]
	return r
}

func evalNetwork(in Input, claim UAClaim, fire func(string)) {
	if in.TLS != nil {
		if claim.Family == "chromium" && in.TLS.GREASEKnown && !in.TLS.HasGREASE {
			fire("net_tls_no_grease")
		}
		if claim.Family != "other" && (!in.TLS.HasH2 || !in.TLS.HasTLS13) {
			fire("net_tls_browser_mismatch")
		}
	}
	if in.Datacenter {
		fire("net_datacenter")
	}
	if in.Tor {
		fire("obs_tor")
	}
	if in.NetFailures >= 3 {
		fire("net_recent_failures")
	}
	if in.SoftLimit > 0 {
		switch {
		case in.Velocity > in.SoftLimit*4:
			fire("net_velocity_high")
		case in.Velocity > in.SoftLimit:
			fire("net_velocity")
		}
	}
	if claim.Family != "other" {
		// Older Safari versions do not send Sec-Fetch headers.
		if in.Header.Get("Sec-Fetch-Site") == "" && claim.Family != "safari" {
			fire("net_no_sec_fetch")
		}
		if in.Header.Get("Accept-Language") == "" {
			fire("net_no_accept_language")
		}
	}
	if major := SecCHUAMajor(in.Header.Get("Sec-CH-UA")); major != 0 && claim.ChromiumMajor != 0 && major != claim.ChromiumMajor {
		fire("uach_mismatch")
	}
}

func evalClient(in Input, claim UAClaim, fire func(string)) {
	s := in.Signals
	if s.Auto.Webdriver {
		fire("auto_webdriver")
	}
	if len(s.Auto.Artefacts) > 0 {
		fire("auto_artefact")
	}
	for _, t := range s.Tamper {
		switch {
		case t == "webdriver":
			fire("tamper_webdriver")
		case strings.HasPrefix(t, "proxy:"):
			fire("tamper_proxy")
		case strings.HasPrefix(t, "native:"):
			fire("tamper_native")
		}
	}
	if s.Trap {
		fire("trap_hit")
	}
	if s.Hash.UA != KeyedHash(in.Nonce, in.Header.Get("User-Agent")) {
		fire("header_ua_mismatch")
	}
	compareContexts(s.Hash, s.Worker, "worker_mismatch", "worker_soft_mismatch", fire)
	compareContexts(s.Hash, s.Iframe, "iframe_mismatch", "", fire)
	if claim.Engine != "" && s.Engine.Family != "unknown" && s.Engine.Family != claim.Engine {
		fire("engine_mismatch")
	}
	evalUACH(s, claim, fire)
	evalDevice(s, claim, fire)
	evalBehaviour(s.Beh, in.Replay, fire)
}

func compareContexts(page Hashes, other *Hashes, hard, soft string, fire func(string)) {
	if other == nil {
		return
	}
	if other.UA != page.UA || other.Platform != page.Platform {
		fire(hard)
	}
	if soft != "" && (other.Langs != page.Langs || other.Cores != page.Cores || other.TZ != page.TZ) {
		fire(soft)
	}
}

func evalUACH(s *Signals, claim UAClaim, fire func(string)) {
	if claim.Family != "chromium" {
		return
	}
	if s.UACH == nil {
		if s.Secure && claim.ChromiumMajor >= 100 {
			fire("uach_missing")
		}
		return
	}
	if s.UACH.ChromiumMajor != 0 && s.UACH.ChromiumMajor != claim.ChromiumMajor {
		fire("uach_mismatch")
	}
	if s.UACH.Mobile != claim.Mobile {
		fire("uach_mismatch")
	}
	if claim.Platform != "" && s.UACH.Platform != "" && !strings.EqualFold(s.UACH.Platform, claim.Platform) {
		fire("uach_mismatch")
	}
}

func evalDevice(s *Signals, claim UAClaim, fire func(string)) {
	d := s.Device
	if d.GPU == "software" {
		fire("env_software_gpu")
	}
	if d.ScreenZero || d.WindowZero {
		fire("env_zero_screen")
	}
	if d.Langs == 0 {
		fire("env_no_languages")
	}
	if claim.Mobile && d.Touch == 0 {
		fire("mobile_no_touch")
	}
	if d.NotifLie {
		fire("notification_lie")
	}
	switch {
	case d.GPUAPI == "d3d" && claim.Platform != "Windows" && claim.Platform != "":
		fire("gpu_api_mismatch")
	case d.GPUAPI == "metal" && claim.Platform != "macOS" && claim.Platform != "iOS" && claim.Platform != "":
		fire("gpu_api_mismatch")
	}
}

// evalBehaviour keeps three kinds of absence apart: not applicable (touch has no
// hover), abstained (too little data) and contradictory (a mouse click with no
// approach path). Only the last counts as evidence.
func evalBehaviour(b *Behaviour, replay bool, fire func(string)) {
	if b == nil {
		return
	}
	if replay {
		fire("beh_replay")
	}
	mouseClicks := b.Clicks - b.KbClicks
	if b.Mode == "mouse" && mouseClicks > 0 && b.NoApproach > 0 && float64(b.NoApproach)/float64(mouseClicks) >= 0.5 {
		fire("beh_click_no_approach")
	}
	if b.Keys >= 5 {
		switch {
		case b.KeyMedianMS < 15:
			fire("beh_burst_typing")
		case b.KeyMedianMS > 40 && b.KeyCV > 0.25:
			fire("beh_natural_typing")
		}
	}
	if b.Programmatic > 0 {
		fire("beh_programmatic_input")
	}
	if b.Mode == "mouse" && b.Moves >= 20 {
		switch {
		case b.Straightness > 0.995 && b.SpeedCV < 0.15:
			fire("beh_linear_path")
		case b.Straightness < 0.97 && b.SpeedCV > 0.4 && b.DirChanges >= 2:
			fire("beh_rich_motion")
		}
	}
	if b.Mode == "none" && b.Clicks == 0 && b.Keys == 0 && b.Moves == 0 && b.Scrolls == 0 {
		fire("beh_no_interaction")
	}
}

func summarise(hits map[string]bool) Result {
	r := Result{LogOdds: Prior}
	groups := map[string]float64{}
	for id := range hits {
		rule := ruleIndex[id]
		groups[rule.Group] += rule.LLR
		r.Hits = append(r.Hits, id)
		if rule.LLR > 0 && hardGroups[rule.Group] {
			r.Hard = true
		}
		if rule.LLR > 0 && rule.Group == GroupNetwork {
			r.RateOrNet = true
		}
		if rule.Group == GroupAutomation {
			r.Definitive = true
		}
	}
	sort.Strings(r.Hits)
	for g, v := range groups {
		if limit, ok := groupCap[g]; ok && v > limit {
			v = limit
		}
		r.LogOdds += v
	}
	return r
}

// Click describes how the "Verify you are human" checkbox was activated.
type Click struct {
	Pointer  string `json:"pointer"` // mouse, touch, pen or keyboard
	Approach bool   `json:"approach"`
	Trusted  bool   `json:"trusted"`
	ShownMS  int64  `json:"shownMs"`
}

// EvaluateClick scores the checkbox step on its own. The caller adds the result to
// the evidence held from the first evaluation.
func EvaluateClick(c *Click) Result {
	hits := map[string]bool{}
	switch {
	case c == nil:
		hits["proto_checkbox_missing"] = true
	case !c.Trusted:
		hits["proto_checkbox_untrusted"] = true
	default:
		if c.Pointer == "mouse" && !c.Approach {
			hits["beh_checkbox_no_approach"] = true
		}
		if c.ShownMS >= 0 && c.ShownMS < 200 {
			hits["beh_checkbox_instant"] = true
		}
	}
	r := summarise(hits)
	r.LogOdds -= Prior // Only the added evidence, without a second prior.
	return r
}

// ClientReads lists every browser property the standard-mode collectors read.
// docs/SIGNALS.md and the transparency endpoint are generated from it.
var ClientReads = []string{
	"navigator.webdriver, and the presence of named automation globals",
	"Native-code appearance of a fixed set of browser functions",
	"navigator.userAgent, platform, languages and hardwareConcurrency (keyed hashes, for page, Worker and iframe comparison)",
	"Intl timezone (keyed hash, for the same comparison)",
	"navigator.userAgentData: Chromium major version, mobile flag and platform (low-entropy values only)",
	"navigator.maxTouchPoints, and pointer media queries (coarse)",
	"Whether screen and window sizes are zero (no dimensions are sent)",
	"Number of navigator.languages",
	"WebGL renderer, reduced to a vendor class and a graphics API class",
	"Whether canvas read-back is stable (a boolean, with no image hash)",
	"Notification.permission against permissions.query (a boolean)",
	"JavaScript engine family, from error stack format",
	"When the checkbox is shown: whether the pointer moved to it, whether the click was real, and how soon it came (no coordinates)",
	"Page interaction reduced to counts and ratios: pointer path shape, click approach, key timing without key values, paste, scroll",
	"A short hash of a coarsely quantised pointer path, for replay detection",
	"Server side: User-Agent, Sec-CH-UA, Sec-Fetch and Accept-Language headers, TLS ClientHello when terminated here, and address class from local lists",
}
