//go:build !strictonly

// Package risk scores evidence on the server. It is compiled out of strict-only
// builds. Client-supplied values are treated as claims that may be fabricated:
// they can raise suspicion when they contradict each other or the network view,
// but their absence never proves humanity.
package risk

// Signals is the document produced by the standard-mode collectors. It holds
// coarse values and keyed hashes, and it is discarded after evaluation.
type Signals struct {
	V      int        `json:"v"`
	Secure bool       `json:"secure"`
	Auto   Auto       `json:"auto"`
	Tamper []string   `json:"tamper"`
	Hash   Hashes     `json:"hash"`
	Worker *Hashes    `json:"worker"`
	Iframe *Hashes    `json:"iframe"`
	Engine Engine     `json:"engine"`
	UACH   *UACH      `json:"uach"`
	Device Device     `json:"device"`
	Trap   bool       `json:"trap"`
	CDP    bool       `json:"cdp"`
	Beh    *Behaviour `json:"beh"`
}

// Auto holds explicit automation markers.
type Auto struct {
	Webdriver bool     `json:"webdriver"`
	Artefacts []string `json:"artefacts"`
}

// Hashes holds keyed hashes used only for equality checks between contexts.
type Hashes struct {
	UA       string `json:"ua"`
	Platform string `json:"platform"`
	Langs    string `json:"langs"`
	Cores    string `json:"cores"`
	TZ       string `json:"tz"`
}

// Engine describes which JavaScript engine the code observed.
type Engine struct {
	Family  string `json:"family"` // v8, spidermonkey, jsc or unknown
	EvalLen int    `json:"evalLen"`
}

// UACH holds low-entropy User-Agent Client Hints.
type UACH struct {
	ChromiumMajor int    `json:"chromiumMajor"`
	Mobile        bool   `json:"mobile"`
	Platform      string `json:"platform"`
}

// Device holds bucketed device claims.
type Device struct {
	Platform     string `json:"platform"`
	Touch        int    `json:"touch"`
	Pointer      string `json:"pointer"` // fine, coarse or none
	ScreenZero   bool   `json:"screenZero"`
	WindowZero   bool   `json:"windowZero"`
	Langs        int    `json:"langs"`
	GPU          string `json:"gpu"`    // software, none or a vendor class
	GPUAPI       string `json:"gpuApi"` // d3d, metal, opengl, vulkan or unknown
	CanvasStable bool   `json:"canvasStable"`
	NotifLie     bool   `json:"notifLie"`
}

// Behaviour holds interaction features computed in the browser. Key values and
// raw coordinates never leave the page.
type Behaviour struct {
	Mode          string  `json:"mode"` // mouse, touch, keyboard or none
	Moves         int     `json:"moves"`
	Clicks        int     `json:"clicks"`
	KbClicks      int     `json:"kbClicks"`
	NoApproach    int     `json:"noApproach"`
	Straightness  float64 `json:"straightness"`
	SpeedCV       float64 `json:"speedCv"`
	DirChanges    int     `json:"dirChanges"`
	Keys          int     `json:"keys"`
	KeyMedianMS   float64 `json:"keyMedianMs"`
	KeyCV         float64 `json:"keyCv"`
	Pastes        int     `json:"pastes"`
	Programmatic  int     `json:"programmatic"`
	Scrolls       int     `json:"scrolls"`
	DwellMS       int64   `json:"dwellMs"`
	Sketch        string  `json:"sketch"`
	CoalescedMean float64 `json:"coalescedMean"`
}
