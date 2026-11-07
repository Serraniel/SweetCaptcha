//go:build !strictonly

package assets

import (
	"embed"
	"io/fs"
)

//go:embed all:dist/signals
var signalsFS embed.FS

// Signals returns the collector bundles. Strict-only builds do not embed them.
func Signals() (Manifest, fs.FS) { return load(signalsFS, "dist/signals") }
