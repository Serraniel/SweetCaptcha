//go:build strictonly

package assets

import (
	"io/fs"
	"testing/fstest"
)

// Signals is empty in strict-only builds: the collector code is not in the binary.
func Signals() (Manifest, fs.FS) { return Manifest{}, fstest.MapFS{} }
