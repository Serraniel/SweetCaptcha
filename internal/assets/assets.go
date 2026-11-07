// Package assets serves the widget bundles compiled from web/.
package assets

import (
	"encoding/json"
	"io/fs"
)

// File is one bundle.
type File struct {
	Path string `json:"path"`
	SRI  string `json:"sri"`
}

// Manifest maps logical names to hashed file names.
type Manifest map[string]File

func load(fsys fs.FS, dir string) (Manifest, fs.FS) {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		return Manifest{}, sub
	}
	raw, err := fs.ReadFile(sub, "manifest.json")
	if err != nil {
		return Manifest{}, sub
	}
	var m Manifest
	if json.Unmarshal(raw, &m) != nil {
		return Manifest{}, sub
	}
	return m, sub
}

// Core returns the bundles every edition ships.
func Core() (Manifest, fs.FS) { return load(coreFS, "dist/core") }
