package assets

import "embed"

//go:embed all:dist/core
var coreFS embed.FS
