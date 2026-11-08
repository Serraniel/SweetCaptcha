//go:build !strictonly

// Package edition reports which build of SweetCaptcha is running.
package edition

// Version is set at build time.
var Version = "dev"

// StrictOnly is true for builds compiled with the strictonly tag, which omit
// every signal collector and the risk engine.
const StrictOnly = false
