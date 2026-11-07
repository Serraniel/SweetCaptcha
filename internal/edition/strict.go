//go:build strictonly

// Package edition reports which build of SweetCaptcha is running.
package edition

// StrictOnly is true for builds compiled with the strictonly tag, which omit
// every signal collector and the risk engine.
const StrictOnly = true
