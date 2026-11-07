//go:build !strictonly

package main

import (
	"os"
	"testing"
)

func TestSignalsDocMatchesRegister(t *testing.T) {
	want := SignalsMarkdown()
	got, err := os.ReadFile("../../docs/SIGNALS.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatal("docs/SIGNALS.md is stale. Regenerate it with: go run ./cmd/sweetcaptcha signals > docs/SIGNALS.md")
	}
}
