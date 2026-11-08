//go:build !strictonly

package puzzle

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// TestDumpSamples writes sample images when SC_PUZZLE_DUMP names a directory.
func TestDumpSamples(t *testing.T) {
	dir := os.Getenv("SC_PUZZLE_DUMP")
	if dir == "" {
		t.Skip("set SC_PUZZLE_DUMP to write samples")
	}
	for _, f := range []string{Kinetic, StackOrder} {
		pub, ans, err := Generate(f)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(pub.Images[0], "data:image/png;base64,"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dir+"/"+f+".png", raw, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s answer %v, %d bytes", f, ans.Values, len(raw))
	}
}
