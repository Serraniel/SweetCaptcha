package config

import (
	"strings"
	"testing"

	"github.com/Serraniel/SweetCaptcha/internal/edition"
)

const validKey = "0000000000000000000000000000000000000000000000000000000000000000"

func doc(site string) string {
	return "secret:\n  master_key: " + validKey + "\nsites:\n  - name: a\n    sitekey: sitekey_a\n    secret: secret_secret_secret\n    hostnames: [example.com, \"*.example.org\"]\n" + site
}

func TestDefaults(t *testing.T) {
	c, err := Parse([]byte(doc("")))
	if err != nil {
		t.Fatal(err)
	}
	s := c.Sites[0]
	if s.PoW.Base.Bits == 0 || s.Policy.PuzzleAbove == 0 || s.TokenTTL == 0 {
		t.Fatalf("defaults not applied: %+v", s)
	}
}

func TestHostAllowed(t *testing.T) {
	c, err := Parse([]byte(doc("")))
	if err != nil {
		t.Fatal(err)
	}
	s := c.Sites[0]
	for host, want := range map[string]bool{
		"example.com": true, "EXAMPLE.com.": true, "a.example.com": false,
		"a.example.org": true, "example.org": false, "evilexample.org": false,
	} {
		if got := s.HostAllowed(host); got != want {
			t.Errorf("HostAllowed(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestRejects(t *testing.T) {
	for name, extra := range map[string]string{
		"bad mode":    "    mode: nonsense\n",
		"bad policy":  "    policy: {step_up_above: 0.9, puzzle_above: 0.5}\n",
		"bad pow":     "    pow: {base: {algo: md5}}\n",
		"unknown key": "    surprise: true\n",
	} {
		if _, err := Parse([]byte(doc(extra))); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := Parse([]byte("sites: []\nsecret:\n  master_key: " + validKey)); err == nil {
		t.Error("expected an error for no sites")
	}
	if _, err := Parse([]byte(strings.ReplaceAll(doc(""), validKey, "short"))); err == nil {
		t.Error("expected an error for a short key")
	}
}

func TestEnvReferencesInCommentsAreIgnored(t *testing.T) {
	if _, err := Parse([]byte("# Values like ${SC_TEST_UNSET} are read from the environment.\n" + doc(""))); err != nil {
		t.Fatal(err)
	}
}

func TestExampleConfigsParse(t *testing.T) {
	for _, name := range []string{"SWEETCAPTCHA_ADMIN_TOKEN", "SWEETCAPTCHA_DEMO_SECRET", "SWEETCAPTCHA_DEMO_STRICT_SECRET"} {
		t.Setenv(name, "a-test-secret-that-is-long-enough-"+name)
	}
	t.Setenv("SWEETCAPTCHA_MASTER_KEY", validKey)
	paths := []string{"../../config/sweetcaptcha.strict.example.yaml"}
	if !edition.StrictOnly {
		paths = append(paths, "../../config/sweetcaptcha.example.yaml")
	}
	for _, path := range paths {
		if _, err := Load(path); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

func TestEnvExpansion(t *testing.T) {
	t.Setenv("SC_TEST_KEY", validKey)
	raw := strings.ReplaceAll(doc(""), validKey, "${SC_TEST_KEY}")
	if _, err := Parse([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(strings.ReplaceAll(doc(""), validKey, "${SC_TEST_UNSET}"))); err == nil {
		t.Error("expected an error for an unset variable")
	}
}
