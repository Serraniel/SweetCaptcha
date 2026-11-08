package config

import (
	"strings"
	"testing"

	"github.com/Serraniel/SweetCaptcha/internal/edition"
)

func TestRulesValidate(t *testing.T) {
	ok := "    rules:\n      - name: scraper\n        match: {user_agent: \"(?i)scrapy\"}\n        force: deny\n      - name: office\n        match: {action: login, header: {name: X-Office, present: true}}\n        adjust: -1.5\n"
	_, err := Parse([]byte(doc(ok)))
	if edition.StrictOnly {
		// Every site is strict in this build, and strict sites have no scoring.
		if err == nil {
			t.Fatal("rules accepted in the strict-only build")
		}
		return
	}
	if err != nil {
		t.Fatalf("valid rules rejected: %v", err)
	}
	for name, rules := range map[string]string{
		"no condition":      "    rules:\n      - name: x\n        match: {}\n        adjust: 1\n",
		"bad regexp":        "    rules:\n      - name: x\n        match: {user_agent: \"(\"}\n        adjust: 1\n",
		"both effects":      "    rules:\n      - name: x\n        match: {hostname: a}\n        adjust: 1\n        force: deny\n",
		"no effect":         "    rules:\n      - name: x\n        match: {hostname: a}\n",
		"adjust too large":  "    rules:\n      - name: x\n        match: {hostname: a}\n        adjust: 9\n",
		"unknown force":     "    rules:\n      - name: x\n        match: {hostname: a}\n        force: maybe\n",
		"unknown address":   "    rules:\n      - name: x\n        match: {address: mars}\n        adjust: 1\n",
		"duplicate name":    "    rules:\n      - name: x\n        match: {hostname: a}\n        adjust: 1\n      - name: x\n        match: {hostname: b}\n        adjust: 1\n",
		"strict mode rules": "    mode: strict\n    rules:\n      - name: x\n        match: {hostname: a}\n        adjust: 1\n",
	} {
		if _, err := Parse([]byte(doc(rules))); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "rule") {
			t.Errorf("%s: unclear error %v", name, err)
		}
	}
}
