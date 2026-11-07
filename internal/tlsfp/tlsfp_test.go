//go:build !strictonly

package tlsfp

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestParseBrowserLikeHello(t *testing.T) {
	f := Parse(&tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x0a0a, 0x1301, 0x1302},
		SupportedVersions: []uint16{0x2a2a, tls.VersionTLS13, tls.VersionTLS12},
		SupportedProtos:   []string{"h2", "http/1.1"},
		ServerName:        "captcha.example.com",
		Extensions:        []uint16{0x1a1a, 0, 16, 43, 13},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
	})
	if !f.HasGREASE || !f.HasH2 || !f.HasTLS13 {
		t.Errorf("facts: %+v", f)
	}
	if !strings.HasPrefix(f.JA4, "t13d0204h2_") {
		t.Errorf("ja4 prefix: %s", f.JA4)
	}
	parts := strings.Split(f.JA4, "_")
	if len(parts) != 3 || len(parts[1]) != 12 || len(parts[2]) != 12 {
		t.Errorf("ja4 shape: %s", f.JA4)
	}
}

func TestParseHTTPClientHello(t *testing.T) {
	f := Parse(&tls.ClientHelloInfo{CipherSuites: []uint16{0x1301}, SupportedVersions: []uint16{tls.VersionTLS12}})
	if f.HasGREASE || f.HasH2 || f.HasTLS13 {
		t.Errorf("facts: %+v", f)
	}
	if !strings.HasPrefix(f.JA4, "t12i010000_") {
		t.Errorf("ja4: %s", f.JA4)
	}
}

func TestJA4IgnoresOrder(t *testing.T) {
	a := Parse(&tls.ClientHelloInfo{CipherSuites: []uint16{1, 2}, Extensions: []uint16{5, 6}})
	b := Parse(&tls.ClientHelloInfo{CipherSuites: []uint16{2, 1}, Extensions: []uint16{6, 5}})
	if a.JA4 != b.JA4 {
		t.Errorf("%s != %s", a.JA4, b.JA4)
	}
}
