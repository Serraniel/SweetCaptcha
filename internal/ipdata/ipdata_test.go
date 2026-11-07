//go:build !strictonly

package ipdata

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestLookups(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(fileASN, "198.51.100.0\t198.51.100.255\t64500\tDE\tHETZNER-AS\n203.0.113.0\t203.0.113.255\t64501\tDE\tDEUTSCHE-TELEKOM\n192.0.2.0\t192.0.2.255\t0\tNone\tNot routed\n")
	write(fileCloud, "100.64.0.0/16\n100.64.1.0/24\n2001:db8::/32\n")
	write(fileTor, "# comment\n192.0.2.9\n")
	d := Open(dir)
	for ip, want := range map[string]bool{
		"198.51.100.7": true, "203.0.113.7": false, "100.64.9.1": true,
		"2001:db8::1": true, "8.8.4.4": false, "::ffff:198.51.100.7": true,
	} {
		if got := d.Datacenter(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Datacenter(%s) = %v, want %v", ip, got, want)
		}
	}
	if !d.Tor(netip.MustParseAddr("192.0.2.9")) || d.Tor(netip.MustParseAddr("192.0.2.10")) {
		t.Error("tor lookup wrong")
	}
}

func TestEmptyDirAnswersFalse(t *testing.T) {
	d := Open("")
	if d.Datacenter(netip.MustParseAddr("198.51.100.7")) || d.Tor(netip.MustParseAddr("192.0.2.9")) {
		t.Error("empty DB returned a positive")
	}
}

func TestCloudCIDRs(t *testing.T) {
	got, err := cloudCIDRs(
		[]byte(`{"prefixes":[{"ip_prefix":"3.0.0.0/8"}],"ipv6_prefixes":[{"ipv6_prefix":"2600::/16"}]}`),
		[]byte(`{"prefixes":[{"ipv4Prefix":"34.0.0.0/8"},{"ipv6Prefix":"2600:1900::/28"}]}`))
	if err != nil || len(got) != 4 {
		t.Fatalf("got %v, %v", got, err)
	}
}
