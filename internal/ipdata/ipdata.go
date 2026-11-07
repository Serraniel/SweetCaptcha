//go:build !strictonly

// Package ipdata classifies addresses using local files only. Lookups never
// leave the machine. The files come from `sweetcaptcha ipdata update`, which
// downloads public lists and sends nothing about visitors.
package ipdata

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// File names inside the data directory.
const (
	fileASN   = "ip2asn-combined.tsv"
	fileTor   = "tor-exits.txt"
	fileCloud = "cloud-cidrs.txt"
)

// Sources are the public lists fetched by Update.
var Sources = struct{ ASN, Tor, AWS, GCP string }{
	ASN: "https://iptoasn.com/data/ip2asn-combined.tsv.gz",
	Tor: "https://check.torproject.org/torbulkexitlist",
	AWS: "https://ip-ranges.amazonaws.com/ip-ranges.json",
	GCP: "https://www.gstatic.com/ipranges/cloud.json",
}

// hostingNames matches autonomous systems that mainly sell servers. The list is
// hand-maintained: no free classification of hosting ASNs was found. Residential
// proxies bypass it regardless, so it only carries a small weight.
var hostingNames = regexp.MustCompile(`(?i)\b(amazon|aws|google-cloud|googlecloud|microsoft-corp-msn|azure|digitalocean|ovh|hetzner|linode|akamai-linode|vultr|choopa|constant|oracle|alibaba|tencent|contabo|scaleway|online s\.?a\.?s|leaseweb|m247|datacamp|psychz|colocrossing|hostinger|ionos|netcup|upcloud|fly\.io|gcore|kamatera|quadranet|hostwinds|racknerd|cogent-hosting)\b`)

type asRange struct {
	start, end netip.Addr
	hosting    bool
}

type dataset struct {
	ranges []asRange
	cloud  []netip.Prefix
	tor    map[netip.Addr]bool
}

// DB is a hot-reloadable view of the data directory. A zero or empty DB answers
// false for everything, so the service works without data.
type DB struct {
	dir     string
	current atomic.Pointer[dataset]
	stamp   atomic.Int64
}

// Open loads dir if it holds data.
func Open(dir string) *DB {
	d := &DB{dir: dir}
	d.current.Store(&dataset{tor: map[netip.Addr]bool{}})
	if dir != "" {
		d.reload()
	}
	return d
}

// Watch reloads when the files change, until ctx ends.
func (d *DB) Watch(ctx context.Context, every time.Duration) {
	if d.dir == "" {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reload()
		}
	}
}

func (d *DB) reload() {
	var newest int64
	for _, f := range []string{fileASN, fileTor, fileCloud} {
		if st, err := os.Stat(filepath.Join(d.dir, f)); err == nil && st.ModTime().UnixNano() > newest {
			newest = st.ModTime().UnixNano()
		}
	}
	if newest == 0 || newest == d.stamp.Load() {
		return
	}
	ds, err := load(d.dir)
	if err != nil {
		slog.Warn("ipdata: reload failed", "error", err)
		return
	}
	d.current.Store(ds)
	d.stamp.Store(newest)
	slog.Info("ipdata: loaded", "ranges", len(ds.ranges), "cloud", len(ds.cloud), "tor", len(ds.tor))
}

// Datacenter reports whether addr belongs to a cloud or hosting network.
func (d *DB) Datacenter(addr netip.Addr) bool {
	ds := d.current.Load()
	addr = addr.Unmap()
	for _, p := range ds.cloud {
		if p.Contains(addr) {
			return true
		}
	}
	i := sort.Search(len(ds.ranges), func(i int) bool { return ds.ranges[i].end.Compare(addr) >= 0 })
	return i < len(ds.ranges) && ds.ranges[i].start.Compare(addr) <= 0 && ds.ranges[i].hosting
}

// Tor reports whether addr is a known Tor exit.
func (d *DB) Tor(addr netip.Addr) bool { return d.current.Load().tor[addr.Unmap()] }

func load(dir string) (*dataset, error) {
	ds := &dataset{tor: map[netip.Addr]bool{}}
	if err := readLines(filepath.Join(dir, fileTor), func(l string) {
		if a, err := netip.ParseAddr(l); err == nil {
			ds.tor[a.Unmap()] = true
		}
	}); err != nil {
		return nil, err
	}
	if err := readLines(filepath.Join(dir, fileCloud), func(l string) {
		if p, err := netip.ParsePrefix(l); err == nil {
			ds.cloud = append(ds.cloud, p)
		}
	}); err != nil {
		return nil, err
	}
	ds.cloud = collapse(ds.cloud)
	if err := readLines(filepath.Join(dir, fileASN), func(l string) {
		// range_start, range_end, AS_number, country_code, AS_description
		f := strings.Split(l, "\t")
		if len(f) < 5 || f[2] == "0" {
			return
		}
		start, err1 := netip.ParseAddr(f[0])
		end, err2 := netip.ParseAddr(f[1])
		if err1 != nil || err2 != nil || !hostingNames.MatchString(f[4]) {
			return
		}
		ds.ranges = append(ds.ranges, asRange{start, end, true})
	}); err != nil {
		return nil, err
	}
	sort.Slice(ds.ranges, func(i, j int) bool { return ds.ranges[i].end.Compare(ds.ranges[j].end) < 0 })
	return ds, nil
}

// collapse removes prefixes already covered by a shorter one, which keeps the
// linear scan in Datacenter small.
func collapse(in []netip.Prefix) []netip.Prefix {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Bits() != in[j].Bits() {
			return in[i].Bits() < in[j].Bits()
		}
		return in[i].Addr().Compare(in[j].Addr()) < 0
	})
	var out []netip.Prefix
	for _, p := range in {
		covered := false
		for _, q := range out {
			if q.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	return out
}

func readLines(path string, fn func(string)) error {
	f, err := os.Open(path) //nolint:gosec // Paths are built from the configured data directory.
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			fn(l)
		}
	}
	return sc.Err()
}

// Update downloads all sources into dir. A failed source leaves its previous
// file in place, and the error is returned after the others have been tried.
func Update(ctx context.Context, dir string, client *http.Client) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	var failed []string
	step := func(name string, fn func() error) {
		if err := fn(); err != nil {
			failed = append(failed, name+": "+err.Error())
		}
	}
	step("asn", func() error {
		body, err := fetch(ctx, client, Sources.ASN)
		if err != nil {
			return err
		}
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return err
		}
		plain, err := io.ReadAll(io.LimitReader(zr, 512<<20))
		if err != nil {
			return err
		}
		return writeAtomic(filepath.Join(dir, fileASN), plain)
	})
	step("tor", func() error {
		body, err := fetch(ctx, client, Sources.Tor)
		if err != nil {
			return err
		}
		return writeAtomic(filepath.Join(dir, fileTor), body)
	})
	step("cloud", func() error {
		aws, err := fetch(ctx, client, Sources.AWS)
		if err != nil {
			return err
		}
		gcp, err := fetch(ctx, client, Sources.GCP)
		if err != nil {
			return err
		}
		cidrs, err := cloudCIDRs(aws, gcp)
		if err != nil {
			return err
		}
		return writeAtomic(filepath.Join(dir, fileCloud), []byte(strings.Join(cidrs, "\n")+"\n"))
	})
	if len(failed) > 0 {
		return fmt.Errorf("ipdata update: %s", strings.Join(failed, "; "))
	}
	return nil
}

func cloudCIDRs(aws, gcp []byte) ([]string, error) {
	var a struct {
		Prefixes []struct {
			IP string `json:"ip_prefix"`
		} `json:"prefixes"`
		V6 []struct {
			IP string `json:"ipv6_prefix"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(aws, &a); err != nil {
		return nil, fmt.Errorf("aws: %w", err)
	}
	var g struct {
		Prefixes []struct {
			V4 string `json:"ipv4Prefix"`
			V6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(gcp, &g); err != nil {
		return nil, fmt.Errorf("gcp: %w", err)
	}
	var out []string
	for _, p := range a.Prefixes {
		out = append(out, p.IP)
	}
	for _, p := range a.V6 {
		out = append(out, p.IP)
	}
	for _, p := range g.Prefixes {
		if p.V4 != "" {
			out = append(out, p.V4)
		}
		if p.V6 != "" {
			out = append(out, p.V6)
		}
	}
	return out, nil
}

func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SweetCaptcha-ipdata/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: status %s", url, strconv.Itoa(resp.StatusCode))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
