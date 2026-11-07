//go:build !strictonly

// Package tlsfp reads TLS ClientHello facts on connections this service
// terminates itself. It implements JA4 (the TLS client fingerprint, BSD-3-Clause,
// FoxIO). The other JA4+ methods are under a more restrictive licence and are
// deliberately not implemented. See NOTICE.
package tlsfp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Facts summarises one ClientHello.
type Facts struct {
	JA4       string
	HasGREASE bool
	HasH2     bool
	HasTLS13  bool
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// Parse derives Facts from a ClientHello.
func Parse(h *tls.ClientHelloInfo) Facts {
	f := Facts{}
	for _, list := range [][]uint16{h.CipherSuites, h.SupportedVersions, h.Extensions} {
		for _, v := range list {
			if isGREASE(v) {
				f.HasGREASE = true
			}
		}
	}
	for _, v := range h.SupportedVersions {
		if v == tls.VersionTLS13 {
			f.HasTLS13 = true
		}
	}
	for _, p := range h.SupportedProtos {
		if p == "h2" {
			f.HasH2 = true
		}
	}
	f.JA4 = ja4(h)
	return f
}

func hex4(v uint16) string { return fmt.Sprintf("%04x", v) }

func truncHash(items []string, tail []string) string {
	if len(items) == 0 {
		return "000000000000"
	}
	s := strings.Join(items, ",")
	if len(tail) > 0 {
		s += "_" + strings.Join(tail, ",")
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func ja4(h *tls.ClientHelloInfo) string {
	version := "00"
	var maxV uint16
	for _, v := range h.SupportedVersions {
		if !isGREASE(v) && v > maxV {
			maxV = v
		}
	}
	switch maxV {
	case tls.VersionTLS13:
		version = "13"
	case tls.VersionTLS12:
		version = "12"
	case tls.VersionTLS11:
		version = "11"
	case tls.VersionTLS10:
		version = "10"
	}
	sni := "i"
	if h.ServerName != "" {
		sni = "d"
	}
	alpn := "00"
	if len(h.SupportedProtos) > 0 && len(h.SupportedProtos[0]) >= 2 {
		p := h.SupportedProtos[0]
		alpn = string(p[0]) + string(p[len(p)-1])
	}
	var ciphers, exts []string
	for _, c := range h.CipherSuites {
		if !isGREASE(c) {
			ciphers = append(ciphers, hex4(c))
		}
	}
	extCount := 0
	for _, e := range h.Extensions {
		if isGREASE(e) {
			continue
		}
		extCount++
		if e != 0 && e != 16 { // SNI and ALPN are excluded from the hash only.
			exts = append(exts, hex4(e))
		}
	}
	sort.Strings(ciphers)
	sort.Strings(exts)
	var sigs []string
	for _, s := range h.SignatureSchemes {
		if !isGREASE(uint16(s)) {
			sigs = append(sigs, hex4(uint16(s)))
		}
	}
	return fmt.Sprintf("t%s%s%02d%02d%s_%s_%s", version, sni, min(len(ciphers), 99), min(extCount, 99), alpn,
		truncHash(ciphers, nil), truncHash(exts, sigs))
}

type ctxKey struct{}

// Capture records ClientHello facts per connection for the lifetime of the conn.
type Capture struct{ conns sync.Map }

// Wrap returns a TLS config that records each ClientHello.
func (c *Capture) Wrap(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	cfg.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		c.conns.Store(h.Conn, Parse(h))
		return nil, nil
	}
	return cfg
}

// ConnContext stores the connection in the request context.
func (c *Capture) ConnContext(ctx context.Context, conn net.Conn) context.Context {
	if t, ok := conn.(*tls.Conn); ok {
		return context.WithValue(ctx, ctxKey{}, t.NetConn())
	}
	return ctx
}

// ConnState forgets facts as soon as a connection closes.
func (c *Capture) ConnState(conn net.Conn, state http.ConnState) {
	if state == http.StateClosed || state == http.StateHijacked {
		if t, ok := conn.(*tls.Conn); ok {
			c.conns.Delete(t.NetConn())
		}
	}
}

// FromContext returns facts for the connection serving ctx, if any.
func (c *Capture) FromContext(ctx context.Context) (Facts, bool) {
	conn := ctx.Value(ctxKey{})
	if conn == nil {
		return Facts{}, false
	}
	v, ok := c.conns.Load(conn)
	if !ok {
		return Facts{}, false
	}
	return v.(Facts), true
}
