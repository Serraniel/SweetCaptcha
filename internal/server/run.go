package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"
)

func (s *Server) directPeerTrusted(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && s.trusted(addr.Unmap())
}

func (s *Server) newHTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr: addr, Handler: s.handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
		// net/http logs peer addresses on handshake errors, and this service
		// promises not to record addresses.
		ErrorLog: log.New(io.Discard, "", 0),
	}
}

// Run serves until ctx ends, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	go s.std.start(ctx)
	servers := []*http.Server{s.newHTTPServer(s.cfg.Server.Listen)}
	errs := make(chan error, 2)
	go func() {
		slog.Info("listening", "addr", servers[0].Addr, "tls", false)
		errs <- servers[0].ListenAndServe()
	}()
	if t := s.cfg.Server.TLS; t.Listen != "" {
		ts := s.newHTTPServer(t.Listen)
		ts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
		s.std.wrapListener(ts, s.cfg)
		servers = append(servers, ts)
		go func() {
			slog.Info("listening", "addr", ts.Addr, "tls", true)
			errs <- ts.ListenAndServeTLS(t.CertFile, t.KeyFile)
		}()
	}
	select {
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var first error
	for _, srv := range servers {
		if err := srv.Shutdown(shutdown); err != nil && first == nil {
			first = err
		}
	}
	return first
}
