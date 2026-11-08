//go:build strictonly

package server

import (
	"context"
	"net/http"

	"github.com/Serraniel/SweetCaptcha/internal/config"
)

// standard is empty in strict-only builds. Configuration validation already
// rejects standard-mode sites, so none of these paths can be reached.
type standard struct{}

func newStandard(*config.Config) *standard { return &standard{} }

func (*standard) routes(*http.ServeMux, *Server) {}

func (*standard) submit(w http.ResponseWriter, _ *http.Request, _ *Server, _ *config.Site, _ *claims, _ submitRequest) {
	writeJSON(w, http.StatusInternalServerError, submitResponse{Status: "retry"})
}

func (*standard) register() ([]string, any) { return []string{}, []any{} }

func (*standard) start(context.Context) {}

func (*standard) counterNames(*config.Config) []string { return nil }

func (*standard) wrapListener(srv *http.Server, _ *config.Config) {}
