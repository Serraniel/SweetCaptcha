// Command sweetcaptcha runs the service and its maintenance tasks.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Serraniel/SweetCaptcha/internal/config"
	"github.com/Serraniel/SweetCaptcha/internal/edition"
	"github.com/Serraniel/SweetCaptcha/internal/server"
	"github.com/Serraniel/SweetCaptcha/internal/store"
)

// version is set at build time.
var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "keygen":
		err = keygen()
	case "healthcheck":
		err = healthcheck(args)
	case "version":
		fmt.Printf("sweetcaptcha %s strict_only=%v\n", version, edition.StrictOnly)
	default:
		if !extraCommand(cmd, args, &err) {
			err = fmt.Errorf("unknown command %q; expected serve, keygen, healthcheck, version%s", cmd, extraCommandNames)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", "/etc/sweetcaptcha/config.yaml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	var st store.Store = store.NewMemory()
	if cfg.Store.Type == "valkey" {
		v, err := store.NewValkey(cfg.Store.URL)
		if err != nil {
			return fmt.Errorf("store: %w", err)
		}
		st = v
	}
	defer st.Close()
	srv, err := server.New(cfg, st)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	slog.Info("starting", "version", version, "strict_only", edition.StrictOnly, "sites", len(cfg.Sites))
	return srv.Run(ctx)
}

func keygen() error {
	master := make([]byte, 32)
	secret := make([]byte, 24)
	key := make([]byte, 12)
	for _, b := range [][]byte{master, secret, key} {
		if _, err := rand.Read(b); err != nil {
			return err
		}
	}
	fmt.Printf("SWEETCAPTCHA_MASTER_KEY=%s\n", hex.EncodeToString(master))
	fmt.Printf("sitekey: sc_%s\n", base64.RawURLEncoding.EncodeToString(key))
	fmt.Printf("secret:  %s\n", base64.RawURLEncoding.EncodeToString(secret))
	return nil
}

// healthcheck lets the distroless container probe itself, since it has no shell.
func healthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:8080/readyz", "URL to probe")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(*url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
