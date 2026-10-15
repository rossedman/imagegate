// Command imagegate is a Docker authorization plugin that denies container
// creation unless the image is cosign-signed by a trusted identity and
// carries a signed SBOM attestation.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rossedman/image-gate/internal/admin"
	"github.com/rossedman/image-gate/internal/audit"
	"github.com/rossedman/image-gate/internal/authz"
	"github.com/rossedman/image-gate/internal/cache"
	"github.com/rossedman/image-gate/internal/docker"
	"github.com/rossedman/image-gate/internal/gate"
	"github.com/rossedman/image-gate/internal/metrics"
	"github.com/rossedman/image-gate/internal/policy"
	"github.com/rossedman/image-gate/internal/verify"
)

var version = "dev"

const usage = `imagegate — Docker authorization plugin for image signatures and SBOMs

Usage:
  imagegate serve [flags]           run the plugin (default)
  imagegate validate [-policy path] validate a policy file and print its hash
  imagegate warm <ref>...           pre-verify images on a running imagegate
  imagegate cache purge [digest]    drop cached verdicts on a running imagegate
  imagegate health                  check the plugin socket answers
  imagegate version

Run "imagegate <command> -h" for flags.
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "validate":
		err = validate(args)
	case "warm":
		err = warm(args)
	case "cache":
		err = cachePurge(args)
	case "health":
		err = health(args)
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "imagegate:", err)
		os.Exit(1)
	}
}

type paths struct {
	socket, policy, overrides, registry, cacheDB, tufCache, dockerSocket, adminSocket string
}

func commonFlags(fs *flag.FlagSet) *paths {
	p := &paths{}
	fs.StringVar(&p.socket, "socket", "/run/docker/plugins/imagegate.sock", "plugin socket dockerd discovers")
	fs.StringVar(&p.policy, "policy", "/etc/imagegate/policy.yaml", "policy file")
	fs.StringVar(&p.overrides, "overrides", "/etc/imagegate/overrides.d", "break-glass override directory")
	fs.StringVar(&p.registry, "registry-config", "/etc/imagegate/registry", "directory with config.json and credential helpers for reading signatures")
	fs.StringVar(&p.cacheDB, "cache", "/var/lib/imagegate/cache.db", "persistent verdict cache")
	fs.StringVar(&p.tufCache, "tuf-cache", "/var/lib/imagegate/tuf", "Sigstore TUF metadata cache")
	fs.StringVar(&p.dockerSocket, "docker-socket", "/var/run/docker.sock", "dockerd API socket, for image inspect")
	fs.StringVar(&p.adminSocket, "admin-socket", "/run/imagegate/admin.sock", "root-only admin socket for warm and cache purge")
	return p
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	p := commonFlags(fs)
	metricsAddr := fs.String("metrics-addr", "127.0.0.1:9732", "localhost address for /metrics and /healthz")
	cacheSize := fs.Int("cache-size", 10000, "in-memory verdict cache entries")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	fs.Parse(args)

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*logLevel)); err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)

	// Registry credentials are imagegate's own, never a user's.
	os.Setenv("DOCKER_CONFIG", p.registry)
	os.Setenv("PATH", p.registry+string(os.PathListSeparator)+os.Getenv("PATH"))

	m := metrics.New()
	if err := os.MkdirAll(filepath.Dir(p.cacheDB), 0o700); err != nil {
		return err
	}
	c, err := cache.Open(p.cacheDB, *cacheSize)
	if err != nil {
		return fmt.Errorf("open cache: %w", err)
	}
	defer c.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tuf := verify.NewTUFTrust(p.tufCache, 6*time.Hour, log, func() { m.UpstreamErrors.WithLabelValues("tuf").Inc() })
	var tufOnce sync.Once
	keychain := authn.DefaultKeychain
	compile := func(pol *policy.Policy) (gate.Verifier, error) {
		var trust verify.TrustSource
		if pol.Trust.Sigstore == "public-good" {
			// Background refresh only; never inline with a request.
			tufOnce.Do(func() { go tuf.Run(ctx) })
			trust = tuf
		} else {
			t, err := verify.TrustFromFile(pol.Trust.Sigstore)
			if err != nil {
				return nil, err
			}
			trust = t
		}
		return verify.NewEngine(verify.Options{Trust: trust, Keychain: keychain}).Compile(pol)
	}

	g := gate.New(gate.Config{
		PolicyPath:   p.policy,
		OverridesDir: p.overrides,
		Docker:       docker.New(p.dockerSocket),
		Compile:      compile,
		Resolver:     verify.NewEngine(verify.Options{Keychain: keychain}),
		Cache:        c,
		Audit:        audit.New(os.Stdout),
		Metrics:      m,
		Log:          log,
	})
	_ = g.ReloadPolicy() // an invalid policy at boot denies creates (NO_POLICY)
	g.ReloadOverrides()

	go func() {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		tick := time.NewTicker(10 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				log.Info("SIGHUP: reloading policy and overrides")
				_ = g.ReloadPolicy()
				g.ReloadOverrides()
			case <-tick.C:
				// Overrides are picked up without a signal, and expired
				// ones drop out of the gauge.
				g.ReloadOverrides()
			}
		}
	}()

	plugin, err := listenUnix(p.socket, 0o600)
	if err != nil {
		return err
	}
	adminL, err := listenUnix(p.adminSocket, 0o600)
	if err != nil {
		return err
	}
	metricsL, err := net.Listen("tcp", *metricsAddr)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if g.Policy() == nil {
			http.Error(w, "no valid policy loaded", http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, "ok\n")
	})

	servers := []*http.Server{
		{Handler: &authz.Handler{Gate: g, Log: log}, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second},
		{Handler: admin.Handler(g), ReadTimeout: 30 * time.Second},
		{Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second},
	}
	listeners := []net.Listener{plugin, adminL, metricsL}
	errc := make(chan error, len(servers))
	for i, s := range servers {
		go func() { errc <- s.Serve(listeners[i]) }()
	}
	log.Info("imagegate serving", "version", version, "socket", p.socket, "metrics", *metricsAddr)

	select {
	case <-ctx.Done():
	case err = <-errc:
		log.Error("server stopped", "err", err)
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
	os.Remove(p.socket)
	os.Remove(p.adminSocket)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func listenUnix(path string, mode os.FileMode) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func validate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	path := fs.String("policy", "/etc/imagegate/policy.yaml", "policy file")
	fs.Parse(args)
	if fs.NArg() > 0 {
		*path = fs.Arg(0)
	}
	pol, err := policy.Load(*path)
	if err != nil {
		return err
	}
	if _, err := verify.NewEngine(verify.Options{}).Compile(pol); err != nil {
		return err
	}
	if pol.Trust.Sigstore != "public-good" {
		if _, err := verify.TrustFromFile(pol.Trust.Sigstore); err != nil {
			return err
		}
	}
	fmt.Printf("%s: valid (mode %s, %d rules, policyHash %s)\n", *path, pol.Mode, len(pol.Rules), pol.Hash)
	return nil
}

func warm(args []string) error {
	fs := flag.NewFlagSet("warm", flag.ExitOnError)
	p := commonFlags(fs)
	fs.Parse(args)
	if fs.NArg() == 0 {
		return errors.New("usage: imagegate warm <ref>...")
	}
	res, err := admin.NewClient(p.adminSocket).Warm(fs.Args())
	if err != nil {
		return err
	}
	failed := false
	for _, r := range res {
		switch {
		case r.Error != "":
			failed = true
			fmt.Printf("ERROR  %s: %s\n", r.Ref, r.Error)
		case r.Allow:
			fmt.Printf("ALLOW  %s (%s)\n", r.Image, r.Reason)
		default:
			failed = true
			fmt.Printf("DENY   %s: %s — %s\n", r.Image, r.Reason, r.Detail)
		}
	}
	if failed {
		return errors.New("some images would be denied")
	}
	return nil
}

func cachePurge(args []string) error {
	if len(args) == 0 || args[0] != "purge" {
		return errors.New("usage: imagegate cache purge [digest]")
	}
	fs := flag.NewFlagSet("cache purge", flag.ExitOnError)
	p := commonFlags(fs)
	fs.Parse(args[1:])
	n, err := admin.NewClient(p.adminSocket).Purge(fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Printf("purged %d cached verdicts\n", n)
	return nil
}

// health checks the plugin socket independently of dockerd.
func health(args []string) error {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	p := commonFlags(fs)
	fs.Parse(args)
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", p.socket)
		},
	}}
	resp, err := client.Post("http://plugin/Plugin.Activate", "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("plugin socket answered %s", resp.Status)
	}
	fmt.Println("ok")
	return nil
}
