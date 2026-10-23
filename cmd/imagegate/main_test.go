package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rossedman/imagegate/internal/admin"
	"github.com/rossedman/imagegate/internal/authz"
	"github.com/rossedman/imagegate/internal/verdict"
)

// shortDir returns a temp directory short enough for Unix socket paths
// (macOS limits them to 104 bytes; t.TempDir can exceed that).
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "ig")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// stdoutMu serializes tests that swap os.Stdout.
var stdoutMu sync.Mutex

// run calls fn with os.Stdout redirected and returns what it wrote and
// fn's error.
func run(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	orig := os.Stdout
	os.Stdout = w
	ferr := func() error {
		defer func() { os.Stdout = orig }()
		return fn()
	}()
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return string(out), ferr
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// minimalTrustedRoot is the smallest trusted_root.json sigstore-go accepts;
// it lets tests use a file trust source instead of public-good TUF, which
// would reach the network.
const minimalTrustedRoot = `{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`

func policyYAML(mode, trust string) string {
	return fmt.Sprintf(`apiVersion: imagegate.dev/v1
mode: %s
defaults:
  failClosed: true
  verifyTimeout: 10s
  cache:
    allowTTL: 24h
    denyTTL: 60s
trust:
  sigstore: %s
identities:
  ci-main:
    issuer: https://token.actions.githubusercontent.com
    subjectRegExp: ^https://github\.com/example-org/.+$
localImages: deny
rules:
  - name: internal
    images: ["ghcr.io/example-org/**"]
    signature:
      identities: [ci-main]
    sbom:
      identities: [ci-main]
`, mode, trust)
}

func TestCommonFlagsDefaults(t *testing.T) {
	t.Parallel()
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	p := commonFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	want := paths{
		socket:       "/run/docker/plugins/imagegate.sock",
		policy:       "/etc/imagegate/policy.yaml",
		overrides:    "/etc/imagegate/overrides.d",
		registry:     "/etc/imagegate/registry",
		cacheDB:      "/var/lib/imagegate/cache.db",
		tufCache:     "/var/lib/imagegate/tuf",
		dockerSocket: "/var/run/docker.sock",
		adminSocket:  "/run/imagegate/admin.sock",
	}
	if *p != want {
		t.Errorf("defaults = %+v, want %+v", *p, want)
	}

	fs = flag.NewFlagSet("x", flag.ContinueOnError)
	p = commonFlags(fs)
	err := fs.Parse([]string{
		"-socket", "a", "-policy", "b", "-overrides", "c", "-registry-config", "d",
		"-cache", "e", "-tuf-cache", "f", "-docker-socket", "g", "-admin-socket", "h",
	})
	if err != nil {
		t.Fatal(err)
	}
	want = paths{"a", "b", "c", "d", "e", "f", "g", "h"}
	if *p != want {
		t.Errorf("parsed = %+v, want %+v", *p, want)
	}
}

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	trustFile := filepath.Join(dir, "trusted_root.json")
	writeFile(t, trustFile, minimalTrustedRoot)

	fileTrust := filepath.Join(dir, "file-trust.yaml")
	writeFile(t, fileTrust, policyYAML("enforce", trustFile))
	missingTrust := filepath.Join(dir, "missing-trust.yaml")
	writeFile(t, missingTrust, policyYAML("enforce", filepath.Join(dir, "nope.json")))
	badTrust := filepath.Join(dir, "bad-trust.yaml")
	garbage := filepath.Join(dir, "garbage.json")
	writeFile(t, garbage, "not json")
	writeFile(t, badTrust, policyYAML("enforce", garbage))
	badYAML := filepath.Join(dir, "bad.yaml")
	writeFile(t, badYAML, "apiVersion: [unclosed\n")
	missingKey := filepath.Join(dir, "missing-key.yaml")
	writeFile(t, missingKey, strings.Replace(policyYAML("enforce", "public-good"),
		"  ci-main:\n    issuer: https://token.actions.githubusercontent.com\n    subjectRegExp: ^https://github\\.com/example-org/.+$\n",
		"  ci-main:\n    publicKey: "+filepath.Join(dir, "absent.pub")+"\n", 1))

	garbageKey := filepath.Join(dir, "garbage.pub")
	writeFile(t, garbageKey, "not a PEM key")
	badKey := filepath.Join(dir, "bad-key.yaml")
	writeFile(t, badKey, strings.Replace(policyYAML("enforce", "public-good"),
		"  ci-main:\n    issuer: https://token.actions.githubusercontent.com\n    subjectRegExp: ^https://github\\.com/example-org/.+$\n",
		"  ci-main:\n    publicKey: "+garbageKey+"\n", 1))

	tests := []struct {
		name    string
		args    []string
		wantOut string // substring of stdout on success
		wantErr string // substring of the error, empty for success
	}{
		{
			name:    "shipped package policy via flag",
			args:    []string{"-policy", "../../packaging/policy.yaml"},
			wantOut: "../../packaging/policy.yaml: valid (mode audit, 1 rules, policyHash ",
		},
		{
			name:    "positional path wins over flag",
			args:    []string{"-policy", "/nonexistent", fileTrust},
			wantOut: fileTrust + ": valid (mode enforce, 1 rules, policyHash ",
		},
		{name: "default path is missing", args: nil, wantErr: "/etc/imagegate/policy.yaml"},
		{name: "unparseable yaml", args: []string{badYAML}, wantErr: "parse policy"},
		{name: "malformed public key fails compile", args: []string{badKey}, wantErr: "garbage.pub"},
		{name: "public key that does not exist fails load", args: []string{missingKey}, wantErr: "absent.pub"},
		{name: "example policy references keys not on this host", args: []string{"../../deploy/policy.example.yaml"}, wantErr: "vendor.pub"},
		{name: "trusted root file missing", args: []string{missingTrust}, wantErr: "nope.json"},
		{name: "trusted root file malformed", args: []string{badTrust}, wantErr: "garbage.json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.args == nil {
				if _, err := os.Stat("/etc/imagegate/policy.yaml"); err == nil {
					t.Fatal("test assumes /etc/imagegate/policy.yaml does not exist on this host")
				}
			}
			out, err := run(t, func() error { return validate(tc.args) })
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				if out != "" {
					t.Errorf("stdout on error = %q, want empty", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if !strings.HasPrefix(out, tc.wantOut) || !strings.HasSuffix(out, ")\n") {
				t.Errorf("stdout = %q, want prefix %q", out, tc.wantOut)
			}
			hash := strings.TrimSuffix(out[len(tc.wantOut):], ")\n")
			if len(hash) != 64 {
				t.Errorf("policyHash %q is not a sha256 hex digest", hash)
			}
		})
	}
}

func TestListenUnix(t *testing.T) {
	t.Parallel()
	dir := shortDir(t)

	t.Run("creates parent dir and sets mode", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "a", "b", "s.sock")
		l, err := listenUnix(path, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSocket == 0 {
			t.Errorf("mode %v is not a socket", fi.Mode())
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("perm = %o, want 600", got)
		}
		if l.Addr().Network() != "unix" {
			t.Errorf("network = %s", l.Addr().Network())
		}
		pfi, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if !pfi.IsDir() {
			t.Error("parent is not a directory")
		}
	})

	t.Run("other mode is applied", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "m.sock")
		l, err := listenUnix(path, 0o660)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o660 {
			t.Errorf("perm = %o, want 660", got)
		}
	})

	t.Run("replaces a stale file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "stale.sock")
		writeFile(t, path, "stale")
		l, err := listenUnix(path, 0o600)
		if err != nil {
			t.Fatalf("stale file not replaced: %v", err)
		}
		defer func() { _ = l.Close() }()
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatalf("dial replaced socket: %v", err)
		}
		_ = c.Close()
	})

	t.Run("replaces a stale socket from a dead listener", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "dead.sock")
		first, err := listenUnix(path, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		// Keep the socket file on close, as a crashed process would.
		first.(*net.UnixListener).SetUnlinkOnClose(false)
		_ = first.Close()
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("stale socket should remain: %v", err)
		}
		l, err := listenUnix(path, 0o600)
		if err != nil {
			t.Fatalf("stale socket not replaced: %v", err)
		}
		_ = l.Close()
	})

	errCases := []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{"parent is a file", func(t *testing.T) string {
			f := filepath.Join(dir, "file")
			writeFile(t, f, "x")
			return filepath.Join(f, "s.sock")
		}},
		{"path is a non-empty directory", func(t *testing.T) string {
			d := filepath.Join(dir, "full")
			if err := os.MkdirAll(filepath.Join(d, "child"), 0o700); err != nil {
				t.Fatal(err)
			}
			return d
		}},
		{"path too long for a unix socket", func(t *testing.T) string {
			return filepath.Join(dir, strings.Repeat("x", 200))
		}},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, err := listenUnix(tc.setup(t), 0o600)
			if err == nil {
				_ = l.Close()
				t.Fatal("want error")
			}
			if l != nil {
				t.Error("listener must be nil on error")
			}
		})
	}
}

// fakeGate is an admin.Gate with canned answers.
type fakeGate struct {
	mu       sync.Mutex
	purged   []string
	purgeErr error
	warm     map[string]verdict.Verdict
}

func (f *fakeGate) Warm(_ context.Context, ref string) (verdict.Verdict, string, error) {
	v, ok := f.warm[ref]
	if !ok {
		return verdict.Verdict{}, "", errors.New("cannot resolve " + ref)
	}
	return v, "img-" + ref, nil
}

func (f *fakeGate) PurgeCache(digest string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.purged = append(f.purged, digest)
	if f.purgeErr != nil {
		return 0, f.purgeErr
	}
	return 7, nil
}

// serveUnix serves h on a fresh unix socket and returns its path.
func serveUnix(t *testing.T, h http.Handler) string {
	t.Helper()
	path := filepath.Join(shortDir(t), "s.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return path
}

func TestWarm(t *testing.T) {
	g := &fakeGate{warm: map[string]verdict.Verdict{
		"good": {Allow: true, Reason: verdict.Reason("SIGNED")},
		"bad":  {Allow: false, Reason: verdict.Reason("NO_SIGNATURE"), Detail: "nothing found"},
	}}
	sock := serveUnix(t, admin.Handler(g))
	missing := filepath.Join(shortDir(t), "none.sock")

	tests := []struct {
		name    string
		args    []string
		wantOut []string
		wantErr string
	}{
		{name: "no refs", args: []string{"-admin-socket", sock}, wantErr: "usage: imagegate warm <ref>"},
		{name: "server not running", args: []string{"-admin-socket", missing, "good"}, wantErr: "is imagegate running?"},
		{name: "all allowed", args: []string{"-admin-socket", sock, "good"}, wantOut: []string{"ALLOW  img-good (SIGNED)\n"}},
		{
			name:    "deny fails",
			args:    []string{"-admin-socket", sock, "good", "bad"},
			wantOut: []string{"ALLOW  img-good (SIGNED)\n", "DENY   img-bad: NO_SIGNATURE — nothing found\n"},
			wantErr: "some images would be denied",
		},
		{
			name:    "error fails",
			args:    []string{"-admin-socket", sock, "ugly"},
			wantOut: []string{"ERROR  ugly: cannot resolve ugly\n"},
			wantErr: "some images would be denied",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := run(t, func() error { return warm(tc.args) })
			if want := strings.Join(tc.wantOut, ""); out != want {
				t.Errorf("stdout = %q, want %q", out, want)
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestCachePurge(t *testing.T) {
	ok := &fakeGate{}
	okSock := serveUnix(t, admin.Handler(ok))
	failing := &fakeGate{purgeErr: errors.New("bolt is closed")}
	failSock := serveUnix(t, admin.Handler(failing))
	missing := filepath.Join(shortDir(t), "none.sock")

	tests := []struct {
		name       string
		gate       *fakeGate
		args       []string
		wantOut    string
		wantErr    string
		wantPurged []string
	}{
		{name: "no subcommand", args: nil, wantErr: "usage: imagegate cache purge [digest]"},
		{name: "wrong subcommand", args: []string{"list"}, wantErr: "usage: imagegate cache purge [digest]"},
		{name: "server not running", args: []string{"purge", "-admin-socket", missing}, wantErr: "is imagegate running?"},
		{name: "purge all", gate: ok, args: []string{"purge", "-admin-socket", okSock}, wantOut: "purged 7 cached verdicts\n", wantPurged: []string{""}},
		{name: "purge one digest", gate: ok, args: []string{"purge", "-admin-socket", okSock, "sha256:abc"}, wantOut: "purged 7 cached verdicts\n", wantPurged: []string{"sha256:abc"}},
		{name: "server error", gate: failing, args: []string{"purge", "-admin-socket", failSock}, wantErr: "bolt is closed", wantPurged: []string{""}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.gate != nil {
				tc.gate.mu.Lock()
				tc.gate.purged = nil
				tc.gate.mu.Unlock()
			}
			out, err := run(t, func() error { return cachePurge(tc.args) })
			if out != tc.wantOut {
				t.Errorf("stdout = %q, want %q", out, tc.wantOut)
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
			if tc.gate != nil {
				tc.gate.mu.Lock()
				got := tc.gate.purged
				tc.gate.mu.Unlock()
				if strings.Join(got, ",") != strings.Join(tc.wantPurged, ",") || len(got) != len(tc.wantPurged) {
					t.Errorf("purged = %q, want %q", got, tc.wantPurged)
				}
			}
		})
	}
}

func TestHealth(t *testing.T) {
	var gotMethod, gotPath string
	var mu sync.Mutex
	okSock := serveUnix(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotMethod, gotPath = r.Method, r.URL.Path
		mu.Unlock()
		_, _ = io.WriteString(w, `{"Implements":["authz"]}`)
	}))
	badSock := serveUnix(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	missing := filepath.Join(shortDir(t), "none.sock")

	tests := []struct {
		name    string
		sock    string
		wantOut string
		wantErr string
	}{
		{name: "healthy", sock: okSock, wantOut: "ok\n"},
		{name: "non-200", sock: badSock, wantErr: "plugin socket answered 500 Internal Server Error"},
		{name: "no socket", sock: missing, wantErr: "none.sock"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := run(t, func() error { return health([]string{"-socket", tc.sock}) })
			if out != tc.wantOut {
				t.Errorf("stdout = %q, want %q", out, tc.wantOut)
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
	mu.Lock()
	defer mu.Unlock()
	if gotMethod != http.MethodPost || gotPath != "/Plugin.Activate" {
		t.Errorf("health called %s %s, want POST /Plugin.Activate", gotMethod, gotPath)
	}
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func unixClient(sock string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
}

// eventually polls cond until it returns nil or the deadline passes.
func eventually(t *testing.T, what string, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		err := cond()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %v", what, err)
		}
		<-tick.C
	}
}

func authzReq(t *testing.T, c *http.Client, req authz.Request) authz.Response {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Post("http://plugin/AuthZPlugin.AuthZReq", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out authz.Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func healthz(c *http.Client, addr string) (int, error) {
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// TestServe runs the real server end to end: it boots with an invalid
// policy (healthz 503, creates denied), reloads a valid one on SIGHUP, and
// stops cleanly on SIGTERM. The test registers its own handlers for both
// signals first, so a signal can never hit the default action and kill the
// test binary.
func TestServe(t *testing.T) {
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGTERM)
	t.Cleanup(func() { signal.Stop(sigs) })

	dir := shortDir(t)
	reg := filepath.Join(dir, "registry")
	// serve rewrites DOCKER_CONFIG and PATH; restore them afterwards.
	t.Setenv("DOCKER_CONFIG", os.Getenv("DOCKER_CONFIG"))
	t.Setenv("PATH", os.Getenv("PATH"))

	trustFile := filepath.Join(dir, "trusted_root.json")
	writeFile(t, trustFile, minimalTrustedRoot)
	polPath := filepath.Join(dir, "policy.yaml")
	// Boot with a policy whose trusted root is malformed: it loads but
	// fails to compile, so no policy is active.
	badRoot := filepath.Join(dir, "bad-root.json")
	writeFile(t, badRoot, "not json")
	writeFile(t, polPath, policyYAML("enforce", badRoot))

	plugin := filepath.Join(dir, "run", "p.sock")
	adminSock := filepath.Join(dir, "run", "a.sock")
	metricsAddr := freeTCPAddr(t)
	args := []string{
		"-socket", plugin,
		"-admin-socket", adminSock,
		"-policy", polPath,
		"-overrides", filepath.Join(dir, "overrides.d"),
		"-registry-config", reg,
		"-cache", filepath.Join(dir, "state", "cache.db"),
		"-tuf-cache", filepath.Join(dir, "tuf"),
		"-docker-socket", filepath.Join(dir, "no-docker.sock"),
		"-metrics-addr", metricsAddr,
		"-log-level", "error",
	}

	errc := make(chan error, 1)
	go func() { errc <- serve(args) }()

	pc := unixClient(plugin)
	eventually(t, "plugin socket answers", func() error {
		select {
		case err := <-errc:
			t.Fatalf("serve exited early: %v", err)
		default:
		}
		resp, err := pc.Post("http://plugin/Plugin.Activate", "application/json", nil)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		if strings.TrimSpace(string(b)) != `{"Implements":["authz"]}` {
			return fmt.Errorf("activate = %s", b)
		}
		return nil
	})

	if got := os.Getenv("DOCKER_CONFIG"); got != reg {
		t.Errorf("DOCKER_CONFIG = %q, want %q", got, reg)
	}
	if got := os.Getenv("PATH"); !strings.HasPrefix(got, reg+string(os.PathListSeparator)) {
		t.Errorf("PATH = %q, want prefix %q", got, reg)
	}
	for _, s := range []string{plugin, adminSock} {
		fi, err := os.Stat(s)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s perm = %o, want 600", s, fi.Mode().Perm())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "cache.db")); err != nil {
		t.Errorf("cache db not created: %v", err)
	}

	hc := &http.Client{Timeout: 5 * time.Second}
	if code, err := healthz(hc, metricsAddr); err != nil || code != http.StatusServiceUnavailable {
		t.Errorf("healthz with no policy = %d, %v; want 503", code, err)
	}
	resp, err := hc.Get("http://" + metricsAddr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	mb, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(mb), "imagegate_") {
		t.Errorf("metrics = %d, body lacks imagegate_ metrics", resp.StatusCode)
	}

	// Invariant 1: non-gated calls are allowed even with no policy.
	if r := authzReq(t, pc, authz.Request{RequestMethod: "GET", RequestURI: "/v1.47/info"}); !r.Allow {
		t.Errorf("GET /info denied: %+v", r)
	}
	// Invariant 2: a gated create fails closed with no valid policy.
	create := authz.Request{RequestMethod: "POST", RequestURI: "/v1.47/containers/create", RequestBody: []byte(`{"Image":"ghcr.io/example-org/app:1"}`)}
	if r := authzReq(t, pc, create); r.Allow {
		t.Errorf("create allowed with no policy: %+v", r)
	}

	// The health subcommand works against the real plugin socket.
	if out, err := run(t, func() error { return health([]string{"-socket", plugin}) }); err != nil || out != "ok\n" {
		t.Errorf("health = %q, %v", out, err)
	}
	// And cache purge against the real admin socket.
	if out, err := run(t, func() error { return cachePurge([]string{"purge", "-admin-socket", adminSock}) }); err != nil || out != "purged 0 cached verdicts\n" {
		t.Errorf("cache purge = %q, %v", out, err)
	}

	// Fix the policy and reload it with SIGHUP until healthz goes green.
	// The reload goroutine may not have registered for SIGHUP yet, so
	// resend on every poll; our own registration keeps it harmless.
	writeFile(t, polPath, policyYAML("enforce", trustFile))
	eventually(t, "SIGHUP reload makes healthz ok", func() error {
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			return err
		}
		code, err := healthz(hc, metricsAddr)
		if err != nil {
			return err
		}
		if code != http.StatusOK {
			return fmt.Errorf("healthz = %d", code)
		}
		return nil
	})

	// With a policy, a create still fails closed: dockerd is unreachable.
	if r := authzReq(t, pc, create); r.Allow {
		t.Errorf("create allowed with dockerd unreachable: %+v", r)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve returned %v after SIGTERM, want nil", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not stop after SIGTERM")
	}
	for _, s := range []string{plugin, adminSock} {
		if _, err := os.Stat(s); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s not removed on shutdown: %v", s, err)
		}
	}
}

func TestServeErrors(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", os.Getenv("DOCKER_CONFIG"))
	t.Setenv("PATH", os.Getenv("PATH"))
	dir := shortDir(t)
	afile := filepath.Join(dir, "afile")
	writeFile(t, afile, "x")

	base := func(name string, extra ...string) []string {
		d := filepath.Join(dir, name)
		args := []string{
			"-socket", filepath.Join(d, "p.sock"),
			"-admin-socket", filepath.Join(d, "a.sock"),
			"-policy", filepath.Join(d, "policy.yaml"),
			"-overrides", filepath.Join(d, "overrides.d"),
			"-registry-config", filepath.Join(d, "reg"),
			"-cache", filepath.Join(d, "cache.db"),
			"-tuf-cache", filepath.Join(d, "tuf"),
			"-docker-socket", filepath.Join(d, "docker.sock"),
			"-metrics-addr", "127.0.0.1:0",
			"-log-level", "error",
		}
		return append(args, extra...)
	}
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"bad log level", base("ll", "-log-level", "loud"), "loud"},
		{"cache dir under a file", base("cd", "-cache", filepath.Join(afile, "c.db")), "afile"},
		{"cache path is a directory", base("cp", "-cache", dir), "open cache"},
		{"plugin socket under a file", base("ps", "-socket", filepath.Join(afile, "p.sock")), "afile"},
		{"admin socket under a file", base("as", "-admin-socket", filepath.Join(afile, "a.sock")), "afile"},
		{"bad metrics address", base("ma", "-metrics-addr", "not-an-address"), "not-an-address"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := serve(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestMainInProcess covers main's dispatch for commands that return
// instead of exiting.
func TestMainInProcess(t *testing.T) {
	adminSock := serveUnix(t, admin.Handler(&fakeGate{warm: map[string]verdict.Verdict{
		"good": {Allow: true, Reason: verdict.Reason("SIGNED")},
	}}))
	pluginSock := serveUnix(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "{}")
	}))
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"warm", "-admin-socket", adminSock, "good"}, "ALLOW  img-good (SIGNED)\n"},
		{[]string{"cache", "purge", "-admin-socket", adminSock}, "purged 7 cached verdicts\n"},
		{[]string{"health", "-socket", pluginSock}, "ok\n"},
		{[]string{"version"}, version + "\n"},
		{[]string{"help"}, usage},
		{[]string{"validate", "../../packaging/policy.yaml"}, "../../packaging/policy.yaml: valid (mode audit"},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			orig := os.Args
			os.Args = append([]string{"imagegate"}, tc.args...)
			defer func() { os.Args = orig }()
			out, _ := run(t, func() error { main(); return nil })
			if !strings.HasPrefix(out, tc.want) {
				t.Errorf("stdout = %q, want prefix %q", out, tc.want)
			}
		})
	}
}

const mainArgsEnv = "IMAGEGATE_TEST_MAIN_ARGS"

// TestMainSubprocess re-executes the test binary to run main with args
// that end in os.Exit.
func TestMainSubprocess(t *testing.T) {
	if args, ok := os.LookupEnv(mainArgsEnv); ok {
		os.Args = append([]string{"imagegate"}, strings.Fields(args)...)
		main()
		os.Exit(0)
	}
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	tests := []struct {
		name       string
		args       string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version", args: "version", wantCode: 0, wantStdout: version + "\n"},
		// A leading flag selects serve, so -h and --help print serve's
		// flags rather than the command usage.
		{name: "help flag goes to serve", args: "--help", wantCode: 0, wantStderr: "Usage of serve:"},
		{name: "short help flag goes to serve", args: "-h", wantCode: 0, wantStderr: "Usage of serve:"},
		{name: "unknown command", args: "frobnicate", wantCode: 2, wantStderr: usage},
		{name: "command error", args: "validate " + missing, wantCode: 1, wantStderr: "imagegate: "},
		{name: "default is serve", args: "-log-level loud", wantCode: 1, wantStderr: "imagegate: "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestMainSubprocess$")
			cmd.Env = append(os.Environ(), mainArgsEnv+"="+tc.args)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d (stderr %q)", code, tc.wantCode, stderr.String())
			}
			if tc.wantStdout != "" && stdout.String() != tc.wantStdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), tc.wantStdout)
			}
			if !strings.HasPrefix(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want prefix %q", stderr.String(), tc.wantStderr)
			}
		})
	}
}
