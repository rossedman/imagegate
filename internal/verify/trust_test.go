package verify

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// testdata/trusted_root.json is the public-good trusted root from the
// sigstore-go examples. testdata/tuf is a static, consistent-snapshot TUF
// repository (expiring 2125) whose only target is that file; root.json is
// its trust anchor.

func TestTrustFromFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	malformed := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(malformed, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("public good", func(t *testing.T) {
		t.Parallel()
		st, err := TrustFromFile(filepath.Join("testdata", "trusted_root.json"))
		if err != nil {
			t.Fatal(err)
		}
		tm, err := st.TrustedMaterial()
		if err != nil {
			t.Fatal(err)
		}
		if len(tm.FulcioCertificateAuthorities()) == 0 || len(tm.RekorLogs()) == 0 || len(tm.CTLogs()) == 0 {
			t.Errorf("trusted root is missing CAs or logs: %d CAs, %d rekor, %d ct",
				len(tm.FulcioCertificateAuthorities()), len(tm.RekorLogs()), len(tm.CTLogs()))
		}
	})
	for _, tc := range []struct {
		name, path string
		is         error
	}{
		{name: "missing", path: filepath.Join(dir, "nope.json"), is: fs.ErrNotExist},
		{name: "malformed", path: malformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st, err := TrustFromFile(tc.path)
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.path) {
				t.Errorf("error %q does not name the file", err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("error %v is not %v", err, tc.is)
			}
			if _, err := st.TrustedMaterial(); !errors.Is(err, ErrNoTrustedRoot) {
				t.Errorf("failed load still provides material: %v", err)
			}
		})
	}
	t.Run("valid but empty root", func(t *testing.T) {
		t.Parallel()
		st, err := TrustFromFile(empty)
		if err != nil {
			t.Fatal(err)
		}
		tm, err := st.TrustedMaterial()
		if err != nil || len(tm.FulcioCertificateAuthorities()) != 0 {
			t.Fatalf("material = %v, %v", tm, err)
		}
	})
}

func TestNewTUFTrustDefaults(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	cases := []struct {
		refresh, want time.Duration
	}{
		{0, 6 * time.Hour},
		{-time.Second, 6 * time.Hour},
		{time.Minute, time.Minute},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		tt := NewTUFTrust(dir, tc.refresh, log, nil)
		if tt.refresh != tc.want {
			t.Errorf("refresh(%v) = %v, want %v", tc.refresh, tt.refresh, tc.want)
		}
		if tt.opts.CachePath != dir {
			t.Errorf("cache path = %q, want %q", tt.opts.CachePath, dir)
		}
		if tt.opts.RepositoryBaseURL == "" || len(tt.opts.Root) == 0 {
			t.Error("public-good TUF defaults are not set")
		}
		tt.onError() // nil onError must be replaced by a no-op
		if _, err := tt.TrustedMaterial(); !errors.Is(err, ErrNoTrustedRoot) {
			t.Errorf("before load: %v, want ErrNoTrustedRoot", err)
		}
	}
	var called bool
	NewTUFTrust(t.TempDir(), 0, log, func() { called = true }).onError()
	if !called {
		t.Error("onError was not kept")
	}
}

// tufRepo serves testdata/tuf over HTTP; down makes every request fail.
type tufRepo struct {
	url      string
	root     []byte
	down     atomic.Bool
	requests atomic.Int64
	// timestamps, when set, receives a value per timestamp.json request
	// (dropped if full).
	timestamps chan struct{}
}

func newTUFRepo(t *testing.T) *tufRepo {
	t.Helper()
	rootJSON, err := os.ReadFile(filepath.Join("testdata", "tuf", "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := &tufRepo{root: rootJSON}
	files := http.FileServer(http.Dir(filepath.Join("testdata", "tuf")))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.requests.Add(1)
		if r.timestamps != nil && strings.HasSuffix(req.URL.Path, "/timestamp.json") {
			select {
			case r.timestamps <- struct{}{}:
			default:
			}
		}
		if r.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		files.ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)
	r.url = srv.URL
	return r
}

// syncBuffer is a log sink safe for concurrent writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (r *tufRepo) trust(t *testing.T, cacheDir string, onError func()) (*TUFTrust, *syncBuffer) {
	t.Helper()
	var buf syncBuffer
	tt := NewTUFTrust(cacheDir, time.Hour, slog.New(slog.NewTextHandler(&buf, nil)), onError)
	tt.opts.Root = r.root
	tt.opts.RepositoryBaseURL = r.url
	return tt, &buf
}

func wantPublicGood(t *testing.T, tm root.TrustedMaterial) {
	t.Helper()
	want, err := root.NewTrustedRootFromPath(filepath.Join("testdata", "trusted_root.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tm.FulcioCertificateAuthorities()) != len(want.FulcioCertificateAuthorities()) || len(tm.RekorLogs()) != len(want.RekorLogs()) {
		t.Fatal("loaded trusted root is not the TUF target")
	}
	for id := range want.RekorLogs() {
		if _, ok := tm.RekorLogs()[id]; !ok {
			t.Fatalf("rekor log %s missing", id)
		}
	}
}

func TestTUFTrustLoad(t *testing.T) {
	t.Parallel()
	repo := newTUFRepo(t)
	cache := t.TempDir()

	// Online: fetch and verify through TUF.
	online, _ := repo.trust(t, cache, nil)
	if err := online.load(); err != nil {
		t.Fatal(err)
	}
	tm, err := online.TrustedMaterial()
	if err != nil {
		t.Fatal(err)
	}
	wantPublicGood(t, tm)

	repo.down.Store(true)

	// A running instance keeps its current root and reports the failure.
	if err := online.load(); err == nil {
		t.Fatal("refresh against a down repository reported success")
	}
	if got, err := online.TrustedMaterial(); err != nil || got != tm {
		t.Fatalf("failed refresh replaced the trusted root: %v", err)
	}

	// A fresh start while offline falls back to the on-disk cache.
	restarted, log := repo.trust(t, cache, nil)
	if err := restarted.load(); err != nil {
		t.Fatalf("cached fallback: %v", err)
	}
	if !strings.Contains(log.String(), "using cached sigstore trusted root") {
		t.Errorf("fallback not logged: %q", log.String())
	}
	tm, err = restarted.TrustedMaterial()
	if err != nil {
		t.Fatal(err)
	}
	wantPublicGood(t, tm)

	// Offline with no cache: no trust, and both failures are reported.
	cold, _ := repo.trust(t, t.TempDir(), nil)
	if err := cold.load(); err == nil {
		t.Fatal("load without network or cache succeeded")
	}
	if _, err := cold.TrustedMaterial(); !errors.Is(err, ErrNoTrustedRoot) {
		t.Fatalf("got %v, want ErrNoTrustedRoot", err)
	}
}

func TestTUFTrustRejectsWrongRoot(t *testing.T) {
	t.Parallel()
	repo := newTUFRepo(t)
	tt, _ := repo.trust(t, t.TempDir(), nil)
	// The public-good root did not sign this repository's metadata.
	tt.opts.Root = NewTUFTrust(t.TempDir(), 0, slog.New(slog.DiscardHandler), nil).opts.Root
	if err := tt.load(); err == nil {
		t.Fatal("metadata signed by an untrusted root was accepted")
	}
	if _, err := tt.TrustedMaterial(); !errors.Is(err, ErrNoTrustedRoot) {
		t.Fatalf("got %v, want ErrNoTrustedRoot", err)
	}
}

func TestTUFTrustRun(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		down      bool
		wantError int64
		wantLog   string
		wantRoot  bool
	}{
		{name: "loads, then stops with the context", wantRoot: true},
		{name: "failure calls onError and logs", down: true, wantError: 1, wantLog: "refresh sigstore trusted root", wantRoot: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			repo := newTUFRepo(t)
			repo.down.Store(tc.down)
			var errs atomic.Int64
			tt, log := repo.trust(t, t.TempDir(), func() { errs.Add(1) })
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			// Run loads once before waiting, then returns because ctx is
			// done.
			tt.Run(ctx)
			if errs.Load() != tc.wantError {
				t.Errorf("onError called %d times, want %d", errs.Load(), tc.wantError)
			}
			if !strings.Contains(log.String(), tc.wantLog) {
				t.Errorf("log = %q, want %q", log.String(), tc.wantLog)
			}
			_, err := tt.TrustedMaterial()
			if (err == nil) != tc.wantRoot {
				t.Errorf("TrustedMaterial err = %v, want root loaded = %v", err, tc.wantRoot)
			}
			if repo.requests.Load() == 0 {
				t.Error("Run did not contact the TUF repository")
			}
		})
	}
}

// TestTUFTrustRunRefreshes checks Run keeps refreshing on its timer until
// the context ends. Every load fetches timestamp.json once.
func TestTUFTrustRunRefreshes(t *testing.T) {
	t.Parallel()
	repo := newTUFRepo(t)
	repo.timestamps = make(chan struct{}, 16)
	tt, _ := repo.trust(t, t.TempDir(), func() { t.Error("refresh failed") })
	tt.refresh = time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tt.Run(ctx)
	}()
	for range 3 {
		select {
		case <-repo.timestamps:
		case <-done:
			t.Fatal("Run returned before the context ended")
		case <-t.Context().Done():
			t.Fatal("test deadline")
		}
	}
	cancel()
	<-done
	if _, err := tt.TrustedMaterial(); err != nil {
		t.Fatal(err)
	}
}
