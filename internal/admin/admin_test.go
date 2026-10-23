package admin

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rossedman/imagegate/internal/verdict"
)

type fakeGate struct {
	mu       sync.Mutex
	warmed   []string
	purged   []string
	purgeN   int
	purgeErr error
}

func (f *fakeGate) Warm(_ context.Context, ref string) (verdict.Verdict, string, error) {
	f.mu.Lock()
	f.warmed = append(f.warmed, ref)
	f.mu.Unlock()
	switch ref {
	case "good":
		return verdict.Verdict{Allow: true, Reason: verdict.Allowed}, "ghcr.io/acme/good@sha256:aa", nil
	case "bad":
		return verdict.Verdict{Reason: verdict.NoSBOM, Detail: "no sbom"}, "ghcr.io/acme/bad@sha256:bb", nil
	default:
		return verdict.Verdict{Allow: true}, "", errors.New("resolve " + ref + ": unauthorized")
	}
}

func (f *fakeGate) PurgeCache(digest string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.purged = append(f.purged, digest)
	return f.purgeN, f.purgeErr
}

func socketDir(t *testing.T) string {
	t.Helper()
	// macOS limits Unix socket paths to 104 bytes.
	if d := t.TempDir(); len(d) < 80 {
		return d
	}
	d, err := os.MkdirTemp("", "adm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// serve runs h on a Unix socket and returns a client for it.
func serve(t *testing.T, h http.Handler) *Client {
	t.Helper()
	sock := filepath.Join(socketDir(t), "a.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return NewClient(sock)
}

func TestWarm(t *testing.T) {
	t.Parallel()
	g := &fakeGate{}
	c := serve(t, Handler(g))
	got, err := c.Warm([]string{"good", "bad", "broken"})
	if err != nil {
		t.Fatal(err)
	}
	want := []WarmResult{
		{Ref: "good", Image: "ghcr.io/acme/good@sha256:aa", Allow: true, Reason: "ALLOWED"},
		{Ref: "bad", Image: "ghcr.io/acme/bad@sha256:bb", Reason: "NO_SBOM", Detail: "no sbom"},
		// An error never reports the verdict fields, even if the gate
		// returned Allow alongside it.
		{Ref: "broken", Error: "resolve broken: unauthorized"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d results: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("result %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if strings.Join(g.warmed, ",") != "good,bad,broken" {
		t.Errorf("warmed %v", g.warmed)
	}

	// No refs: an empty list, not null.
	got, err = c.Warm(nil)
	if err != nil || got == nil || len(got) != 0 {
		t.Errorf("empty warm = %#v, %v", got, err)
	}
}

func TestPurge(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		digest string
		n      int
		err    error
		errHas string
	}{
		{name: "all", digest: "", n: 7},
		{name: "one digest with query characters", digest: "sha256:aa&digest=x y", n: 1},
		{name: "gate error", digest: "sha256:aa", err: errors.New("bolt: database not open"), errHas: "500 Internal Server Error: bolt: database not open"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			g := &fakeGate{purgeN: c.n, purgeErr: c.err}
			n, err := serve(t, Handler(g)).Purge(c.digest)
			if c.errHas != "" {
				if err == nil || err.Error() != c.errHas {
					t.Fatalf("err = %v, want %q", err, c.errHas)
				}
				return
			}
			if err != nil || n != c.n {
				t.Fatalf("purge = %d, %v; want %d", n, err, c.n)
			}
			if len(g.purged) != 1 || g.purged[0] != c.digest {
				t.Errorf("gate saw digest %q, want %q", g.purged, c.digest)
			}
		})
	}
}

func TestHandlerRejects(t *testing.T) {
	t.Parallel()
	g := &fakeGate{}
	h := Handler(g)
	cases := []struct {
		method, path, body string
		status             int
	}{
		{"POST", "/warm", `not json`, http.StatusBadRequest},
		{"POST", "/warm", `{"ref":"x"}`, http.StatusBadRequest},
		{"GET", "/warm", ``, http.StatusMethodNotAllowed},
		{"GET", "/cache/purge", ``, http.StatusMethodNotAllowed},
		{"POST", "/nope", ``, http.StatusNotFound},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, strings.NewReader(c.body)))
		if rec.Code != c.status {
			t.Errorf("%s %s %q = %d, want %d", c.method, c.path, c.body, rec.Code, c.status)
		}
	}
	if len(g.warmed) != 0 || len(g.purged) != 0 {
		t.Errorf("rejected requests reached the gate: %v %v", g.warmed, g.purged)
	}
}

func TestClientErrors(t *testing.T) {
	t.Parallel()

	// Nothing listening.
	c := NewClient(filepath.Join(socketDir(t), "missing.sock"))
	if _, err := c.Warm([]string{"x"}); err == nil || !strings.HasPrefix(err.Error(), "is imagegate running? ") {
		t.Errorf("missing socket: %v", err)
	}
	if _, err := c.Purge(""); err == nil || !strings.HasPrefix(err.Error(), "is imagegate running? ") {
		t.Errorf("missing socket: %v", err)
	}

	// Non-200 bodies are trimmed and limited to 4 KiB.
	c = serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "  "+strings.Repeat("z", 10000), http.StatusTeapot)
	}))
	_, err := c.Warm(nil)
	if err == nil || !strings.HasPrefix(err.Error(), "418 I'm a teapot: zzz") || len(err.Error()) > 4096+len("418 I'm a teapot: ") {
		t.Errorf("non-200: %.80v (len %d)", err, len(err.Error()))
	}

	// A 200 that is not JSON is an error.
	c = serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>"))
	}))
	if _, err := c.Warm(nil); err == nil {
		t.Error("malformed response accepted")
	}
	if _, err := c.Purge(""); err == nil {
		t.Error("malformed response accepted")
	}
}
