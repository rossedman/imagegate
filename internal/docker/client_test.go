package docker

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
)

// socketDir returns a short temporary directory: macOS limits Unix socket
// paths to 104 bytes, which t.TempDir's test-name-derived path can exceed.
func socketDir(t *testing.T) string {
	t.Helper()
	if d := t.TempDir(); len(d) < 80 {
		return d
	}
	d, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// fakeDockerd serves h on a Unix socket and returns the socket path and a
// function that returns every request path it saw.
func fakeDockerd(t *testing.T, h http.HandlerFunc) (string, func() []string) {
	t.Helper()
	sock := filepath.Join(socketDir(t), "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		h(w, r)
	}))
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return sock, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

func reply(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func TestInspectImage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		status   int
		body     string
		want     *Image
		notFound bool
		errHas   []string
	}{
		{
			name:   "ok",
			status: 200,
			body: `{"Id":"sha256:11","RepoTags":["ghcr.io/acme/api:1"],"RepoDigests":["ghcr.io/acme/api@sha256:aa"],` +
				`"Os":"linux","Architecture":"arm64","Variant":"v8","Size":123}`,
			want: &Image{
				ID: "sha256:11", RepoTags: []string{"ghcr.io/acme/api:1"}, RepoDigests: []string{"ghcr.io/acme/api@sha256:aa"},
				Os: "linux", Architecture: "arm64", Variant: "v8",
			},
		},
		{name: "404", status: 404, body: `{"message":"No such image: ghcr.io/acme/api:1"}`, notFound: true},
		{name: "500", status: 500, body: "  daemon on fire \n", errHas: []string{"dockerd: GET /images/ghcr.io/acme/api:1/json", "500 Internal Server Error", ": daemon on fire"}},
		{name: "503 truncated body", status: 503, body: strings.Repeat("y", 4096), errHas: []string{"503", strings.Repeat("y", 512)}},
		{name: "malformed JSON", status: 200, body: `{"Id":`, errHas: []string{"unexpected EOF"}},
		{name: "wrong JSON type", status: 200, body: `{"Id":5}`, errHas: []string{"cannot unmarshal"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			sock, seen := fakeDockerd(t, reply(c.status, c.body))
			img, err := New(sock).InspectImage(t.Context(), "ghcr.io/acme/api:1")
			if got := seen(); len(got) != 1 || got[0] != "GET /images/ghcr.io/acme/api:1/json" {
				t.Errorf("requests = %v", got)
			}
			switch {
			case c.notFound:
				if !errors.Is(err, ErrNotFound) || img != nil {
					t.Fatalf("got %v, %v; want ErrNotFound", img, err)
				}
			case c.errHas != nil:
				if err == nil || img != nil || errors.Is(err, ErrNotFound) {
					t.Fatalf("got %v, %v; want error", img, err)
				}
				for _, s := range c.errHas {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("error %q missing %q", err, s)
					}
				}
				if c.status == 503 && strings.Contains(err.Error(), strings.Repeat("y", 513)) {
					t.Error("error body not limited to 512 bytes")
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				if img.ID != c.want.ID || img.Os != c.want.Os || img.Architecture != c.want.Architecture || img.Variant != c.want.Variant ||
					strings.Join(img.RepoTags, ",") != strings.Join(c.want.RepoTags, ",") ||
					strings.Join(img.RepoDigests, ",") != strings.Join(c.want.RepoDigests, ",") {
					t.Errorf("image = %+v, want %+v", img, c.want)
				}
			}
		})
	}
}

func TestInspectContainer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		status   int
		body     string
		notFound bool
		wantErr  bool
	}{
		{name: "ok", status: 200, body: `{"Id":"c1","Image":"sha256:11","Config":{"Image":"ghcr.io/acme/api:1","Cmd":["x"]}}`},
		{name: "404", status: 404, body: `{"message":"No such container"}`, notFound: true},
		{name: "500", status: 500, body: "boom", wantErr: true},
		{name: "malformed", status: 200, body: `not json`, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			sock, seen := fakeDockerd(t, reply(c.status, c.body))
			ct, err := New(sock).InspectContainer(t.Context(), "web/db")
			if got := seen(); len(got) != 1 || got[0] != "GET /containers/web/db/json" {
				t.Errorf("requests = %v", got)
			}
			switch {
			case c.notFound:
				if !errors.Is(err, ErrNotFound) || ct != nil {
					t.Fatalf("got %v, %v; want ErrNotFound", ct, err)
				}
			case c.wantErr:
				if err == nil || ct != nil || errors.Is(err, ErrNotFound) {
					t.Fatalf("got %v, %v; want error", ct, err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				if ct.ID != "c1" || ct.Image != "sha256:11" || ct.Config.Image != "ghcr.io/acme/api:1" {
					t.Errorf("container = %+v", ct)
				}
			}
		})
	}
}

func TestTransportErrors(t *testing.T) {
	t.Parallel()
	// No daemon listening.
	c := New(filepath.Join(socketDir(t), "missing.sock"))
	if _, err := c.InspectImage(t.Context(), "nginx"); err == nil || !strings.HasPrefix(err.Error(), "dockerd: ") || errors.Is(err, ErrNotFound) {
		t.Errorf("missing socket: %v", err)
	}
	if _, err := c.InspectContainer(t.Context(), "x"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("missing socket: %v", err)
	}

	// A reference that cannot form a URL is an error, not a request.
	sock, seen := fakeDockerd(t, reply(200, `{}`))
	if _, err := New(sock).InspectImage(t.Context(), "bad\x7fref"); err == nil {
		t.Error("invalid URL accepted")
	}
	if n := len(seen()); n != 0 {
		t.Errorf("invalid URL reached dockerd (%d requests)", n)
	}

	// A canceled context stops the call.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := New(sock).InspectImage(ctx, "nginx"); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled context: %v", err)
	}
}

// One client serves repeated calls (pooled transport).
func TestSequentialCalls(t *testing.T) {
	t.Parallel()
	sock, seen := fakeDockerd(t, reply(200, `{"Id":"sha256:11"}`))
	c := New(sock)
	for range 5 {
		if _, err := c.InspectImage(t.Context(), "nginx"); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(seen()); n != 5 {
		t.Errorf("requests = %d", n)
	}
}
