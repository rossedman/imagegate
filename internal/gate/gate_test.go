package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rossedman/image-gate/internal/audit"
	"github.com/rossedman/image-gate/internal/cache"
	"github.com/rossedman/image-gate/internal/docker"
	"github.com/rossedman/image-gate/internal/metrics"
	"github.com/rossedman/image-gate/internal/policy"
	"github.com/rossedman/image-gate/internal/verdict"
	"github.com/rossedman/image-gate/internal/verify"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	idA     = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	idB     = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	idLocal = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

const basePolicy = `apiVersion: imagegate.dev/v1
mode: %s
defaults:
  failClosed: %t
  helpURL: https://wiki.acme.internal/imagegate
identities:
  ci-main:
    issuer: https://token.actions.githubusercontent.com
    subject: https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main
localImages: %s
rules:
  - name: internal
    images: ["ghcr.io/acme/**"]
    signature: {identities: [ci-main]}
    sbom: {identities: [ci-main]}
`

type fakeDocker struct {
	mu         sync.Mutex
	images     map[string]*docker.Image
	containers map[string]*docker.Container
	err        error
}

func (f *fakeDocker) InspectImage(_ context.Context, ref string) (*docker.Image, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if img, ok := f.images[ref]; ok {
		return img, nil
	}
	// Like dockerd: a pinned digest or an image ID prefix also resolves.
	for _, img := range f.images {
		for _, rd := range img.RepoDigests {
			if strings.HasSuffix(ref, "@"+strings.SplitN(rd, "@", 2)[1]) {
				return img, nil
			}
		}
		if len(ref) >= 4 && strings.HasPrefix(strings.TrimPrefix(img.ID, "sha256:"), strings.TrimPrefix(ref, "sha256:")) {
			return img, nil
		}
	}
	return nil, docker.ErrNotFound
}

func (f *fakeDocker) InspectContainer(_ context.Context, id string) (*docker.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.containers[id]; ok {
		return c, nil
	}
	return nil, docker.ErrNotFound
}

type fakeVerifier struct {
	calls   atomic.Int32
	delay   time.Duration
	results map[string]verify.Result // by digest
}

func (f *fakeVerifier) Verify(ctx context.Context, t verify.Target, _ *policy.Rule) verify.Result {
	f.calls.Add(1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return verify.Result{Reason: verdict.Timeout}
		}
	}
	if r, ok := f.results[t.Digest]; ok {
		return r
	}
	return verify.Result{Reason: verdict.NoSignature, Detail: "no cosign signature found for this digest"}
}

type harness struct {
	g      *Gate
	docker *fakeDocker
	ver    *fakeVerifier
	audit  *bytes.Buffer
	dir    string
	now    time.Time
}

func newHarness(t *testing.T, mode string, failClosed bool, local string) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{
		docker: &fakeDocker{
			images: map[string]*docker.Image{
				"ghcr.io/acme/api:1": {ID: idA, RepoDigests: []string{"ghcr.io/acme/api@" + digestA}, Os: "linux", Architecture: "amd64"},
				idA:                  {ID: idA, RepoDigests: []string{"ghcr.io/acme/api@" + digestA}, Os: "linux", Architecture: "amd64"},
				"ghcr.io/acme/bad:1": {ID: idB, RepoDigests: []string{"ghcr.io/acme/bad@" + digestB}},
				idB:                  {ID: idB, RepoDigests: []string{"ghcr.io/acme/bad@" + digestB}},
				"busybox":            {ID: "sha256:9999", RepoDigests: []string{"busybox@" + digestB}},
				"myapp:dev":          {ID: idLocal},
				idLocal:              {ID: idLocal},
			},
			containers: map[string]*docker.Container{},
		},
		ver: &fakeVerifier{results: map[string]verify.Result{
			digestA: {Reason: verdict.Allowed, Signer: "ci-main"},
			digestB: {Reason: verdict.NoSBOM, Detail: `no SPDX or CycloneDX attestation signed by identity "ci-main"`},
		}},
		audit: &bytes.Buffer{},
		dir:   dir,
		now:   time.Now(),
	}
	h.writePolicy(t, fmt.Sprintf(basePolicy, mode, failClosed, local))
	c, err := cache.Open(filepath.Join(dir, "cache.db"), 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetClock(func() time.Time { return h.now })
	h.g = New(Config{
		PolicyPath:   filepath.Join(dir, "policy.yaml"),
		OverridesDir: filepath.Join(dir, "overrides.d"),
		Docker:       h.docker,
		Compile:      func(*policy.Policy) (Verifier, error) { return h.ver, nil },
		Cache:        c,
		Audit:        audit.New(h.audit),
		Metrics:      metrics.New(),
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:          func() time.Time { return h.now },
	})
	if err := h.g.ReloadPolicy(); err != nil {
		t.Fatal(err)
	}
	h.g.ReloadOverrides()
	return h
}

func (h *harness) writePolicy(t *testing.T, doc string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, "policy.yaml"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) create(image string) Decision {
	body, _ := json.Marshal(map[string]string{"Image": image})
	return h.g.Create(context.Background(), "", body, url.Values{})
}

func (h *harness) lastAudit(t *testing.T) audit.Record {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(h.audit.String()), "\n")
	var r audit.Record
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCreate(t *testing.T) {
	h := newHarness(t, "enforce", true, "deny")
	cases := []struct {
		image  string
		allow  bool
		reason verdict.Reason
	}{
		{"ghcr.io/acme/api:1", true, verdict.Allowed},
		{"ghcr.io/acme/bad:1", false, verdict.NoSBOM},
		{"busybox", false, verdict.NoRule},
		{"myapp:dev", false, verdict.LocalImage},
		{"ghcr.io/acme/api@" + digestA, true, verdict.Allowed},
		{idA[7:19], true, verdict.Allowed}, // short image ID
		{"Not A Ref", false, verdict.BadRequest},
	}
	for _, c := range cases {
		d := h.create(c.image)
		r := h.lastAudit(t)
		if d.Allow != c.allow || r.Reason != string(c.reason) {
			t.Errorf("%s: allow=%v reason=%s, want %v %s (%s)", c.image, d.Allow, r.Reason, c.allow, c.reason, d.Msg)
		}
	}
}

func TestDenialMessage(t *testing.T) {
	h := newHarness(t, "enforce", true, "deny")
	d := h.create("ghcr.io/acme/bad:1")
	want := "imagegate: denied ghcr.io/acme/bad@" + digestB + "\n" +
		`reason: NO_SBOM — no SPDX or CycloneDX attestation signed by identity "ci-main"` + "\n" +
		"fix: https://wiki.acme.internal/imagegate#NO_SBOM"
	if d.Msg != want {
		t.Errorf("message:\n%s\nwant:\n%s", d.Msg, want)
	}
	r := h.lastAudit(t)
	if r.Image != "ghcr.io/acme/bad:1" || r.Digest != digestB || r.Rule != "internal" || r.Endpoint != "containers/create" || r.PolicyHash == "" || r.Cache != "miss" {
		t.Errorf("audit record: %+v", r)
	}
}

func TestBadRequest(t *testing.T) {
	h := newHarness(t, "enforce", true, "deny")
	for _, body := range []string{"", "{", `{"Image":""}`, `{"Cmd":["x"]}`} {
		if d := h.g.Create(context.Background(), "", []byte(body), nil); d.Allow || !strings.Contains(d.Msg, "BAD_REQUEST") {
			t.Errorf("body %q: %+v", body, d)
		}
	}
}

// An image not present locally is left to dockerd so `docker run` can
// pull it and retry the create.
func TestImageNotPresent(t *testing.T) {
	h := newHarness(t, "enforce", true, "deny")
	if d := h.create("ghcr.io/acme/new:1"); !d.Allow {
		t.Error("missing image should pass through to dockerd")
	}
}

func TestCacheAndPolicyChange(t *testing.T) {
	h := newHarness(t, "enforce", true, "deny")
	h.create("ghcr.io/acme/api:1")
	h.create("ghcr.io/acme/api:1")
	if n := h.ver.calls.Load(); n != 1 {
		t.Fatalf("verifications = %d, want 1", n)
	}
	if r := h.lastAudit(t); r.Cache != "hit" {
		t.Errorf("second create cache = %q", r.Cache)
	}
	// A policy change invalidates old verdicts.
	h.writePolicy(t, strings.Replace(fmt.Sprintf(basePolicy, "enforce", true, "deny"), "helpURL", "# changed\n  helpURL", 1)+"  # trailing comment\n")
	h.g.ReloadPolicy()
	h.create("ghcr.io/acme/api:1")
	if n := h.ver.calls.Load(); n != 1 {
		t.Errorf("comment-only change re-verified (%d)", n)
	}
	h.writePolicy(t, strings.Replace(fmt.Sprintf(basePolicy, "enforce", true, "deny"), "release.yml", "release.yaml", 1))
	h.g.ReloadPolicy()
	h.create("ghcr.io/acme/api:1")
	if n := h.ver.calls.Load(); n != 2 {
		t.Errorf("policy change did not re-verify (%d)", n)
	}
	// Deny verdicts expire after denyTTL (60s).
	h.create("ghcr.io/acme/bad:1")
	h.create("ghcr.io/acme/bad:1")
	if n := h.ver.calls.Load(); n != 3 {
		t.Errorf("deny not cached (%d)", n)
	}
	h.now = h.now.Add(61 * time.Second)
	h.create("ghcr.io/acme/bad:1")
	if n := h.ver.calls.Load(); n != 4 {
		t.Errorf("deny cached past denyTTL (%d)", n)
	}
}

func TestInvalidReloadKeepsLastGood(t *testing.T) {
	h := newHarness(t, "enforce", true, "deny")
	good := h.g.Policy().Hash
	h.writePolicy(t, "apiVersion: nope")
	if err := h.g.ReloadPolicy(); err == nil {
		t.Fatal("invalid policy accepted")
	}
	if h.g.Policy().Hash != good {
		t.Error("last good policy replaced")
	}
	if d := h.create("ghcr.io/acme/api:1"); !d.Allow {
		t.Error("last good policy not enforced")
	}
}

func TestNoPolicyAtBoot(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("rules: ["), 0o644)
	c, _ := cache.Open("", 10)
	g := New(Config{
		PolicyPath: filepath.Join(dir, "policy.yaml"), OverridesDir: dir, Docker: &fakeDocker{},
		Compile: func(*policy.Policy) (Verifier, error) { return &fakeVerifier{}, nil },
		Cache:   c, Audit: audit.New(io.Discard), Metrics: metrics.New(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err := g.ReloadPolicy(); err == nil {
		t.Fatal("expected error")
	}
	d := g.Create(context.Background(), "", []byte(`{"Image":"x"}`), nil)
	if d.Allow || !strings.Contains(d.Msg, "NO_POLICY") {
		t.Errorf("got %+v", d)
	}
	if d := g.Start(context.Background(), "", "containers/start", "x"); !d.Allow {
		t.Error("start must be allowed without a policy (only creates are denied)")
	}
}

func TestAuditMode(t *testing.T) {
	h := newHarness(t, "audit", true, "deny")
	for _, img := range []string{"ghcr.io/acme/bad:1", "busybox", "myapp:dev"} {
		if d := h.create(img); !d.Allow {
			t.Errorf("%s denied in audit mode", img)
		}
		r := h.lastAudit(t)
		if r.Decision != "deny" || r.Mode != "audit" || r.Enforced {
			t.Errorf("%s: audit record should log the would-be deny: %+v", img, r)
		}
	}
}

func TestOverrides(t *testing.T) {
	h := newHarness(t, "enforce", true, "deny")
	os.MkdirAll(filepath.Join(h.dir, "overrides.d"), 0o755)
	write := func(expires time.Time) {
		os.WriteFile(filepath.Join(h.dir, "overrides.d", "inc.yaml"), []byte(fmt.Sprintf(
			"- digest: %s\n  expires: %s\n  ticket: INC-4821\n  reason: vendor hotfix\n", digestB, expires.UTC().Format(time.RFC3339))), 0o644)
		h.g.ReloadOverrides()
	}

	write(h.now.Add(24 * time.Hour))
	d := h.create("ghcr.io/acme/bad:1")
	r := h.lastAudit(t)
	if !d.Allow || r.Reason != "OVERRIDE" || r.Ticket != "INC-4821" || r.Severity != "high" {
		t.Errorf("valid override: %+v %+v", d, r)
	}

	write(h.now.Add(-time.Minute))
	if d := h.create("ghcr.io/acme/bad:1"); d.Allow {
		t.Error("expired override allowed")
	}

	write(h.now.Add(8 * 24 * time.Hour))
	if d := h.create("ghcr.io/acme/bad:1"); d.Allow {
		t.Error("override longer than 7 days allowed")
	}
}

func TestLocalImagesAllow(t *testing.T) {
	h := newHarness(t, "enforce", true, "allow")
	if d := h.create("myapp:dev"); !d.Allow {
		t.Error("localImages: allow denied a local image")
	}
}

func TestFailClosed(t *testing.T) {
	for _, failClosed := range []bool{true, false} {
		h := newHarness(t, "enforce", failClosed, "deny")
		h.ver.results[digestA] = verify.Result{Reason: verdict.UpstreamUnavailable, Detail: "registry: connection refused"}
		d := h.create("ghcr.io/acme/api:1")
		if d.Allow == failClosed {
			t.Errorf("failClosed=%v: allow=%v", failClosed, d.Allow)
		}
		// Transient failures are never cached.
		h.ver.results[digestA] = verify.Result{Reason: verdict.Allowed}
		if d := h.create("ghcr.io/acme/api:1"); !d.Allow {
			t.Errorf("failClosed=%v: recovered registry still denied", failClosed)
		}
		h.docker.err = fmt.Errorf("dockerd down")
		if d := h.create("ghcr.io/acme/api:1"); d.Allow == failClosed {
			t.Errorf("failClosed=%v: dockerd error allow=%v", failClosed, d.Allow)
		}
	}
}

func TestVerifyTimeout(t *testing.T) {
	h := newHarness(t, "enforce", true, "deny")
	h.writePolicy(t, strings.Replace(fmt.Sprintf(basePolicy, "enforce", true, "deny"), "defaults:", "defaults:\n  verifyTimeout: 50ms", 1))
	if err := h.g.ReloadPolicy(); err != nil {
		t.Fatal(err)
	}
	h.ver.delay = time.Second
	d := h.create("ghcr.io/acme/api:1")
	if d.Allow || !strings.Contains(d.Msg, "TIMEOUT") {
		t.Errorf("got %+v", d)
	}
}

// The start re-check verifies the image the container actually uses.
func TestStartRecheck(t *testing.T) {
	h := newHarness(t, "enforce", true, "deny")
	if d := h.create("ghcr.io/acme/api:1"); !d.Allow {
		t.Fatal(d.Msg)
	}
	// Tag race: the create was checked against api:1 = digestA, but the
	// daemon created the container from another image.
	h.docker.images[idB] = &docker.Image{ID: idB, RepoDigests: []string{"ghcr.io/acme/api@" + digestB}}
	h.ver.results[digestB] = verify.Result{Reason: verdict.NoSignature}
	h.docker.containers["c-race"] = &docker.Container{ID: "c-race", Image: idB}
	h.docker.containers["c-race"].Config.Image = "ghcr.io/acme/api:1"
	if d := h.g.Start(context.Background(), "", "containers/start", "c-race"); d.Allow {
		t.Error("start of a container whose image differs from the verified one was allowed")
	}

	// Normal path: create mapped idA to digestA; start is a cache hit.
	h.docker.containers["c-ok"] = &docker.Container{ID: "c-ok", Image: idA}
	h.docker.containers["c-ok"].Config.Image = "ghcr.io/acme/api:1"
	calls := h.ver.calls.Load()
	if d := h.g.Start(context.Background(), "", "containers/start", "c-ok"); !d.Allow {
		t.Error(d.Msg)
	}
	if h.ver.calls.Load() != calls || h.lastAudit(t).Cache != "hit" {
		t.Error("start of a verified image was not a cache hit")
	}

	// A container created before imagegate, from a local image.
	h.docker.containers["c-old"] = &docker.Container{ID: "c-old", Image: idLocal}
	h.docker.containers["c-old"].Config.Image = "myapp:dev"
	if d := h.g.Start(context.Background(), "", "containers/start", "c-old"); d.Allow {
		t.Error("pre-existing container with a local image was allowed")
	}
	if d := h.g.Start(context.Background(), "", "containers/start", "missing"); d.Allow {
		t.Error("start of a container imagegate cannot see must fail closed")
	}
}

// 200 concurrent creates of one uncached image trigger exactly one
// verification.
func TestSingleflight(t *testing.T) {
	h := newHarness(t, "enforce", true, "deny")
	h.ver.delay = 100 * time.Millisecond
	var wg sync.WaitGroup
	var denied atomic.Int32
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d := h.create("ghcr.io/acme/api:1"); !d.Allow {
				denied.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := h.ver.calls.Load(); n != 1 {
		t.Errorf("verifications = %d, want 1", n)
	}
	if denied.Load() != 0 {
		t.Errorf("%d creates denied", denied.Load())
	}
}

func TestPickDigest(t *testing.T) {
	img := &docker.Image{ID: idA, RepoDigests: []string{"nginx@" + digestA, "ghcr.io/acme/api@" + digestB}}
	cases := []struct {
		ref         string
		trustPinned bool
		repo, d     string
		ok          bool
	}{
		{"nginx", true, "docker.io/library/nginx", digestA, true},
		{"docker.io/library/nginx:latest", true, "docker.io/library/nginx", digestA, true},
		{"ghcr.io/acme/api:1", true, "ghcr.io/acme/api", digestB, true},
		{"ghcr.io/acme/other:1", true, "", "", false},
		{"ghcr.io/acme/api@" + digestA, true, "ghcr.io/acme/api", digestA, true},
		{"ghcr.io/acme/api@" + digestA, false, "ghcr.io/acme/api", digestB, true},
		{idA, true, "docker.io/library/nginx", digestA, true},
		{"deadbeef", true, "", "", false},
	}
	for _, c := range cases {
		repo, d, ok := pickDigest(c.ref, img, c.trustPinned)
		if repo != c.repo || d != c.d || ok != c.ok {
			t.Errorf("pickDigest(%q, %v) = %q %q %v", c.ref, c.trustPinned, repo, d, ok)
		}
	}
}

// BenchmarkCreateCacheHit measures imagegate's own overhead on the hot path
// (excluding dockerd's image inspect, which is faked).
func BenchmarkCreateCacheHit(b *testing.B) {
	t := &testing.T{}
	h := newHarness(t, "enforce", true, "deny")
	h.g.cfg.Audit = audit.New(io.Discard)
	body := []byte(`{"Image":"ghcr.io/acme/api:1"}`)
	h.g.Create(context.Background(), "", body, nil)
	b.ResetTimer()
	for range b.N {
		if d := h.g.Create(context.Background(), "", body, nil); !d.Allow {
			b.Fatal(d.Msg)
		}
	}
}

// With the containerd image store a local build has a RepoDigests entry;
// the verifier reports LOCAL_IMAGE when the registry lacks the digest, and
// localImages decides.
func TestLocalImageFromVerifier(t *testing.T) {
	for _, local := range []string{"deny", "allow"} {
		h := newHarness(t, "enforce", true, local)
		h.ver.results[digestA] = verify.Result{Reason: verdict.LocalImage, Detail: "digest is not in registry"}
		d := h.create("ghcr.io/acme/api:1")
		if d.Allow != (local == "allow") || h.lastAudit(t).Reason != "LOCAL_IMAGE" {
			t.Errorf("localImages=%s: %+v", local, d)
		}
	}
}

type panicVerifier struct{}

func (panicVerifier) Verify(context.Context, verify.Target, *policy.Rule) verify.Result {
	var m map[string]int
	m["boom"]++ // nil map write: panics
	return verify.Result{}
}

// A panic while verifying (registry-controlled input) must deny, not crash
// the process.
func TestVerifyPanic(t *testing.T) {
	h := newHarness(t, "enforce", true, "deny")
	h.g.cfg.Compile = func(*policy.Policy) (Verifier, error) { return panicVerifier{}, nil }
	h.g.ReloadPolicy()
	if d := h.create("ghcr.io/acme/api:1"); d.Allow || !strings.Contains(d.Msg, "internal error") {
		t.Errorf("got %+v", d)
	}
}
