package gate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rossedman/imagegate/internal/audit"
	"github.com/rossedman/imagegate/internal/cache"
	"github.com/rossedman/imagegate/internal/docker"
	"github.com/rossedman/imagegate/internal/imageref"
	"github.com/rossedman/imagegate/internal/metrics"
	"github.com/rossedman/imagegate/internal/policy"
	"github.com/rossedman/imagegate/internal/verdict"
	"github.com/rossedman/imagegate/internal/verify"
)

// metricValue returns the counter or gauge value of the series of name
// whose label values are exactly values (in label-name order), or 0.
func metricValue(t *testing.T, m *metrics.Metrics, name string, values ...string) float64 {
	t.Helper()
	fams, err := m.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
	series:
		for _, s := range f.GetMetric() {
			if len(s.GetLabel()) != len(values) {
				continue
			}
			for i, l := range s.GetLabel() {
				if l.GetValue() != values[i] {
					continue series
				}
			}
			if s.GetCounter() != nil {
				return s.GetCounter().GetValue()
			}
			return s.GetGauge().GetValue()
		}
	}
	return 0
}

// seriesCount returns how many series of name have been observed.
func seriesCount(t *testing.T, m *metrics.Metrics, name string) int {
	t.Helper()
	fams, err := m.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() == name {
			return len(f.GetMetric())
		}
	}
	return 0
}

func (h *harness) addContainer(id, imageID, ref string) {
	c := &docker.Container{ID: id, Image: imageID}
	c.Config.Image = ref
	h.docker.mu.Lock()
	h.docker.containers[id] = c
	h.docker.mu.Unlock()
}

func (h *harness) start(id string) Decision {
	return h.g.Start(context.Background(), "bob", "containers/start", id)
}

func TestStartPaths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		local   string
		setup   func(h *harness)
		id      string
		allow   bool
		reason  verdict.Reason
		digest  string
		upCount float64 // dockerd upstream errors
	}{
		{
			name:  "uncached mapping inspects the image",
			setup: func(h *harness) { h.addContainer("c1", idA, "ghcr.io/acme/api:1") },
			id:    "c1", allow: true, reason: verdict.Allowed, digest: digestA,
		},
		{
			// At start the pinned digest in Config.Image is not trusted:
			// the image's own RepoDigests decide (invariant 4).
			name:  "pinned reference is not trusted at start",
			setup: func(h *harness) { h.addContainer("c2", idB, "ghcr.io/acme/bad@"+digestA) },
			id:    "c2", reason: verdict.NoSBOM, digest: digestB, // the image's digest, not the pinned allowed one
		},
		{
			name:  "image removed since create is local and denied",
			setup: func(h *harness) { h.addContainer("c3", "sha256:dead", "ghcr.io/acme/api:1") },
			id:    "c3", reason: verdict.LocalImage,
		},
		{
			name:  "image removed since create with localImages allow",
			local: "allow",
			setup: func(h *harness) { h.addContainer("c3", "sha256:dead", "ghcr.io/acme/api:1") },
			id:    "c3", allow: true, reason: verdict.LocalImage,
		},
		{
			name: "container inspect error fails closed",
			setup: func(h *harness) {
				h.addContainer("c4", idA, "ghcr.io/acme/api:1")
				h.docker.ctErr = errors.New("dockerd: connection refused")
			},
			id: "c4", reason: verdict.UpstreamUnavailable, upCount: 1,
		},
		{
			name: "image inspect error fails closed",
			setup: func(h *harness) {
				h.addContainer("c5", idA, "ghcr.io/acme/api:1")
				h.docker.err = errors.New("dockerd: 500")
			},
			id: "c5", reason: verdict.UpstreamUnavailable, upCount: 1,
		},
		{
			name:  "missing container fails closed",
			setup: func(*harness) {},
			id:    "nope", reason: verdict.BadRequest,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			local := c.local
			if local == "" {
				local = "deny"
			}
			h := newHarness(t, "enforce", true, local)
			c.setup(h)
			d := h.start(c.id)
			r := h.lastAudit(t)
			if d.Allow != c.allow || r.Reason != string(c.reason) || r.Digest != c.digest {
				t.Errorf("allow=%v reason=%s digest=%s, want %v %s %s (%s)", d.Allow, r.Reason, r.Digest, c.allow, c.reason, c.digest, d.Msg)
			}
			if r.Endpoint != "containers/start" || r.User != "bob" {
				t.Errorf("audit endpoint/user = %q %q", r.Endpoint, r.User)
			}
			if got := metricValue(t, h.g.cfg.Metrics, "imagegate_upstream_errors_total", "dockerd"); got != c.upCount {
				t.Errorf("dockerd upstream errors = %v, want %v", got, c.upCount)
			}
			if !c.allow && d.Msg == "" {
				t.Error("denial without message")
			}
		})
	}
}

// A start in audit mode logs the would-be deny but allows.
func TestStartAuditMode(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "audit", true, "deny")
	h.addContainer("c", idB, "ghcr.io/acme/bad:1")
	if d := h.start("c"); !d.Allow {
		t.Fatal(d.Msg)
	}
	if r := h.lastAudit(t); r.Decision != "deny" || r.Enforced || r.Reason != string(verdict.NoSBOM) {
		t.Errorf("audit record %+v", r)
	}
}

func TestPolicyBeforeLoad(t *testing.T) {
	t.Parallel()
	g := New(Config{})
	if g.Policy() != nil {
		t.Error("policy before any load")
	}
	if g.cfg.Now == nil || g.cfg.Log == nil {
		t.Error("New did not default Now and Log")
	}
}

func TestCompileErrorKeepsPolicy(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "enforce", true, "deny")
	good := h.g.Policy()
	boom := errors.New("bad identity")
	h.g.cfg.Compile = func(*policy.Policy) (Verifier, error) { return nil, boom }
	if err := h.g.ReloadPolicy(); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if h.g.Policy() != good {
		t.Error("policy replaced after compile error")
	}
	if got := metricValue(t, h.g.cfg.Metrics, "imagegate_policy_reload_errors_total"); got != 1 {
		t.Errorf("reload errors = %v", got)
	}
}

func TestReloadOverridesInvalidFile(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "enforce", true, "deny")
	dir := filepath.Join(h.dir, "overrides.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	good := fmt.Sprintf("- digest: %s\n  expires: %s\n  ticket: INC-1\n  reason: hotfix\n", digestB, h.now.Add(time.Hour).UTC().Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte("{not: [yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.g.ReloadOverrides()
	if got := metricValue(t, h.g.cfg.Metrics, "imagegate_overrides_active"); got != 1 {
		t.Errorf("active overrides = %v, want 1", got)
	}
	if d := h.create("ghcr.io/acme/bad:1"); !d.Allow {
		t.Error("valid override ignored because another file was invalid")
	}
}

func TestVerifyMetrics(t *testing.T) {
	t.Parallel()
	cases := []struct {
		detail string
		target string
	}{
		{"fetch trusted root: tuf unreachable", "tuf"},
		{"registry: 503", "registry"},
	}
	for _, c := range cases {
		t.Run(c.target, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, "enforce", true, "deny")
			h.ver.results[digestA] = verify.Result{
				Reason: verdict.UpstreamUnavailable, Detail: c.detail,
				Stages: map[string]time.Duration{"resolve": time.Millisecond, "signature": 2 * time.Millisecond},
			}
			if d := h.create("ghcr.io/acme/api:1"); d.Allow {
				t.Fatal("transient failure allowed with failClosed")
			}
			m := h.g.cfg.Metrics
			if got := metricValue(t, m, "imagegate_upstream_errors_total", c.target); got != 1 {
				t.Errorf("%s errors = %v", c.target, got)
			}
			if n := seriesCount(t, m, "imagegate_verify_duration_seconds"); n != 2 {
				t.Errorf("stage series = %d, want 2", n)
			}
			if got := metricValue(t, m, "imagegate_cache_requests_total", "miss"); got != 1 {
				t.Errorf("cache misses = %v", got)
			}
		})
	}
}

type fakeResolver struct {
	mu    sync.Mutex
	calls []string
	byRef map[string]string
}

func (f *fakeResolver) ResolveDigest(_ context.Context, r imageref.Ref) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.String())
	if d, ok := f.byRef[r.String()]; ok {
		return d, nil
	}
	return "", errors.New("manifest unknown")
}

func TestWarm(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		ref      string
		allow    bool
		reason   verdict.Reason
		image    string
		errHas   string
		resolved int
		verifies int32
	}{
		{
			name: "tag resolved and verified", ref: "ghcr.io/acme/api:1", allow: true, reason: verdict.Allowed,
			image: "ghcr.io/acme/api@" + digestA, resolved: 1, verifies: 1,
		},
		{
			name: "pinned digest skips the resolver", ref: "ghcr.io/acme/bad@" + digestB, reason: verdict.NoSBOM,
			image: "ghcr.io/acme/bad@" + digestB, verifies: 1,
		},
		{name: "no rule", ref: "nginx@" + digestA, reason: verdict.NoRule, image: "docker.io/library/nginx@" + digestA},
		{name: "resolve error", ref: "ghcr.io/acme/missing:1", errHas: "resolve ghcr.io/acme/missing:1: manifest unknown", resolved: 1},
		{name: "invalid reference", ref: "Not A Ref", errHas: "invalid image reference"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, "enforce", true, "deny")
			res := &fakeResolver{byRef: map[string]string{"ghcr.io/acme/api:1": digestA}}
			h.g.cfg.Resolver = res
			v, img, err := h.g.Warm(t.Context(), c.ref)
			if c.errHas != "" {
				if err == nil || !strings.Contains(err.Error(), c.errHas) || img != "" || v.Allow {
					t.Fatalf("got %+v %q %v, want error %q", v, img, err, c.errHas)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if v.Allow != c.allow || v.Reason != c.reason || img != c.image {
					t.Errorf("got %+v %q, want allow=%v %s %q", v, img, c.allow, c.reason, c.image)
				}
				if r := h.lastAudit(t); r.Endpoint != "warm" || r.Image != c.ref {
					t.Errorf("audit %+v", r)
				}
			}
			if len(res.calls) != c.resolved || h.ver.calls.Load() != c.verifies {
				t.Errorf("resolver calls %v, verifies %d; want %d %d", res.calls, h.ver.calls.Load(), c.resolved, c.verifies)
			}
		})
	}
}

// Warming makes the next create a cache hit, and purging undoes it.
func TestWarmThenCreateThenPurge(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "enforce", true, "deny")
	h.g.cfg.Resolver = &fakeResolver{byRef: map[string]string{"ghcr.io/acme/api:1": digestA}}
	if _, _, err := h.g.Warm(t.Context(), "ghcr.io/acme/api:1"); err != nil {
		t.Fatal(err)
	}
	if d := h.create("ghcr.io/acme/api:1"); !d.Allow || h.lastAudit(t).Cache != "hit" || h.ver.calls.Load() != 1 {
		t.Fatalf("create after warm: %+v cache=%q verifies=%d", d, h.lastAudit(t).Cache, h.ver.calls.Load())
	}
	h.create("ghcr.io/acme/bad:1")

	n, err := h.g.PurgeCache(digestA)
	if err != nil || n != 1 {
		t.Fatalf("purge digestA = %d, %v; want 1", n, err)
	}
	h.create("ghcr.io/acme/api:1")
	if h.ver.calls.Load() != 3 || h.lastAudit(t).Cache != "miss" {
		t.Errorf("purged verdict still cached (verifies %d)", h.ver.calls.Load())
	}
	n, err = h.g.PurgeCache("")
	if err != nil || n != 2 {
		t.Errorf("purge all = %d, %v; want 2", n, err)
	}
}

func TestWarmUnavailable(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "enforce", true, "deny")
	if _, _, err := h.g.Warm(t.Context(), "ghcr.io/acme/api:1"); err == nil || err.Error() != "warm is not available" {
		t.Errorf("nil resolver: %v", err)
	}

	c, err := cache.Open("", 10)
	if err != nil {
		t.Fatal(err)
	}
	g := New(Config{
		Cache: c, Resolver: &fakeResolver{}, Audit: audit.New(io.Discard), Metrics: metrics.New(),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if _, _, err := g.Warm(t.Context(), "ghcr.io/acme/api:1"); err == nil || err.Error() != "no valid policy is loaded" {
		t.Errorf("no policy: %v", err)
	}
}

// A 64-hex image ID is not a valid reference but is a valid image ID.
func TestCreateByFullImageID(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "enforce", true, "deny")
	if _, err := imageref.Parse(idA[7:]); err == nil {
		t.Fatal("precondition: 64-hex should not parse as a reference")
	}
	if d := h.create(idA[7:]); !d.Allow {
		t.Error(d.Msg)
	}
}

func TestLatencyMs(t *testing.T) {
	t.Parallel()
	if got := latencyMs(time.Time{}); got != 0 {
		t.Errorf("zero start = %d", got)
	}
	if got := latencyMs(time.Now().Add(-1500 * time.Millisecond)); got < 1500 || got > 60_000 {
		t.Errorf("1.5s ago = %d", got)
	}
}
