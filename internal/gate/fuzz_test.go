package gate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/rossedman/imagegate/internal/audit"
	"github.com/rossedman/imagegate/internal/docker"
	"github.com/rossedman/imagegate/internal/verdict"
)

// FuzzCreateBody sends arbitrary container-create bodies through Create.
// Invariants: no panic; a body that does not parse (or names no image) is
// denied; an allow is either an image dockerd does not have (dockerd will
// answer "No such image") or a verified allow of the one allowed digest.
func FuzzCreateBody(f *testing.F) {
	for _, s := range []string{
		`{"Image":"ghcr.io/acme/api:1","Cmd":["serve"],"HostConfig":{"Privileged":false}}`,
		`{"Image":"ghcr.io/acme/bad:1"}`,
		`{"Image":"ghcr.io/acme/api@` + digestA + `"}`,
		`{"Image":"ghcr.io/acme/bad@` + digestA + `"}`,
		`{"Image":"` + idA[7:19] + `"}`,
		`{"Image":"` + idA + `"}`,
		`{"Image":"busybox","Env":["A=1"]}`,
		`{"Image":"myapp:dev"}`,
		`{"Image":"ghcr.io/acme/new:1"}`,
		`{"image":"ghcr.io/acme/api:1"}`,
		`{"Image":"ghcr.io/acme/bad:1","Image":"ghcr.io/acme/api:1"}`,
		`{"Image":""}`, `{"Image":5}`, `{"Image":null}`, `{}`, `[]`, `null`, ``, `{`, `{"Cmd":["x"]}`,
		`{"Image":"Not A Ref"}`, `{"Image":"ghcr.io/acme/api:1"} trailing`,
	} {
		f.Add([]byte(s))
	}
	h := newHarness(f, "enforce", true, "deny")
	f.Fuzz(func(t *testing.T, body []byte) {
		h.audit.Reset()
		d := h.g.Create(context.Background(), "fuzz", body, nil)

		var req struct {
			Image string `json:"Image"`
		}
		if err := json.Unmarshal(body, &req); err != nil || req.Image == "" {
			if d.Allow || !strings.Contains(d.Msg, string(verdict.BadRequest)) {
				t.Fatalf("unparseable body %q: %+v", body, d)
			}
			return
		}
		if !d.Allow {
			if d.Msg == "" {
				t.Fatalf("denial without message for %q", body)
			}
			if r := h.lastAudit(t); r.Decision != "deny" || !r.Enforced {
				t.Fatalf("deny recorded as %+v", r)
			}
			return
		}
		if strings.TrimSpace(h.audit.String()) == "" {
			// Silent allow: only for an image dockerd does not have.
			if _, err := h.docker.InspectImage(context.Background(), req.Image); !errors.Is(err, docker.ErrNotFound) {
				t.Fatalf("image %q allowed without audit though dockerd has it", req.Image)
			}
			return
		}
		if r := h.lastAudit(t); r.Reason != string(verdict.Allowed) || r.Digest != digestA || r.Decision != "allow" {
			t.Fatalf("image %q allowed with %+v", req.Image, r)
		}
	})
}

// BenchmarkStartCacheHit measures a start re-check whose image mapping and
// verdict are cached.
func BenchmarkStartCacheHit(b *testing.B) {
	h := newHarness(b, "enforce", true, "deny")
	h.g.cfg.Audit = audit.New(io.Discard)
	if d := h.create("ghcr.io/acme/api:1"); !d.Allow {
		b.Fatal(d.Msg)
	}
	h.addContainer("c", idA, "ghcr.io/acme/api:1")
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if d := h.g.Start(ctx, "", "containers/start", "c"); !d.Allow {
			b.Fatal(d.Msg)
		}
	}
	if n := h.ver.calls.Load(); n != 1 {
		b.Fatalf("verifications = %d, want 1", n)
	}
}
