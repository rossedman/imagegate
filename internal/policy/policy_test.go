package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// specExample is the policy from the spec, with the vendor key path left
// as written (keys are read by the verifier, not the policy loader).
const specExample = `apiVersion: imagegate.dev/v1
mode: enforce            # enforce | audit

defaults:
  failClosed: true
  verifyTimeout: 10s
  cache:
    allowTTL: 24h
    denyTTL: 60s

trust:
  sigstore: public-good  # or a path to a private trusted_root.json

identities:
  ci-main:
    issuer: https://token.actions.githubusercontent.com
    subjectRegExp: ^https://github\.com/acme/.+/\.github/workflows/release\.ya?ml@refs/heads/main$
  vendor-key:
    publicKey: /etc/imagegate/keys/vendor.pub

localImages: deny        # deny | allow

rules:
  - name: internal
    images: ["ghcr.io/acme/**", "registry.acme.internal/**"]
    signature:
      identities: [ci-main]
    sbom:
      required: true
      identities: [ci-main]
      predicateTypes:
        - https://spdx.dev/Document
        - https://cyclonedx.org/bom

  - name: vetted-vendor
    images: ["registry.vendor.example/agent"]
    signature:
      identities: [vendor-key]
    sbom:
      required: false
`

func TestSpecExample(t *testing.T) {
	p, err := Parse([]byte(specExample))
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != ModeEnforce || !p.FailClosed() || p.Defaults.VerifyTimeout.D() != 10*time.Second {
		t.Errorf("unexpected defaults: %+v", p.Defaults)
	}
	if p.Defaults.Cache.AllowTTL.D() != 24*time.Hour || p.Defaults.Cache.DenyTTL.D() != time.Minute {
		t.Errorf("unexpected cache TTLs: %+v", p.Defaults.Cache)
	}
	if !p.Identities["vendor-key"].Keyed() || p.Identities["ci-main"].Keyed() {
		t.Error("identity kinds wrong")
	}
	if p.Rules[1].SBOM.IsRequired() {
		t.Error("vetted-vendor should not require an SBOM")
	}
	if len(p.Hash) != 64 {
		t.Errorf("hash = %q", p.Hash)
	}
}

func TestDefaults(t *testing.T) {
	p, err := Parse([]byte(`apiVersion: imagegate.dev/v1
identities:
  k: {publicKey: /k.pub}
rules:
  - name: r
    images: ["x/**"]
    signature: {identities: [k]}
    sbom: {identities: [k]}
`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != ModeEnforce || !p.FailClosed() || p.LocalImages != "deny" || p.Trust.Sigstore != "public-good" || !*p.Trust.RequireSCT {
		t.Errorf("unsafe defaults: %+v", p)
	}
	if !p.Rules[0].SBOM.IsRequired() {
		t.Error("SBOM must be required by default")
	}
	if len(p.Rules[0].SBOM.PredicateTypes) != 2 {
		t.Errorf("predicate types = %v", p.Rules[0].SBOM.PredicateTypes)
	}
}

func TestMatchGlobs(t *testing.T) {
	p, err := Parse([]byte(specExample + `
  - name: one-level
    images: ["docker.io/library/*"]
    signature: {identities: [vendor-key]}
    sbom: {required: false}
`))
	if err != nil {
		t.Fatal(err)
	}
	for repo, want := range map[string]string{
		"ghcr.io/acme/api":                   "internal",
		"ghcr.io/acme/team/api":              "internal",
		"registry.acme.internal/x/y/z":       "internal",
		"ghcr.io/acme":                       "",
		"ghcr.io/acmecorp/api":               "",
		"registry.vendor.example/agent":      "vetted-vendor",
		"registry.vendor.example/agent/evil": "",
		"docker.io/library/nginx":            "one-level",
		"docker.io/library/nginx/sub":        "",
		"docker.io/someone/nginx":            "",
	} {
		got := ""
		if r := p.Match(repo); r != nil {
			got = r.Name
		}
		if got != want {
			t.Errorf("Match(%q) = %q, want %q", repo, got, want)
		}
	}
}

// First match wins.
func TestFirstMatchWins(t *testing.T) {
	p, err := Parse([]byte(`apiVersion: imagegate.dev/v1
identities:
  k: {publicKey: /k.pub}
rules:
  - name: first
    images: ["ghcr.io/acme/api"]
    signature: {identities: [k]}
    sbom: {required: false}
  - name: second
    images: ["ghcr.io/acme/**"]
    signature: {identities: [k]}
    sbom: {identities: [k]}
`))
	if err != nil {
		t.Fatal(err)
	}
	if r := p.Match("ghcr.io/acme/api"); r.Name != "first" {
		t.Errorf("got %s", r.Name)
	}
}

func TestValidationErrors(t *testing.T) {
	base := `apiVersion: imagegate.dev/v1
identities:
  k: {publicKey: /k.pub}
`
	cases := map[string]string{
		"bad apiVersion":      strings.Replace(base, "v1", "v2", 1) + "rules: [{name: r, images: [x], signature: {identities: [k]}, sbom: {required: false}}]",
		"no rules":            base,
		"unknown identity":    base + "rules: [{name: r, images: [x], signature: {identities: [nope]}, sbom: {required: false}}]",
		"no signature ids":    base + "rules: [{name: r, images: [x], sbom: {required: false}}]",
		"sbom ids missing":    base + "rules: [{name: r, images: [x], signature: {identities: [k]}}]",
		"tag in glob":         base + "rules: [{name: r, images: [\"x/y:latest\"], signature: {identities: [k]}, sbom: {required: false}}]",
		"digest in glob":      base + "rules: [{name: r, images: [\"x/y@sha256:00\"], signature: {identities: [k]}, sbom: {required: false}}]",
		"duplicate rule":      base + "rules: [{name: r, images: [x], signature: {identities: [k]}, sbom: {required: false}}, {name: r, images: [y], signature: {identities: [k]}, sbom: {required: false}}]",
		"bad mode":            strings.Replace(base, "identities:", "mode: off\nidentities:", 1) + "rules: [{name: r, images: [x], signature: {identities: [k]}, sbom: {required: false}}]",
		"bad duration":        strings.Replace(base, "identities:", "defaults: {verifyTimeout: soon}\nidentities:", 1),
		"unknown field":       strings.Replace(base, "identities:", "mod: audit\nidentities:", 1),
		"keyless without san": "apiVersion: imagegate.dev/v1\nidentities: {c: {issuer: https://x}}\nrules: [{name: r, images: [x], signature: {identities: [c]}, sbom: {required: false}}]",
		"key and keyless":     "apiVersion: imagegate.dev/v1\nidentities: {c: {issuer: https://x, subject: y, publicKey: /k}}\nrules: [{name: r, images: [x], signature: {identities: [c]}, sbom: {required: false}}]",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// policyHash ignores comments and formatting but changes with content.
func TestHash(t *testing.T) {
	a, _ := Parse([]byte(specExample))
	reformatted := strings.ReplaceAll(specExample, "            # enforce | audit", "")
	reformatted = strings.ReplaceAll(reformatted, "\n\n", "\n")
	b, err := Parse([]byte(reformatted))
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash != b.Hash {
		t.Error("comments/whitespace changed the hash")
	}
	c, _ := Parse([]byte(strings.Replace(specExample, "denyTTL: 60s", "denyTTL: 30s", 1)))
	if a.Hash == c.Hash {
		t.Error("content change did not change the hash")
	}
}

func TestOverrides(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	d1 := "sha256:" + strings.Repeat("a", 64)
	d2 := "sha256:" + strings.Repeat("b", 64)
	d3 := "sha256:" + strings.Repeat("c", 64)
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.yaml", `
- digest: `+d1+`
  expires: 2026-10-21T00:00:00Z
  ticket: INC-4821
  reason: vendor hotfix, signature pending
- digest: `+d2+`
  expires: 2026-10-14T11:00:00Z
  ticket: INC-1
`)
	write("b.yaml", `
- digest: `+d3+`
  expires: 2026-11-30T00:00:00Z
  ticket: INC-2
- digest: sha256:short
  expires: 2026-10-15T00:00:00Z
  ticket: INC-3
- digest: `+d3+`
  expires: 2026-10-15T00:00:00Z
`)
	write("ignored.txt", "not yaml")

	ov, err := LoadOverrides(dir, now)
	if err == nil {
		t.Error("expected errors for invalid entries")
	}
	if o, ok := ov.Lookup(d1, now); !ok || o.Ticket != "INC-4821" {
		t.Errorf("valid override not found: %+v", o)
	}
	if _, ok := ov.Lookup(d2, now); ok {
		t.Error("expired override matched")
	}
	if _, ok := ov.Lookup(d3, now); ok {
		t.Error("override longer than 7 days or without ticket matched")
	}
	if _, ok := ov.Lookup(d1, time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)); ok {
		t.Error("override matched at its expiry")
	}
	if n := ov.Active(now); n != 1 {
		t.Errorf("Active = %d, want 1", n)
	}
	empty, err := LoadOverrides(filepath.Join(dir, "missing"), now)
	if err != nil || empty.Active(now) != 0 {
		t.Errorf("missing dir: %v", err)
	}
}
