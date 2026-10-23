package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rossedman/imagegate/internal/policy"
	"github.com/rossedman/imagegate/internal/verdict"
)

func testPolicy(t *testing.T, w *world, extra string) *policy.Policy {
	t.Helper()
	doc := fmt.Sprintf(`apiVersion: imagegate.dev/v1
trust:
  requireSCT: false
identities:
  ci-main:
    issuer: %s
    subjectRegExp: ^https://github\.com/acme/.+/\.github/workflows/release\.ya?ml@refs/heads/main$
  ci-key:
    publicKey: %s
rules:
  - name: internal
    images: ["%s/acme/**"]
    signature:
      identities: [ci-main]
    sbom:
      identities: [ci-main]
  - name: keyed
    images: ["%s/keyed/**"]
    signature:
      identities: [ci-key]
    sbom:
      identities: [ci-key]
  - name: sig-only
    images: ["%s/vendor/**"]
    signature:
      identities: [ci-key]
    sbom:
      required: false
%s`, ghIssuer, w.keyPath, w.host, w.host, w.host, extra)
	p, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func run(t *testing.T, w *world, p *policy.Policy, repo, digest string) Result {
	t.Helper()
	v, err := w.engine().Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	full := w.host + "/" + repo
	rule := p.Match(full)
	if rule == nil {
		t.Fatalf("no rule for %s", full)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return v.Verify(ctx, Target{Repo: full, Digest: digest}, rule)
}

// TestMatrix is the spec's fixture matrix, for keyless Sigstore bundles
// (cosign v3 layout, via OCI referrers).
func TestMatrix(t *testing.T) {
	w := newWorld(t)
	p := testPolicy(t, w, "")
	sign := func(repo, digest string) {
		w.attachBundle(repo, digest, w.keylessDSSE(ciMainSAN, digest, CosignSignPredicate))
	}

	cases := []struct {
		name   string
		setup  func() (repo, digest string)
		want   verdict.Reason
		signer string
		detail string
	}{
		{
			name: "signed by ci-main, signed SPDX attestation",
			setup: func() (string, string) {
				d := w.pushImage("acme/spdx")
				sign("acme/spdx", d)
				w.attachBundle("acme/spdx", d, w.keylessDSSE(ciMainSAN, d, spdxType))
				return "acme/spdx", d
			},
			want: verdict.Allowed, signer: "ci-main",
		},
		{
			name: "signed by ci-main, signed CycloneDX attestation",
			setup: func() (string, string) {
				d := w.pushImage("acme/cdx")
				sign("acme/cdx", d)
				w.attachBundle("acme/cdx", d, w.keylessDSSE(ciMainSAN, d, cdxType))
				return "acme/cdx", d
			},
			want: verdict.Allowed, signer: "ci-main",
		},
		{
			name: "versioned SPDX predicate type",
			setup: func() (string, string) {
				d := w.pushImage("acme/spdx23")
				sign("acme/spdx23", d)
				w.attachBundle("acme/spdx23", d, w.keylessDSSE(ciMainSAN, d, spdxType+"/v2.3"))
				return "acme/spdx23", d
			},
			want: verdict.Allowed,
		},
		{
			name: "signed, no attestation",
			setup: func() (string, string) {
				d := w.pushImage("acme/nosbom")
				sign("acme/nosbom", d)
				return "acme/nosbom", d
			},
			want: verdict.NoSBOM, detail: `signed by identity "ci-main"`,
		},
		{
			name: "signed, BuildKit SBOM attached but unsigned",
			setup: func() (string, string) {
				d, _ := w.pushIndex("acme/buildkit", true)
				sign("acme/buildkit", d)
				return "acme/buildkit", d
			},
			want: verdict.SBOMUntrusted, detail: "unsigned",
		},
		{
			name: "signed, unsigned SPDX referrer",
			setup: func() (string, string) {
				d := w.pushImage("acme/plainsbom")
				sign("acme/plainsbom", d)
				w.attachUnsignedSBOM("acme/plainsbom", d)
				return "acme/plainsbom", d
			},
			want: verdict.SBOMUntrusted,
		},
		{
			name: "SBOM attested by another workflow",
			setup: func() (string, string) {
				d := w.pushImage("acme/forksbom")
				sign("acme/forksbom", d)
				w.attachBundle("acme/forksbom", d, w.keylessDSSE(forkSAN, d, spdxType))
				return "acme/forksbom", d
			},
			want: verdict.SBOMUntrusted, detail: "someone",
		},
		{
			name: "signed by another workflow",
			setup: func() (string, string) {
				d := w.pushImage("acme/fork")
				w.attachBundle("acme/fork", d, w.keylessDSSE(forkSAN, d, CosignSignPredicate))
				w.attachBundle("acme/fork", d, w.keylessDSSE(forkSAN, d, spdxType))
				return "acme/fork", d
			},
			want: verdict.IdentityMismatch, detail: forkSAN,
		},
		{
			name: "unsigned",
			setup: func() (string, string) {
				return "acme/unsigned", w.pushImage("acme/unsigned")
			},
			want: verdict.NoSignature,
		},
		{
			name: "SBOM attestation is not a signature",
			setup: func() (string, string) {
				d := w.pushImage("acme/attonly")
				w.attachBundle("acme/attonly", d, w.keylessDSSE(ciMainSAN, d, spdxType))
				return "acme/attonly", d
			},
			want: verdict.NoSignature,
		},
		{
			name: "signature for another digest attached here",
			setup: func() (string, string) {
				d := w.pushImage("acme/wrongsubject")
				other := w.pushImage("acme/other")
				w.attachBundle("acme/wrongsubject", d, w.keylessDSSE(ciMainSAN, other, CosignSignPredicate))
				return "acme/wrongsubject", d
			},
			want: verdict.NoSignature, detail: "none valid",
		},
		{
			name: "multi-platform, signed at index",
			setup: func() (string, string) {
				d, _ := w.pushIndex("acme/multi", false)
				sign("acme/multi", d)
				w.attachBundle("acme/multi", d, w.keylessDSSE(ciMainSAN, d, spdxType))
				return "acme/multi", d
			},
			want: verdict.Allowed,
		},
		{
			// Only the digest dockerd resolved counts: a signature on one
			// platform child must not let another child run.
			name: "multi-platform, signed only on a platform manifest",
			setup: func() (string, string) {
				d, child := w.pushIndex("acme/childonly", false)
				sign("acme/childonly", child)
				w.attachBundle("acme/childonly", child, w.keylessDSSE(ciMainSAN, child, spdxType))
				return "acme/childonly", d
			},
			want: verdict.NoSignature,
		},
		{
			name: "malformed bundle referrers alongside a valid signature",
			setup: func() (string, string) {
				d := w.pushImage("acme/junk")
				w.attachArtifact("acme/junk", d, bundleType, []byte("not a bundle"))
				w.attachArtifact("acme/junk", d, bundleType)
				sign("acme/junk", d)
				w.attachBundle("acme/junk", d, w.keylessDSSE(ciMainSAN, d, spdxType))
				return "acme/junk", d
			},
			want: verdict.Allowed, signer: "ci-main",
		},
		{
			name: "keyed signature where the rule requires keyless",
			setup: func() (string, string) {
				d := w.pushImage("acme/keyedsig")
				w.attachBundle("acme/keyedsig", d, w.keyedDSSE(d, CosignSignPredicate, w.key))
				return "acme/keyedsig", d
			},
			want: verdict.IdentityMismatch, detail: "rule requires a keyless identity",
		},
		{
			name: "attestation with another predicate is not an SBOM",
			setup: func() (string, string) {
				d := w.pushImage("acme/slsa")
				sign("acme/slsa", d)
				w.attachBundle("acme/slsa", d, w.keylessDSSE(ciMainSAN, d, "https://slsa.dev/provenance/v1"))
				return "acme/slsa", d
			},
			want: verdict.NoSBOM,
		},
		{
			name: "SBOM attestation for another digest",
			setup: func() (string, string) {
				d := w.pushImage("acme/sbomother")
				other := w.pushImage("acme/sbomother-x")
				sign("acme/sbomother", d)
				w.attachBundle("acme/sbomother", d, w.keylessDSSE(ciMainSAN, other, spdxType))
				return "acme/sbomother", d
			},
			want: verdict.SBOMUntrusted, detail: "not signed by an allowed identity",
		},
		{
			name: "BuildKit attestation without an SBOM",
			setup: func() (string, string) {
				d, _ := w.pushIndexAtt("acme/bkprov", "https://slsa.dev/provenance/v1")
				sign("acme/bkprov", d)
				return "acme/bkprov", d
			},
			want: verdict.NoSBOM,
		},
		{
			name: "signed index whose BuildKit SBOM is only an annotation on a child",
			setup: func() (string, string) {
				d, child := w.pushIndex("acme/bkchild", true)
				sign("acme/bkchild", child)
				w.attachBundle("acme/bkchild", child, w.keylessDSSE(ciMainSAN, child, spdxType))
				return "acme/bkchild", d
			},
			want: verdict.NoSignature,
		},
		{
			name: "digest not in registry",
			setup: func() (string, string) {
				return "acme/missing", "sha256:" + strings.Repeat("ab", 32)
			},
			want: verdict.LocalImage, detail: "not in registry",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo, digest := tc.setup()
			got := run(t, w, p, repo, digest)
			if got.Reason != tc.want {
				t.Fatalf("reason = %s (%s), want %s", got.Reason, got.Detail, tc.want)
			}
			if tc.signer != "" && got.Signer != tc.signer {
				t.Errorf("signer = %q, want %q", got.Signer, tc.signer)
			}
			if !strings.Contains(got.Detail, tc.detail) {
				t.Errorf("detail = %q, want it to contain %q", got.Detail, tc.detail)
			}
		})
	}
}

// TestLegacyLayout covers cosign v2's sha256-<digest>.sig/.att tags.
func TestLegacyLayout(t *testing.T) {
	w := newWorld(t)
	p := testPolicy(t, w, "")
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	t.Run("keyless signature with Rekor SET and keyless attestation", func(t *testing.T) {
		d := w.pushImage("acme/legacy")
		w.pushLegacy("acme/legacy", d, ".sig", w.legacyKeylessSig(ciMainSAN, w.host+"/acme/legacy", d))
		w.attachBundle("acme/legacy", d, w.keylessDSSE(ciMainSAN, d, spdxType))
		if got := run(t, w, p, "acme/legacy", d); got.Reason != verdict.Allowed {
			t.Fatalf("got %s: %s", got.Reason, got.Detail)
		}
	})
	t.Run("keyless signature from another identity", func(t *testing.T) {
		d := w.pushImage("acme/legacyfork")
		w.pushLegacy("acme/legacyfork", d, ".sig", w.legacyKeylessSig(forkSAN, w.host+"/acme/legacyfork", d))
		if got := run(t, w, p, "acme/legacyfork", d); got.Reason != verdict.IdentityMismatch {
			t.Fatalf("got %s: %s", got.Reason, got.Detail)
		}
	})
	t.Run("keyed signature and attestation without tlog", func(t *testing.T) {
		d := w.pushImage("keyed/app")
		w.pushLegacy("keyed/app", d, ".sig", w.legacyKeyedSig(w.host+"/keyed/app", d, w.key))
		w.pushLegacy("keyed/app", d, ".att", w.legacyKeyedAtt(d, spdxType, w.key))
		got := run(t, w, p, "keyed/app", d)
		if got.Reason != verdict.Allowed || got.Signer != "ci-key" {
			t.Fatalf("got %s %q: %s", got.Reason, got.Signer, got.Detail)
		}
	})
	t.Run("keyed signature by an unknown key", func(t *testing.T) {
		d := w.pushImage("keyed/otherkey")
		w.pushLegacy("keyed/otherkey", d, ".sig", w.legacyKeyedSig(w.host+"/keyed/otherkey", d, other))
		if got := run(t, w, p, "keyed/otherkey", d); got.Reason != verdict.IdentityMismatch {
			t.Fatalf("got %s: %s", got.Reason, got.Detail)
		}
	})
	t.Run("signed payload names another digest", func(t *testing.T) {
		d := w.pushImage("keyed/replay")
		other := w.pushImage("keyed/replay-other")
		w.pushLegacy("keyed/replay", d, ".sig", w.legacyKeyedSig(w.host+"/keyed/replay", other, w.key))
		if got := run(t, w, p, "keyed/replay", d); got.Reason == verdict.Allowed {
			t.Fatalf("replayed signature was accepted")
		}
	})
	t.Run("tampered payload", func(t *testing.T) {
		d := w.pushImage("keyed/tamper")
		l := w.legacyKeyedSig(w.host+"/keyed/tamper", d, w.key)
		l.content = append([]byte(nil), l.content...)
		l.content[len(l.content)-2] = ' '
		w.pushLegacy("keyed/tamper", d, ".sig", l)
		if got := run(t, w, p, "keyed/tamper", d); got.Reason == verdict.Allowed {
			t.Fatalf("tampered signature was accepted")
		}
	})
	t.Run("keyed bundle via referrers (cosign v3 without Rekor)", func(t *testing.T) {
		d := w.pushImage("keyed/v3")
		w.attachBundle("keyed/v3", d, w.keyedDSSE(d, CosignSignPredicate, w.key))
		w.attachBundle("keyed/v3", d, w.keyedDSSE(d, spdxType, w.key))
		if got := run(t, w, p, "keyed/v3", d); got.Reason != verdict.Allowed {
			t.Fatalf("got %s: %s", got.Reason, got.Detail)
		}
	})
	t.Run("unreadable layers skipped, valid keyed signature verifies", func(t *testing.T) {
		d := w.pushImage("keyed/junk")
		nosig := w.legacyKeyedSig(w.host+"/keyed/junk", d, w.key)
		nosig.annotations = nil
		w.pushLegacy("keyed/junk", d, ".sig",
			legacyLayer{mediaType: "application/octet-stream", content: []byte("x")},
			nosig,
			legacyLayer{mediaType: dsseLayerType, content: []byte("{")},
			w.legacyKeyedSig(w.host+"/keyed/junk", d, w.key),
		)
		w.pushLegacy("keyed/junk", d, ".att", w.legacyKeyedAtt(d, spdxType, w.key))
		if got := run(t, w, p, "keyed/junk", d); got.Reason != verdict.Allowed || got.Signer != "ci-key" {
			t.Fatalf("got %s %q: %s", got.Reason, got.Signer, got.Detail)
		}
	})
	t.Run("keyed attestation by an unknown key", func(t *testing.T) {
		d := w.pushImage("keyed/attother")
		w.pushLegacy("keyed/attother", d, ".sig", w.legacyKeyedSig(w.host+"/keyed/attother", d, w.key))
		w.pushLegacy("keyed/attother", d, ".att", w.legacyKeyedAtt(d, spdxType, other))
		if got := run(t, w, p, "keyed/attother", d); got.Reason != verdict.SBOMUntrusted {
			t.Fatalf("got %s: %s", got.Reason, got.Detail)
		}
	})
	t.Run("only unsigned legacy layers", func(t *testing.T) {
		d := w.pushImage("keyed/nosig")
		l := w.legacyKeyedSig(w.host+"/keyed/nosig", d, w.key)
		l.annotations = nil
		w.pushLegacy("keyed/nosig", d, ".sig", l)
		got := run(t, w, p, "keyed/nosig", d)
		if got.Reason != verdict.NoSignature || !strings.Contains(got.Detail, "no cosign signature found") {
			t.Fatalf("got %s: %s", got.Reason, got.Detail)
		}
	})
	t.Run("sbom not required", func(t *testing.T) {
		d := w.pushImage("vendor/agent")
		w.attachBundle("vendor/agent", d, w.keyedDSSE(d, CosignSignPredicate, w.key))
		if got := run(t, w, p, "vendor/agent", d); got.Reason != verdict.Allowed {
			t.Fatalf("got %s: %s", got.Reason, got.Detail)
		}
	})
}

func TestTrustRootUnavailable(t *testing.T) {
	w := newWorld(t)
	p := testPolicy(t, w, "")
	d := w.pushImage("acme/notrust")
	w.attachBundle("acme/notrust", d, w.keylessDSSE(ciMainSAN, d, CosignSignPredicate))
	v, err := NewEngine(Options{Trust: StaticTrust{}, NameOptions: w.engine().nameOpts}).Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	full := w.host + "/acme/notrust"
	got := v.Verify(context.Background(), Target{Repo: full, Digest: d}, p.Match(full))
	if got.Reason != verdict.UpstreamUnavailable {
		t.Fatalf("got %s: %s", got.Reason, got.Detail)
	}
}

func TestRegistryDown(t *testing.T) {
	w := newWorld(t)
	p := testPolicy(t, w, `  - name: down
    images: ["127.0.0.1:1/**"]
    signature: {identities: [ci-key]}
    sbom: {required: false}
`)
	v, _ := w.engine().Compile(p)
	got := v.Verify(context.Background(), Target{Repo: "127.0.0.1:1/x", Digest: "sha256:" + strings.Repeat("0", 64)}, p.Match("127.0.0.1:1/x"))
	if got.Reason != verdict.UpstreamUnavailable {
		t.Fatalf("got %s: %s", got.Reason, got.Detail)
	}
}

func TestTimeout(t *testing.T) {
	w := newWorld(t)
	p := testPolicy(t, w, "")
	d := w.pushImage("acme/slow")
	v, _ := w.engine().Compile(p)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	full := w.host + "/acme/slow"
	if got := v.Verify(ctx, Target{Repo: full, Digest: d}, p.Match(full)); got.Reason != verdict.Timeout {
		t.Fatalf("got %s: %s", got.Reason, got.Detail)
	}
}

func TestPredicateAllowed(t *testing.T) {
	allowed := policy.DefaultPredicateTypes
	for pt, want := range map[string]bool{
		"https://spdx.dev/Document":      true,
		"https://spdx.dev/Document/v2.3": true,
		"https://spdx.dev/DocumentX":     false,
		"https://cyclonedx.org/bom":      true,
		"https://cyclonedx.org/bom/v1.5": true,
		"https://slsa.dev/provenance/v1": false,
		"":                               false,
	} {
		if got := predicateAllowed(pt, allowed); got != want {
			t.Errorf("predicateAllowed(%q) = %v, want %v", pt, got, want)
		}
	}
}

// Certificates without an embedded SCT are rejected unless the policy opts
// out with trust.requireSCT: false.
func TestRequireSCT(t *testing.T) {
	w := newWorld(t)
	p := testPolicy(t, w, "")
	*p.Trust.RequireSCT = true
	d := w.pushImage("acme/nosct")
	w.attachBundle("acme/nosct", d, w.keylessDSSE(ciMainSAN, d, CosignSignPredicate))
	if got := run(t, w, p, "acme/nosct", d); got.Reason == verdict.Allowed {
		t.Fatal("certificate without SCT was accepted")
	}
}
