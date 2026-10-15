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

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/rossedman/image-gate/internal/policy"
	"github.com/rossedman/image-gate/internal/verdict"
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

func run(t *testing.T, w *world, p *policy.Policy, repo, digest string, platform *v1.Platform) Result {
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
	return v.Verify(ctx, Target{Repo: full, Digest: digest, Platform: platform}, rule)
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
		setup  func() (repo, digest string, platform *v1.Platform)
		want   verdict.Reason
		signer string
		detail string
	}{
		{
			name: "signed by ci-main, signed SPDX attestation",
			setup: func() (string, string, *v1.Platform) {
				d := w.pushImage("acme/spdx")
				sign("acme/spdx", d)
				w.attachBundle("acme/spdx", d, w.keylessDSSE(ciMainSAN, d, spdxType))
				return "acme/spdx", d, nil
			},
			want: verdict.Allowed, signer: "ci-main",
		},
		{
			name: "signed by ci-main, signed CycloneDX attestation",
			setup: func() (string, string, *v1.Platform) {
				d := w.pushImage("acme/cdx")
				sign("acme/cdx", d)
				w.attachBundle("acme/cdx", d, w.keylessDSSE(ciMainSAN, d, cdxType))
				return "acme/cdx", d, nil
			},
			want: verdict.Allowed, signer: "ci-main",
		},
		{
			name: "versioned SPDX predicate type",
			setup: func() (string, string, *v1.Platform) {
				d := w.pushImage("acme/spdx23")
				sign("acme/spdx23", d)
				w.attachBundle("acme/spdx23", d, w.keylessDSSE(ciMainSAN, d, spdxType+"/v2.3"))
				return "acme/spdx23", d, nil
			},
			want: verdict.Allowed,
		},
		{
			name: "signed, no attestation",
			setup: func() (string, string, *v1.Platform) {
				d := w.pushImage("acme/nosbom")
				sign("acme/nosbom", d)
				return "acme/nosbom", d, nil
			},
			want: verdict.NoSBOM, detail: `signed by identity "ci-main"`,
		},
		{
			name: "signed, BuildKit SBOM attached but unsigned",
			setup: func() (string, string, *v1.Platform) {
				d, _ := w.pushIndex("acme/buildkit", true)
				sign("acme/buildkit", d)
				return "acme/buildkit", d, &v1.Platform{OS: "linux", Architecture: "amd64"}
			},
			want: verdict.SBOMUntrusted, detail: "unsigned",
		},
		{
			name: "signed, unsigned SPDX referrer",
			setup: func() (string, string, *v1.Platform) {
				d := w.pushImage("acme/plainsbom")
				sign("acme/plainsbom", d)
				w.attachUnsignedSBOM("acme/plainsbom", d)
				return "acme/plainsbom", d, nil
			},
			want: verdict.SBOMUntrusted,
		},
		{
			name: "SBOM attested by another workflow",
			setup: func() (string, string, *v1.Platform) {
				d := w.pushImage("acme/forksbom")
				sign("acme/forksbom", d)
				w.attachBundle("acme/forksbom", d, w.keylessDSSE(forkSAN, d, spdxType))
				return "acme/forksbom", d, nil
			},
			want: verdict.SBOMUntrusted, detail: "someone",
		},
		{
			name: "signed by another workflow",
			setup: func() (string, string, *v1.Platform) {
				d := w.pushImage("acme/fork")
				w.attachBundle("acme/fork", d, w.keylessDSSE(forkSAN, d, CosignSignPredicate))
				w.attachBundle("acme/fork", d, w.keylessDSSE(forkSAN, d, spdxType))
				return "acme/fork", d, nil
			},
			want: verdict.IdentityMismatch, detail: forkSAN,
		},
		{
			name: "unsigned",
			setup: func() (string, string, *v1.Platform) {
				return "acme/unsigned", w.pushImage("acme/unsigned"), nil
			},
			want: verdict.NoSignature,
		},
		{
			name: "SBOM attestation is not a signature",
			setup: func() (string, string, *v1.Platform) {
				d := w.pushImage("acme/attonly")
				w.attachBundle("acme/attonly", d, w.keylessDSSE(ciMainSAN, d, spdxType))
				return "acme/attonly", d, nil
			},
			want: verdict.NoSignature,
		},
		{
			name: "signature for another digest attached here",
			setup: func() (string, string, *v1.Platform) {
				d := w.pushImage("acme/wrongsubject")
				other := w.pushImage("acme/other")
				w.attachBundle("acme/wrongsubject", d, w.keylessDSSE(ciMainSAN, other, CosignSignPredicate))
				return "acme/wrongsubject", d, nil
			},
			want: verdict.NoSignature, detail: "none valid",
		},
		{
			name: "multi-platform, signed at index",
			setup: func() (string, string, *v1.Platform) {
				d, _ := w.pushIndex("acme/multi", false)
				sign("acme/multi", d)
				w.attachBundle("acme/multi", d, w.keylessDSSE(ciMainSAN, d, spdxType))
				return "acme/multi", d, &v1.Platform{OS: "linux", Architecture: "arm64"}
			},
			want: verdict.Allowed,
		},
		{
			name: "multi-platform, signed at index, SBOM on platform manifest",
			setup: func() (string, string, *v1.Platform) {
				d, child := w.pushIndex("acme/multichild", false)
				sign("acme/multichild", d)
				w.attachBundle("acme/multichild", child, w.keylessDSSE(ciMainSAN, child, spdxType))
				return "acme/multichild", d, &v1.Platform{OS: "linux", Architecture: "amd64"}
			},
			want: verdict.Allowed,
		},
		{
			name: "digest not in registry",
			setup: func() (string, string, *v1.Platform) {
				return "acme/missing", "sha256:" + strings.Repeat("ab", 32), nil
			},
			want: verdict.LocalImage, detail: "not in registry",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo, digest, platform := tc.setup()
			got := run(t, w, p, repo, digest, platform)
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
		if got := run(t, w, p, "acme/legacy", d, nil); got.Reason != verdict.Allowed {
			t.Fatalf("got %s: %s", got.Reason, got.Detail)
		}
	})
	t.Run("keyless signature from another identity", func(t *testing.T) {
		d := w.pushImage("acme/legacyfork")
		w.pushLegacy("acme/legacyfork", d, ".sig", w.legacyKeylessSig(forkSAN, w.host+"/acme/legacyfork", d))
		if got := run(t, w, p, "acme/legacyfork", d, nil); got.Reason != verdict.IdentityMismatch {
			t.Fatalf("got %s: %s", got.Reason, got.Detail)
		}
	})
	t.Run("keyed signature and attestation without tlog", func(t *testing.T) {
		d := w.pushImage("keyed/app")
		w.pushLegacy("keyed/app", d, ".sig", w.legacyKeyedSig(w.host+"/keyed/app", d, w.key))
		w.pushLegacy("keyed/app", d, ".att", w.legacyKeyedAtt(d, spdxType, w.key))
		got := run(t, w, p, "keyed/app", d, nil)
		if got.Reason != verdict.Allowed || got.Signer != "ci-key" {
			t.Fatalf("got %s %q: %s", got.Reason, got.Signer, got.Detail)
		}
	})
	t.Run("keyed signature by an unknown key", func(t *testing.T) {
		d := w.pushImage("keyed/otherkey")
		w.pushLegacy("keyed/otherkey", d, ".sig", w.legacyKeyedSig(w.host+"/keyed/otherkey", d, other))
		if got := run(t, w, p, "keyed/otherkey", d, nil); got.Reason != verdict.IdentityMismatch {
			t.Fatalf("got %s: %s", got.Reason, got.Detail)
		}
	})
	t.Run("signed payload names another digest", func(t *testing.T) {
		d := w.pushImage("keyed/replay")
		other := w.pushImage("keyed/replay-other")
		w.pushLegacy("keyed/replay", d, ".sig", w.legacyKeyedSig(w.host+"/keyed/replay", other, w.key))
		if got := run(t, w, p, "keyed/replay", d, nil); got.Reason == verdict.Allowed {
			t.Fatalf("replayed signature was accepted")
		}
	})
	t.Run("tampered payload", func(t *testing.T) {
		d := w.pushImage("keyed/tamper")
		l := w.legacyKeyedSig(w.host+"/keyed/tamper", d, w.key)
		l.content = append([]byte(nil), l.content...)
		l.content[len(l.content)-2] = ' '
		w.pushLegacy("keyed/tamper", d, ".sig", l)
		if got := run(t, w, p, "keyed/tamper", d, nil); got.Reason == verdict.Allowed {
			t.Fatalf("tampered signature was accepted")
		}
	})
	t.Run("keyed bundle via referrers (cosign v3 without Rekor)", func(t *testing.T) {
		d := w.pushImage("keyed/v3")
		w.attachBundle("keyed/v3", d, w.keyedDSSE(d, CosignSignPredicate, w.key))
		w.attachBundle("keyed/v3", d, w.keyedDSSE(d, spdxType, w.key))
		if got := run(t, w, p, "keyed/v3", d, nil); got.Reason != verdict.Allowed {
			t.Fatalf("got %s: %s", got.Reason, got.Detail)
		}
	})
	t.Run("sbom not required", func(t *testing.T) {
		d := w.pushImage("vendor/agent")
		w.attachBundle("vendor/agent", d, w.keyedDSSE(d, CosignSignPredicate, w.key))
		if got := run(t, w, p, "vendor/agent", d, nil); got.Reason != verdict.Allowed {
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
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
	if got := run(t, w, p, "acme/nosct", d, nil); got.Reason == verdict.Allowed {
		t.Fatal("certificate without SCT was accepted")
	}
}
