package verify

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/rossedman/imagegate/internal/imageref"
	"github.com/rossedman/imagegate/internal/policy"
	"github.com/rossedman/imagegate/internal/verdict"
)

func writePEM(t *testing.T, dir, name string, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCompile(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	dir := t.TempDir()
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, "garbage.pub")
	if err := os.WriteFile(garbage, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	ed := writePEM(t, dir, "ed.pub", edPub)
	rsaPath := writePEM(t, dir, "rsa.pub", &rsaKey.PublicKey)
	x25519 := writePEM(t, dir, "x25519.pub", xKey.PublicKey())

	keyless := policy.Identity{Issuer: ghIssuer, Subject: ciMainSAN}
	cases := []struct {
		name    string
		ids     map[string]policy.Identity
		keyed   []string
		keyless []string
		wantErr []string
	}{
		{name: "empty"},
		{
			name:    "keyless and keyed",
			ids:     map[string]policy.Identity{"ci": keyless, "ec": {PublicKey: w.keyPath}, "ed": {PublicKey: ed}, "rsa": {PublicKey: rsaPath}},
			keyed:   []string{"ec", "ed", "rsa"},
			keyless: []string{"ci"},
		},
		{
			name:    "regexp identity",
			ids:     map[string]policy.Identity{"re": {IssuerRegExp: "^https://token\\.actions\\.githubusercontent\\.com$", SubjectRegExp: "^https://github\\.com/acme/"}},
			keyless: []string{"re"},
		},
		{
			name:    "missing key file",
			ids:     map[string]policy.Identity{"gone": {PublicKey: filepath.Join(dir, "nope.pub")}, "ci": keyless},
			keyless: []string{"ci"},
			wantErr: []string{"identities.gone", "nope.pub"},
		},
		{
			name:    "not PEM",
			ids:     map[string]policy.Identity{"bad": {PublicKey: garbage}},
			wantErr: []string{"identities.bad", "parse public key " + garbage},
		},
		{
			name:    "unsupported key type",
			ids:     map[string]policy.Identity{"x": {PublicKey: x25519}},
			wantErr: []string{"identities.x"},
		},
		{
			name:    "bad subject regexp",
			ids:     map[string]policy.Identity{"re": {Issuer: ghIssuer, SubjectRegExp: "("}},
			wantErr: []string{"identities.re"},
		},
		{
			name:    "every failure is reported",
			ids:     map[string]policy.Identity{"a": {PublicKey: garbage}, "b": {Issuer: ghIssuer, SubjectRegExp: "["}, "ok": {PublicKey: w.keyPath}},
			keyed:   []string{"ok"},
			wantErr: []string{"identities.a", "identities.b"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, sct := range []bool{false, true} {
				p := &policy.Policy{Trust: policy.Trust{RequireSCT: &sct}, Identities: tc.ids}
				v, err := w.engine().Compile(p)
				if v == nil {
					t.Fatal("Compile returned a nil verifier")
				}
				if v.requireSCT != sct {
					t.Errorf("requireSCT = %v, want %v", v.requireSCT, sct)
				}
				if len(tc.wantErr) == 0 && err != nil {
					t.Fatal(err)
				}
				for _, want := range tc.wantErr {
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Errorf("err = %v, want it to contain %q", err, want)
					}
				}
				if got := len(v.identities); got != len(tc.keyed)+len(tc.keyless) {
					t.Errorf("compiled %d identities, want %d", got, len(tc.keyed)+len(tc.keyless))
				}
				for _, n := range tc.keyed {
					if id := v.identities[n]; id.key == nil || id.keyless != nil || id.name != n {
						t.Errorf("identity %s = %+v, want keyed", n, id)
					}
				}
				for _, n := range tc.keyless {
					if id := v.identities[n]; id.keyless == nil || id.key != nil || id.name != n {
						t.Errorf("identity %s = %+v, want keyless", n, id)
					}
				}
			}
		})
	}
}

func TestNewEngineDefaults(t *testing.T) {
	t.Parallel()
	e := NewEngine(Options{})
	if e.reg.keychain == nil || e.reg.transport == nil {
		t.Fatal("default keychain or transport not set")
	}
	if _, err := e.trust.TrustedMaterial(); err == nil {
		t.Fatal("default trust must be empty, not a trusted root")
	}
}

func TestArtifact(t *testing.T) {
	t.Parallel()
	v := &Verifier{}
	cases := []struct {
		name    string
		c       candidate
		wantErr string
	}{
		{name: "legacy payload", c: candidate{entity: entity{payload: []byte("{}")}, subject: "anything"}},
		{name: "sha256 digest", c: candidate{subject: "sha256:" + strings.Repeat("ab", 32)}},
		{name: "sha512 digest", c: candidate{subject: "sha512:" + strings.Repeat("ab", 64)}, wantErr: "unsupported digest"},
		{name: "no algorithm", c: candidate{subject: strings.Repeat("ab", 32)}, wantErr: "unsupported digest"},
		{name: "not hex", c: candidate{subject: "sha256:zz"}, wantErr: "invalid byte"},
		{name: "odd length", c: candidate{subject: "sha256:abc"}, wantErr: "odd length"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			art, err := v.artifact(tc.c)
			if tc.wantErr == "" {
				if err != nil || art == nil {
					t.Fatalf("artifact = %v, %v", art, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func dsseEntity(t *testing.T, payloadType string, payload []byte) entity {
	t.Helper()
	env := map[string]any{"payloadType": payloadType, "payload": payload, "signatures": []map[string]any{{"sig": []byte("sig")}}}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	e, err := legacyEntity(dsseLayerType, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestPredicateType(t *testing.T) {
	t.Parallel()
	_, fx := newLegacyFixtures(t)
	msg, err := legacyEntity(simpleSigningType, fx.keyed.content, fx.keyed.annotations)
	if err != nil {
		t.Fatal(err)
	}
	msgNoPayload := msg
	msgNoPayload.payload = nil
	d := "sha256:" + strings.Repeat("ab", 32)
	cases := []struct {
		name string
		e    entity
		pt   string
		ok   bool
	}{
		{name: "legacy simplesigning", e: msg, pt: "", ok: true},
		{name: "message signature without payload", e: msgNoPayload, ok: false},
		{name: "in-toto statement", e: dsseEntity(t, "application/vnd.in-toto+json", statement(d, spdxType)), pt: spdxType, ok: true},
		{name: "cosign sign statement", e: dsseEntity(t, "application/vnd.in-toto+json", statement(d, CosignSignPredicate)), pt: CosignSignPredicate, ok: true},
		{name: "statement without predicate type", e: dsseEntity(t, "application/vnd.in-toto+json", statement(d, "")), ok: false},
		{name: "not in-toto", e: dsseEntity(t, "text/plain", statement(d, spdxType)), ok: false},
		{name: "payload not JSON", e: dsseEntity(t, "application/vnd.in-toto+json", []byte("nope")), ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pt, ok := candidate{entity: tc.e, subject: d}.predicateType()
			if pt != tc.pt || ok != tc.ok {
				t.Fatalf("predicateType = %q, %v; want %q, %v", pt, ok, tc.pt, tc.ok)
			}
		})
	}
}

func TestPostCheck(t *testing.T) {
	t.Parallel()
	d := "sha256:" + strings.Repeat("ab", 32)
	stmt := func(pt string) *sgverify.VerificationResult {
		e := dsseEntity(t, "application/vnd.in-toto+json", statement(d, pt))
		env, err := e.bundle.Envelope()
		if err != nil {
			t.Fatal(err)
		}
		st, err := env.Statement()
		if err != nil {
			t.Fatal(err)
		}
		return &sgverify.VerificationResult{Statement: st}
	}
	dsse := candidate{subject: d}
	legacy := func(digest string) candidate {
		return candidate{entity: entity{payload: simpleSigningPayload("reg/app", digest)}, subject: d}
	}
	cases := []struct {
		name string
		c    candidate
		res  *sgverify.VerificationResult
		ok   bool
	}{
		{name: "verified signature statement", c: dsse, res: stmt(CosignSignPredicate), ok: true},
		{name: "verified statement of another type", c: dsse, res: stmt(spdxType)},
		{name: "no verified statement", c: dsse, res: &sgverify.VerificationResult{}},
		{name: "legacy payload for this digest", c: legacy(d), res: &sgverify.VerificationResult{}, ok: true},
		{name: "legacy payload for another digest", c: legacy("sha256:" + strings.Repeat("cd", 32)), res: &sgverify.VerificationResult{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := postCheck(tc.c, tc.res, isSignature); (err == nil) != tc.ok {
				t.Fatalf("postCheck = %v, want ok = %v", err, tc.ok)
			}
		})
	}
}

func TestResolveDigest(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	img := w.pushImage("acme/resolve")
	idx, _ := w.pushIndex("acme/resolveidx", false)
	cases := []struct {
		name     string
		ref      imageref.Ref
		want     string
		notFound bool
		wantErr  bool
	}{
		{name: "image tag", ref: imageref.Ref{Repo: w.host + "/acme/resolve", Tag: "latest"}, want: img},
		{name: "index tag resolves to the index", ref: imageref.Ref{Repo: w.host + "/acme/resolveidx", Tag: "latest"}, want: idx},
		{name: "unknown tag", ref: imageref.Ref{Repo: w.host + "/acme/resolve", Tag: "v9"}, wantErr: true, notFound: true},
		{name: "unknown repository", ref: imageref.Ref{Repo: w.host + "/acme/none", Tag: "latest"}, wantErr: true, notFound: true},
		{name: "invalid repository", ref: imageref.Ref{Repo: "Not A Repo", Tag: "latest"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := w.engine().ResolveDigest(t.Context(), tc.ref)
			if tc.wantErr {
				if err == nil || got != "" {
					t.Fatalf("got %q, %v; want an error", got, err)
				}
				if isNotFound(err) != tc.notFound {
					t.Errorf("isNotFound(%v) = %v, want %v", err, !tc.notFound, tc.notFound)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestResolveDigestRegistryDown(t *testing.T) {
	t.Parallel()
	_, err := NewEngine(Options{Keychain: authn.NewMultiKeychain()}).ResolveDigest(t.Context(), imageref.Ref{Repo: "127.0.0.1:1/x", Tag: "latest"})
	if err == nil || !isTransient(err) {
		t.Fatalf("err = %v, want a transient error", err)
	}
}

func TestVerifyBadRepository(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	p := testPolicy(t, w, "")
	v, err := w.engine().Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	got := v.Verify(t.Context(), Target{Repo: "Not A Repo", Digest: "sha256:" + strings.Repeat("ab", 32)}, &p.Rules[0])
	if got.Reason != verdict.BadRequest {
		t.Fatalf("got %s: %s", got.Reason, got.Detail)
	}
}

// BenchmarkVerify is a full keyless verification (signature and SBOM
// attestation, both Sigstore bundles via referrers) against the in-process
// registry.
func BenchmarkVerify(b *testing.B) {
	w := newWorld(b)
	d := w.pushImage("acme/bench")
	w.attachBundle("acme/bench", d, w.keylessDSSE(ciMainSAN, d, CosignSignPredicate))
	w.attachBundle("acme/bench", d, w.keylessDSSE(ciMainSAN, d, spdxType))
	sct := false
	p, err := policy.Parse([]byte(`apiVersion: imagegate.dev/v1
trust:
  requireSCT: false
identities:
  ci-main:
    issuer: ` + ghIssuer + `
    subject: ` + ciMainSAN + `
rules:
  - name: internal
    images: ["` + w.host + `/acme/**"]
    signature: {identities: [ci-main]}
    sbom: {identities: [ci-main]}
`))
	if err != nil {
		b.Fatal(err)
	}
	p.Trust.RequireSCT = &sct
	v, err := w.engine().Compile(p)
	if err != nil {
		b.Fatal(err)
	}
	full := w.host + "/acme/bench"
	rule := p.Match(full)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	b.ReportAllocs()
	for b.Loop() {
		if got := v.Verify(ctx, Target{Repo: full, Digest: d}, rule); got.Reason != verdict.Allowed {
			b.Fatalf("got %s: %s", got.Reason, got.Detail)
		}
	}
}
