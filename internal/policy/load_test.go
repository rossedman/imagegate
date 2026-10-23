package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// minimal is the smallest valid policy, with a keyed identity whose key
// path is substituted by the caller.
func minimal(key string) string {
	return "apiVersion: imagegate.dev/v1\nidentities: {k: {publicKey: " + key + "}}\n" +
		"rules: [{name: r, images: [x], signature: {identities: [k]}, sbom: {required: false}}]\n"
}

func TestLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	key := filepath.Join(dir, "k.pub")
	mustWrite(t, key, "key")

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		_, err := Load(filepath.Join(dir, "nope.yaml"))
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("err = %v, want not-exist", err)
		}
	})
	t.Run("invalid policy", func(t *testing.T) {
		t.Parallel()
		pol := filepath.Join(t.TempDir(), "policy.yaml")
		mustWrite(t, pol, strings.Replace(minimal(key), "v1", "v9", 1))
		p, err := Load(pol)
		if err == nil || p != nil || !strings.Contains(err.Error(), "apiVersion must be") {
			t.Errorf("Load = %v, %v; want apiVersion error", p, err)
		}
	})
	t.Run("missing key file", func(t *testing.T) {
		t.Parallel()
		pol := filepath.Join(t.TempDir(), "policy.yaml")
		mustWrite(t, pol, minimal(filepath.Join(dir, "gone.pub")))
		p, err := Load(pol)
		if !errors.Is(err, fs.ErrNotExist) || p != nil {
			t.Errorf("Load = %v, %v; want not-exist", p, err)
		}
	})
	t.Run("missing trusted root", func(t *testing.T) {
		t.Parallel()
		pol := filepath.Join(t.TempDir(), "policy.yaml")
		mustWrite(t, pol, "trust: {sigstore: "+filepath.Join(dir, "gone.json")+"}\n"+minimal(key))
		p, err := Load(pol)
		if !errors.Is(err, fs.ErrNotExist) || p != nil {
			t.Errorf("Load = %v, %v; want not-exist", p, err)
		}
	})
	t.Run("hash folds in files", func(t *testing.T) {
		t.Parallel()
		pol := filepath.Join(t.TempDir(), "policy.yaml")
		mustWrite(t, pol, minimal(key))
		parsed, err := Parse([]byte(minimal(key)))
		if err != nil {
			t.Fatal(err)
		}
		a, err := Load(pol)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Load(pol)
		if err != nil {
			t.Fatal(err)
		}
		if a.Hash != b.Hash {
			t.Error("Load hash is not deterministic")
		}
		if a.Hash == parsed.Hash || len(a.Hash) != 64 {
			t.Errorf("Load hash %q should be a new sha256 over the parse hash %q", a.Hash, parsed.Hash)
		}
	})
}

// Replacing a private trusted_root.json at the same path changes the hash.
func TestHashIncludesTrustedRoot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	key := filepath.Join(dir, "k.pub")
	root := filepath.Join(dir, "trusted_root.json")
	pol := filepath.Join(dir, "policy.yaml")
	mustWrite(t, key, "key")
	mustWrite(t, root, `{"one":1}`)
	mustWrite(t, pol, "trust: {sigstore: "+root+"}\n"+minimal(key))
	a, err := Load(pol)
	if err != nil {
		t.Fatal(err)
	}
	if a.Trust.Sigstore != root {
		t.Errorf("sigstore = %q", a.Trust.Sigstore)
	}
	mustWrite(t, root, `{"two":2}`)
	b, err := Load(pol)
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash == b.Hash {
		t.Error("trusted root rotation did not change the hash")
	}
	// The key is hashed too, independently of the root.
	mustWrite(t, key, "other key")
	c, err := Load(pol)
	if err != nil {
		t.Fatal(err)
	}
	if c.Hash == b.Hash {
		t.Error("key rotation did not change the hash")
	}
}

// The hash depends on referenced file paths as well as their contents.
func TestHashIncludesKeyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	k1, k2 := filepath.Join(dir, "a.pub"), filepath.Join(dir, "b.pub")
	mustWrite(t, k1, "same")
	mustWrite(t, k2, "same")
	p1, p2 := filepath.Join(dir, "p1.yaml"), filepath.Join(dir, "p2.yaml")
	mustWrite(t, p1, minimal(k1))
	mustWrite(t, p2, minimal(k2))
	a, err := Load(p1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(p2)
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash == b.Hash {
		t.Error("different key paths produced the same hash")
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	const head = "apiVersion: imagegate.dev/v1\nidentities:\n  k: {publicKey: /k.pub}\n"
	rule := func(body string) string { return head + "rules: [" + body + "]\n" }
	const ok = "{name: r, images: [x], signature: {identities: [k]}, sbom: {required: false}}"
	tests := []struct {
		name, doc, want string
	}{
		{"bad apiVersion", strings.Replace(rule(ok), "v1", "v2", 1), `apiVersion must be "imagegate.dev/v1", got "imagegate.dev/v2"`},
		{"missing apiVersion", strings.Replace(rule(ok), "apiVersion: imagegate.dev/v1\n", "", 1), `got ""`},
		{"no rules", head, "rules: at least one rule is required"},
		{"bad mode", "mode: off\n" + rule(ok), `mode must be enforce or audit, got "off"`},
		{"bad localImages", "localImages: maybe\n" + rule(ok), `localImages must be deny or allow, got "maybe"`},
		{"negative timeout", "defaults: {verifyTimeout: -1s}\n" + rule(ok), "durations must be positive"},
		{"negative allowTTL", "defaults: {cache: {allowTTL: -1h}}\n" + rule(ok), "durations must be positive"},
		{"negative denyTTL", "defaults: {cache: {denyTTL: -1s}}\n" + rule(ok), "durations must be positive"},
		{"timeout too long", "defaults: {verifyTimeout: 60s}\n" + rule(ok), "verifyTimeout must be at most 25s"},
		{"timeout just too long", "defaults: {verifyTimeout: 25001ms}\n" + rule(ok), "verifyTimeout must be at most"},
		{"bad duration", "defaults: {verifyTimeout: soon}\n" + rule(ok), "parse policy"},
		{"non-scalar duration", "defaults: {verifyTimeout: [1s]}\n" + rule(ok), "parse policy"},
		{"unknown field", "mod: audit\n" + rule(ok), "field mod not found"},
		{"empty document", "", "parse policy"},
		{"not a mapping", "- a\n- b\n", "parse policy"},
		// .nan decodes into the string field but cannot be canonicalized as JSON.
		{"NaN scalar", "defaults: {helpURL: .nan}\n" + rule(ok), "canonicalize policy"},
		{"rule without name", rule("{images: [x], signature: {identities: [k]}, sbom: {required: false}}"), "rules[0]: name is required"},
		{"rule without images", rule("{name: r, signature: {identities: [k]}, sbom: {required: false}}"), "rules[0] (r): images must list at least one glob"},
		{"empty glob", rule(`{name: r, images: [""], signature: {identities: [k]}, sbom: {required: false}}`), "empty image glob"},
		{"tag in glob", rule(`{name: r, images: ["x/y:latest"], signature: {identities: [k]}, sbom: {required: false}}`), "must not include a tag or digest"},
		{"tag in single segment glob", rule(`{name: r, images: ["x:1"], signature: {identities: [k]}, sbom: {required: false}}`), "must not include a tag or digest"},
		{"digest in glob", rule(`{name: r, images: ["x/y@sha256:00"], signature: {identities: [k]}, sbom: {required: false}}`), "must not include a tag or digest"},
		{"no signature ids", rule("{name: r, images: [x], sbom: {required: false}}"), "signature.identities must list at least one identity"},
		{"unknown signature id", rule("{name: r, images: [x], signature: {identities: [nope]}, sbom: {required: false}}"), `signature.identities: unknown identity "nope"`},
		{"sbom ids missing", rule("{name: r, images: [x], signature: {identities: [k]}}"), "sbom.identities is required when sbom.required is true"},
		{"sbom ids missing, explicit", rule("{name: r, images: [x], signature: {identities: [k]}, sbom: {required: true}}"), "sbom.identities is required"},
		{"unknown sbom id", rule("{name: r, images: [x], signature: {identities: [k]}, sbom: {identities: [nope]}}"), `sbom.identities: unknown identity "nope"`},
		{"duplicate rule", head + "rules: [" + ok + ", " + strings.Replace(ok, "[x]", "[y]", 1) + "]\n", "rules[1] (r): duplicate rule name"},
		{"empty identity", "apiVersion: imagegate.dev/v1\nidentities: {c: {}}\nrules: [{name: r, images: [x], signature: {identities: [c]}, sbom: {required: false}}]", "identities.c: set publicKey, or issuer"},
		{"keyless without subject", "apiVersion: imagegate.dev/v1\nidentities: {c: {issuer: https://x}}\nrules: [{name: r, images: [x], signature: {identities: [c]}, sbom: {required: false}}]", "set exactly one of subject or subjectRegExp"},
		{"keyless without issuer", "apiVersion: imagegate.dev/v1\nidentities: {c: {subject: s}}\nrules: [{name: r, images: [x], signature: {identities: [c]}, sbom: {required: false}}]", "set exactly one of issuer or issuerRegExp"},
		{"issuer and issuerRegExp", "apiVersion: imagegate.dev/v1\nidentities: {c: {issuer: a, issuerRegExp: b, subject: s}}\nrules: [{name: r, images: [x], signature: {identities: [c]}, sbom: {required: false}}]", "set exactly one of issuer or issuerRegExp"},
		{"subject and subjectRegExp", "apiVersion: imagegate.dev/v1\nidentities: {c: {issuer: a, subject: s, subjectRegExp: t}}\nrules: [{name: r, images: [x], signature: {identities: [c]}, sbom: {required: false}}]", "set exactly one of subject or subjectRegExp"},
		{"key and keyless", "apiVersion: imagegate.dev/v1\nidentities: {c: {issuer: https://x, subject: y, publicKey: /k}}\nrules: [{name: r, images: [x], signature: {identities: [c]}, sbom: {required: false}}]", "not both"},
		{"key and subjectRegExp", "apiVersion: imagegate.dev/v1\nidentities: {c: {subjectRegExp: y, publicKey: /k}}\nrules: [{name: r, images: [x], signature: {identities: [c]}, sbom: {required: false}}]", "not both"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := Parse([]byte(tt.doc))
			if err == nil {
				t.Fatalf("Parse succeeded: %+v", p)
			}
			if p != nil {
				t.Errorf("Parse returned a policy with an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

// Every problem is reported at once, not just the first.
func TestParseReportsAllErrors(t *testing.T) {
	t.Parallel()
	_, err := Parse([]byte("apiVersion: v0\nmode: off\nlocalImages: maybe\n"))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"apiVersion must be", "mode must be", "localImages must be", "at least one rule"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err %q missing %q", err, want)
		}
	}
}

func TestParseAccepts(t *testing.T) {
	t.Parallel()
	const ids = "identities:\n  k: {publicKey: /k.pub}\n  re: {issuerRegExp: ^https://x$, subjectRegExp: ^s$}\n  mix: {issuer: https://x, subjectRegExp: ^s$}\n"
	tests := []struct {
		name  string
		doc   string
		check func(t *testing.T, p *Policy)
	}{
		{
			name: "audit mode, fail open, allow local, no SCT",
			doc: "apiVersion: imagegate.dev/v1\nmode: audit\nlocalImages: allow\ndefaults: {failClosed: false, verifyTimeout: 25s, helpURL: https://h}\ntrust: {requireSCT: false}\n" + ids +
				"rules: [{name: r, images: [x], signature: {identities: [k, re, mix]}, sbom: {required: false}}]\n",
			check: func(t *testing.T, p *Policy) {
				if p.Mode != ModeAudit || p.FailClosed() || p.LocalImages != "allow" || *p.Trust.RequireSCT {
					t.Errorf("explicit settings not kept: %+v", p)
				}
				if p.Defaults.VerifyTimeout.D() != MaxVerifyTimeout {
					t.Errorf("verifyTimeout = %s, want the 25s maximum", p.Defaults.VerifyTimeout.D())
				}
				if p.Defaults.HelpURL != "https://h" {
					t.Errorf("helpURL = %q", p.Defaults.HelpURL)
				}
				if p.Identities["re"].Keyed() || !p.Identities["k"].Keyed() {
					t.Error("identity kinds wrong")
				}
			},
		},
		{
			name: "custom predicate types kept",
			doc: "apiVersion: imagegate.dev/v1\n" + ids +
				"rules: [{name: r, images: [x], signature: {identities: [k]}, sbom: {identities: [k], predicateTypes: [https://example.com/p]}}]\n",
			check: func(t *testing.T, p *Policy) {
				if got := p.Rules[0].SBOM.PredicateTypes; len(got) != 1 || got[0] != "https://example.com/p" {
					t.Errorf("predicateTypes = %v", got)
				}
				if !p.Rules[0].SBOM.IsRequired() {
					t.Error("sbom should be required")
				}
			},
		},
		{
			name: "default TTLs",
			doc:  "apiVersion: imagegate.dev/v1\n" + ids + "rules: [{name: r, images: [x], signature: {identities: [k]}, sbom: {required: false}}]\n",
			check: func(t *testing.T, p *Policy) {
				if p.Defaults.VerifyTimeout.D() != 10*time.Second || p.Defaults.Cache.AllowTTL.D() != 24*time.Hour || p.Defaults.Cache.DenyTTL.D() != time.Minute {
					t.Errorf("defaults = %+v", p.Defaults)
				}
			},
		},
		{
			name: "explicit zero durations get defaults",
			doc:  "apiVersion: imagegate.dev/v1\ndefaults: {verifyTimeout: 0s, cache: {allowTTL: 0s, denyTTL: 0s}}\n" + ids + "rules: [{name: r, images: [x], signature: {identities: [k]}, sbom: {required: false}}]\n",
			check: func(t *testing.T, p *Policy) {
				if p.Defaults.VerifyTimeout.D() != 10*time.Second || p.Defaults.Cache.AllowTTL.D() != 24*time.Hour || p.Defaults.Cache.DenyTTL.D() != time.Minute {
					t.Errorf("defaults = %+v", p.Defaults)
				}
			},
		},
		{
			name: "glob with port",
			doc:  "apiVersion: imagegate.dev/v1\n" + ids + "rules: [{name: r, images: [\"localhost:5000/**\"], signature: {identities: [k]}, sbom: {required: false}}]\n",
			check: func(t *testing.T, p *Policy) {
				if r := p.Match("localhost:5000/acme/api"); r == nil || r.Name != "r" {
					t.Errorf("Match = %v", r)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := Parse([]byte(tt.doc))
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, p)
		})
	}
}

// Re-validating a policy does not accumulate globs.
func TestValidateResetsGlobs(t *testing.T) {
	t.Parallel()
	p, err := Parse([]byte(specExample))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Rules {
		if len(r.globs) != len(r.Images) {
			t.Errorf("rule %s has %d globs for %d images", r.Name, len(r.globs), len(r.Images))
		}
	}
}

func TestMatchNoRule(t *testing.T) {
	t.Parallel()
	p, err := Parse([]byte(specExample))
	if err != nil {
		t.Fatal(err)
	}
	for _, repo := range []string{"", "docker.io/library/nginx", "ghcr.io/acme", "GHCR.IO/acme/api"} {
		if r := p.Match(repo); r != nil {
			t.Errorf("Match(%q) = %s, want nil", repo, r.Name)
		}
	}
}

func TestGlob(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern string
		match   []string
		nomatch []string
	}{
		{"ghcr.io/acme/api", []string{"ghcr.io/acme/api"}, []string{"ghcr.io/acme/api/x", "ghcr.io/acme/apix", "xghcr.io/acme/api", "ghcr.io/acme"}},
		{"ghcr.io/acme/*", []string{"ghcr.io/acme/api", "ghcr.io/acme/"}, []string{"ghcr.io/acme/a/b", "ghcr.io/acme"}},
		{"ghcr.io/acme/**", []string{"ghcr.io/acme/api", "ghcr.io/acme/a/b/c"}, []string{"ghcr.io/acme", "ghcr.io/acmecorp/api"}},
		{"ghcr.io/acme/ap?", []string{"ghcr.io/acme/api", "ghcr.io/acme/apx"}, []string{"ghcr.io/acme/ap", "ghcr.io/acme/ap/", "ghcr.io/acme/apis"}},
		{"ghcr.io/*/api", []string{"ghcr.io/acme/api"}, []string{"ghcr.io/a/b/api"}},
		{"**/api", []string{"ghcr.io/acme/api", "x/api"}, []string{"ghcr.io/acme/api2"}},
		// Regexp metacharacters are literal.
		{"ghcr.io/a.b", []string{"ghcr.io/a.b"}, []string{"ghcr.io/aXb"}},
		{"ghcr.io/a+b", []string{"ghcr.io/a+b"}, []string{"ghcr.io/aab"}},
		{"ghcr.io/(a|b)", []string{"ghcr.io/(a|b)"}, []string{"ghcr.io/a"}},
		{"localhost:5000/x", []string{"localhost:5000/x"}, []string{"localhost:5001/x"}},
		{"ghcr.io/***", []string{"ghcr.io/a/b"}, []string{"ghcr.io"}},
		// Multi-byte runes are quoted whole, so a literal matches itself.
		{"ghcr.io/café", []string{"ghcr.io/café"}, []string{"ghcr.io/cafe", "ghcr.io/cafÃ©"}},
		{"ghcr.io/é?", []string{"ghcr.io/éa", "ghcr.io/éé"}, []string{"ghcr.io/é"}},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			t.Parallel()
			g, err := compileGlob(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range tt.match {
				if !g.match(s) {
					t.Errorf("%q should match %q", tt.pattern, s)
				}
			}
			for _, s := range tt.nomatch {
				if g.match(s) {
					t.Errorf("%q should not match %q", tt.pattern, s)
				}
			}
		})
	}
	for _, bad := range []string{"", "x@y", "x:1", "a/b:c", "a/b@sha256:00", "ghcr.io/\x80"} {
		if _, err := compileGlob(bad); err == nil {
			t.Errorf("compileGlob(%q) should fail", bad)
		}
	}
}

func TestLastSegment(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"a": "a", "a/b": "b", "a/b/": "", "": "", "host:5000/x": "x"} {
		if got := lastSegment(in); got != want {
			t.Errorf("lastSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDurationUnmarshal(t *testing.T) {
	t.Parallel()
	p, err := Parse([]byte("defaults: {verifyTimeout: 1500ms, cache: {allowTTL: 1h30m, denyTTL: 5s}}\n" + minimal("/k")))
	if err != nil {
		t.Fatal(err)
	}
	if p.Defaults.VerifyTimeout.D() != 1500*time.Millisecond || p.Defaults.Cache.AllowTTL.D() != 90*time.Minute || p.Defaults.Cache.DenyTTL.D() != 5*time.Second {
		t.Errorf("durations = %+v", p.Defaults)
	}
	_, err = Parse([]byte("defaults:\n  verifyTimeout: soon\n" + minimal("/k")))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("err = %v, want the line number", err)
	}
}

// --- overrides ---

var (
	dA = "sha256:" + strings.Repeat("a", 64)
	dB = "sha256:" + strings.Repeat("b", 64)
)

var ovNow = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func TestOverridesNil(t *testing.T) {
	t.Parallel()
	var o *Overrides
	if _, ok := o.Lookup(dA, ovNow); ok {
		t.Error("nil overrides matched")
	}
	if n := o.Active(ovNow); n != 0 {
		t.Errorf("nil Active = %d", n)
	}
}

func TestOverrideValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		o    Override
		want string
	}{
		{"valid", Override{Digest: dA, Expires: ovNow.Add(time.Hour), Ticket: "T"}, ""},
		{"exactly seven days", Override{Digest: dA, Expires: ovNow.Add(MaxOverrideLifetime), Ticket: "T"}, ""},
		{"already expired is valid but inactive", Override{Digest: dA, Expires: ovNow.Add(-time.Hour), Ticket: "T"}, ""},
		{"seven days and a second", Override{Digest: dA, Expires: ovNow.Add(MaxOverrideLifetime + time.Second), Ticket: "T"}, "more than 7 days away"},
		{"no digest", Override{Expires: ovNow.Add(time.Hour), Ticket: "T"}, "digest must be"},
		{"short digest", Override{Digest: "sha256:abc", Expires: ovNow.Add(time.Hour), Ticket: "T"}, "digest must be"},
		{"uppercase digest", Override{Digest: "sha256:" + strings.Repeat("A", 64), Expires: ovNow.Add(time.Hour), Ticket: "T"}, "digest must be"},
		{"sha512 digest", Override{Digest: "sha512:" + strings.Repeat("a", 64), Expires: ovNow.Add(time.Hour), Ticket: "T"}, "digest must be"},
		{"tag instead of digest", Override{Digest: "nginx:latest", Expires: ovNow.Add(time.Hour), Ticket: "T"}, "digest must be"},
		{"digest with suffix", Override{Digest: dA + "\n", Expires: ovNow.Add(time.Hour), Ticket: "T"}, "digest must be"},
		{"no expiry", Override{Digest: dA, Ticket: "T"}, "expires is required"},
		{"no ticket", Override{Digest: dA, Expires: ovNow.Add(time.Hour)}, "ticket is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.o.validate(ovNow)
			if tt.want == "" {
				if err != nil {
					t.Errorf("validate = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("validate = %v, want %q", err, tt.want)
			}
		})
	}
}

func ovEntry(d string, exp time.Time, ticket string) string {
	return fmt.Sprintf("- digest: %s\n  expires: %s\n  ticket: %s\n", d, exp.Format(time.RFC3339), ticket)
}

func TestLoadOverridesDuplicates(t *testing.T) {
	t.Parallel()
	early, late := ovNow.Add(time.Hour), ovNow.Add(48*time.Hour)
	tests := []struct {
		name  string
		files map[string]string
	}{
		{"later entry expires later", map[string]string{"a.yaml": ovEntry(dA, early, "EARLY") + ovEntry(dA, late, "LATE")}},
		{"earlier entry expires later", map[string]string{"a.yaml": ovEntry(dA, late, "LATE") + ovEntry(dA, early, "EARLY")}},
		{"across files, first file later", map[string]string{"a.yaml": ovEntry(dA, late, "LATE"), "b.yaml": ovEntry(dA, early, "EARLY")}},
		{"across files, second file later", map[string]string{"a.yaml": ovEntry(dA, early, "EARLY"), "b.yaml": ovEntry(dA, late, "LATE")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for name, body := range tt.files {
				mustWrite(t, filepath.Join(dir, name), body)
			}
			ov, err := LoadOverrides(dir, ovNow)
			if err != nil {
				t.Fatal(err)
			}
			o, ok := ov.Lookup(dA, ovNow)
			if !ok || o.Ticket != "LATE" || !o.Expires.Equal(late) {
				t.Errorf("Lookup = %+v %v, want the entry that expires last", o, ok)
			}
			// Still valid after the earlier one would have expired.
			if _, ok := ov.Lookup(dA, early.Add(time.Minute)); !ok {
				t.Error("override expired with the shorter duplicate")
			}
			if n := ov.Active(ovNow); n != 1 {
				t.Errorf("Active = %d, want 1", n)
			}
		})
	}
}

func TestLoadOverridesErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	mustWrite(t, good, ovEntry(dA, ovNow.Add(time.Hour), "INC-1"))
	mustWrite(t, filepath.Join(dir, "broken.yaml"), "- digest: [unterminated\n")
	mustWrite(t, filepath.Join(dir, "mapping.yaml"), "digest: "+dB+"\nexpires: 2026-10-15T00:00:00Z\nticket: X\n")
	mustWrite(t, filepath.Join(dir, "partial.yaml"), ovEntry("sha256:nope", ovNow.Add(time.Hour), "X")+ovEntry(dB, ovNow.Add(time.Hour), "INC-2"))
	mustWrite(t, filepath.Join(dir, "ignored.yml"), ovEntry(dB, ovNow.Add(2*time.Hour), "YML"))
	// A directory named *.yaml cannot be read as a file.
	if err := os.Mkdir(filepath.Join(dir, "dir.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}

	ov, err := LoadOverrides(dir, ovNow)
	if err == nil {
		t.Fatal("expected errors")
	}
	msg := err.Error()
	for _, want := range []string{
		filepath.Join(dir, "broken.yaml") + ":",
		filepath.Join(dir, "mapping.yaml") + ":",
		filepath.Join(dir, "partial.yaml") + "[0]: digest must be",
		"dir.yaml",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q missing %q", msg, want)
		}
	}
	if strings.Contains(msg, "good.yaml") || strings.Contains(msg, "partial.yaml[1]") {
		t.Errorf("valid entries reported as errors: %q", msg)
	}
	o, ok := ov.Lookup(dA, ovNow)
	if !ok || o.Ticket != "INC-1" || o.File != good {
		t.Errorf("good override = %+v %v", o, ok)
	}
	// Valid entries in a file with invalid ones still load.
	if o, ok := ov.Lookup(dB, ovNow); !ok || o.Ticket != "INC-2" {
		t.Errorf("partial file entry = %+v %v (only *.yaml is read)", o, ok)
	}
	if n := ov.Active(ovNow); n != 2 {
		t.Errorf("Active = %d, want 2", n)
	}
}

func TestLoadOverridesBadPattern(t *testing.T) {
	t.Parallel()
	ov, err := LoadOverrides(filepath.Join(t.TempDir(), "["), ovNow)
	if !errors.Is(err, filepath.ErrBadPattern) {
		t.Errorf("err = %v, want ErrBadPattern", err)
	}
	if ov == nil || ov.Active(ovNow) != 0 {
		t.Errorf("want an empty, non-nil set, got %+v", ov)
	}
}

func TestLoadOverridesEmpty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "empty.yaml"), "")
	mustWrite(t, filepath.Join(dir, "null.yaml"), "[]\n")
	ov, err := LoadOverrides(dir, ovNow)
	if err != nil {
		t.Fatal(err)
	}
	if ov.Active(ovNow) != 0 {
		t.Error("empty files produced overrides")
	}
}

// Active counts only unexpired entries, and Lookup is false at expiry.
func TestOverridesExpiry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.yaml"), ovEntry(dA, ovNow.Add(time.Hour), "A")+ovEntry(dB, ovNow.Add(2*time.Hour), "B"))
	ov, err := LoadOverrides(dir, ovNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		at     time.Time
		active int
		a, b   bool
	}{
		{ovNow, 2, true, true},
		{ovNow.Add(time.Hour - time.Nanosecond), 2, true, true},
		{ovNow.Add(time.Hour), 1, false, true},
		{ovNow.Add(2 * time.Hour), 0, false, false},
	} {
		if n := ov.Active(tc.at); n != tc.active {
			t.Errorf("Active(%s) = %d, want %d", tc.at, n, tc.active)
		}
		if _, ok := ov.Lookup(dA, tc.at); ok != tc.a {
			t.Errorf("Lookup(a, %s) = %v", tc.at, ok)
		}
		if _, ok := ov.Lookup(dB, tc.at); ok != tc.b {
			t.Errorf("Lookup(b, %s) = %v", tc.at, ok)
		}
	}
	if _, ok := ov.Lookup("sha256:"+strings.Repeat("c", 64), ovNow); ok {
		t.Error("unknown digest matched")
	}
}

// checkOwnership is a no-op unless imagegate runs as root, where it
// rejects files a non-root user could have written. The euid is not
// injectable, so the expected result depends on who runs the test.
func TestCheckOwnership(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	root := os.Geteuid() == 0

	safe := filepath.Join(dir, "safe.yaml")
	mustWrite(t, safe, "[]")
	if err := os.Chmod(safe, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkOwnership(safe); err != nil {
		t.Errorf("0644 file owned by the current user: %v", err)
	}

	writable := filepath.Join(dir, "writable.yaml")
	mustWrite(t, writable, "[]")
	if err := os.Chmod(writable, 0o666); err != nil {
		t.Fatal(err)
	}
	err := checkOwnership(writable)
	if root {
		if err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
			t.Errorf("world-writable file as root: %v", err)
		}
	} else if err != nil {
		t.Errorf("non-root must not check ownership: %v", err)
	}

	missing := filepath.Join(dir, "missing.yaml")
	err = checkOwnership(missing)
	if root {
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("missing file as root: %v", err)
		}
	} else if err != nil {
		t.Errorf("non-root must not stat: %v", err)
	}

	if root {
		notRoot := filepath.Join(dir, "nobody.yaml")
		mustWrite(t, notRoot, "[]")
		if err := os.Chown(notRoot, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if err := checkOwnership(notRoot); err == nil || !strings.Contains(err.Error(), "must be owned by root") {
			t.Errorf("non-root-owned file as root: %v", err)
		}
	}
}

// When running as root, LoadOverrides skips a writable file and reports
// it; otherwise the file loads.
func TestLoadOverridesOwnership(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := filepath.Join(dir, "a.yaml")
	mustWrite(t, f, ovEntry(dA, ovNow.Add(time.Hour), "T"))
	if err := os.Chmod(f, 0o666); err != nil {
		t.Fatal(err)
	}
	ov, err := LoadOverrides(dir, ovNow)
	_, ok := ov.Lookup(dA, ovNow)
	if os.Geteuid() == 0 {
		if err == nil || ok {
			t.Errorf("writable override loaded as root: %v %v", err, ok)
		}
	} else if err != nil || !ok {
		t.Errorf("override not loaded: %v %v", err, ok)
	}
}

// --- fuzz ---

func fuzzPolicySeeds(f *testing.F) {
	f.Add([]byte(specExample))
	f.Add([]byte(minimal("/k.pub")))
	for _, p := range []string{"../../packaging/policy.yaml", "../../deploy/policy.example.yaml"} {
		raw, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte(""))
	f.Add([]byte("apiVersion: imagegate.dev/v1\nidentities: {1: {publicKey: /k}}\n"))
	f.Add([]byte("defaults: {verifyTimeout: soon}\n"))
	f.Add([]byte("&a [*a]"))
}

func FuzzParse(f *testing.F) {
	fuzzPolicySeeds(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := Parse(raw)
		if err != nil {
			if p != nil {
				t.Fatalf("Parse returned a policy with error %v", err)
			}
			return
		}
		q, err := Parse(raw)
		if err != nil {
			t.Fatalf("second Parse failed: %v", err)
		}
		if p.Hash != q.Hash || len(p.Hash) != 64 {
			t.Fatalf("hash unstable or malformed: %q vs %q", p.Hash, q.Hash)
		}
		_ = p.FailClosed()
		if p.APIVersion != APIVersion || (p.Mode != ModeEnforce && p.Mode != ModeAudit) {
			t.Fatalf("invalid policy accepted: %+v", p)
		}
		if p.LocalImages != "deny" && p.LocalImages != "allow" {
			t.Fatalf("localImages %q accepted", p.LocalImages)
		}
		if d := p.Defaults.VerifyTimeout.D(); d <= 0 || d > MaxVerifyTimeout {
			t.Fatalf("verifyTimeout %s accepted", d)
		}
		if len(p.Rules) == 0 {
			t.Fatal("policy without rules accepted")
		}
		for _, r := range p.Rules {
			if r.Name == "" || len(r.globs) != len(r.Images) || len(r.globs) == 0 {
				t.Fatalf("rule %+v accepted", r)
			}
			for _, id := range append(append([]string{}, r.Signature.Identities...), r.SBOM.Identities...) {
				if _, ok := p.Identities[id]; !ok {
					t.Fatalf("rule %s references unknown identity %q", r.Name, id)
				}
			}
			if r.SBOM.IsRequired() && len(r.SBOM.Identities) == 0 {
				t.Fatalf("rule %s requires an SBOM without identities", r.Name)
			}
			for _, img := range r.Images {
				_ = p.Match(img)
			}
		}
	})
}

func FuzzGlob(f *testing.F) {
	for _, s := range [][2]string{
		{"ghcr.io/acme/**", "ghcr.io/acme/api"},
		{"ghcr.io/acme/*", "ghcr.io/acme/a/b"},
		{"docker.io/library/?ginx", "docker.io/library/nginx"},
		{"registry.vendor.example/agent", "registry.vendor.example/agent"},
		{"localhost:5000/**", "localhost:5000/x"},
		{"a.b+c(d)[e]", "a.b+c(d)[e]"},
		{"x:1", "x:1"},
		{"", ""},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, repo string) {
		g, err := compileGlob(pattern)
		if err != nil {
			return
		}
		got := g.match(repo)
		if !strings.ContainsAny(pattern, "*?") {
			if !g.match(pattern) {
				t.Fatalf("literal glob %q does not match itself", pattern)
			}
			if got != (repo == pattern) {
				t.Fatalf("literal glob %q match(%q) = %v", pattern, repo, got)
			}
		}
		// "*" and "?" never cross "/": without "**", a match keeps the
		// pattern's number of segments.
		if got && !strings.Contains(pattern, "**") && strings.Count(repo, "/") != strings.Count(pattern, "/") {
			t.Fatalf("glob %q matched %q across a /", pattern, repo)
		}
	})
}

// FuzzOverride drives LoadOverrides with arbitrary file contents. As a
// non-root user checkOwnership is a no-op; as root the 0600 file created
// here passes it, so the YAML and validation paths are reached either way.
func FuzzOverride(f *testing.F) {
	f.Add([]byte(ovEntry(dA, ovNow.Add(time.Hour), "INC-4821")))
	f.Add([]byte(ovEntry(dA, ovNow.Add(time.Hour), "A") + ovEntry(dA, ovNow.Add(2*time.Hour), "B")))
	f.Add([]byte(ovEntry("sha256:short", ovNow.Add(time.Hour), "X")))
	f.Add([]byte(ovEntry(dB, ovNow.Add(30*24*time.Hour), "X")))
	f.Add([]byte("- digest: " + dA + "\n  expires: 2026-10-15T00:00:00Z\n"))
	f.Add([]byte("digest: " + dA))
	f.Add([]byte("- {digest: " + dA + ", expires: 2026-10-15, ticket: T}"))
	f.Add([]byte(""))
	// Fuzz workers are separate processes and run inputs one at a time,
	// so one directory per process is enough.
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, raw []byte) {
		if err := os.WriteFile(filepath.Join(dir, "o.yaml"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		ov, _ := LoadOverrides(dir, ovNow)
		if ov == nil {
			t.Fatal("LoadOverrides returned nil")
		}
		for d, o := range ov.byDigest {
			if d != o.Digest || !digestRE.MatchString(d) {
				t.Fatalf("override keyed %q has digest %q", d, o.Digest)
			}
			if o.Ticket == "" || o.Expires.IsZero() || o.Expires.Sub(ovNow) > MaxOverrideLifetime {
				t.Fatalf("invalid override loaded: %+v", o)
			}
			if _, ok := ov.Lookup(d, ovNow); ok != ovNow.Before(o.Expires) {
				t.Fatalf("Lookup(%s) = %v for expiry %s", d, ok, o.Expires)
			}
		}
		if n := ov.Active(ovNow.Add(MaxOverrideLifetime)); n != 0 {
			t.Fatalf("%d overrides active past the maximum lifetime", n)
		}
	})
}

// --- benchmarks ---

func BenchmarkPolicyParse(b *testing.B) {
	raw := []byte(specExample)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Parse(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMatch(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("apiVersion: imagegate.dev/v1\nidentities: {k: {publicKey: /k.pub}}\nrules:\n")
	for i := range 20 {
		fmt.Fprintf(&sb, "  - {name: r%d, images: [\"ghcr.io/team%d/**\", \"registry%d.example/*/api\"], signature: {identities: [k]}, sbom: {required: false}}\n", i, i, i)
	}
	p, err := Parse([]byte(sb.String()))
	if err != nil {
		b.Fatal(err)
	}
	// The last rule's second glob: the worst case for a match.
	const repo = "registry19.example/acme/api"
	if r := p.Match(repo); r == nil || r.Name != "r19" {
		b.Fatalf("Match = %v", r)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = p.Match(repo)
	}
}
