package imageref

import (
	"regexp"
	"strings"
	"testing"
)

const testDigest = "sha256:3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c"

func TestParse(t *testing.T) {
	t.Parallel()
	d := testDigest
	tests := []struct {
		in   string
		want Ref
	}{
		{"nginx", Ref{Repo: "docker.io/library/nginx", Tag: "latest"}},
		{"nginx:1.27", Ref{Repo: "docker.io/library/nginx", Tag: "1.27"}},
		{"acme/api", Ref{Repo: "docker.io/acme/api", Tag: "latest"}},
		{"ghcr.io/acme/api:1.4.2", Ref{Repo: "ghcr.io/acme/api", Tag: "1.4.2"}},
		{"localhost:5000/acme/api", Ref{Repo: "localhost:5000/acme/api", Tag: "latest"}},
		{"localhost:5000/acme/api:1", Ref{Repo: "localhost:5000/acme/api", Tag: "1"}},
		{"localhost/acme/api", Ref{Repo: "localhost/acme/api", Tag: "latest"}},
		// A digest-only reference does not invent a tag.
		{"ghcr.io/acme/api@" + d, Ref{Repo: "ghcr.io/acme/api", Digest: d}},
		{"ghcr.io/acme/api:1.4.2@" + d, Ref{Repo: "ghcr.io/acme/api", Tag: "1.4.2", Digest: d}},
		{"docker.io/library/nginx:latest", Ref{Repo: "docker.io/library/nginx", Tag: "latest"}},
		// Hostnames are case-insensitive; the path is not.
		{"GHCR.IO/acme/api:1", Ref{Repo: "ghcr.io/acme/api", Tag: "1"}},
		{"ghcr.io:443/acme/api:1", Ref{Repo: "ghcr.io/acme/api", Tag: "1"}},
		{"GHCR.io:443/acme/api", Ref{Repo: "ghcr.io/acme/api", Tag: "latest"}},
		// :443 is only the default port, other ports are kept.
		{"ghcr.io:8443/acme/api", Ref{Repo: "ghcr.io:8443/acme/api", Tag: "latest"}},
		// Every Docker Hub alias is one repository.
		{"registry-1.docker.io/nginx", Ref{Repo: "docker.io/library/nginx", Tag: "latest"}},
		{"registry-1.docker.io/acme/api", Ref{Repo: "docker.io/acme/api", Tag: "latest"}},
		{"index.docker.io/nginx", Ref{Repo: "docker.io/library/nginx", Tag: "latest"}},
		{"registry.hub.docker.com/nginx:1", Ref{Repo: "docker.io/library/nginx", Tag: "1"}},
		{"docker.io:443/nginx", Ref{Repo: "docker.io/library/nginx", Tag: "latest"}},
		{"Docker.IO/acme/api", Ref{Repo: "docker.io/acme/api", Tag: "latest"}},
		{"docker.io/library/nginx@" + d, Ref{Repo: "docker.io/library/nginx", Digest: d}},
		// Dotless hosts must stay hosts: lowercasing "A" or stripping
		// ":443" from "registry:443" would name a Docker Hub repository
		// instead of the registry dockerd pulls from.
		{"A/0", Ref{Repo: "a:443/0", Tag: "latest"}},
		{"REGISTRY/app", Ref{Repo: "registry:443/app", Tag: "latest"}},
		{"registry:443/app", Ref{Repo: "registry:443/app", Tag: "latest"}},
		{"Registry:443/app:1", Ref{Repo: "registry:443/app", Tag: "1"}},
		{"LOCALHOST/app", Ref{Repo: "localhost/app", Tag: "latest"}},
		{"localhost:443/app", Ref{Repo: "localhost/app", Tag: "latest"}},
		{"registry/app", Ref{Repo: "docker.io/registry/app", Tag: "latest"}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			r, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.in, err)
			}
			if r != tt.want {
				t.Errorf("Parse(%q) = %+v, want %+v", tt.in, r, tt.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"",
		"acme/UpperCase",
		"a b",
		"x@sha256:zz",
		"x@sha256:" + strings.Repeat("a", 63),
		"ghcr.io/acme/api:",
		"ghcr.io/acme/api:bad tag",
		"/acme/api",
		"ghcr.io//api",
	} {
		t.Run(bad, func(t *testing.T) {
			t.Parallel()
			r, err := Parse(bad)
			if err == nil {
				t.Fatalf("Parse(%q) = %+v, want an error", bad, r)
			}
			if r != (Ref{}) {
				t.Errorf("Parse(%q) returned %+v with an error", bad, r)
			}
			if !strings.Contains(err.Error(), "invalid image reference") {
				t.Errorf("error %q lacks context", err)
			}
		})
	}
}

func TestString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		r    Ref
		want string
	}{
		{Ref{Repo: "r"}, "r"},
		{Ref{Repo: "r", Tag: "t"}, "r:t"},
		{Ref{Repo: "r", Digest: "sha256:x"}, "r@sha256:x"},
		{Ref{Repo: "r", Tag: "t", Digest: "sha256:x"}, "r:t@sha256:x"},
	}
	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("%+v.String() = %q, want %q", tt.r, got, tt.want)
		}
	}
}

func TestSplitRepoDigest(t *testing.T) {
	t.Parallel()
	const bb = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
	tests := []struct {
		in         string
		repo, dgst string
		wantErr    string
	}{
		{in: "busybox@" + bb, repo: "docker.io/library/busybox", dgst: bb},
		{in: "ghcr.io/acme/api@" + bb, repo: "ghcr.io/acme/api", dgst: bb},
		{in: "GHCR.IO:443/acme/api:1@" + bb, repo: "ghcr.io/acme/api", dgst: bb},
		{in: "busybox:1.36", wantErr: "has no digest"},
		{in: "busybox", wantErr: "has no digest"},
		{in: "", wantErr: "invalid image reference"},
		{in: "busybox@sha256:zz", wantErr: "invalid image reference"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			repo, d, err := SplitRepoDigest(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("SplitRepoDigest(%q) err = %v, want %q", tt.in, err, tt.wantErr)
				}
				if repo != "" || d != "" {
					t.Errorf("SplitRepoDigest(%q) = %q %q with an error", tt.in, repo, d)
				}
				return
			}
			if err != nil || repo != tt.repo || d != tt.dgst {
				t.Errorf("SplitRepoDigest(%q) = %q %q %v, want %q %q", tt.in, repo, d, err, tt.repo, tt.dgst)
			}
		})
	}
}

func TestLooksLikeID(t *testing.T) {
	t.Parallel()
	full := strings.Repeat("a", 64)
	tests := map[string]bool{
		"73aaf090f3d8":        true,
		"sha256:73aaf090f3d8": true,
		"deadbeef":            true,
		"abcd":                true, // shortest prefix
		full:                  true, // full ID
		"sha256:" + full:      true,
		"nginx":               false,
		"abc":                 false,
		"sha256:abc":          false,
		full + "a":            false,
		"ABCD":                false, // IDs are lowercase hex
		"abcg":                false,
		"sha256:":             false,
		"":                    false,
		"sha512:abcd":         false,
		"abcd/":               false,
	}
	for in, want := range tests {
		if got := LooksLikeID(in); got != want {
			t.Errorf("LooksLikeID(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCanonicalRepo(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"nginx":                       "nginx", // no host: left as is
		"docker.io/nginx":             "docker.io/library/nginx",
		"index.docker.io/acme/api":    "docker.io/acme/api",
		"Registry.Hub.Docker.Com/x/y": "docker.io/x/y",
		"ghcr.io:443/a":               "ghcr.io/a",
		"ghcr.io:5000/a":              "ghcr.io:5000/a",
		"A/0":                         "a:443/0",
		"foo:443/x":                   "foo:443/x",
		"Foo:443/x":                   "foo:443/x",
	} {
		if got := canonicalRepo(in); got != want {
			t.Errorf("canonicalRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

// fuzzSeeds are real references from the docs, tests and Docker Hub.
var fuzzSeeds = []string{
	"nginx", "nginx:1.27", "acme/api", "ghcr.io/acme/api:1.4.2",
	"localhost:5000/acme/api", "ghcr.io/acme/api@" + testDigest,
	"ghcr.io/acme/api:1.4.2@" + testDigest, "GHCR.IO/acme/api:1",
	"ghcr.io:443/acme/api:1", "registry-1.docker.io/nginx",
	"busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662",
	"sha256:73aaf090f3d8", "73aaf090f3d8", "", "a b", "x@sha256:zz",
	"[::1]:5000/acme/api", "192.168.1.1:443/acme/api",
}

func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := Parse(s)
		if err != nil {
			if r != (Ref{}) {
				t.Fatalf("Parse(%q) returned %+v with error %v", s, r, err)
			}
			return
		}
		if r.Repo == "" || (r.Tag == "" && r.Digest == "") {
			t.Fatalf("Parse(%q) = %+v: missing repo or tag/digest", s, r)
		}
		again, err := Parse(r.String())
		if err != nil {
			t.Fatalf("Parse(%q) = %q does not reparse: %v", s, r.String(), err)
		}
		if again != r {
			t.Fatalf("Parse(%q) = %+v, but Parse(%q) = %+v", s, r, r.String(), again)
		}
	})
}

var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func FuzzSplitRepoDigest(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Add("x@sha512:" + strings.Repeat("ab", 64))
	f.Fuzz(func(t *testing.T, s string) {
		repo, d, err := SplitRepoDigest(s)
		if err != nil {
			if repo != "" || d != "" {
				t.Fatalf("SplitRepoDigest(%q) = %q %q with error %v", s, repo, d, err)
			}
			return
		}
		// Only sha256 digests are verified, and digestRE is what
		// overrides are keyed by.
		if !digestRE.MatchString(d) {
			t.Fatalf("SplitRepoDigest(%q) digest = %q, want sha256:<64 lowercase hex>", s, d)
		}
		if repo == "" || strings.ContainsAny(repo, "@") {
			t.Fatalf("SplitRepoDigest(%q) repo = %q", s, repo)
		}
	})
}

func FuzzLooksLikeID(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := LooksLikeID(s)
		hex := strings.TrimPrefix(s, "sha256:")
		want := len(hex) >= 4 && len(hex) <= 64 && strings.Trim(hex, "0123456789abcdef") == ""
		if got != want {
			t.Fatalf("LooksLikeID(%q) = %v, want %v", s, got, want)
		}
	})
}

func BenchmarkParse(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Parse("ghcr.io/acme/api:1.4.2@" + testDigest); err != nil {
			b.Fatal(err)
		}
	}
}
