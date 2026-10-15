package imageref

import "testing"

func TestParse(t *testing.T) {
	d := "sha256:3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c"
	for in, want := range map[string]string{
		"nginx":                          "docker.io/library/nginx:latest",
		"nginx:1.27":                     "docker.io/library/nginx:1.27",
		"acme/api":                       "docker.io/acme/api:latest",
		"ghcr.io/acme/api:1.4.2":         "ghcr.io/acme/api:1.4.2",
		"localhost:5000/acme/api":        "localhost:5000/acme/api:latest",
		"ghcr.io/acme/api@" + d:          "ghcr.io/acme/api@" + d,
		"ghcr.io/acme/api:1.4.2@" + d:    "ghcr.io/acme/api:1.4.2@" + d,
		"docker.io/library/nginx:latest": "docker.io/library/nginx:latest",
	} {
		r, err := Parse(in)
		if err != nil {
			t.Errorf("Parse(%q): %v", in, err)
			continue
		}
		if r.String() != want {
			t.Errorf("Parse(%q) = %q, want %q", in, r.String(), want)
		}
	}
	for _, bad := range []string{"", "acme/UpperCase", "a b", "x@sha256:zz"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) should fail", bad)
		}
	}
}

func TestSplitRepoDigest(t *testing.T) {
	repo, d, err := SplitRepoDigest("busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662")
	if err != nil || repo != "docker.io/library/busybox" || d != "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662" {
		t.Errorf("got %q %q %v", repo, d, err)
	}
	if _, _, err := SplitRepoDigest("busybox:1.36"); err == nil {
		t.Error("expected error without digest")
	}
}

func TestLooksLikeID(t *testing.T) {
	for in, want := range map[string]bool{
		"73aaf090f3d8":        true,
		"sha256:73aaf090f3d8": true,
		"nginx":               false,
		"abc":                 false,
		"deadbeef":            true,
	} {
		if got := LooksLikeID(in); got != want {
			t.Errorf("LooksLikeID(%q) = %v", in, got)
		}
	}
}
