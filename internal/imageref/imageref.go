// Package imageref normalizes Docker image references.
package imageref

import (
	"fmt"
	"strings"

	"github.com/distribution/reference"
)

// Ref is a normalized image reference.
type Ref struct {
	// Repo is the full repository name, e.g. docker.io/library/nginx.
	Repo string
	// Tag is the tag, "latest" when none was given and no digest pinned.
	Tag string
	// Digest is set when the reference pins @sha256:...
	Digest string
}

// String returns repo:tag, repo@digest or repo:tag@digest.
func (r Ref) String() string {
	s := r.Repo
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

// Parse expands a reference to its full form:
// nginx → docker.io/library/nginx:latest.
func Parse(s string) (Ref, error) {
	named, err := reference.ParseNormalizedNamed(s)
	if err != nil {
		return Ref{}, fmt.Errorf("invalid image reference %q: %w", s, err)
	}
	r := Ref{Repo: canonicalRepo(named.Name())}
	if t, ok := named.(reference.Tagged); ok {
		r.Tag = t.Tag()
	}
	if d, ok := named.(reference.Digested); ok {
		r.Digest = d.Digest().String()
	}
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}
	return r, nil
}

// SplitRepoDigest parses a RepoDigests entry such as nginx@sha256:... into
// its normalized repository and digest.
func SplitRepoDigest(s string) (repo, digest string, err error) {
	r, err := Parse(s)
	if err != nil {
		return "", "", err
	}
	if r.Digest == "" {
		return "", "", fmt.Errorf("repo digest %q has no digest", s)
	}
	return r.Repo, r.Digest, nil
}

// LooksLikeID reports whether s could be a (possibly short) image ID rather
// than a name, e.g. "sha256:73aa..." or "73aaf090f3d8".
func LooksLikeID(s string) bool {
	s = strings.TrimPrefix(s, "sha256:")
	if len(s) < 4 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// isHost reports whether a lowercase first path component is parsed as a
// registry host, mirroring distribution/reference's splitDockerDomain.
func isHost(s string) bool {
	return strings.ContainsAny(s, ".:") || s == "localhost"
}

// dockerHubAliases are hostnames that serve Docker Hub.
var dockerHubAliases = map[string]bool{
	"docker.io": true, "index.docker.io": true, "registry-1.docker.io": true, "registry.hub.docker.com": true,
}

// canonicalRepo gives every spelling of a repository one form, so policy
// globs cannot be sidestepped: hostnames are case-insensitive, :443 is the
// default HTTPS port, and Docker Hub has several hostnames.
//
// The form must still name the same registry when parsed again. A first
// component is only a host when it has a "." or ":", is "localhost", or has
// an uppercase letter, so lowercasing "A/x" or stripping "registry:443/x"
// would turn a private registry into a Docker Hub repository. Such hosts
// keep an explicit :443, the same endpoint.
func canonicalRepo(name string) string {
	host, path, ok := strings.Cut(name, "/")
	if !ok {
		return name
	}
	host = strings.TrimSuffix(strings.ToLower(host), ":443")
	if !isHost(host) {
		host += ":443"
	}
	if dockerHubAliases[host] {
		host = "docker.io"
		if !strings.Contains(path, "/") {
			path = "library/" + path
		}
	}
	return host + "/" + path
}
