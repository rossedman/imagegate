# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [semantic versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Repository normalization no longer turns a dotless registry host into a
  Docker Hub path. `registry:443/app` and `REGISTRY/app` were normalized to
  `registry/app`, which reads as `docker.io/registry/app`: rules for that
  Docker Hub repository applied, and signatures were fetched from Docker
  Hub, while dockerd pulled from the private registry. Both now normalize
  to `registry:443/app`.
- Image globs with multi-byte characters (`ghcr.io/café`) never matched,
  because each byte was quoted as its own character. Such globs could only
  cause `NO_RULE` denials.
- Go 1.27.3, golang.org/x/net 0.60.0 and grpc 1.83.1: fixes 13 reachable
  vulnerabilities reported by govulncheck in the standard library and
  dependencies.

- Docs site: code punctuation, plain values and console output rendered
  near-black on the dark code background, and several greys in the light
  scheme fell below WCAG AA. All text now meets AA in both schemes;
  `make docs-contrast` checks it.

### Added

- Identities guide: verified identities for Chainguard, Flux, Trivy,
  distroless, Kubernetes and Sigstore images; subject formats for GitLab,
  Buildkite, CircleCI, Codefresh, Google Cloud, Kubernetes workloads and
  people; KMS keys; and how to discover an image's signer with `warm`.
- Docker authorization plugin that gates container create, start and
  restart on a cosign signature and a signed SBOM attestation.
- Verification of Sigstore bundles via OCI referrers (cosign v3) and legacy
  `.sig`/`.att` tags (cosign v2), keyless and keyed, with sigstore-go.
- YAML policy with first-match rules, audit mode, `failClosed`, local image
  handling and SIGHUP reload that keeps the last good policy.
- Break-glass overrides, verdict cache (memory + bbolt) with singleflight,
  JSON audit log and Prometheus metrics.
- `serve`, `validate`, `warm`, `cache purge` and `health` commands, systemd
  units, runbook and documentation site.
- GoReleaser releases: linux amd64, arm64, arm/v7, ppc64le and s390x
  binaries; deb and rpm packages with systemd units, apk with an OpenRC
  service; multi-arch images on ghcr.io; SBOMs; keyless cosign signatures.
  Packages refuse removal while dockerd still enables the plugin.
