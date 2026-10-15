# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [semantic versioning](https://semver.org/).

## [Unreleased]

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
