<p align="center">
  <img src="docs/assets/banner.svg" alt="imagegate: Docker authorization plugin that admits an image only if its digest is signed and carries a signed SBOM" width="100%">
</p>

<p align="center">
  <a href="https://github.com/rossedman/image-gate/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/rossedman/image-gate/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://rossedman.github.io/image-gate/"><img alt="Docs" src="https://img.shields.io/badge/docs-rossedman.github.io-13263c"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-13263c"></a>
  <img alt="Go version" src="https://img.shields.io/github/go-mod/go-version/rossedman/image-gate?color=13263c">
</p>

**imagegate** is a Docker authorization plugin. It denies container creation
unless the image digest carries a [cosign](https://github.com/sigstore/cosign)
signature from an identity you trust **and** a signed SPDX or CycloneDX SBOM
attestation. It runs on the host, next to dockerd, so Dockerfiles, Compose
files and `docker run` commands stay exactly as they are.

```console
$ docker run ghcr.io/acme/api:1.4.2
docker: Error response from daemon: authorization denied by plugin imagegate: imagegate: denied ghcr.io/acme/api@sha256:3f9c…
reason: NO_SBOM — no SPDX or CycloneDX attestation signed by identity "ci-main"
fix: https://wiki.acme.internal/imagegate#no_sbom
```

**[Documentation](https://rossedman.github.io/image-gate/)** ·
[Getting started](https://rossedman.github.io/image-gate/getting-started/) ·
[Policy reference](https://rossedman.github.io/image-gate/policy/) ·
[Runbook](https://rossedman.github.io/image-gate/runbook/) ·
[Security model](https://rossedman.github.io/image-gate/security/)

## How it works

```mermaid
sequenceDiagram
  autonumber
  participant C as docker run
  participant D as dockerd
  participant G as imagegate
  participant R as registry
  C->>D: POST /containers/create
  D->>G: AuthZReq (every API call)
  G->>D: inspect image → digest
  G->>R: signatures + attestations for the digest
  Note over G: verify with sigstore-go,<br/>cache the verdict
  G-->>D: allow, or deny + reason
  D-->>C: container, or the denial
```

Only `POST /containers/create`, `/start` and `/restart` are ever denied.
Every other call passes, even when imagegate errors, so it can't lock you
out of the daemon.

```mermaid
flowchart LR
  ref["image ref"] --> digest["resolve digest<br/>(never a tag)"] --> rule{"first matching<br/>policy rule"}
  rule -->|none| deny1["NO_RULE"]
  rule --> sig{"cosign signature<br/>from allowed identity?"}
  sig -->|no| deny2["NO_SIGNATURE /<br/>IDENTITY_MISMATCH"]
  sig -->|yes| sbom{"signed SBOM<br/>for same digest?"}
  sbom -->|no| deny3["NO_SBOM /<br/>SBOM_UNTRUSTED"]
  sbom -->|yes| ok["ALLOWED · cached 24 h"]
```

- **Verifies by digest.** Tags resolve through dockerd to the digest it will
  run, and start re-checks the container's actual image.
- **Real Sigstore.** Keyless (Fulcio, SCT, Rekor, TUF trusted root) or your
  own public keys; cosign v2 `.sig`/`.att` tags and v3 bundles via OCI
  referrers.
- **Fast when warm.** One verification per digest and policy, cached in
  memory and on disk. Concurrent requests share it.
- **Built for rollout.** Audit mode, ticketed break-glass overrides that
  expire within 7 days, a JSON audit log and Prometheus metrics.

## Quick start

```sh
make build && sudo install -m 0755 bin/imagegate /usr/local/bin/
sudo install -d /etc/imagegate/overrides.d /etc/imagegate/registry
sudo install -m 0644 deploy/policy.example.yaml /etc/imagegate/policy.yaml   # edit, keep mode: audit
imagegate validate
sudo install -m 0644 deploy/systemd/imagegate*.{service,timer} /etc/systemd/system/
sudo systemctl enable --now imagegate imagegate-health.timer
# add {"authorization-plugins": ["imagegate"]} to /etc/docker/daemon.json, then:
sudo systemctl restart docker
```

Then follow [Rolling out](https://rossedman.github.io/image-gate/rollout/)
and [Signing in CI](https://rossedman.github.io/image-gate/signing/).

> [!WARNING]
> A dead authorization plugin makes dockerd reject every API call. Read the
> [lockout runbook](docs/runbook.md#lockout-dockerd-rejects-every-call)
> before enabling imagegate.

## A minimal policy

```yaml
apiVersion: imagegate.dev/v1
mode: enforce
identities:
  ci-main:
    issuer: https://token.actions.githubusercontent.com
    subjectRegExp: ^https://github\.com/acme/.+/\.github/workflows/release\.ya?ml@refs/heads/main$
rules:
  - name: internal
    images: ["ghcr.io/acme/**"]
    signature: { identities: [ci-main] }
    sbom:      { identities: [ci-main] }
```

## Status

imagegate is new and pre-1.0. It has unit tests for the full verification
matrix (keyless and keyed, both cosign layouts, multi-platform images,
tampered and replayed signatures) and an end-to-end suite against a real
dockerd, a zot registry and cosign v2 and v3. Read the
[security model](https://rossedman.github.io/image-gate/security/) for what
it does not cover: it proves where an image came from, not what a container
may do.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
