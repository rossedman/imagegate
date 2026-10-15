# imagegate

imagegate is a Docker authorization plugin that denies container creation
unless the image is cosign-signed by a trusted identity and carries a signed
SBOM attestation (SPDX or CycloneDX) for the same digest. It enforces
supply-chain policy on every Docker host without changes to Dockerfiles,
Compose files or `docker run` commands.

```
$ docker run ghcr.io/acme/api:1.4.2
docker: Error response from daemon: authorization denied by plugin imagegate: imagegate: denied ghcr.io/acme/api@sha256:3f9c…
reason: NO_SBOM — no SPDX or CycloneDX attestation signed by identity "ci-main"
fix: https://wiki.acme.internal/imagegate#NO_SBOM
```

## How it works

imagegate is a standalone Go process. dockerd calls it over
`/run/docker/plugins/imagegate.sock` for every API request:

| Request | What imagegate does |
| --- | --- |
| `POST /containers/create` | Full verification of the image digest |
| `POST /containers/{id}/start`, `/restart` | Re-check the container's actual image ID (cache hit after a create) |
| Everything else, and every response | Allow, never verify |

For a create it normalizes the reference, resolves the digest through
dockerd's image inspect (by digest, never by tag), checks break-glass
overrides and the verdict cache, picks the first matching policy rule, then:

1. **Signature**: fetches Sigstore bundles from OCI 1.1 referrers (cosign v3)
   and legacy `sha256-<digest>.sig` tags (cosign v2), and verifies them with
   sigstore-go: keyless (Fulcio chain, SCT, Rekor inclusion proof or signed
   entry timestamp, TUF-distributed trusted root) or a listed public key.
2. **SBOM**: the same for in-toto attestations (`.att` tags and referrers).
   It needs a DSSE envelope signed by an allowed identity, an allowed
   `predicateType`, and a subject equal to the image digest. An unsigned SBOM
   (BuildKit `--sbom=true`, a plain SPDX referrer) is reported as
   `SBOM_UNTRUSTED`.

Verdicts are cached per (repository, digest, policyHash): 24 h for allows,
60 s for denies, in memory with a bbolt file behind it. Concurrent requests
for the same digest share one verification.

## Install

```sh
go build -o /usr/local/bin/imagegate ./cmd/imagegate
install -d -m 0755 /etc/imagegate /etc/imagegate/overrides.d /etc/imagegate/registry
install -m 0644 deploy/policy.example.yaml /etc/imagegate/policy.yaml   # then edit
imagegate validate
install -m 0644 deploy/systemd/imagegate*.{service,timer} /etc/systemd/system/
systemctl enable --now imagegate imagegate-health.timer
# Add {"authorization-plugins": ["imagegate"]} to /etc/docker/daemon.json, then:
systemctl restart docker   # a SIGHUP does not add the plugin (verified on Docker 29.8)
```

Read [docs/runbook.md](docs/runbook.md) before enforcing: a dead plugin makes
dockerd reject every call.

| Path | Purpose |
| --- | --- |
| `/usr/local/bin/imagegate` | Binary |
| `/run/docker/plugins/imagegate.sock` | Plugin socket dockerd discovers |
| `/etc/imagegate/policy.yaml` | Policy |
| `/etc/imagegate/overrides.d/` | Break-glass overrides |
| `/etc/imagegate/registry/` | `config.json` and credential helpers for reading signatures |
| `/var/lib/imagegate/cache.db` | Persistent verdict cache |
| `/var/lib/imagegate/tuf/` | Sigstore TUF metadata cache |
| `/run/imagegate/admin.sock` | Root-only socket for `warm` and `cache purge` |
| `127.0.0.1:9732` | `/metrics` and `/healthz` |

## Policy

See [deploy/policy.example.yaml](deploy/policy.example.yaml). Rules are
evaluated top to bottom; the first rule whose `images` glob matches the
normalized repository wins (`*` stops at `/`, `**` crosses it); no match
denies. `mode: audit` evaluates everything and logs the would-be verdict but
always allows. The file is validated on load and on SIGHUP
(`systemctl reload imagegate`); an invalid file is rejected and the last
good policy stays active. An invalid policy at boot denies all creates
(`NO_POLICY`) and allows every other call.

Settings beyond the spec's example:

| Setting | Default | Purpose |
| --- | --- | --- |
| `defaults.helpURL` | none | Denials print `fix: <helpURL>#<REASON>`; without it a built-in hint is printed |
| `trust.requireSCT` | `true` | Set `false` only for private Sigstore stacks without a CT log |
| `identities.*.issuerRegExp`, `.subject` | | Exact or regex forms of issuer and subject |
| `sbom.predicateTypes` | SPDX and CycloneDX | `https://spdx.dev/Document` also matches versioned forms such as `.../Document/v2.3` |

## Commands

```
imagegate serve [flags]           run the plugin (default)
imagegate validate [policy]       validate a policy, check its keys, print its hash
imagegate warm <ref>...           pre-verify images on the running daemon
imagegate cache purge [digest]    drop cached verdicts
imagegate health                  check the plugin socket answers, independently of dockerd
```

## Observability

One JSON audit record per decision on stdout (journald):

```json
{"ts":"2026-10-14T19:20:03Z","decision":"deny","mode":"enforce","reason":"NO_SBOM",
 "image":"ghcr.io/acme/api:1.4.2","digest":"sha256:3f9c…","rule":"internal",
 "signer":"ci-main","cache":"miss","latencyMs":842,"endpoint":"containers/create",
 "user":"","policyHash":"9b1e…","enforced":true,"detail":"…"}
```

`enforced` is `false` when a deny was only logged (audit mode, or
`failClosed: false`). Override uses add `ticket` and `"severity":"high"`.
Metrics: `imagegate_decisions_total`, `imagegate_verify_duration_seconds`,
`imagegate_cache_requests_total`, `imagegate_upstream_errors_total`,
`imagegate_overrides_active`, `imagegate_policy_reload_errors_total`.

## Tests

```sh
make test          # unit tests, including the spec's fixture matrix
make e2e           # real dockerd + zot + cosign; needs root, dockerd, cosign
```

The Go tests run the spec's test matrix against an in-process OCI registry
with referrers support and a virtual Sigstore (Fulcio, Rekor, TSA): keyless
and keyed, Sigstore bundles and legacy tags, multi-platform indexes, BuildKit
SBOMs, tampered and replayed signatures, timeouts and outages. They also
cover overrides, audit mode, fail-open, policy reload, the start re-check and
200 concurrent creates triggering exactly one verification.

`test/e2e/run.sh` starts its own dockerd with imagegate as its plugin and
runs the matrix with images signed by cosign v2 (legacy tags) and, if
`COSIGN_V3` is set, cosign v3 (bundles via referrers). Signing is keyed
because CI has no OIDC identity; keyless is covered by the Go tests.

## Decisions and deviations from the spec

- **Cache key includes the repository**: (repository, digest, policyHash),
  not (digest, policyHash). The matching rule, and where signatures are
  fetched from, depend on the repository.
- **Local images on the containerd image store.** Docker 29's default image
  store gives local builds and `docker load`ed images a RepoDigests entry, so
  "no RepoDigests" alone does not detect them. A digest the registry does not
  have is also treated as `LOCAL_IMAGE`.
- **Images not present yet.** If dockerd does not have the image, the create
  is allowed so dockerd answers "No such image" and `docker run` pulls and
  retries; the retried create is verified. If the image appears in between,
  the start re-check catches it.
- **Start fails closed** if imagegate cannot find the container through its
  dockerd socket, so a wrong `-docker-socket` blocks starts instead of
  silently allowing everything. `restart` is re-checked like `start`.
- **Index and platform digests** (open question 1): a signature or SBOM on
  the index digest or on the platform manifest selected by `platform` (or
  the image's own platform) is accepted.
- **Signature layouts** (open question 4): both; referrers first, then legacy
  tags.
- **SIGHUP and `authorization-plugins`** (open question 6): on Docker 29.8.2,
  dockerd reloads its config on SIGHUP but never consults a newly added
  plugin. Adding or removing the plugin needs a dockerd restart.

Not implemented in v1, as the spec scopes them: Swarm `/services/*`
verification, container-config rules (privileged mode, host mounts, the
Docker socket), and SBOM content checks.

Paths that run image code without a create or start API call, so imagegate
never sees them (in addition to the spec's gap table):

- **Daemon-initiated restarts.** Containers with a restart policy are
  restarted by dockerd itself after a crash or a daemon restart, with no API
  call. A container created before imagegate was enabled keeps running and
  restarting until someone starts it through the API.
- **`docker build`.** `RUN` steps execute the `FROM` image inside BuildKit,
  not through `/containers/create`.
- **Managed plugins.** `docker plugin install` runs a plugin image; imagegate
  allows `/plugins/*` so it can never lock out plugin management.

**Latency.** imagegate's own overhead on a cached create is about 15 µs
(`go test -bench . ./internal/gate`), and a cached start takes 1–2 ms end to
end. A create also runs dockerd's image inspect to resolve the digest; on
the containerd image store in the test environment that call alone took
about 20 ms, above the 5 ms p99 target. Measure on your own hosts before
relying on the target.
