# Security model

imagegate proves where an image came from. It does not control what a
container may do once it runs.

## In scope

- Unsigned, tampered or re-pushed images.
- Images signed by the wrong identity: a fork's workflow, another branch, a
  personal key.
- Missing, unsigned or mismatched SBOMs.
- Mutable tags: every check is by digest, and start re-checks the image the
  container actually uses.

## Design invariants

1. **Never lock operators out.** Only POST create, start and restart can be
   denied. Every other call and every response passes, even on internal
   errors.
2. **Fail closed on gated paths.** Unparseable requests, panics and missing
   containers deny. Only genuine "could not reach" errors follow
   `failClosed`.
3. **Match dockerd's router.** Any `/v[0-9.]+` prefix and container names
   containing `/` are classified exactly as dockerd routes them.
4. **Verify what runs.** Only the digest dockerd resolved counts, never a
   platform child whose selection imagegate cannot see.
5. **Registry data is hostile.** Reads are bounded, annotations are never
   trusted for decisions, and the verified statement is what's checked.

## Known gaps

These run image code without a create or start API call, or sit outside
what an image gate can see.

| Gap | Impact | Mitigation |
| --- | --- | --- |
| An allowed image run with `--privileged` or `-v /:/host` | Can edit the policy or stop imagegate | Planned v1.1 container-config rules |
| `ctr`, `nerdctl`, Podman on the same host | Bypass outside Docker | Remove or restrict those tools |
| Daemon-initiated restarts (restart policies) | No API call to gate | Containers predating imagegate keep restarting until started via the API |
| `docker build` | `RUN` executes the `FROM` image in BuildKit | Restrict builds on enforced hosts |
| `docker plugin install` | Runs a plugin image; `/plugins/*` is never gated | Restrict plugin management |
| `swarm init` + `services create` | Task containers are created internally | Disable Swarm on enforced hosts until v1.1 |
| `PUT /containers/{id}/archive` | Can change a created container's files before start | Restrict API access |
| Revoked signing identity | Cached allows linger up to `allowTTL` | Remove the identity (changes the policy hash) or `imagegate cache purge` |
| `failClosed: false` | Unreachable registries allow | Keep `true` for any registry attackers can influence |

!!! danger "Not a boundary against full API access"
    Anyone who can talk to the Docker API can use the paths above, or run an
    allowed image with `--privileged`. imagegate raises the bar against
    unsigned and tampered images; it does not make API access safe.

## Hardening the plugin itself

- Policy, overrides and keys root-owned, mode 0644 (keys 0600). Override
  files that are not root-owned or are group/world-writable are ignored.
- Outbound calls only to configured registries and Sigstore endpoints.
- Verify the imagegate binary itself at install with your configuration
  management; release checksums are published with each release.
- The systemd unit runs with no capabilities, `NoNewPrivileges` and
  `ProtectSystem=strict`.

## Reporting vulnerabilities

See [SECURITY.md](https://github.com/rossedman/image-gate/blob/main/SECURITY.md).
Report privately through GitHub security advisories, not issues.
