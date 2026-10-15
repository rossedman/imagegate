# imagegate runbook

## Lockout: dockerd rejects every call

dockerd sends every API call through its authorization plugins, including
`docker plugin disable`. If imagegate is down, dockerd rejects everything:

```
Error response from daemon: plugin imagegate failed with error: Post "http://plugin.moby.localhost/AuthZPlugin.AuthZReq": dial unix /run/docker/plugins/imagegate.sock: connect: no such file or directory
```

1. Restart imagegate: `systemctl restart imagegate`. This does not restart
   dockerd. Check it with `imagegate health` and `journalctl -u imagegate`.
2. If imagegate will not start, remove the plugin from dockerd:
   - delete `"authorization-plugins"` from `/etc/docker/daemon.json`;
   - `systemctl restart docker` (a SIGHUP does not drop or add the plugin;
     verified on Docker 29.8);
   - containers with a restart policy come back; nothing is verified until
     the plugin is re-enabled.
3. Re-enable: restore `daemon.json` and restart dockerd once imagegate is
   healthy.

imagegate itself never denies `GET` requests, `/_ping`, `/info`, `/plugins/*`
or anything other than container create, start and restart, even on internal
errors.

## Break-glass overrides

As root, drop a file into `/etc/imagegate/overrides.d/`:

```yaml
- digest: sha256:3f9c...          # the full digest from the denial message
  expires: 2026-10-21T00:00:00Z   # at most 7 days from now
  ticket: INC-4821
  reason: vendor hotfix, signature pending
```

The file must be owned by root and not group- or world-writable. imagegate
picks it up within 10 seconds (or immediately on `systemctl reload
imagegate`). Every use is logged at high severity with the ticket and counted
in `imagegate_decisions_total{reason="OVERRIDE"}`; alert on it. Entries with
an expiry more than 7 days out, or without a ticket, are rejected and logged.
Labels and environment variables are never accepted as overrides.

## Reason codes

Each denial prints `fix: <helpURL>#<REASON>`; these are the anchors.

### NO_SIGNATURE
No cosign signature for the image digest, or none that verifies. Sign the
digest in CI: `cosign sign <image>@<digest>`. Verify locally with
`imagegate warm <ref>`.

### IDENTITY_MISMATCH
The image is signed, but not by an identity the matching rule allows. The
detail names the actual signer. Typical causes: a fork's workflow, a
release workflow on a branch other than `main`, a personal key.

### NO_SBOM
No signed SPDX or CycloneDX attestation for the digest. Attach one in CI:
`cosign attest --type spdxjson --predicate sbom.spdx.json <image>@<digest>`.

### SBOM_UNTRUSTED
An SBOM exists but is unsigned (for example BuildKit `--sbom=true` alone, or
an SBOM pushed as a plain referrer), or it is signed by an identity the rule
does not allow. Publish it with `cosign attest` from the CI identity.

### LOCAL_IMAGE
The image was built, loaded (`docker load`) or committed locally: it has no
registry digest, or the registry does not have its digest. Push it, sign it,
and run it by its registry reference. Set `localImages: allow` to permit
local images on hosts where that is acceptable.

### NO_RULE
No policy rule matches the image's repository. Use an image from a covered
repository or add a rule.

### UPSTREAM_UNAVAILABLE
imagegate could not reach the registry, the Sigstore TUF repository, or
dockerd. Cached verdicts keep working; uncached images are denied while
`failClosed: true`. Check `imagegate_upstream_errors_total{target}`.

### TIMEOUT
Verification took longer than `verifyTimeout`. Retry, or pre-verify from the
deploy pipeline with `imagegate warm <ref>`.

### NO_POLICY
No valid policy has been loaded since imagegate started; every create is
denied. Fix `/etc/imagegate/policy.yaml` (`imagegate validate`) and run
`systemctl reload imagegate`. A bad policy on reload never causes this: the
last good policy stays active.

### BAD_REQUEST
The create request could not be parsed, or a container being started could
not be found through imagegate's dockerd socket (check `-docker-socket`).

## Revoking trust quickly

Remove the identity from the policy and reload; the policy hash changes and
every cached verdict is invalidated. To drop cached verdicts without a policy
change: `imagegate cache purge [digest]`.
