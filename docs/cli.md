# CLI

```text
imagegate serve [flags]           run the plugin (default)
imagegate validate [-policy path] validate a policy, check its keys, print its hash
imagegate warm <ref>...           pre-verify images on the running daemon
imagegate cache purge [digest]    drop cached verdicts, all or for one digest
imagegate health                  check the plugin socket answers
imagegate version                 print the version
```

Run `imagegate <command> -h` for a command's flags.

## serve

| Flag | Default | Purpose |
| --- | --- | --- |
| `-socket` | `/run/docker/plugins/imagegate.sock` | Plugin socket dockerd discovers |
| `-policy` | `/etc/imagegate/policy.yaml` | Policy file |
| `-overrides` | `/etc/imagegate/overrides.d` | Break-glass overrides, re-read every 10 s and on SIGHUP |
| `-registry-config` | `/etc/imagegate/registry` | `config.json` and credential helpers for reading signatures |
| `-cache` | `/var/lib/imagegate/cache.db` | Persistent verdict cache |
| `-cache-size` | `10000` | In-memory verdict entries |
| `-tuf-cache` | `/var/lib/imagegate/tuf` | Sigstore TUF metadata cache |
| `-docker-socket` | `/var/run/docker.sock` | dockerd API, for image and container inspect |
| `-admin-socket` | `/run/imagegate/admin.sock` | Root-only socket for `warm` and `cache purge` |
| `-metrics-addr` | `127.0.0.1:9732` | `/metrics` and `/healthz` |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error` |

Signals: `SIGHUP` reloads the policy and overrides; `SIGINT` or `SIGTERM`
shuts down.

!!! warning "`-docker-socket` must be the daemon that uses the plugin"
    If imagegate inspects a different dockerd, starts fail closed with
    `BAD_REQUEST` ("container not found via imagegate's dockerd socket").

## validate

```console
$ imagegate validate /etc/imagegate/policy.yaml
/etc/imagegate/policy.yaml: valid (mode enforce, 3 rules, policyHash 9f75c3c6…)
```

The path is `-policy` (default `/etc/imagegate/policy.yaml`) or the first
argument, which wins over the flag. Exits non-zero with every problem
listed, including unreadable or invalid public keys.

## warm

```console
$ imagegate warm ghcr.io/acme/api:1.4.2 ghcr.io/acme/web:2.0
ALLOW  ghcr.io/acme/api@sha256:3f9c… (ALLOWED)
DENY   ghcr.io/acme/web@sha256:91ac…: NO_SBOM — no SPDX or CycloneDX attestation signed by identity "ci-main"
```

Resolves each tag in the registry, verifies it against the running policy
and caches the verdict. Exits non-zero if any image would be denied, so it
works as a deploy-pipeline gate.

`warm` and `cache purge` talk to the running daemon over `-admin-socket`
(default `/run/imagegate/admin.sock`), so they need root. They and `health`
accept `serve`'s path flags (all but `-metrics-addr`, `-cache-size` and
`-log-level`); `warm` and `cache purge` use only `-admin-socket`.

## cache purge

```console
$ imagegate cache purge sha256:3f9c…
purged 1 cached verdicts
```

## health

Posts `/Plugin.Activate` to the plugin socket (`-socket`, default
`/run/docker/plugins/imagegate.sock`) with a 2 s timeout, independently of
dockerd, and prints `ok` on a 200. `deploy/systemd/imagegate-health.timer` runs it
every minute.
