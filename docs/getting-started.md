# Getting started

This page takes one Docker host from nothing to enforcing, starting in
audit mode so nothing breaks while you look.

!!! warning "Read the runbook first"
    dockerd sends every API call through its authorization plugins. If
    imagegate is down, dockerd rejects everything, including
    `docker plugin disable`. Keep the [lockout recovery steps](runbook.md#lockout-dockerd-rejects-every-call)
    to hand before enabling the plugin.

## Requirements

- Linux with Docker Engine. Tested on Docker 29.8 with the containerd image store.
- systemd, root access, and outbound HTTPS to your registries and to the
  Sigstore TUF repository (for keyless verification).
- Go, to build from source, or a release binary.

## Install

Every release on the [releases page](https://github.com/rossedman/imagegate/releases)
has packages, archives and a container image for `linux/amd64`, `arm64`,
`arm/v7`, `ppc64le` and `s390x`, with SBOMs and cosign signatures.

=== "Debian / Ubuntu"

    ```sh
    VERSION=0.1.0 ARCH=amd64
    curl -fsSLO https://github.com/rossedman/imagegate/releases/download/v$VERSION/imagegate_${VERSION}_$ARCH.deb
    sudo apt install ./imagegate_${VERSION}_$ARCH.deb
    ```

=== "RHEL / Fedora"

    ```sh
    VERSION=0.1.0 ARCH=x86_64
    sudo dnf install https://github.com/rossedman/imagegate/releases/download/v$VERSION/imagegate-$VERSION-1.$ARCH.rpm
    ```

=== "Alpine"

    ```sh
    VERSION=0.1.0 ARCH=x86_64
    curl -fsSLO https://github.com/rossedman/imagegate/releases/download/v$VERSION/imagegate_${VERSION}_$ARCH.apk
    sudo apk add --allow-untrusted ./imagegate_${VERSION}_$ARCH.apk
    ```

=== "Binary"

    ```sh
    VERSION=0.1.0 ARCH=amd64
    curl -fsSL https://github.com/rossedman/imagegate/releases/download/v$VERSION/imagegate_${VERSION}_linux_$ARCH.tar.gz \
      | sudo tar -xz -C /usr/local/bin imagegate
    # systemd units, example policy and runbook are in the same archive under deploy/
    ```

=== "From source"

    ```sh
    git clone https://github.com/rossedman/imagegate && cd imagegate
    make build
    sudo install -m 0755 bin/imagegate /usr/local/bin/imagegate
    ```

The packages install:

| Path | What |
| --- | --- |
| `/usr/bin/imagegate` | Binary |
| `/etc/imagegate/policy.yaml` | A valid starter policy in **audit mode**; kept across upgrades |
| `/etc/imagegate/{overrides.d,registry,keys}/` | Break-glass overrides, registry credentials, public keys |
| `/var/lib/imagegate/` | Verdict cache and TUF metadata |
| systemd units (deb, rpm) or `/etc/init.d/imagegate` (apk, OpenRC) | Enabled, not started |
| `/usr/share/imagegate/` | `daemon.json` snippet and the full example policy |

Packages never edit `/etc/docker/daemon.json`. On upgrade they restart
imagegate; dockerd rejects API calls for the second or so that takes. Removal
is refused while `daemon.json` still enables the plugin, because dockerd
would then reject every call (deb and rpm abort; apk only warns). Set
`IMAGEGATE_FORCE_REMOVE=1` to override.

### Verify a release

Checksums are signed keylessly by the release workflow:

```sh
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/rossedman/imagegate/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

Container images are signed the same way:

```sh
cosign verify ghcr.io/rossedman/imagegate:0.1.0 \
  --certificate-identity-regexp '^https://github.com/rossedman/imagegate/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Every archive and package also has an SPDX SBOM (`*.sbom.json`) and a SLSA
build provenance attestation:

```sh
gh attestation verify imagegate_0.1.0_linux_amd64.tar.gz --repo rossedman/imagegate
```

### Container image

`ghcr.io/rossedman/imagegate` runs `imagegate serve` by default. It is also
handy in CI for `imagegate validate`:

```sh
docker run --rm -v "$PWD/policy.yaml:/p.yaml:ro" ghcr.io/rossedman/imagegate:0.1.0 validate /p.yaml
```

To run the plugin itself in a container, create the container **before**
enabling the plugin in dockerd:

```sh
docker run -d --name imagegate --restart always --network host \
  -v /run/docker/plugins:/run/docker/plugins \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc/imagegate:/etc/imagegate:ro \
  -v /var/lib/imagegate:/var/lib/imagegate \
  -v /run/imagegate:/run/imagegate \
  ghcr.io/rossedman/imagegate:0.1.0
```

dockerd restarts it on boot through its restart policy, which needs no API
call. Audit records go to `docker logs imagegate`.

!!! warning "Prefer the package for production"
    A containerized plugin can't be replaced while it's enabled: stopping it
    makes dockerd reject the API calls needed to start its replacement. To
    upgrade, remove the plugin from `daemon.json`, restart dockerd, recreate
    the container, then re-enable. The systemd and OpenRC services restart
    independently of dockerd and don't have this problem.

## Write a policy

The packages install a starter policy. For a binary install:

```sh
install -d -m 0755 /etc/imagegate /etc/imagegate/overrides.d /etc/imagegate/registry
curl -fsSLo /etc/imagegate/policy.yaml \
  https://raw.githubusercontent.com/rossedman/imagegate/main/deploy/policy.example.yaml
```

Edit the identities and rules for your registries, keep `mode: audit`, and
check it:

```console
$ imagegate validate
/etc/imagegate/policy.yaml: valid (mode audit, 2 rules, policyHash b13322d2…)
```

`validate` also reads every public key the policy names. See the
[policy reference](policy.md) for every field.

If your registries need credentials to read signatures, put a Docker-format
`config.json` (and any credential helpers) in `/etc/imagegate/registry/`.
imagegate never uses a user's own credentials.

## Start the service

```sh
systemctl enable --now imagegate imagegate-health.timer   # packages already enabled them
# Alpine: rc-service imagegate start
imagegate health          # → ok
```

For a binary install, copy the units from `deploy/systemd/` in the archive to
`/etc/systemd/system/` and run `systemctl daemon-reload` first.

The unit starts before `docker.service` and restarts on failure. Restarting
imagegate never restarts dockerd.

## Enable the plugin in dockerd

Add the plugin to `/etc/docker/daemon.json`:

```json
{ "authorization-plugins": ["imagegate"] }
```

Then restart dockerd. A `SIGHUP` reloads the file but does not add the
plugin; this was verified on Docker 29.8.

```sh
systemctl restart docker
```

## Check it works

```console
$ docker run --rm alpine true          # audit mode: allowed, but logged
$ journalctl -u imagegate -o cat | grep '"decision":"deny"' | head -1
{"decision":"deny","mode":"audit","reason":"NO_RULE","image":"alpine",…}
```

In audit mode every would-be denial is logged with `"enforced":false`.
Follow [Rolling out](rollout.md) to get from here to `mode: enforce`, and
[Signing in CI](signing.md) to produce images that pass.
