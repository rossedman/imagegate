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

## Install the binary

=== "Release binary"

    ```sh
    VERSION=v0.1.0   # see the releases page
    curl -fsSLo /usr/local/bin/imagegate \
      https://github.com/rossedman/imagegate/releases/download/$VERSION/imagegate-linux-amd64
    chmod 0755 /usr/local/bin/imagegate
    ```

=== "From source"

    ```sh
    git clone https://github.com/rossedman/imagegate && cd imagegate
    make build
    install -m 0755 bin/imagegate /usr/local/bin/imagegate
    ```

## Write a policy

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

## Run imagegate under systemd

```sh
curl -fsSL https://raw.githubusercontent.com/rossedman/imagegate/main/deploy/systemd/imagegate.service \
  -o /etc/systemd/system/imagegate.service
systemctl daemon-reload
systemctl enable --now imagegate
imagegate health          # → ok
```

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
