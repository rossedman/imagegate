# Contributing to imagegate

Thanks for helping. imagegate sits in the path of every container start on a
host, so changes are held to a high bar for correctness and for failing
safely. This guide covers how to build, test and send changes.

## Ground rules

- **Security issues go to [SECURITY.md](https://github.com/rossedman/imagegate/blob/main/SECURITY.md), not the issue tracker.**
- Open an issue before large changes (new endpoints, policy schema changes,
  new verification paths) so the design can be agreed first.
- Every change that affects a verdict needs a test that fails without it.
- Never weaken a fail-closed path to make a test pass.

## Development setup

You need Go (the version in `go.mod`; the toolchain downloads it if needed).

```sh
git clone https://github.com/rossedman/imagegate
cd imagegate
make build      # bin/imagegate
make test       # gofmt check, go vet, go test -race
```

### End-to-end tests

`test/e2e/run.sh` starts its own dockerd with imagegate as its authorization
plugin, a zot registry, and cosign-signed fixtures. It needs root, dockerd,
the docker CLI and cosign, and never touches the host's own daemon.

```sh
COSIGN=$(which cosign) COSIGN_V3=/path/to/cosign-v3 sudo -E ./test/e2e/run.sh
```

Run it on a disposable VM or in a privileged Docker-in-Docker container.

### Docs site

```sh
pip install -r docs/requirements.txt
mkdocs serve    # http://127.0.0.1:8000
```

## Making a change

1. Fork and branch from `main`.
2. Keep the change focused; one concern per pull request.
3. Run `make test` (and the e2e script if you touched `authz`, `gate`,
   `verify` or `docker`).
4. Update the docs in `docs/` and `CHANGELOG.md` when behaviour changes.
5. Open a pull request and fill in the template.

### Code style

- `gofmt` and `go vet` clean; no new dependencies without discussion.
- Comments explain *why*, especially for security decisions.
- Errors from registries are classified deliberately: "could not check"
  (transient, subject to `failClosed`) versus "checked and failed" (deny).
- Reason codes are a public contract shown to users, logged and alerted on.
  Do not rename them; add new ones only with docs.

### Commit messages

Use the imperative mood ("Add", "Fix") and explain the reason in the body.
Reference issues with `Fixes #123`.

## Releasing

Maintainers tag `vX.Y.Z` on `main`; the release workflow builds Linux
binaries and checksums and publishes a GitHub release.

## Code of conduct

This project follows the [Code of Conduct](https://github.com/rossedman/imagegate/blob/main/CODE_OF_CONDUCT.md).
