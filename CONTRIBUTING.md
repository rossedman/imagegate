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
make check      # everything CI runs (see below); run before every PR
```

`make check` needs [golangci-lint](https://golangci-lint.run) v2,
[GoReleaser](https://goreleaser.com) and mkdocs (`pip install -r
docs/requirements.txt`); govulncheck runs through `go run`.

### Quality bars

CI enforces each of these; `make check` runs the same checks locally.

| Check | Command | Bar |
| --- | --- | --- |
| Format, vet, race tests | `make test` | clean |
| Lint | `make lint` | no findings |
| Coverage | `make cover` | 90% of statements in hand-written code |
| Vulnerabilities | `make vuln` | no reachable findings |
| Doc comments | `make doccheck` | every function, method and package |
| Benchmarks | `make bench-smoke` | every benchmark runs |
| Fuzzing | `make fuzz` | every target runs clean (30s each in CI) |
| Docs | `make docs` | strict build |

Every function and method, exported or not, has a doc comment starting
with its name. Benchmarks use `b.ReportAllocs()` and `b.Loop()`; compare
runs with `make bench` and [benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat).
Commit any input a fuzz target finds under that package's `testdata/fuzz/`
along with the fix.

### Critical paths

These functions parse attacker-controlled input or sit on the hot path of
every container create. Each has a benchmark; each that takes external
input has a fuzz target. Keep it that way when you change them, and add a
row when you add one.

| Function | Why | Fuzz | Benchmark |
| --- | --- | --- | --- |
| `authz.Classify` | decides which dockerd requests are gated (invariants 1 and 3) | yes | yes |
| `authz.Handler.ServeHTTP` | parses every dockerd authorization request | yes | yes |
| `gate.Gate.Create` | parses container-create bodies; hot path | yes | yes (cache hit) |
| `gate.Gate.Start` | start/restart re-check; hot path | — | yes (cache hit) |
| `imageref.Parse`, `SplitRepoDigest`, `LooksLikeID` | parse references from requests and dockerd | yes | yes |
| `policy.Parse`, glob matching | parse operator policy; `Match` runs per request | yes | yes |
| `verify.legacyEntity`, `checkSimpleSigning` | parse registry-controlled signature data | yes | yes |
| `verify.Engine` verification | cold-path cost of one image | — | yes |
| `cache.Cache.Get`, `Put` | verdict lookups on every request | — | yes |
| `verdict.Message` | every denial message | — | yes |

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
3. Run `make check` (and the e2e script if you touched `authz`, `gate`,
   `verify` or `docker`).
4. Update the docs in `docs/` and `CHANGELOG.md` when behaviour changes.
5. Open a pull request and fill in the template.

### Code style

- `gofmt`, `go vet` and `golangci-lint` clean; no new dependencies without
  discussion.
- Comments explain *why*, especially for security decisions.
- Errors from registries are classified deliberately: "could not check"
  (transient, subject to `failClosed`) versus "checked and failed" (deny).
- Reason codes are a public contract shown to users, logged and alerted on.
  Do not rename them; add new ones only with docs.

### Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org) (`fix:`,
`feat:`, `docs:`, `test:`, `ci:`, `build:`) in the imperative mood, and
explain the reason in the body.
Reference issues with `Fixes #123`.

## Releasing

Releases are built by [GoReleaser](https://goreleaser.com) from
`.goreleaser.yaml`: binaries and archives for linux amd64, arm64, arm/v7,
ppc64le and s390x; deb, rpm (systemd) and apk (OpenRC) packages;
multi-arch images on `ghcr.io/rossedman/imagegate`; SBOMs; and keyless
cosign signatures for the checksums and images.

```sh
make snapshot    # full local build into dist/, no signing or publishing
```

Maintainers tag `vX.Y.Z` on `main` and push the tag; `release.yml` runs
the tests and GoReleaser. Update `CHANGELOG.md` first.

## Code of conduct

This project follows the [Code of Conduct](https://github.com/rossedman/imagegate/blob/main/CODE_OF_CONDUCT.md).
