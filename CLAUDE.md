# imagegate

Docker authorization plugin (Go) that denies container create/start/restart
unless the image digest has a cosign signature from an allowed identity and
a signed SBOM attestation. dockerd calls it over a Unix socket for every API
request. Read `README.md` for the overview and `docs/` for the full docs.

## Commands

```sh
make build        # bin/imagegate
make test         # gofmt check, go vet, go test -race (run before every commit)
make docs         # mkdocs build --strict (run when docs/ or mkdocs.yml change)
go test -run TestMatrix -v ./internal/verify    # the spec's fixture matrix
sudo -E ./test/e2e/run.sh   # real dockerd + zot + cosign; needs root, dockerd, COSIGN
```

## Layout

| Path | What it does |
| --- | --- |
| `cmd/imagegate` | CLI: serve, validate, warm, cache purge, health |
| `internal/authz` | Docker plugin protocol; classifies requests (only create/start/restart are gated) |
| `internal/gate` | Decision engine: digest resolution, overrides, cache, rules, audit mode, failClosed |
| `internal/verify` | Registry fetch (referrers + legacy cosign tags) and sigstore-go verification |
| `internal/policy` | Policy YAML, validation, globs, hash, break-glass overrides |
| `internal/cache` | Verdict cache (LRU + bbolt), image ID → digest mapping |
| `internal/verdict` | Reason codes and the denial message format |
| `internal/{audit,metrics,admin,docker,imageref}` | Audit log, Prometheus, admin socket, dockerd client, reference parsing |
| `test/e2e/run.sh` | End-to-end suite against a dedicated dockerd |
| `docs/`, `mkdocs.yml` | Documentation site (MkDocs Material, deployed to GitHub Pages) |

## Invariants (never break these)

1. Only POST create, start and restart may ever be denied. Every other call,
   every response, and every error on a non-gated path is allowed, or
   operators get locked out of dockerd.
2. Gated paths fail closed: on doubt, parse failure, panic or missing data,
   deny (subject only to `failClosed` for genuine "could not reach" errors).
3. Request classification must match dockerd's router exactly
   (`/v[0-9.]+` prefixes, container names containing `/`). A POST that looks
   gated but does not parse is denied.
4. Verify by digest, and only the digest dockerd resolved; never by tag and
   never a platform child.
5. Reason codes in `internal/verdict` are a public contract. Do not rename.

More detail lives in `.claude/rules/`.
