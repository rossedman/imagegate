# Design notes

Decisions made while building imagegate from its original specification,
and the questions the spec left open.

## Decisions

- **Cache key includes the repository**: (repository, digest, policyHash),
  not (digest, policyHash). The matching rule, and where signatures are
  fetched from, depend on the repository.
- **Local images on the containerd image store.** Docker 29's default image
  store gives local builds and `docker load`ed images a RepoDigests entry,
  so "no RepoDigests" alone does not detect them. A digest the registry does
  not have is also treated as `LOCAL_IMAGE`.
- **Images not present yet.** If dockerd does not have the image, the create
  is allowed so dockerd answers "No such image" and `docker run` pulls and
  retries. The retried create is verified; if the image appears in between,
  the start re-check catches it.
- **Start fails closed** when imagegate cannot find the container through
  its dockerd socket, so a wrong `-docker-socket` blocks starts instead of
  silently allowing everything. `restart` is re-checked like `start`.
- **Request classification mirrors dockerd's router.** Any `/v[0-9.]+`
  version prefix, and container names containing `/`. A POST that ends like
  a gated endpoint but does not parse is denied. An earlier version only
  stripped `/vX.Y`, so `/v1.45.0/containers/create` bypassed it.
- **Registry hostnames are canonicalized** before rule matching, so
  `GHCR.IO`, `:443` or `registry-1.docker.io` cannot fall through to a
  looser rule.
- **Malformed registry responses deny.** Only network errors, timeouts, 5xx,
  429 and auth failures count as "could not check" under `failClosed`.
- **Panics in verification become denials**; singleflight would otherwise
  re-panic in a new goroutine and take dockerd's API down with it.
- **`verifyTimeout` is capped at 25 s**, below dockerd's plugin call timeout.
- **Denial links use lowercase anchors** (`#no_sbom`), because heading
  anchors are lowercase and URL fragments are case-sensitive.

## Open questions, answered

| Question | Answer |
| --- | --- |
| Accept a signature on the index digest, the platform manifest, or both? | Only the digest dockerd resolved: the index on the containerd store. Accepting a platform child made the verdict depend on platform selection imagegate cannot see |
| Public-good Sigstore or a private instance? | Both: `trust.sigstore: public-good` or a path to `trusted_root.json` |
| Check SBOM content? | Not in v1: presence and provenance only |
| Support both cosign signature layouts? | Yes, referrers first, then legacy `.sig`/`.att` tags |
| Swarm `/services/create` in v1? | Not implemented; see the [security model](security.md) |
| Does SIGHUP reload `authorization-plugins`? | No. On Docker 29.8.2 dockerd reloads its config but never consults a newly added plugin; a restart is needed |
| Container-config rules in v1? | Deferred to v1.1 |
