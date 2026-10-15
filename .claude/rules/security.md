---
paths:
  - "internal/**/*.go"
  - "cmd/**/*.go"
---

# Security rules

imagegate is a security control. Treat every change as a possible bypass or
lockout.

- **Think like an attacker with Docker API access** who can push to
  registries they control. Before finishing a change to `authz`, `gate` or
  `verify`, ask: can a request reach dockerd's create/start handler without
  being gated? Can an untrusted digest end up cached as allowed?
- **Fail closed on gated paths, open on everything else.** Never add a deny
  to a non-gated path. Never add an allow on a gated path without a test
  that shows why it is safe.
- **Registry data is attacker-controlled.** Bound every read (`maxBlob`,
  `maxEntities`), never trust annotations for decisions (cosign v3 labels
  SBOM referrers with the signing predicate), and check the verified
  statement, not the unverified one.
- **Classify errors deliberately.** Network, timeout, 5xx, 429 and auth
  errors are transient (`UPSTREAM_UNAVAILABLE`, subject to `failClosed`).
  Malformed data and other 4xx deny. 404 on the image digest means a local
  image.
- **Never cache transient verdicts.** Cache keys must include everything a
  verdict depends on (repository, digest, policy hash).
- **No panics escape.** Code that runs inside singleflight or a goroutine
  must recover and turn a panic into a deny.
- **Never log secrets**: registry credentials, full certificates, tokens.
- Overrides are digest-pinned, root-owned, ticketed and expire within 7 days.
  Never accept overrides from labels, environment variables or the request.
