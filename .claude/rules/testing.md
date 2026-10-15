---
paths:
  - "**/*_test.go"
  - "test/**"
---

# Testing rules

- Every verdict-affecting change needs a test that fails without it.
  Security fixes also get a regression case in `test/e2e/run.sh` when they
  involve raw API paths.
- `internal/verify` tests build real fixtures: an in-process OCI registry
  with referrers (`ocireg`) and a virtual Sigstore (`ca.VirtualSigstore`).
  Add new cases to `TestMatrix` or `TestLegacyLayout` instead of mocking
  sigstore-go.
- `internal/gate` tests use the fake dockerd and fake verifier in
  `gate_test.go`; control time through the harness clock, never `time.Sleep`
  for expiry.
- Run with `-race`. The singleflight test (200 concurrent creates, one
  verification) must stay.
- Never skip, disable or loosen a test to make a change pass.
- The e2e script must never touch the host's dockerd: it uses its own data
  root, exec root, socket and plugin name.
