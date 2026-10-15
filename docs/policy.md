# Policy reference

The policy is one YAML file, `/etc/imagegate/policy.yaml`. Rules are
evaluated top to bottom; the first match wins, and the implicit final rule
is deny.

```yaml
--8<-- "deploy/policy.example.yaml"
```

## Top level

| Field | Default | Meaning |
| --- | --- | --- |
| `apiVersion` | required | Must be `imagegate.dev/v1` |
| `mode` | `enforce` | `enforce`, or `audit` to log would-be denials and allow everything |
| `localImages` | `deny` | `deny` or `allow` images built, loaded or committed on the host |
| `identities` | required | Named signers, referenced by rules |
| `rules` | required | Ordered list; at least one |

## defaults

| Field | Default | Meaning |
| --- | --- | --- |
| `failClosed` | `true` | When verification cannot complete (registry down, timeout), deny. `false` allows; see the warning below |
| `verifyTimeout` | `10s` | Per-verification budget; at most `25s`, below dockerd's plugin timeout |
| `cache.allowTTL` | `24h` | How long an allow is cached |
| `cache.denyTTL` | `60s` | How long a deny is cached, so freshly signed images work within a minute |
| `helpURL` | none | Denials print `fix: <helpURL>#<reason>` (lowercase), e.g. pointing at this site's [runbook](runbook.md) |

!!! warning "`failClosed: false`"
    Anyone who can make a rule's registry unreachable or slow for imagegate
    then gets their image run. Use it only for rules whose registries
    attackers cannot influence.

## trust

| Field | Default | Meaning |
| --- | --- | --- |
| `sigstore` | `public-good` | The public Sigstore instance via TUF, or a path to a private `trusted_root.json` |
| `requireSCT` | `true` | Require an embedded certificate transparency SCT on keyless certificates. Set `false` only for private Sigstore stacks without a CT log |

## identities

Each identity is keyless or keyed, not both.

=== "Keyless (Fulcio)"

    ```yaml
    ci-main:
      issuer: https://token.actions.githubusercontent.com    # or issuerRegExp
      subjectRegExp: ^https://github\.com/acme/.+/\.github/workflows/release\.ya?ml@refs/heads/main$   # or subject
    ```

    Exactly one of `issuer` / `issuerRegExp`, and one of `subject` /
    `subjectRegExp`. Anchor regexes with `^…$`.

=== "Keyed"

    ```yaml
    vendor-key:
      publicKey: /etc/imagegate/keys/vendor.pub   # PEM; ECDSA, RSA or Ed25519
    ```

See [Identities](identities.md) for verified examples from Chainguard, Flux,
Trivy, distroless and Kubernetes, subject formats for GitLab, Buildkite,
CircleCI, Google Cloud and Kubernetes, KMS keys, and how to find who signed
an image.

## rules

| Field | Default | Meaning |
| --- | --- | --- |
| `name` | required | Unique; shown in audit records and metrics |
| `images` | required | Globs over the normalized repository |
| `signature.identities` | required | Any one match passes |
| `sbom.required` | `true` | Require a signed SBOM attestation |
| `sbom.identities` | required if `required` | Who may sign the SBOM |
| `sbom.predicateTypes` | SPDX, CycloneDX | Allowed in-toto predicate types |

### Globs

Globs match the normalized repository: no tag, no digest.

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `ghcr.io/acme/**` | `ghcr.io/acme/api`, `ghcr.io/acme/team/api` | `ghcr.io/acme`, `ghcr.io/acmecorp/api` |
| `docker.io/library/*` | `docker.io/library/nginx` | `docker.io/library/nginx/x` |
| `registry.vendor.example/agent` | exactly that | `registry.vendor.example/agent/evil` |

`*` and `?` stop at `/`; `**` crosses it. Repositories are normalized first:
`nginx` is `docker.io/library/nginx`, hostnames are lower-cased, `:443` is
dropped, and `registry-1.docker.io` and `index.docker.io` become
`docker.io`.

### Predicate types

`https://spdx.dev/Document` also matches versioned forms such as
`https://spdx.dev/Document/v2.3`. cosign `--type spdxjson` produces
`https://spdx.dev/Document`; `--type cyclonedx` produces
`https://cyclonedx.org/bom`.

## Reloading

```sh
imagegate validate              # checks the file and every key it names
systemctl reload imagegate      # SIGHUP
```

An invalid file on reload is rejected, logged and counted in
`imagegate_policy_reload_errors_total`; the last good policy stays active.
An invalid policy at boot denies every create (`NO_POLICY`) and allows
every other call.

## Policy hash

`policyHash` is the SHA-256 of the canonicalized file (comments and
formatting don't count) plus the contents of every public key and private
trusted root it names. It is part of every cache key, so editing the policy
or rotating a key at the same path invalidates cached verdicts.
