# Signing in CI

imagegate admits images that carry two things on their digest: a cosign
signature and a signed SBOM attestation. This page shows how to produce
both in GitHub Actions with keyless signing, so there are no keys to manage.

## GitHub Actions

```yaml title=".github/workflows/release.yml"
name: release
on:
  push:
    branches: [main]

permissions:
  contents: read
  packages: write
  id-token: write   # lets cosign get a Fulcio certificate for this workflow

jobs:
  image:
    runs-on: ubuntu-latest
    env:
      IMAGE: ghcr.io/${{ github.repository }}
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ github.token }}
      - uses: docker/setup-buildx-action@v3
      - id: build
        uses: docker/build-push-action@v6
        with:
          push: true
          tags: ${{ env.IMAGE }}:${{ github.sha }}
      - uses: sigstore/cosign-installer@v3
      - uses: anchore/sbom-action@v0
        with:
          image: ${{ env.IMAGE }}@${{ steps.build.outputs.digest }}
          format: spdx-json
          output-file: sbom.spdx.json
      - name: Sign and attest the digest
        env:
          REF: ${{ env.IMAGE }}@${{ steps.build.outputs.digest }}
        run: |
          cosign sign --yes "$REF"
          cosign attest --yes --type spdxjson --predicate sbom.spdx.json "$REF"
```

Always sign `image@digest`, never a tag. `steps.build.outputs.digest` is the
digest that was pushed; for a multi-platform build it is the index, which is
what dockerd resolves on the containerd image store.

## Matching policy identity

The certificate's subject is the workflow file and ref:

```yaml
identities:
  ci-main:
    issuer: https://token.actions.githubusercontent.com
    subjectRegExp: ^https://github\.com/acme/.+/\.github/workflows/release\.ya?ml@refs/heads/main$
```

Anchor the regex (`^…$`), pin the organisation, the workflow file and the
branch. A fork's workflow, another branch, or a personal key then fails
with `IDENTITY_MISMATCH`, and the denial names the actual signer.

## Keyed signing

For CI without OIDC, use a key pair and list the public key:

```sh
cosign generate-key-pair
cosign sign --key cosign.key "$REF"
cosign attest --key cosign.key --type spdxjson --predicate sbom.spdx.json "$REF"
```

```yaml
identities:
  ci-key:
    publicKey: /etc/imagegate/keys/ci.pub
```

## Check an image before deploying

On a host running imagegate:

```console
$ imagegate warm ghcr.io/acme/api:1.4.2
ALLOW  ghcr.io/acme/api@sha256:3f9c… (ALLOWED)
```

`warm` resolves the tag in the registry, verifies, and caches the verdict,
so the first `docker run` on that host is a cache hit.

## What does not count

| Artifact | Verdict |
| --- | --- |
| BuildKit `--sbom=true` on its own | `SBOM_UNTRUSTED`: unsigned |
| SBOM pushed as a plain OCI referrer (`oras attach`) | `SBOM_UNTRUSTED`: unsigned |
| Signature on a tag pushed later to another digest | `NO_SIGNATURE`: signatures bind to digests |
| Signature or SBOM only on one platform's manifest | `NO_SIGNATURE` / `NO_SBOM`: sign the digest dockerd resolves |
