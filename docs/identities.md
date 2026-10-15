# Identities

An identity says who may sign. A keyless identity is an OIDC **issuer** plus
a certificate **subject**; a keyed identity is a public key. Rules list the
identities they accept for the signature and for the SBOM, and any one match
passes.

```yaml
identities:
  ci-main:                                   # name used by rules
    issuer: https://token.actions.githubusercontent.com    # or issuerRegExp
    subject: https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main   # or subjectRegExp
  vendor-key:
    publicKey: /etc/imagegate/keys/vendor.pub
```

imagegate matches the issuer and the subject (the certificate's SAN) only.
Other Fulcio certificate extensions, such as the source repository or
trigger event, are not checked.

## Find who signed an image

Give a rule a placeholder identity and ask imagegate. The denial names the
real signer, after verifying the certificate chain, SCT and Rekor entry:

```yaml
identities:
  probe: { issuer: https://example.invalid, subject: probe }
rules:
  - name: probe
    images: ["**"]
    signature: { identities: [probe] }
    sbom: { required: false }
```

```console
$ imagegate warm cgr.dev/chainguard/static:latest
DENY   cgr.dev/chainguard/static@sha256:fe55…: IDENTITY_MISMATCH — signed by
"https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main"
(issuer https://token.actions.githubusercontent.com), which is not an allowed identity
```

Copy the issuer and subject into a real identity, then tighten the subject
to a regex if it contains a version.

## Verified examples

Each of these was checked with `imagegate warm` against the public image on
2026-10-15. Re-check after a vendor changes its release pipeline.

| Image | Provider | Signed SBOM? | Result |
| --- | --- | --- | --- |
| `cgr.dev/chainguard/static` | GitHub Actions, branch | yes | `ALLOWED` with SBOM required |
| `ghcr.io/fluxcd/*` | GitHub Actions, tags + reusable workflow | no, unsigned BuildKit SBOM | `ALLOWED` signature-only; `SBOM_UNTRUSTED` if SBOM required |
| `ghcr.io/aquasecurity/trivy` | GitHub Actions, reusable workflow | no | `ALLOWED` signature-only |
| `gcr.io/distroless/*` | Google service account | no | `ALLOWED` signature-only |
| `registry.k8s.io/*` | Google service account | no | `ALLOWED` signature-only |
| `ghcr.io/sigstore/cosign/cosign` | Google service account | no | `ALLOWED` signature-only |

```yaml
identities:
  # GitHub Actions on a branch. Signs images and SPDX attestations.
  chainguard:
    issuer: https://token.actions.githubusercontent.com
    subject: https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main

  # GitHub Actions on version tags. Some Flux controllers release from their
  # own workflow, others from a shared reusable workflow in another repo.
  flux:
    issuer: https://token.actions.githubusercontent.com
    subjectRegExp: ^https://github\.com/fluxcd/([a-z-]+/\.github/workflows/release\.yml|gha-workflows/\.github/workflows/controller-release\.yaml)@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$

  # A reusable workflow called on tags.
  trivy:
    issuer: https://token.actions.githubusercontent.com
    subjectRegExp: ^https://github\.com/aquasecurity/trivy/\.github/workflows/reusable-release\.yaml@refs/tags/v[0-9.]+$

  # Google service accounts (Cloud Build and other Google-run pipelines).
  distroless:
    issuer: https://accounts.google.com
    subject: keyless@distroless.iam.gserviceaccount.com
  kubernetes:
    issuer: https://accounts.google.com
    subject: krel-trust@k8s-releng-prod.iam.gserviceaccount.com
  sigstore:
    issuer: https://accounts.google.com
    subject: keyless@projectsigstore.iam.gserviceaccount.com

rules:
  - name: chainguard
    images: ["cgr.dev/chainguard/**"]
    signature: { identities: [chainguard] }
    sbom: { identities: [chainguard] }          # signed SPDX attestations exist
  - name: flux
    images: ["ghcr.io/fluxcd/**"]
    signature: { identities: [flux] }
    sbom: { required: false }                   # SBOM attached but unsigned
  - name: trivy
    images: ["ghcr.io/aquasecurity/trivy"]
    signature: { identities: [trivy] }
    sbom: { required: false }
  - name: distroless
    images: ["gcr.io/distroless/**"]
    signature: { identities: [distroless] }
    sbom: { required: false }
  - name: kubernetes
    images: ["registry.k8s.io/**"]
    signature: { identities: [kubernetes] }
    sbom: { required: false }
```

!!! note "Reusable workflows sign as themselves"
    When a GitHub workflow calls a reusable workflow, the certificate
    subject is the **reusable** workflow (`job_workflow_ref`), not the
    caller. That's why Flux's `helm-controller` is signed by
    `fluxcd/gha-workflows`. Trusting a shared reusable workflow trusts every
    repository allowed to call it.

## Your own CI

The subject formats below come from
[Fulcio's identity configuration](https://github.com/sigstore/fulcio/blob/main/config/identity/config.yaml).
Except for GitHub Actions and Google service accounts, they were not tested
end to end here. Confirm yours with [the probe above](#find-who-signed-an-image).

### GitHub Actions

Issuer `https://token.actions.githubusercontent.com`. Subject
`https://github.com/<owner>/<repo>/.github/workflows/<file>@<ref>`.

```yaml
identities:
  # Only the release workflow on main.
  ci-main:
    issuer: https://token.actions.githubusercontent.com
    subject: https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main

  # Any repo in the org, release workflow, main branch only.
  ci-org-main:
    issuer: https://token.actions.githubusercontent.com
    subjectRegExp: ^https://github\.com/acme/[^/]+/\.github/workflows/release\.ya?ml@refs/heads/main$

  # Semver tags only.
  ci-tags:
    issuer: https://token.actions.githubusercontent.com
    subjectRegExp: ^https://github\.com/acme/api/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$

  # A central reusable workflow that every team calls.
  platform-release:
    issuer: https://token.actions.githubusercontent.com
    subjectRegExp: ^https://github\.com/acme/workflows/\.github/workflows/sign\.yml@refs/tags/v[0-9]+$
```

Pull request builds run on `refs/pull/<n>/merge`, so anchoring the ref to
`refs/heads/main` or tags keeps PR builds out.

### GitLab CI (gitlab.com)

Issuer `https://gitlab.com`. Subject `https://gitlab.com/<group>/<project>//<ci config path>@<ref>`.
Note the double slash before the CI file.

```yaml
identities:
  gitlab-main:
    issuer: https://gitlab.com
    subject: https://gitlab.com/acme/api//.gitlab-ci.yml@refs/heads/main
  gitlab-group-tags:
    issuer: https://gitlab.com
    subjectRegExp: ^https://gitlab\.com/acme/[^/]+//\.gitlab-ci\.yml@refs/tags/v[0-9.]+$
```

Public-good Fulcio accepts only the GitLab instances it lists (gitlab.com and
a few others). Self-managed GitLab needs a [private Sigstore](#private-sigstore).

### Buildkite

Issuer `https://agent.buildkite.com`. Subject `https://buildkite.com/<organization>/<pipeline>`.

```yaml
identities:
  buildkite-release:
    issuer: https://agent.buildkite.com
    subject: https://buildkite.com/acme/api-release
```

### CircleCI

Issuer `https://oidc.circleci.com/org/<organization-id>`. Subject
`https://circleci.com/api/v2/projects/<project-id>/pipeline-definitions/<pipeline-definition-id>`.

```yaml
identities:
  circleci-release:
    issuer: https://oidc.circleci.com/org/00000000-0000-0000-0000-000000000000
    subjectRegExp: ^https://circleci\.com/api/v2/projects/11111111-1111-1111-1111-111111111111/pipeline-definitions/[0-9a-f-]+$
```

### Codefresh

Issuer `https://oidc.codefresh.io`. Subject
`<platform url>/<account name>/<pipeline name>:<account id>/<pipeline id>`.
Use the probe to read the exact value for your account.

### Google Cloud (service accounts)

Issuer `https://accounts.google.com`, subject the service account's email.
This covers Cloud Build and anything else that signs as a service account.

```yaml
identities:
  cloudbuild:
    issuer: https://accounts.google.com
    subject: release-signer@acme-prod.iam.gserviceaccount.com
```

### Kubernetes workloads

Pods signing with their service account token (EKS, GKE, AKS clusters that
Fulcio trusts) use the cluster's OIDC issuer URL and the subject
`https://kubernetes.io/namespaces/<namespace>/serviceaccounts/<name>`.

```yaml
identities:
  tekton-signer:
    issuer: https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0123456789
    subject: https://kubernetes.io/namespaces/tekton-chains/serviceaccounts/tekton-chains-controller
```

### People

`cosign sign` run interactively signs with an email address. The issuer is
the upstream provider chosen at login:

| Login | `issuer` |
| --- | --- |
| GitHub | `https://github.com/login/oauth` |
| Google | `https://accounts.google.com` |
| Microsoft | `https://login.microsoftonline.com` |

```yaml
identities:
  release-manager:
    issuer: https://github.com/login/oauth
    subject: alice@acme.example
```

Prefer CI identities for anything automated: a person's identity can sign
from any machine.

## Keys

Keyed identities take a PEM public key: ECDSA, RSA or Ed25519.

```sh
cosign generate-key-pair                                # cosign.key + cosign.pub
cosign public-key --key awskms:///alias/image-signing > aws.pub
cosign public-key --key gcpkms://projects/acme/locations/global/keyRings/ci/cryptoKeys/sign > gcp.pub
cosign public-key --key azurekms://acme-vault.vault.azure.net/sign > azure.pub
cosign public-key --key hashivault://image-signing > vault.pub
```

```yaml
identities:
  aws-kms:
    publicKey: /etc/imagegate/keys/aws.pub
```

Keyed signatures made with `--tlog-upload=false` (or a cosign v3 signing
config without Rekor) verify by key alone. If they carry a Rekor entry,
it's checked. The policy hash includes each key file's contents, so
replacing a key at the same path invalidates cached verdicts.

## Patterns

**Rotate without downtime.** List the old and new identity together, deploy,
switch CI to the new one, then remove the old.

```yaml
signature: { identities: [ci-key-2025, ci-key-2026] }
```

**Separate signer and SBOM attester.** The SBOM can come from a different
pipeline, such as a security team's scanner:

```yaml
signature: { identities: [ci-main] }
sbom: { identities: [sec-scanner] }
```

**Write regexes defensively.**

- Anchor with `^…$`; regexes match anywhere in the subject, so without `$`,
  `@refs/heads/main` also matches `@refs/heads/main-hotfix`.
- Escape dots (`github\.com`, `\.github`).
- Use `[^/]+` for a single path segment, not `.+`.
- Pin the ref: a branch, or a tag pattern.

## Private Sigstore

For a private Fulcio and Rekor, point `trust.sigstore` at their
`trusted_root.json`. If your Fulcio has no CT log, also set
`requireSCT: false`.

```yaml
trust:
  sigstore: /etc/imagegate/trusted_root.json
  requireSCT: false
```

## Limitations

- **Signatures in another repository.** Some projects store signatures
  outside the image's repository (`COSIGN_REPOSITORY`); Kyverno uses
  `ghcr.io/kyverno/signatures`. imagegate looks only in the image's own
  repository, so these images show `NO_SIGNATURE`. Mirror and re-sign them.
- **Notation (Notary v2) signatures** are not supported, only cosign and
  Sigstore bundles.
