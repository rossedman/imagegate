# Security policy

imagegate is a security control: a bypass lets unsigned images run, and a
crash can lock operators out of dockerd. We take reports seriously.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:
[Security → Report a vulnerability](https://github.com/rossedman/imagegate/security/advisories/new).

Include:

- the imagegate version or commit, Docker version and image store
  (containerd or graph driver);
- the policy (redacted) and the exact API request or CLI command;
- what happened and what you expected.

We aim to acknowledge reports within 3 business days and to agree a
disclosure date with you. Credit is given in the advisory unless you ask
otherwise.

## Scope

In scope: anything that lets a container be created or started from an
image the policy should deny, or that makes imagegate deny or crash in a way
that blocks the Docker API.

Known, documented limitations are not vulnerabilities on their own; see
[the security model](https://rossedman.github.io/imagegate/security/). They
include users who already have full Docker API access using
`--privileged`, Swarm services, builds or plugins, and anyone with root on
the host.

## Verifying releases

Release checksums and container images are signed keylessly with Sigstore
by the release workflow; there are no long-lived signing keys. Verify the
checksums file, then the files you downloaded against it:

```sh
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/rossedman/imagegate/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

Container images:

```sh
cosign verify ghcr.io/rossedman/imagegate:<version> \
  --certificate-identity-regexp '^https://github.com/rossedman/imagegate/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Every release asset also has a SLSA build provenance attestation:

```sh
gh attestation verify imagegate_<version>_linux_amd64.tar.gz --repo rossedman/imagegate
```

## Supported versions

Security fixes are released for the latest minor version.
