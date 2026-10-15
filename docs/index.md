---
template: home.html
title: imagegate
hide:
  - navigation
  - toc
---

<section class="ig-hero">
<div>
<p class="ig-ref">Sheet IG-01 · <b>Docker authorization plugin</b></p>
<h1 class="ig-title">Only sealed images run.<br><span>Signed, attested, by digest.</span></h1>
<p class="ig-lede">imagegate checks every <code>docker run</code> at the daemon. A container starts only if its image digest has a cosign signature from an identity you trust and a signed SPDX or CycloneDX SBOM. Dockerfiles, Compose files and run commands stay the same.</p>
<div class="ig-actions">
<a class="ig-btn ig-btn--primary" href="getting-started/">Get started</a>
<a class="ig-btn" href="how-it-works/">How it works</a>
<a class="ig-btn" href="https://github.com/rossedman/imagegate">GitHub</a>
</div>
</div>
<div class="ig-drawing">
<svg viewBox="0 0 600 380" role="img" aria-label="Drawing of a container image, identified by digest, with a seal for its signature and SBOM">
<g fill="none" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round">
<path class="l" d="M200.0 78.0 L297.0 134.0 L200.0 190.0 L103.0 134.0 Z"/>
<path class="l" d="M103.0 134.0 V246.0 L200.0 302.0 V190.0"/>
<path class="l" d="M297.0 134.0 V246.0 L200.0 302.0"/>
<path class="s" d="M135.3 152.7 V264.7"/><path class="s" d="M167.7 171.3 V283.3"/>
<path class="a seal" stroke-width="3" d="M225.2 231.4 L241.7 237.6 L271.8 191.1"/>
<path class="d" stroke-width="1" d="M79.0 134.0 V246.0 M74.0 134.0 H84.0 M74.0 246.0 H84.0"/>
<path class="d" stroke-width="1" d="M91.0 266.8 L188.0 322.8"/>
<path class="d" stroke-width="1" d="M200.0 78.0 L260.0 52.0 H430.0"/>
<path class="a" stroke-width="1" d="M252.5 234.5 L350.0 296.4 H510.0"/>
</g>
<text class="t" x="69.0" y="194.0" text-anchor="end">OCI</text>
<text class="t" transform="translate(126.3 317.7) rotate(30)" text-anchor="middle">SHA256 DIGEST</text>
<text class="t" x="264.0" y="45.0">A · IMAGE, BY DIGEST</text>
<text class="ta" x="354.0" y="288.4">B · SEAL: SIGNATURE + SBOM</text>
</svg>
<div class="ig-console"><span class="p">$</span> docker run ghcr.io/acme/web:2.0
docker: Error response from daemon: authorization denied by plugin imagegate:
imagegate: denied ghcr.io/acme/web@sha256:91ac…
<span class="r">reason: NO_SBOM</span> — no SPDX or CycloneDX attestation signed by identity "ci-main"
fix: https://wiki.acme.internal/imagegate#no_sbom</div>
</div>
</section>

<div class="ig-sheet-label"><span>Specification</span><span>6 items</span></div>
<div class="ig-grid">
<div class="ig-cell"><span class="ig-cell__ref">01</span><h3>Verifies by digest</h3><p>Tags resolve through dockerd to the exact digest it will run. Start re-checks the container's real image, so a moved tag can't swap it.</p></div>
<div class="ig-cell"><span class="ig-cell__ref">02</span><h3>Real Sigstore</h3><p>sigstore-go checks Fulcio chains, SCTs, Rekor proofs and signed timestamps, or your public keys. cosign v2 tags and v3 bundles both work.</p></div>
<div class="ig-cell"><span class="ig-cell__ref">03</span><h3>SBOMs that count</h3><p>A signed in-toto attestation bound to the same digest. An unsigned BuildKit SBOM is reported as untrusted.</p></div>
<div class="ig-cell"><span class="ig-cell__ref">04</span><h3>Fast when warm</h3><p>One verification per digest and policy. Cached starts take 1–2 ms; 200 parallel creates trigger one verification.</p></div>
<div class="ig-cell"><span class="ig-cell__ref">05</span><h3>Built for rollout</h3><p>Audit mode logs would-be denials. Break-glass overrides carry a ticket, expire within 7 days and alert on use.</p></div>
<div class="ig-cell"><span class="ig-cell__ref">06</span><h3>Never locks you out</h3><p>Only create, start and restart are gated. <code>docker ps</code>, <code>info</code> and plugin management always pass.</p></div>
</div>

<div class="ig-sheet-label"><span>Verdicts</span><span>every decision has a reason</span></div>
<div class="ig-ledger">
<div class="ig-ledger__row"><b class="ig-pass">ALLOWED</b><span>signed by an allowed identity, with a signed SBOM</span><span>allow</span></div>
<div class="ig-ledger__row"><b class="ig-deny">NO_SIGNATURE</b><span>no valid cosign signature for the digest</span><span>deny</span></div>
<div class="ig-ledger__row"><b class="ig-deny">IDENTITY_MISMATCH</b><span>signed, but by a fork's workflow or an unknown key</span><span>deny</span></div>
<div class="ig-ledger__row"><b class="ig-deny">NO_SBOM</b><span>no signed SPDX or CycloneDX attestation</span><span>deny</span></div>
<div class="ig-ledger__row"><b class="ig-deny">SBOM_UNTRUSTED</b><span>an SBOM exists but no trusted identity signed it</span><span>deny</span></div>
<div class="ig-ledger__row"><b class="ig-deny">LOCAL_IMAGE</b><span>built, loaded or committed on the host</span><span>deny</span></div>
<div class="ig-ledger__row"><b class="ig-neutral">OVERRIDE</b><span>break-glass entry with a ticket, expires within 7 days</span><span>allow</span></div>
</div>
<p style="margin-top:1rem"><a href="runbook/">All reason codes and how to fix them →</a></p>
