// Package verdict defines reason codes and the verdicts imagegate caches,
// logs and returns to dockerd.
package verdict

import (
	"fmt"
	"strings"
	"time"
)

// Reason is a stable code shown in denials, audit records and metrics.
type Reason string

// Reason codes. These strings are a public contract: they appear in denial
// messages, audit records, metrics and runbook anchors. Never rename them.
const (
	Allowed             Reason = "ALLOWED"
	Override            Reason = "OVERRIDE"
	NoSignature         Reason = "NO_SIGNATURE"
	IdentityMismatch    Reason = "IDENTITY_MISMATCH"
	NoSBOM              Reason = "NO_SBOM"
	SBOMUntrusted       Reason = "SBOM_UNTRUSTED"
	LocalImage          Reason = "LOCAL_IMAGE"
	NoRule              Reason = "NO_RULE"
	UpstreamUnavailable Reason = "UPSTREAM_UNAVAILABLE"
	Timeout             Reason = "TIMEOUT"
	NoPolicy            Reason = "NO_POLICY"
	BadRequest          Reason = "BAD_REQUEST"
)

// Transient reports whether the reason describes a failure to verify rather
// than a property of the image. Transient verdicts are never cached and are
// subject to defaults.failClosed.
func (r Reason) Transient() bool {
	return r == UpstreamUnavailable || r == Timeout
}

// fixes is the built-in remediation hint for each denial reason.
var fixes = map[Reason]string{
	NoSignature:         "sign the image digest with `cosign sign` from an identity allowed by the matching policy rule",
	IdentityMismatch:    "sign the image from an identity listed in the matching policy rule",
	NoSBOM:              "attach an SBOM with `cosign attest --type spdxjson` (or cyclonedx) from an allowed identity",
	SBOMUntrusted:       "an unsigned SBOM does not count; publish it with `cosign attest` from an allowed identity",
	LocalImage:          "push the image to a registry, sign it, and run it by its registry reference",
	NoRule:              "use an image from a repository covered by /etc/imagegate/policy.yaml, or add a rule",
	UpstreamUnavailable: "retry shortly; imagegate could not reach the registry or Sigstore to verify this image",
	Timeout:             "retry shortly, or pre-verify with `imagegate warm <ref>`",
	NoPolicy:            "fix /etc/imagegate/policy.yaml (`imagegate validate`), then send SIGHUP to imagegate",
	BadRequest:          "the create request could not be parsed; check the client",
}

// Verdict is the outcome of verifying one image digest against one policy.
type Verdict struct {
	Allow  bool   `json:"allow"`
	Reason Reason `json:"reason"`
	Rule   string `json:"rule,omitempty"`
	// Signer is the policy identity name that produced the accepted
	// signature.
	Signer string `json:"signer,omitempty"`
	// Detail is a one-line human explanation of the reason.
	Detail    string    `json:"detail,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Message renders the denial text dockerd shows verbatim to the client.
func Message(image string, r Reason, detail, helpURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "imagegate: denied %s\n", image)
	if detail != "" {
		fmt.Fprintf(&b, "reason: %s — %s\n", r, detail)
	} else {
		fmt.Fprintf(&b, "reason: %s\n", r)
	}
	if helpURL != "" {
		// Lowercase: heading anchors on the docs site and GitHub are
		// lowercase, and URL fragments are case-sensitive.
		fmt.Fprintf(&b, "fix: %s#%s", strings.TrimRight(helpURL, "#"), strings.ToLower(string(r)))
	} else {
		fmt.Fprintf(&b, "fix: %s", fixes[r])
	}
	return b.String()
}
