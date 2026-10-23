package verdict

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// allReasons lists every reason code. Reason codes are a public contract.
var allReasons = []Reason{
	Allowed, Override, NoSignature, IdentityMismatch, NoSBOM, SBOMUntrusted,
	LocalImage, NoRule, UpstreamUnavailable, Timeout, NoPolicy, BadRequest,
}

// TestReasonCodesStable pins the wire value of every reason code.
func TestReasonCodesStable(t *testing.T) {
	t.Parallel()
	want := map[Reason]string{
		Allowed:             "ALLOWED",
		Override:            "OVERRIDE",
		NoSignature:         "NO_SIGNATURE",
		IdentityMismatch:    "IDENTITY_MISMATCH",
		NoSBOM:              "NO_SBOM",
		SBOMUntrusted:       "SBOM_UNTRUSTED",
		LocalImage:          "LOCAL_IMAGE",
		NoRule:              "NO_RULE",
		UpstreamUnavailable: "UPSTREAM_UNAVAILABLE",
		Timeout:             "TIMEOUT",
		NoPolicy:            "NO_POLICY",
		BadRequest:          "BAD_REQUEST",
	}
	if len(want) != len(allReasons) {
		t.Fatalf("allReasons has %d entries, want %d", len(allReasons), len(want))
	}
	for r, s := range want {
		if string(r) != s {
			t.Errorf("reason %q, want %q", r, s)
		}
	}
}

func TestTransient(t *testing.T) {
	t.Parallel()
	for _, r := range allReasons {
		want := r == UpstreamUnavailable || r == Timeout
		if got := r.Transient(); got != want {
			t.Errorf("%s.Transient() = %v, want %v", r, got, want)
		}
	}
	if Reason("").Transient() || Reason("timeout").Transient() {
		t.Error("unknown or differently cased reasons must not be transient")
	}
}

// Every denial reason has a built-in fix hint; allow reasons do not.
func TestFixesCoverDenials(t *testing.T) {
	t.Parallel()
	for _, r := range allReasons {
		_, ok := fixes[r]
		deny := r != Allowed && r != Override
		if ok != deny {
			t.Errorf("fixes[%s] present = %v, want %v", r, ok, deny)
		}
	}
}

func TestMessage(t *testing.T) {
	t.Parallel()
	const img = "ghcr.io/acme/api:1.4.2"
	tests := []struct {
		name    string
		image   string
		reason  Reason
		detail  string
		helpURL string
		want    string
	}{
		{
			name:   "no detail, built-in fix",
			image:  img,
			reason: NoSignature,
			want: "imagegate: denied ghcr.io/acme/api:1.4.2\n" +
				"reason: NO_SIGNATURE\n" +
				"fix: sign the image digest with `cosign sign` from an identity allowed by the matching policy rule",
		},
		{
			name:   "detail, built-in fix",
			image:  img,
			reason: NoSBOM,
			detail: "no SBOM attestation found",
			want: "imagegate: denied ghcr.io/acme/api:1.4.2\n" +
				"reason: NO_SBOM — no SBOM attestation found\n" +
				"fix: attach an SBOM with `cosign attest --type spdxjson` (or cyclonedx) from an allowed identity",
		},
		{
			name:    "help URL lowercases the anchor",
			image:   img,
			reason:  IdentityMismatch,
			detail:  "signed by someone else",
			helpURL: "https://docs.example/denials",
			want: "imagegate: denied ghcr.io/acme/api:1.4.2\n" +
				"reason: IDENTITY_MISMATCH — signed by someone else\n" +
				"fix: https://docs.example/denials#identity_mismatch",
		},
		{
			name:    "trailing hashes trimmed from help URL",
			image:   img,
			reason:  Timeout,
			helpURL: "https://docs.example/denials##",
			want: "imagegate: denied ghcr.io/acme/api:1.4.2\n" +
				"reason: TIMEOUT\n" +
				"fix: https://docs.example/denials#timeout",
		},
		{
			name:   "unknown reason has an empty fix",
			image:  img,
			reason: Reason("SOMETHING_NEW"),
			want: "imagegate: denied ghcr.io/acme/api:1.4.2\n" +
				"reason: SOMETHING_NEW\n" +
				"fix: ",
		},
		{
			name:   "empty image",
			reason: BadRequest,
			want: "imagegate: denied \n" +
				"reason: BAD_REQUEST\n" +
				"fix: the create request could not be parsed; check the client",
		},
		{
			name:   "local image",
			image:  "sha256:73aaf090f3d8",
			reason: LocalImage,
			want: "imagegate: denied sha256:73aaf090f3d8\n" +
				"reason: LOCAL_IMAGE\n" +
				"fix: push the image to a registry, sign it, and run it by its registry reference",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Message(tt.image, tt.reason, tt.detail, tt.helpURL); got != tt.want {
				t.Errorf("Message() =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

// Every denial reason renders the same three-line shape with its own fix.
func TestMessageEveryReason(t *testing.T) {
	t.Parallel()
	for r, fix := range fixes {
		got := Message("img", r, "", "")
		want := "imagegate: denied img\nreason: " + string(r) + "\nfix: " + fix
		if got != want {
			t.Errorf("Message(%s) = %q, want %q", r, got, want)
		}
		if fix == "" {
			t.Errorf("fixes[%s] is empty", r)
		}
		withURL := Message("img", r, "", "https://h/x")
		if !strings.HasSuffix(withURL, "\nfix: https://h/x#"+strings.ToLower(string(r))) {
			t.Errorf("Message(%s) with URL = %q", r, withURL)
		}
	}
}

func TestVerdictJSON(t *testing.T) {
	t.Parallel()
	exp := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	v := Verdict{Allow: true, Reason: Allowed, Rule: "internal", Signer: "ci-main", Detail: "ok", ExpiresAt: exp}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"allow":true,"reason":"ALLOWED","rule":"internal","signer":"ci-main","detail":"ok","expiresAt":"2026-10-23T00:00:00Z"}`
	if string(raw) != want {
		t.Errorf("json = %s, want %s", raw, want)
	}
	var back Verdict
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back != v {
		t.Errorf("round trip = %+v, want %+v", back, v)
	}
	raw, err = json.Marshal(Verdict{Reason: NoRule, ExpiresAt: exp})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"allow":false,"reason":"NO_RULE","expiresAt":"2026-10-23T00:00:00Z"}`; string(raw) != want {
		t.Errorf("json = %s, want %s", raw, want)
	}
}

func BenchmarkMessage(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = Message("ghcr.io/acme/api:1.4.2", IdentityMismatch, "signed by someone else", "https://docs.example/denials")
	}
}
