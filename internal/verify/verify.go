// Package verify checks that an image digest carries a cosign signature
// and a signed SBOM attestation from identities allowed by a policy rule.
//
// Signatures and attestations are fetched from OCI 1.1 referrers (Sigstore
// bundles, cosign v3 default) and from legacy cosign tags
// (sha256-<digest>.sig / .att). Legacy layers are converted to Sigstore
// bundles so everything is verified by sigstore-go.
package verify

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/rossedman/image-gate/internal/imageref"
	"github.com/rossedman/image-gate/internal/policy"
	"github.com/rossedman/image-gate/internal/verdict"
)

// CosignSignPredicate is the in-toto predicate type cosign uses for image
// signatures stored as Sigstore bundles.
const CosignSignPredicate = "https://sigstore.dev/cosign/sign/v1"

// Target is the image being verified.
type Target struct {
	// Repo is the normalized repository, e.g. ghcr.io/acme/api.
	Repo string
	// Digest is the manifest or index digest dockerd resolved. Signatures
	// and SBOMs must be on exactly this digest: accepting one on a
	// platform child would make the verdict depend on which child is
	// selected, and imagegate cannot see which child dockerd runs.
	Digest string
}

// Result is the outcome of verifying one target against one rule.
type Result struct {
	Reason verdict.Reason
	// Signer is the policy identity that produced the accepted signature.
	Signer string
	Detail string
	// Stages records time spent per stage (resolve, signature, sbom).
	Stages map[string]time.Duration
}

// Options configures an Engine.
type Options struct {
	Trust     TrustSource
	Keychain  authn.Keychain
	Transport http.RoundTripper
	// NameOptions are passed when parsing repositories, e.g.
	// name.Insecure for plain-HTTP test registries.
	NameOptions []name.Option
}

// Engine verifies images. Compile it against a policy to get a Verifier.
type Engine struct {
	reg      *registry
	trust    TrustSource
	nameOpts []name.Option
}

func NewEngine(o Options) *Engine {
	if o.Keychain == nil {
		o.Keychain = authn.DefaultKeychain
	}
	if o.Transport == nil {
		o.Transport = http.DefaultTransport
	}
	if o.Trust == nil {
		o.Trust = StaticTrust{}
	}
	return &Engine{
		reg:      &registry{keychain: o.Keychain, transport: o.Transport},
		trust:    o.Trust,
		nameOpts: o.NameOptions,
	}
}

type identity struct {
	name    string
	keyless *sgverify.CertificateIdentity
	key     signature.Verifier
}

// Verifier is an Engine bound to one policy's identities.
type Verifier struct {
	e          *Engine
	identities map[string]identity
	requireSCT bool
}

// Compile resolves the policy's identities: regexes are compiled and public
// key files are read and parsed.
func (e *Engine) Compile(p *policy.Policy) (*Verifier, error) {
	v := &Verifier{e: e, identities: map[string]identity{}, requireSCT: *p.Trust.RequireSCT}
	var errs []error
	for n, id := range p.Identities {
		if id.Keyed() {
			key, err := loadKey(id.PublicKey)
			if err != nil {
				errs = append(errs, fmt.Errorf("identities.%s: %w", n, err))
				continue
			}
			v.identities[n] = identity{name: n, key: key}
			continue
		}
		ci, err := sgverify.NewShortCertificateIdentity(id.Issuer, id.IssuerRegExp, id.Subject, id.SubjectRegExp)
		if err != nil {
			errs = append(errs, fmt.Errorf("identities.%s: %w", n, err))
			continue
		}
		v.identities[n] = identity{name: n, keyless: &ci}
	}
	return v, errors.Join(errs...)
}

func loadKey(path string) (signature.Verifier, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse public key %s: %w", path, err)
	}
	return signature.LoadVerifier(pub, crypto.SHA256)
}

// candidate is an entity found attached to one subject digest.
type candidate struct {
	entity
	subject string
}

// Verify checks t against rule. It never returns an error: failures to
// verify map to UPSTREAM_UNAVAILABLE or TIMEOUT results.
func (v *Verifier) Verify(ctx context.Context, t Target, rule *policy.Rule) (res Result) {
	res.Stages = map[string]time.Duration{}
	defer func() {
		if ctx.Err() != nil && res.Reason != verdict.Allowed {
			res.Reason = verdict.Timeout
			res.Detail = "verification did not finish within verifyTimeout"
		}
	}()

	repo, err := name.NewRepository(t.Repo, v.e.nameOpts...)
	if err != nil {
		return Result{Reason: verdict.BadRequest, Detail: err.Error()}
	}

	start := time.Now()
	unsignedSBOM, err := v.e.reg.unsignedBuildKitSBOM(ctx, repo, t.Digest, rule.SBOM.PredicateTypes)
	if err != nil {
		if isNotFound(err) {
			// With the containerd image store, local builds and loads get
			// a RepoDigests entry too; the registry not having the digest
			// is what marks them as local.
			return Result{Reason: verdict.LocalImage, Detail: fmt.Sprintf("digest is not in registry repository %s (built, loaded or committed locally)", t.Repo)}
		}
		return registryFailure(err)
	}
	f, err := v.e.reg.find(ctx, repo, t.Digest)
	if err != nil {
		return registryFailure(err)
	}
	unsignedSBOM = unsignedSBOM || f.unsignedSBOM
	cands := make([]candidate, 0, len(f.entities))
	for _, e := range f.entities {
		cands = append(cands, candidate{entity: e, subject: t.Digest})
	}
	res.Stages["resolve"] = time.Since(start)

	start = time.Now()
	sig := v.check(cands, rule.Signature.Identities, isSignature)
	res.Stages["signature"] = time.Since(start)
	switch {
	case sig.signer != "":
	case sig.trustErr != nil:
		return Result{Reason: verdict.UpstreamUnavailable, Detail: sig.trustErr.Error(), Stages: res.Stages}
	case sig.mismatch != "":
		return Result{Reason: verdict.IdentityMismatch, Detail: sig.mismatch + "; allowed: " + quoteList(rule.Signature.Identities), Stages: res.Stages}
	case sig.considered > 0:
		return Result{Reason: verdict.NoSignature, Detail: fmt.Sprintf("%d signature(s) found, none valid for this digest", sig.considered), Stages: res.Stages}
	default:
		return Result{Reason: verdict.NoSignature, Detail: "no cosign signature found for this digest", Stages: res.Stages}
	}
	res.Signer = sig.signer

	if !rule.SBOM.IsRequired() {
		res.Reason = verdict.Allowed
		return res
	}
	start = time.Now()
	isSBOM := func(pt string) bool { return predicateAllowed(pt, rule.SBOM.PredicateTypes) }
	sb := v.check(cands, rule.SBOM.Identities, isSBOM)
	res.Stages["sbom"] = time.Since(start)
	switch {
	case sb.signer != "":
		res.Reason = verdict.Allowed
		return res
	case sb.trustErr != nil:
		res.Reason, res.Detail = verdict.UpstreamUnavailable, sb.trustErr.Error()
	case sb.considered > 0:
		res.Reason = verdict.SBOMUntrusted
		res.Detail = fmt.Sprintf("SBOM attestation found but not signed by an allowed identity (%s)", quoteList(rule.SBOM.Identities))
		if sb.mismatch != "" {
			res.Detail = "SBOM attestation " + sb.mismatch + "; allowed: " + quoteList(rule.SBOM.Identities)
		}
	case unsignedSBOM:
		res.Reason = verdict.SBOMUntrusted
		res.Detail = "an SBOM is attached but unsigned (e.g. BuildKit --sbom); publish it with cosign attest"
	default:
		res.Reason = verdict.NoSBOM
		res.Detail = fmt.Sprintf("no SPDX or CycloneDX attestation signed by %s", quoteList(rule.SBOM.Identities))
	}
	return res
}

// registryFailure maps a registry error to a verdict. Only network errors,
// timeouts, 5xx, 429 and auth failures mean "could not check" (subject to
// failClosed); anything else, such as a malformed response, denies.
func registryFailure(err error) Result {
	if isTransient(err) {
		return Result{Reason: verdict.UpstreamUnavailable, Detail: "registry: " + oneLine(err)}
	}
	return Result{Reason: verdict.NoSignature, Detail: "registry returned an invalid response: " + oneLine(err)}
}

// isSignature selects image signatures: legacy simplesigning payloads
// (predicate "") and bundles with the cosign sign predicate.
func isSignature(pt string) bool { return pt == "" || pt == CosignSignPredicate }

type checkResult struct {
	signer     string
	considered int
	mismatch   string
	trustErr   error
}

// check returns the first allowed identity that verifies any candidate
// whose predicate type is selected by want.
func (v *Verifier) check(cands []candidate, allowed []string, want func(string) bool) checkResult {
	var out checkResult
	for _, c := range cands {
		pt, ok := c.predicateType()
		if !ok || !want(pt) {
			continue
		}
		out.considered++
		for _, n := range allowed {
			id, ok := v.identities[n]
			if !ok {
				continue
			}
			err := v.verifyOne(c, id, want)
			if err == nil {
				out.signer = n
				return out
			}
			if errors.Is(err, ErrNoTrustedRoot) && out.trustErr == nil {
				out.trustErr = err
			}
		}
		if out.mismatch == "" {
			out.mismatch = v.diagnose(c, allowed, want)
		}
	}
	if out.signer == "" && out.mismatch != "" {
		// A crypto-valid signature from the wrong identity is not a
		// trust-root outage.
		out.trustErr = nil
	}
	return out
}

// predicateType returns "" for legacy message signatures, the in-toto
// predicate type for DSSE content, and false for anything unreadable.
// It is read before verification only to route the candidate; the
// verified statement is checked again afterwards.
func (c candidate) predicateType() (string, bool) {
	if c.payload != nil {
		return "", true
	}
	env, err := c.bundle.Envelope()
	if err != nil || env == nil {
		return "", false
	}
	st, err := env.Statement()
	if err != nil || st.GetPredicateType() == "" {
		return "", false
	}
	return st.GetPredicateType(), true
}

func (v *Verifier) verifyOne(c candidate, id identity, want func(string) bool) error {
	sv, pol, err := v.verifierFor(c, id)
	if err != nil {
		return err
	}
	res, err := sv.Verify(c.bundle, pol)
	if err != nil {
		return err
	}
	return postCheck(c, res, want)
}

func postCheck(c candidate, res *sgverify.VerificationResult, want func(string) bool) error {
	if c.payload != nil {
		return checkSimpleSigning(c.payload, c.subject)
	}
	if res.Statement == nil || !want(res.Statement.GetPredicateType()) {
		return errors.New("verified statement has an unexpected predicate type")
	}
	return nil
}

func (v *Verifier) artifact(c candidate) (sgverify.ArtifactPolicyOption, error) {
	if c.payload != nil {
		return sgverify.WithArtifact(bytes.NewReader(c.payload)), nil
	}
	hexDigest, ok := strings.CutPrefix(c.subject, "sha256:")
	if !ok {
		return nil, fmt.Errorf("unsupported digest %s", c.subject)
	}
	raw, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, err
	}
	return sgverify.WithArtifactDigest("sha256", raw), nil
}

func (v *Verifier) verifierFor(c candidate, id identity) (*sgverify.Verifier, sgverify.PolicyBuilder, error) {
	art, err := v.artifact(c)
	if err != nil {
		return nil, sgverify.PolicyBuilder{}, err
	}
	trusted, trustErr := v.e.trust.TrustedMaterial()
	if id.keyless != nil {
		if trustErr != nil {
			return nil, sgverify.PolicyBuilder{}, trustErr
		}
		sv, err := sgverify.NewVerifier(trusted, v.keylessOptions()...)
		return sv, sgverify.NewPolicy(art, sgverify.WithCertificateIdentity(*id.keyless)), err
	}

	keyMat := root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		return root.NewExpiringKey(id.key, time.Time{}, time.Time{}), nil
	})
	entries, _ := c.bundle.TlogEntries()
	var sv *sgverify.Verifier
	if len(entries) > 0 && trustErr == nil {
		sv, err = sgverify.NewVerifier(root.TrustedMaterialCollection{trusted, keyMat},
			sgverify.WithTransparencyLog(1), sgverify.WithObserverTimestamps(1))
	} else {
		// Keyed signatures without a transparency log entry (e.g.
		// cosign sign --tlog-upload=false in CI) verify by key alone.
		sv, err = sgverify.NewVerifier(keyMat, sgverify.WithNoObserverTimestamps())
	}
	return sv, sgverify.NewPolicy(art, sgverify.WithKey()), err
}

func (v *Verifier) keylessOptions() []sgverify.VerifierOption {
	opts := []sgverify.VerifierOption{sgverify.WithTransparencyLog(1), sgverify.WithObserverTimestamps(1)}
	if v.requireSCT {
		opts = append(opts, sgverify.WithSignedCertificateTimestamps(1))
	}
	return opts
}

// diagnose explains why no allowed identity verified c: a valid keyless
// signature from another identity, or a key that is not allowed. It
// returns "" when c is simply invalid.
func (v *Verifier) diagnose(c candidate, allowed []string, want func(string) bool) string {
	vc, err := c.bundle.VerificationContent()
	if err != nil {
		return ""
	}
	if vc.Certificate() == nil {
		for _, n := range allowed {
			if id, ok := v.identities[n]; ok && id.key != nil {
				return "signature does not verify with any allowed public key"
			}
		}
		return "signed with a public key, but the rule requires a keyless identity"
	}
	trusted, err := v.e.trust.TrustedMaterial()
	if err != nil {
		return ""
	}
	art, err := v.artifact(c)
	if err != nil {
		return ""
	}
	sv, err := sgverify.NewVerifier(trusted, v.keylessOptions()...)
	if err != nil {
		return ""
	}
	res, err := sv.Verify(c.bundle, sgverify.NewPolicy(art, sgverify.WithoutIdentitiesUnsafe()))
	if err != nil || postCheck(c, res, want) != nil || res.Signature == nil || res.Signature.Certificate == nil {
		return ""
	}
	cert := res.Signature.Certificate
	return fmt.Sprintf("signed by %q (issuer %s), which is not an allowed identity", cert.SubjectAlternativeName, cert.Issuer)
}

// predicateAllowed matches exactly, or a versioned form of an allowed type
// (https://spdx.dev/Document matches https://spdx.dev/Document/v2.3).
func predicateAllowed(pt string, allowed []string) bool {
	if pt == "" {
		return false
	}
	for _, a := range allowed {
		if pt == a || strings.HasPrefix(pt, strings.TrimRight(a, "/")+"/") {
			return true
		}
	}
	return false
}

func quoteList(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = fmt.Sprintf("%q", n)
	}
	return "identity " + strings.Join(q, ", ")
}

func oneLine(err error) string {
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// ResolveDigest looks up the registry digest a tag currently points to.
func (e *Engine) ResolveDigest(ctx context.Context, ref imageref.Ref) (string, error) {
	repo, err := name.NewRepository(ref.Repo, e.nameOpts...)
	if err != nil {
		return "", err
	}
	desc, err := remote.Head(repo.Tag(ref.Tag), e.reg.options(ctx)...)
	if err != nil {
		return "", err
	}
	return desc.Digest.String(), nil
}
