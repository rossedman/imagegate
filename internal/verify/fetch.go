package verify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

const (
	bundleArtifactPrefix = "application/vnd.dev.sigstore.bundle"
	simpleSigningType    = "application/vnd.dev.cosign.simplesigning.v1+json"
	dsseLayerType        = "application/vnd.dsse.envelope.v1+json"

	buildkitRefType   = "vnd.docker.reference.type"
	buildkitRefDigest = "vnd.docker.reference.digest"
	intotoPredicate   = "in-toto.io/predicate-type"

	// maxBlob bounds every signature, attestation and bundle blob read.
	maxBlob = 8 << 20
	// maxEntities bounds how many signatures or attestations are
	// considered per subject, so a registry cannot make us spin.
	maxEntities = 64
)

// entity is one signature or attestation found for a subject digest,
// normalized to a Sigstore bundle.
type entity struct {
	bundle *bundle.Bundle
	// payload is the signed simplesigning payload for legacy cosign
	// message signatures; nil for DSSE content.
	payload []byte
	// source describes where it came from, for logs.
	source string
}

// found is everything attached to one subject digest.
type found struct {
	entities []entity
	// unsignedSBOM is set when an SBOM is attached without a signature
	// (BuildKit attestation manifest, or a plain SBOM referrer).
	unsignedSBOM bool
}

// registry fetches signatures and attestations.
type registry struct {
	keychain  authn.Keychain
	transport http.RoundTripper
}

func (r *registry) options(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(r.keychain),
		remote.WithTransport(r.transport),
		remote.WithUserAgent("imagegate"),
	}
}

// subjects returns the digests to look for signatures on: the image digest
// itself and, when it is an index, the platform manifest for platform. It
// also reports unsigned BuildKit SBOM attestations in the index.
func (r *registry) subjects(ctx context.Context, repo name.Repository, digest string, platform *v1.Platform, sbomTypes []string) ([]string, bool, error) {
	desc, err := remote.Get(repo.Digest(digest), r.options(ctx)...)
	if err != nil {
		return nil, false, err
	}
	subjects := []string{digest}
	if !desc.MediaType.IsIndex() {
		return subjects, false, nil
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, false, err
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, false, err
	}
	var child string
	for _, m := range im.Manifests {
		if m.Annotations[buildkitRefType] != "" || m.Platform == nil {
			continue
		}
		if platform == nil || m.Platform.Satisfies(*platform) {
			child = m.Digest.String()
			break
		}
	}
	if child != "" {
		subjects = append(subjects, child)
	}
	unsigned := false
	for _, m := range im.Manifests {
		if m.Annotations[buildkitRefType] != "attestation-manifest" {
			continue
		}
		if child != "" && m.Annotations[buildkitRefDigest] != child {
			continue
		}
		has, err := r.buildkitHasSBOM(ctx, repo, m.Digest.String(), sbomTypes)
		if err != nil {
			return nil, false, err
		}
		unsigned = unsigned || has
	}
	return subjects, unsigned, nil
}

func (r *registry) buildkitHasSBOM(ctx context.Context, repo name.Repository, digest string, sbomTypes []string) (bool, error) {
	img, err := remote.Image(repo.Digest(digest), r.options(ctx)...)
	if err != nil {
		return false, err
	}
	m, err := img.Manifest()
	if err != nil {
		return false, err
	}
	for _, l := range m.Layers {
		if predicateAllowed(l.Annotations[intotoPredicate], sbomTypes) {
			return true, nil
		}
	}
	return false, nil
}

// find collects bundles from OCI 1.1 referrers (falling back to the
// referrers tag schema), then legacy cosign .sig and .att tags.
func (r *registry) find(ctx context.Context, repo name.Repository, digest string) (found, error) {
	var out found
	if err := r.fromReferrers(ctx, repo, digest, &out); err != nil {
		return out, err
	}
	for _, suffix := range []string{".sig", ".att"} {
		if err := r.fromLegacyTag(ctx, repo, digest, suffix, &out); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (r *registry) fromReferrers(ctx context.Context, repo name.Repository, digest string, out *found) error {
	idx, err := remote.Referrers(repo.Digest(digest), r.options(ctx)...)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return err
	}
	for _, m := range im.Manifests {
		at := m.ArtifactType
		switch {
		case strings.HasPrefix(at, bundleArtifactPrefix):
		case isSBOMMediaType(at):
			out.unsignedSBOM = true
			continue
		default:
			continue
		}
		if len(out.entities) >= maxEntities {
			break
		}
		b, err := r.bundleFromManifest(ctx, repo, m.Digest.String())
		if err != nil {
			if isTransient(err) {
				return err
			}
			// A malformed bundle is ignored like any other invalid
			// signature; others may still verify.
			continue
		}
		out.entities = append(out.entities, entity{bundle: b, source: "referrer " + m.Digest.String()})
	}
	return nil
}

func (r *registry) bundleFromManifest(ctx context.Context, repo name.Repository, digest string) (*bundle.Bundle, error) {
	img, err := remote.Image(repo.Digest(digest), r.options(ctx)...)
	if err != nil {
		return nil, err
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	if len(layers) == 0 {
		return nil, errors.New("bundle manifest has no layers")
	}
	raw, err := readLayer(layers[0])
	if err != nil {
		return nil, err
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return nil, err
	}
	return &b, nil
}

func (r *registry) fromLegacyTag(ctx context.Context, repo name.Repository, digest, suffix string, out *found) error {
	tag := repo.Tag(strings.Replace(digest, ":", "-", 1) + suffix)
	img, err := remote.Image(tag, r.options(ctx)...)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	m, err := img.Manifest()
	if err != nil {
		return err
	}
	layers, err := img.Layers()
	if err != nil {
		return err
	}
	for i, desc := range m.Layers {
		if i >= len(layers) || len(out.entities) >= maxEntities {
			break
		}
		if desc.MediaType != simpleSigningType && desc.MediaType != dsseLayerType {
			continue
		}
		raw, err := readLayer(layers[i])
		if err != nil {
			if isTransient(err) {
				return err
			}
			continue
		}
		e, err := legacyEntity(string(desc.MediaType), raw, desc.Annotations)
		if err != nil {
			continue
		}
		e.source = fmt.Sprintf("%s layer %d", tag.TagStr(), i)
		out.entities = append(out.entities, e)
	}
	return nil
}

func readLayer(l v1.Layer) ([]byte, error) {
	rc, err := l.Compressed()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, maxBlob+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBlob {
		return nil, errors.New("blob too large")
	}
	return raw, nil
}

func isSBOMMediaType(mt string) bool {
	mt = strings.ToLower(mt)
	return strings.Contains(mt, "spdx") || strings.Contains(mt, "cyclonedx")
}

func isNotFound(err error) bool {
	var te *transport.Error
	if errors.As(err, &te) {
		if te.StatusCode == http.StatusNotFound {
			return true
		}
		for _, d := range te.Errors {
			switch d.Code {
			case transport.ManifestUnknownErrorCode, transport.NameUnknownErrorCode, transport.BlobUnknownErrorCode:
				return true
			}
		}
	}
	return false
}

// isTransient reports errors that mean "could not check" rather than
// "checked and found nothing": network failures, timeouts, 5xx, auth.
func isTransient(err error) bool {
	if err == nil || isNotFound(err) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var te *transport.Error
	if errors.As(err, &te) {
		return te.StatusCode >= 500 || te.StatusCode == http.StatusUnauthorized ||
			te.StatusCode == http.StatusForbidden || te.StatusCode == http.StatusTooManyRequests
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	var ue *url.Error
	return errors.As(err, &ue)
}
