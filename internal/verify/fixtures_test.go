package verify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ocireg "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

const (
	ghIssuer   = "https://token.actions.githubusercontent.com"
	ciMainSAN  = "https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main"
	forkSAN    = "https://github.com/someone/api/.github/workflows/release.yml@refs/heads/main"
	spdxType   = "https://spdx.dev/Document"
	cdxType    = "https://cyclonedx.org/bom"
	bundleType = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

// world is a registry plus a virtual Sigstore (Fulcio, Rekor, TSA, CT) and
// a signing key, for building signed image fixtures.
type world struct {
	t       testing.TB
	host    string
	vs      *ca.VirtualSigstore
	key     *ecdsa.PrivateKey
	keyPath string

	mu sync.Mutex
	// fault, when set, may answer a registry request with an HTTP
	// status instead of the registry (0 passes it through).
	fault func(*http.Request) int
}

// setFault installs a registry fault injector; nil removes it.
func (w *world) setFault(f func(*http.Request) int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fault = f
}

func newWorld(t testing.TB) *world {
	t.Helper()
	w := &world{t: t}
	reg := ocireg.New(ocireg.WithReferrersSupport(true), ocireg.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		f := w.fault
		w.mu.Unlock()
		if f != nil {
			if code := f(r); code != 0 {
				http.Error(rw, http.StatusText(code), code)
				return
			}
		}
		reg.ServeHTTP(rw, r)
	}))
	t.Cleanup(srv.Close)
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "ci.pub")
	if err := os.WriteFile(keyPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	w.host, w.vs, w.key, w.keyPath = strings.TrimPrefix(srv.URL, "http://"), vs, key, keyPath
	return w
}

func (w *world) engine() *Engine {
	return NewEngine(Options{Trust: StaticTrust{Material: w.vs}, NameOptions: []name.Option{name.Insecure}})
}

func (w *world) repo(r string) name.Repository {
	repo, err := name.NewRepository(w.host+"/"+r, name.Insecure)
	if err != nil {
		w.t.Fatal(err)
	}
	return repo
}

// pushImage pushes a random single-platform image and returns its digest.
func (w *world) pushImage(r string) string {
	w.t.Helper()
	img, err := random.Image(256, 1)
	if err != nil {
		w.t.Fatal(err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
	ref := w.repo(r).Tag("latest")
	if err := remote.Write(ref, img); err != nil {
		w.t.Fatal(err)
	}
	d, _ := img.Digest()
	return d.String()
}

// pushIndex pushes a two-platform index, optionally with a BuildKit-style
// unsigned SBOM attestation manifest for the amd64 child. It returns the
// index digest and the amd64 child digest.
func (w *world) pushIndex(r string, buildkitSBOM bool) (string, string) {
	w.t.Helper()
	if buildkitSBOM {
		return w.pushIndexAtt(r, spdxType)
	}
	return w.pushIndexAtt(r, "")
}

// pushIndexAtt is pushIndex with a BuildKit attestation manifest whose
// layer has predicate type attPredicate ("" for no attestation manifest).
func (w *world) pushIndexAtt(r, attPredicate string) (string, string) {
	w.t.Helper()
	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	var amd64 string
	for _, arch := range []string{"amd64", "arm64"} {
		img, _ := random.Image(128, 1)
		img = mutate.MediaType(img, types.OCIManifestSchema1)
		img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
		d, _ := img.Digest()
		if arch == "amd64" {
			amd64 = d.String()
		}
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{
			Platform: &v1.Platform{OS: "linux", Architecture: arch},
		}})
	}
	if attPredicate != "" {
		att := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
		att = mutate.ConfigMediaType(att, types.OCIConfigJSON)
		layer := static.NewLayer([]byte(`{"_type":"https://in-toto.io/Statement/v0.1"}`), "application/vnd.in-toto+json")
		att, _ = mutate.Append(att, mutate.Addendum{Layer: layer, Annotations: map[string]string{
			"in-toto.io/predicate-type": attPredicate,
		}})
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: att, Descriptor: v1.Descriptor{
			Platform: &v1.Platform{OS: "unknown", Architecture: "unknown"},
			Annotations: map[string]string{
				"vnd.docker.reference.type":   "attestation-manifest",
				"vnd.docker.reference.digest": amd64,
			},
		}})
	}
	if err := remote.WriteIndex(w.repo(r).Tag("latest"), idx); err != nil {
		w.t.Fatal(err)
	}
	d, _ := idx.Digest()
	return d.String(), amd64
}

func statement(digest, predicateType string) []byte {
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "img", "digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")}}},
		"predicateType": predicateType,
		"predicate":     map[string]any{"spdxVersion": "SPDX-2.3"},
	}
	raw, _ := json.Marshal(st)
	return raw
}

// keylessDSSE returns a Sigstore bundle of a DSSE statement about digest,
// signed through the virtual Fulcio as san.
func (w *world) keylessDSSE(san, digest, predicateType string) []byte {
	w.t.Helper()
	ent, err := w.vs.Attest(san, ghIssuer, statement(digest, predicateType))
	if err != nil {
		w.t.Fatal(err)
	}
	vc, _ := ent.VerificationContent()
	sc, _ := ent.SignatureContent()
	entries, _ := ent.TlogEntries()
	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{X509CertificateChain: &protocommon.X509CertificateChain{
				Certificates: []*protocommon.X509Certificate{{RawBytes: vc.Certificate().Raw}},
			}},
			TlogEntries: []*protorekor.TransparencyLogEntry{w.withSET(entries[0])},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: toProtoEnvelope(w.t, sc.EnvelopeContent().RawEnvelope())},
	}
	return marshalBundle(w.t, pb)
}

// keyedDSSE returns a v0.3 bundle of a DSSE statement signed with the
// world's key and no transparency log entry (cosign v3 without Rekor).
func (w *world) keyedDSSE(digest, predicateType string, key *ecdsa.PrivateKey) []byte {
	w.t.Helper()
	signer, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	if err != nil {
		w.t.Fatal(err)
	}
	es, err := dsselib.NewEnvelopeSigner(&sigdsse.SignerAdapter{SignatureSigner: signer, Pub: key.Public().(*ecdsa.PublicKey)})
	if err != nil {
		w.t.Fatal(err)
	}
	env, err := es.SignPayload(context.Background(), "application/vnd.in-toto+json", statement(digest, predicateType))
	if err != nil {
		w.t.Fatal(err)
	}
	pb := &protobundle.Bundle{
		MediaType: bundleType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{PublicKey: &protocommon.PublicKeyIdentifier{Hint: "ci"}},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: toProtoEnvelope(w.t, env)},
	}
	return marshalBundle(w.t, pb)
}

func toProtoEnvelope(t testing.TB, env *dsselib.Envelope) *protodsse.Envelope {
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	out := &protodsse.Envelope{Payload: payload, PayloadType: env.PayloadType}
	for _, s := range env.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			t.Fatal(err)
		}
		out.Signatures = append(out.Signatures, &protodsse.Signature{Sig: sig, Keyid: s.KeyID})
	}
	return out
}

func marshalBundle(t testing.TB, pb *protobundle.Bundle) []byte {
	b, err := bundle.NewBundle(pb)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// attachBundle pushes a bundle as an OCI referrer of digest.
func (w *world) attachBundle(r, digest string, raw []byte) {
	w.t.Helper()
	repo := w.repo(r)
	subj, err := remote.Get(repo.Digest(digest))
	if err != nil {
		w.t.Fatal(err)
	}
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, bundleType)
	img, err = mutate.Append(img, mutate.Addendum{Layer: static.NewLayer(raw, bundleType)})
	if err != nil {
		w.t.Fatal(err)
	}
	img = mutate.Subject(img, subj.Descriptor).(v1.Image)
	d, _ := img.Digest()
	if err := remote.Write(repo.Digest(d.String()), img); err != nil {
		w.t.Fatal(err)
	}
}

// attachUnsignedSBOM pushes a plain SPDX document as a referrer.
func (w *world) attachUnsignedSBOM(r, digest string) {
	w.t.Helper()
	repo := w.repo(r)
	subj, _ := remote.Get(repo.Digest(digest))
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, "application/spdx+json")
	img, _ = mutate.Append(img, mutate.Addendum{Layer: static.NewLayer([]byte(`{}`), "application/spdx+json")})
	img = mutate.Subject(img, subj.Descriptor).(v1.Image)
	d, _ := img.Digest()
	if err := remote.Write(repo.Digest(d.String()), img); err != nil {
		w.t.Fatal(err)
	}
}

// legacyLayer is one layer of a cosign .sig or .att image.
type legacyLayer struct {
	mediaType   types.MediaType
	content     []byte
	annotations map[string]string
}

// pushLegacy writes layers to the cosign tag sha256-<hex><suffix>.
func (w *world) pushLegacy(r, digest, suffix string, layers ...legacyLayer) {
	w.t.Helper()
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
	for _, l := range layers {
		var err error
		img, err = mutate.Append(img, mutate.Addendum{Layer: static.NewLayer(l.content, l.mediaType), Annotations: l.annotations})
		if err != nil {
			w.t.Fatal(err)
		}
	}
	tag := w.repo(r).Tag(strings.Replace(digest, ":", "-", 1) + suffix)
	if err := remote.Write(tag, img); err != nil {
		w.t.Fatal(err)
	}
}

func simpleSigningPayload(repo, digest string) []byte {
	return []byte(fmt.Sprintf(`{"critical":{"identity":{"docker-reference":%q},"image":{"docker-manifest-digest":%q},"type":"cosign container image signature"},"optional":null}`, repo, digest))
}

// legacyKeyedSig is a cosign v2 `sign --key --tlog-upload=false` layer.
func (w *world) legacyKeyedSig(repo, digest string, key *ecdsa.PrivateKey) legacyLayer {
	payload := simpleSigningPayload(repo, digest)
	sum := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		w.t.Fatal(err)
	}
	return legacyLayer{mediaType: simpleSigningType, content: payload, annotations: map[string]string{
		annSignature: base64.StdEncoding.EncodeToString(sig),
	}}
}

// legacyKeylessSig is a cosign v2 keyless `sign` layer: certificate plus a
// Rekor bundle (signed entry timestamp) in annotations.
func (w *world) legacyKeylessSig(san, repo, digest string) legacyLayer {
	w.t.Helper()
	payload := simpleSigningPayload(repo, digest)
	ent, err := w.vs.Sign(san, ghIssuer, payload)
	if err != nil {
		w.t.Fatal(err)
	}
	vc, _ := ent.VerificationContent()
	sc, _ := ent.SignatureContent()
	entries, _ := ent.TlogEntries()
	tle := w.withSET(entries[0])
	rb := map[string]any{
		"SignedEntryTimestamp": tle.GetInclusionPromise().GetSignedEntryTimestamp(),
		"Payload": map[string]any{
			"body":           base64.StdEncoding.EncodeToString(tle.GetCanonicalizedBody()),
			"integratedTime": tle.GetIntegratedTime(),
			"logIndex":       tle.GetLogIndex(),
			"logID":          hex.EncodeToString(tle.GetLogId().GetKeyId()),
		},
	}
	rbRaw, _ := json.Marshal(rb)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: vc.Certificate().Raw})
	return legacyLayer{mediaType: simpleSigningType, content: payload, annotations: map[string]string{
		annSignature:   base64.StdEncoding.EncodeToString(sc.MessageSignatureContent().Signature()),
		annCertificate: string(certPEM),
		annRekorBundle: string(rbRaw),
	}}
}

// legacyKeyedAtt is a cosign v2 `attest --key --tlog-upload=false` layer.
func (w *world) legacyKeyedAtt(digest, predicateType string, key *ecdsa.PrivateKey) legacyLayer {
	w.t.Helper()
	signer, _ := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	es, _ := dsselib.NewEnvelopeSigner(&sigdsse.SignerAdapter{SignatureSigner: signer, Pub: key.Public().(*ecdsa.PublicKey)})
	env, err := es.SignPayload(context.Background(), "application/vnd.in-toto+json", statement(digest, predicateType))
	if err != nil {
		w.t.Fatal(err)
	}
	raw, _ := json.Marshal(env)
	return legacyLayer{mediaType: dsseLayerType, content: raw, annotations: map[string]string{
		annSignature: "", "predicateType": predicateType,
	}}
}

// withSET returns the entry as a bundle proto with kind/version and a
// signed entry timestamp from the virtual Rekor, as cosign stores it.
func (w *world) withSET(e *tlog.Entry) *protorekor.TransparencyLogEntry {
	w.t.Helper()
	tle := e.TransparencyLogEntry()
	set, err := w.vs.RekorSignPayload(tlog.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(tle.GetCanonicalizedBody()),
		IntegratedTime: tle.GetIntegratedTime(),
		LogIndex:       tle.GetLogIndex(),
		LogID:          hex.EncodeToString(tle.GetLogId().GetKeyId()),
	})
	if err != nil {
		w.t.Fatal(err)
	}
	var kv struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
	}
	if err := json.Unmarshal(tle.GetCanonicalizedBody(), &kv); err != nil {
		w.t.Fatal(err)
	}
	tle.KindVersion = &protorekor.KindVersion{Kind: kv.Kind, Version: kv.APIVersion}
	tle.InclusionPromise = &protorekor.InclusionPromise{SignedEntryTimestamp: set}
	return tle
}
