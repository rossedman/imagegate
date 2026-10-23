package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/sigstore-go/pkg/bundle"

	"github.com/rossedman/imagegate/internal/verdict"
)

// attachArtifact pushes a referrer of digest whose config media type (and
// so artifact type) is artifactType, with one layer per entry of layers.
// It returns the referrer manifest digest.
func (w *world) attachArtifact(r, digest, artifactType string, layers ...[]byte) string {
	w.t.Helper()
	subj, err := remote.Get(w.repo(r).Digest(digest))
	if err != nil {
		w.t.Fatal(err)
	}
	return pushArtifact(w.t, w.repo(r), subj.Descriptor, artifactType, layers...)
}

func pushArtifact(t testing.TB, repo name.Repository, subject v1.Descriptor, artifactType string, layers ...[]byte) string {
	t.Helper()
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.MediaType(artifactType))
	var err error
	for _, l := range layers {
		img, err = mutate.Append(img, mutate.Addendum{Layer: static.NewLayer(l, types.MediaType(artifactType))})
		if err != nil {
			t.Fatal(err)
		}
	}
	img = mutate.Subject(img, subject).(v1.Image)
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(repo.Digest(d.String()), img); err != nil {
		t.Fatal(err)
	}
	return d.String()
}

func transportErr(status int, codes ...transport.ErrorCode) error {
	te := &transport.Error{StatusCode: status}
	for _, c := range codes {
		te.Errors = append(te.Errors, transport.Diagnostic{Code: c})
	}
	return te
}

func TestErrorClassification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		err       error
		notFound  bool
		transient bool
	}{
		{name: "nil", err: nil},
		{name: "plain error", err: errors.New("boom")},
		{name: "404", err: transportErr(http.StatusNotFound), notFound: true},
		{name: "wrapped 404", err: fmt.Errorf("get: %w", transportErr(http.StatusNotFound)), notFound: true},
		{name: "MANIFEST_UNKNOWN on 400", err: transportErr(http.StatusBadRequest, transport.ManifestUnknownErrorCode), notFound: true},
		{name: "NAME_UNKNOWN", err: transportErr(http.StatusBadRequest, transport.NameUnknownErrorCode), notFound: true},
		{name: "BLOB_UNKNOWN", err: transportErr(http.StatusBadRequest, transport.BlobUnknownErrorCode), notFound: true},
		{name: "DENIED on 400 is neither", err: transportErr(http.StatusBadRequest, transport.DeniedErrorCode)},
		{name: "400", err: transportErr(http.StatusBadRequest)},
		{name: "406", err: transportErr(http.StatusNotAcceptable)},
		{name: "401", err: transportErr(http.StatusUnauthorized), transient: true},
		{name: "403", err: transportErr(http.StatusForbidden), transient: true},
		{name: "429", err: transportErr(http.StatusTooManyRequests), transient: true},
		{name: "500", err: transportErr(http.StatusInternalServerError), transient: true},
		{name: "503", err: transportErr(http.StatusServiceUnavailable), transient: true},
		{name: "499 is a client error", err: transportErr(499)},
		{name: "deadline", err: context.DeadlineExceeded, transient: true},
		{name: "wrapped canceled", err: fmt.Errorf("fetch: %w", context.Canceled), transient: true},
		{name: "net.OpError", err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("refused")}, transient: true},
		{name: "DNS error", err: &net.DNSError{Err: "no such host", Name: "reg.invalid"}, transient: true},
		{name: "url.Error", err: &url.Error{Op: "Get", URL: "https://reg.invalid", Err: errors.New("eof")}, transient: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isNotFound(tc.err); got != tc.notFound {
				t.Errorf("isNotFound = %v, want %v", got, tc.notFound)
			}
			if got := isTransient(tc.err); got != tc.transient {
				t.Errorf("isTransient = %v, want %v", got, tc.transient)
			}
			if tc.err == nil {
				return
			}
			want := verdict.NoSignature
			if tc.transient {
				want = verdict.UpstreamUnavailable
			}
			if got := registryFailure(tc.err); got.Reason != want {
				t.Errorf("registryFailure reason = %s, want %s", got.Reason, want)
			}
		})
	}
}

func TestRegistryFailureDetail(t *testing.T) {
	t.Parallel()
	got := registryFailure(transportErr(http.StatusUnauthorized))
	if !strings.HasPrefix(got.Detail, "registry: ") {
		t.Errorf("transient detail = %q", got.Detail)
	}
	got = registryFailure(errors.New("bad\nmanifest"))
	if got.Detail != "registry returned an invalid response: bad manifest" {
		t.Errorf("invalid detail = %q", got.Detail)
	}
}

func TestOneLine(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 301)
	cases := []struct {
		in, want string
	}{
		{"simple", "simple"},
		{"a\nb\nc", "a b c"},
		{strings.Repeat("y", 300), strings.Repeat("y", 300)},
		{long, strings.Repeat("x", 300) + "…"},
		{strings.Repeat("z\n", 200), strings.Repeat("z ", 150) + "…"},
	}
	for _, tc := range cases {
		if got := oneLine(errors.New(tc.in)); got != tc.want {
			t.Errorf("oneLine(%.20q...) = %.40q..., want %.40q... (len %d vs %d)", tc.in, got, tc.want, len(got), len(tc.want))
		}
	}
}

// fakeLayer overrides Compressed to inject read failures.
type fakeLayer struct {
	v1.Layer
	rc  io.ReadCloser
	err error
}

func (f fakeLayer) Compressed() (io.ReadCloser, error) { return f.rc, f.err }

type failingReader struct{ after []byte }

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.after) > 0 {
		n := copy(p, r.after)
		r.after = r.after[n:]
		return n, nil
	}
	return 0, errors.New("connection reset")
}

func TestReadLayer(t *testing.T) {
	t.Parallel()
	exact := bytes.Repeat([]byte{'a'}, maxBlob)
	cases := []struct {
		name    string
		layer   v1.Layer
		want    []byte
		wantErr string
	}{
		{name: "small", layer: static.NewLayer([]byte("hello"), types.OCILayer), want: []byte("hello")},
		{name: "empty", layer: static.NewLayer(nil, types.OCILayer), want: []byte{}},
		{name: "exactly maxBlob", layer: static.NewLayer(exact, types.OCILayer), want: exact},
		{name: "maxBlob+1", layer: static.NewLayer(append(exact, 'b'), types.OCILayer), wantErr: "blob too large"},
		{name: "open fails", layer: fakeLayer{err: errors.New("open failed")}, wantErr: "open failed"},
		{name: "read fails", layer: fakeLayer{rc: io.NopCloser(&failingReader{after: []byte("par")})}, wantErr: "connection reset"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := readLayer(tc.layer)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				if got != nil {
					t.Errorf("returned %d bytes alongside an error", len(got))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %d bytes, want %d", len(got), len(tc.want))
			}
		})
	}
}

func TestIsSBOMMediaType(t *testing.T) {
	t.Parallel()
	for mt, want := range map[string]bool{
		"application/spdx+json":                 true,
		"application/vnd.cyclonedx+json":        true,
		"Application/SPDX+JSON":                 true,
		"application/vnd.dev.sigstore.bundle":   false,
		"application/vnd.in-toto+json":          false,
		"":                                      false,
		"text/spdx":                             true,
		"application/vnd.syft+json":             false,
		"application/vnd.CycloneDX.BOM+xml":     true,
		"application/vnd.oci.image.manifest.v1": false,
	} {
		if got := isSBOMMediaType(mt); got != want {
			t.Errorf("isSBOMMediaType(%q) = %v, want %v", mt, got, want)
		}
	}
}

// TestFind checks what the registry layer collects for a digest: which
// referrers count, which are ignored, and the maxEntities bound.
func TestFind(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	reg := w.engine().reg

	cases := []struct {
		name         string
		setup        func(repo, d string)
		entities     int
		unsignedSBOM bool
	}{
		{
			name:  "nothing attached",
			setup: func(string, string) {},
		},
		{
			name: "valid bundle",
			setup: func(r, d string) {
				w.attachBundle(r, d, w.keyedDSSE(d, CosignSignPredicate, w.key))
			},
			entities: 1,
		},
		{
			name: "malformed, empty and foreign referrers are ignored",
			setup: func(r, d string) {
				w.attachArtifact(r, d, bundleType, []byte("not a bundle"))
				w.attachArtifact(r, d, bundleType)
				w.attachArtifact(r, d, "application/vnd.example+json", w.keyedDSSE(d, CosignSignPredicate, w.key))
				w.attachBundle(r, d, w.keyedDSSE(d, CosignSignPredicate, w.key))
			},
			entities: 1,
		},
		{
			name: "plain SPDX referrer marks an unsigned SBOM",
			setup: func(r, d string) {
				w.attachUnsignedSBOM(r, d)
			},
			unsignedSBOM: true,
		},
		{
			name: "CycloneDX referrer marks an unsigned SBOM",
			setup: func(r, d string) {
				w.attachArtifact(r, d, "application/vnd.cyclonedx+json", []byte(`{}`))
			},
			unsignedSBOM: true,
		},
		{
			name: "referrers are bounded",
			setup: func(r, d string) {
				for range maxEntities + 6 {
					w.attachBundle(r, d, w.keyedDSSE(d, CosignSignPredicate, w.key))
				}
			},
			entities: maxEntities,
		},
		{
			name: "legacy layers are bounded",
			setup: func(r, d string) {
				layers := make([]legacyLayer, maxEntities+6)
				for i := range layers {
					layers[i] = w.legacyKeyedSig(r, d, w.key)
					layers[i].content = append(layers[i].content, fmt.Sprintf(" %d", i)...)
				}
				w.pushLegacy(r, d, ".sig", layers...)
			},
			entities: maxEntities,
		},
		{
			name: "referrers and legacy share one bound",
			setup: func(r, d string) {
				for range maxEntities - 2 {
					w.attachBundle(r, d, w.keyedDSSE(d, CosignSignPredicate, w.key))
				}
				w.pushLegacy(r, d, ".sig", w.legacyKeyedSig(r, d, w.key), w.legacyKeyedSig(r, d, w.key), w.legacyKeyedSig(r, d, w.key))
				w.pushLegacy(r, d, ".att", w.legacyKeyedAtt(d, spdxType, w.key))
			},
			entities: maxEntities,
		},
		{
			name: "legacy .sig and .att both collected",
			setup: func(r, d string) {
				w.pushLegacy(r, d, ".sig", w.legacyKeyedSig(r, d, w.key))
				w.pushLegacy(r, d, ".att", w.legacyKeyedAtt(d, spdxType, w.key))
			},
			entities: 2,
		},
		{
			name: "legacy layers of other types or malformed are skipped",
			setup: func(r, d string) {
				bad := w.legacyKeyedSig(r, d, w.key)
				bad.annotations = nil
				w.pushLegacy(r, d, ".sig",
					legacyLayer{mediaType: "application/octet-stream", content: []byte("x")},
					bad,
					legacyLayer{mediaType: dsseLayerType, content: []byte("{not json")},
					w.legacyKeyedSig(r, d, w.key),
				)
			},
			entities: 1,
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := fmt.Sprintf("find/case%d", i)
			d := w.pushImage(r)
			tc.setup(r, d)
			f, err := reg.find(t.Context(), w.repo(r), d)
			if err != nil {
				t.Fatal(err)
			}
			if len(f.entities) != tc.entities {
				t.Errorf("entities = %d, want %d", len(f.entities), tc.entities)
			}
			if f.unsignedSBOM != tc.unsignedSBOM {
				t.Errorf("unsignedSBOM = %v, want %v", f.unsignedSBOM, tc.unsignedSBOM)
			}
			for _, e := range f.entities {
				if e.bundle == nil || e.source == "" {
					t.Errorf("incomplete entity %+v", e)
				}
			}
		})
	}
}

func TestBundleFromManifest(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	reg := w.engine().reg
	r := "bfm/app"
	d := w.pushImage(r)
	valid := w.keyedDSSE(d, CosignSignPredicate, w.key)

	cases := []struct {
		name    string
		digest  string
		ok      bool
		wantErr string
	}{
		{name: "valid", digest: w.attachArtifact(r, d, bundleType, valid), ok: true},
		{name: "first layer is used", digest: w.attachArtifact(r, d, bundleType, valid, []byte("ignored")), ok: true},
		{name: "no layers", digest: w.attachArtifact(r, d, bundleType), wantErr: "no layers"},
		{name: "not JSON", digest: w.attachArtifact(r, d, bundleType, []byte("garbage"))},
		{name: "JSON but not a bundle", digest: w.attachArtifact(r, d, bundleType, []byte(`{"mediaType":"x"}`))},
		{name: "oversized bundle", digest: w.attachArtifact(r, d, bundleType, bytes.Repeat([]byte{' '}, maxBlob+1)), wantErr: "blob too large"},
		{name: "missing manifest", digest: "sha256:" + strings.Repeat("cd", 32)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, err := reg.bundleFromManifest(t.Context(), w.repo(r), tc.digest)
			if tc.ok {
				if err != nil || b == nil {
					t.Fatalf("bundle = %v, err = %v", b, err)
				}
				if _, err := b.Envelope(); err != nil {
					t.Errorf("envelope: %v", err)
				}
				return
			}
			if err == nil || b != nil {
				t.Fatalf("bundle = %v, err = %v; want an error", b, err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestRegistryFaults checks error classification end to end: network-like
// failures mean UPSTREAM_UNAVAILABLE (subject to failClosed), malformed or
// rejected responses deny, and an unreadable signature is skipped like an
// invalid one. Status codes go-containerregistry retries (500, 502-504,
// 429) are avoided to keep the test fast; isTransient covers them.
func TestRegistryFaults(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	p := testPolicy(t, w, "")

	type fixture struct{ repo, digest string }
	signed := func(r string) fixture {
		d := w.pushImage(r)
		w.attachBundle(r, d, w.keylessDSSE(ciMainSAN, d, CosignSignPredicate))
		w.attachBundle(r, d, w.keylessDSSE(ciMainSAN, d, spdxType))
		return fixture{r, d}
	}
	legacy := func(r string) fixture {
		d := w.pushImage(r)
		w.pushLegacy(r, d, ".sig", w.legacyKeyedSig(w.host+"/"+r, d, w.key))
		return fixture{r, d}
	}
	buildkit := func(r string) fixture {
		d, _ := w.pushIndex(r, true)
		w.attachBundle(r, d, w.keylessDSSE(ciMainSAN, d, CosignSignPredicate))
		return fixture{r, d}
	}

	cases := []struct {
		name   string
		fx     fixture
		fault  func(f fixture, r *http.Request) int
		want   verdict.Reason
		detail string
	}{
		{
			name: "no fault",
			fx:   signed("acme/fault-none"),
			want: verdict.Allowed,
		},
		{
			name: "subject manifest 501",
			fx:   signed("acme/fault-subject501"),
			fault: func(f fixture, r *http.Request) int {
				return when(strings.HasSuffix(r.URL.Path, "/manifests/"+f.digest), http.StatusNotImplemented)
			},
			want: verdict.UpstreamUnavailable, detail: "registry: ",
		},
		{
			name: "subject manifest 400",
			fx:   signed("acme/fault-subject400"),
			fault: func(f fixture, r *http.Request) int {
				return when(strings.HasSuffix(r.URL.Path, "/manifests/"+f.digest), http.StatusBadRequest)
			},
			want: verdict.NoSignature, detail: "invalid response",
		},
		{
			name: "registry requires credentials",
			fx:   signed("acme/fault-401"),
			fault: func(fixture, *http.Request) int {
				return http.StatusUnauthorized
			},
			want: verdict.UpstreamUnavailable,
		},
		{
			name: "referrers 403",
			fx:   signed("acme/fault-ref403"),
			fault: func(_ fixture, r *http.Request) int {
				return when(strings.Contains(r.URL.Path, "/referrers/"), http.StatusForbidden)
			},
			want: verdict.UpstreamUnavailable,
		},
		{
			name: "referrers 505",
			fx:   signed("acme/fault-ref505"),
			fault: func(_ fixture, r *http.Request) int {
				return when(strings.Contains(r.URL.Path, "/referrers/"), http.StatusHTTPVersionNotSupported)
			},
			want: verdict.UpstreamUnavailable,
		},
		{
			name: "bundle manifest 501",
			fx:   signed("acme/fault-bundle501"),
			fault: func(f fixture, r *http.Request) int {
				return when(isManifestOtherThan(r, f.digest), http.StatusNotImplemented)
			},
			want: verdict.UpstreamUnavailable,
		},
		{
			name: "bundle manifests gone are skipped like invalid signatures",
			fx:   signed("acme/fault-bundle404"),
			fault: func(f fixture, r *http.Request) int {
				return when(isManifestOtherThan(r, f.digest), http.StatusNotFound)
			},
			want: verdict.NoSignature, detail: "no cosign signature found",
		},
		{
			name: "bundle blob 501",
			fx:   signed("acme/fault-blob501"),
			fault: func(_ fixture, r *http.Request) int {
				return when(strings.Contains(r.URL.Path, "/blobs/"), http.StatusNotImplemented)
			},
			want: verdict.UpstreamUnavailable,
		},
		{
			name: "legacy .sig tag 401",
			fx:   legacy("keyed/fault-sig401"),
			fault: func(_ fixture, r *http.Request) int {
				return when(strings.HasSuffix(r.URL.Path, ".sig"), http.StatusUnauthorized)
			},
			want: verdict.UpstreamUnavailable,
		},
		{
			name: "legacy .att tag 400",
			fx:   legacy("keyed/fault-att400"),
			fault: func(_ fixture, r *http.Request) int {
				return when(strings.HasSuffix(r.URL.Path, ".att"), http.StatusBadRequest)
			},
			want: verdict.NoSignature, detail: "invalid response",
		},
		{
			name: "legacy layer blob 501",
			fx:   legacy("keyed/fault-lblob501"),
			fault: func(_ fixture, r *http.Request) int {
				return when(strings.Contains(r.URL.Path, "/blobs/"), http.StatusNotImplemented)
			},
			want: verdict.UpstreamUnavailable,
		},
		{
			name: "legacy layer blob 400 is skipped",
			fx:   legacy("keyed/fault-lblob400"),
			fault: func(_ fixture, r *http.Request) int {
				return when(strings.Contains(r.URL.Path, "/blobs/"), http.StatusBadRequest)
			},
			want: verdict.NoSignature, detail: "no cosign signature found",
		},
		{
			name: "BuildKit attestation manifest 501",
			fx:   buildkit("acme/fault-bk501"),
			fault: func(f fixture, r *http.Request) int {
				// The index itself and the referrers succeed; the
				// attestation child manifest fails.
				return when(isManifestOtherThan(r, f.digest), http.StatusNotImplemented)
			},
			want: verdict.UpstreamUnavailable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Not parallel: the fault injector is shared by the world.
			if tc.fault != nil {
				fx := tc.fx
				w.setFault(func(r *http.Request) int { return tc.fault(fx, r) })
				defer w.setFault(nil)
			}
			got := run(t, w, p, tc.fx.repo, tc.fx.digest)
			if got.Reason != tc.want {
				t.Fatalf("reason = %s (%s), want %s", got.Reason, got.Detail, tc.want)
			}
			if !strings.Contains(got.Detail, tc.detail) {
				t.Errorf("detail = %q, want it to contain %q", got.Detail, tc.detail)
			}
		})
	}
}

func when(cond bool, status int) int {
	if cond {
		return status
	}
	return 0
}

func isManifestOtherThan(r *http.Request, digest string) bool {
	return strings.Contains(r.URL.Path, "/manifests/") && !strings.HasSuffix(r.URL.Path, "/manifests/"+digest)
}

// FuzzBundleFromManifest pushes an attacker-chosen bundle blob to the
// in-process registry and reads it back: the result must be exactly what
// sigstore-go makes of the blob, and nothing over maxBlob is parsed.
func FuzzBundleFromManifest(f *testing.F) {
	w := newWorld(f)
	reg := w.engine().reg
	r := "fuzz/bundle"
	d := w.pushImage(r)
	f.Add(w.keyedDSSE(d, CosignSignPredicate, w.key))
	f.Add(w.keylessDSSE(ciMainSAN, d, spdxType))
	f.Add([]byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte("garbage"))

	repo := w.repo(r)
	subj, err := remote.Get(repo.Digest(d))
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		ref := pushArtifact(t, repo, subj.Descriptor, bundleType, raw)
		got, err := reg.bundleFromManifest(t.Context(), repo, ref)

		var want bundle.Bundle
		wantErr := want.UnmarshalJSON(raw)
		if (err == nil) != (wantErr == nil) {
			t.Fatalf("bundleFromManifest err = %v, direct parse err = %v", err, wantErr)
		}
		if err != nil {
			if got != nil {
				t.Fatal("bundle returned alongside an error")
			}
			if isTransient(err) {
				t.Fatalf("malformed bundle classified as transient: %v", err)
			}
			return
		}
		if got == nil {
			t.Fatal("nil bundle without an error")
		}
		a, aerr := got.MarshalJSON()
		b, berr := want.MarshalJSON()
		if aerr != nil || berr != nil || !bytes.Equal(a, b) {
			t.Fatalf("bundle differs from the blob: %v %v", aerr, berr)
		}
	})
}
