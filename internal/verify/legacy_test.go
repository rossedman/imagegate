package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"maps"
	"math/big"
	"strings"
	"testing"
	"time"
)

// legacyFixtures are real cosign v2 layers built against a virtual
// Sigstore: keyed and keyless simplesigning signatures and a keyed DSSE
// attestation.
type legacyFixtures struct {
	digest  string
	keyed   legacyLayer
	keyless legacyLayer
	att     legacyLayer
}

func newLegacyFixtures(t testing.TB) (*world, legacyFixtures) {
	t.Helper()
	w := newWorld(t)
	d := "sha256:" + strings.Repeat("ab", 32)
	return w, legacyFixtures{
		digest:  d,
		keyed:   w.legacyKeyedSig(w.host+"/keyed/app", d, w.key),
		keyless: w.legacyKeylessSig(ciMainSAN, w.host+"/acme/app", d),
		att:     w.legacyKeyedAtt(d, spdxType, w.key),
	}
}

func with(ann map[string]string, kv ...string) map[string]string {
	out := maps.Clone(ann)
	if out == nil {
		out = map[string]string{}
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(out, kv[i])
			continue
		}
		out[kv[i]] = kv[i+1]
	}
	return out
}

func selfSignedPEM(t testing.TB, cn string) (string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), der
}

func rekorAnn(t testing.TB, body, logID string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"SignedEntryTimestamp": []byte("set"),
		"Payload": map[string]any{
			"body": body, "integratedTime": 1700000000, "logIndex": 7, "logID": logID,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestLegacyEntity(t *testing.T) {
	t.Parallel()
	_, fx := newLegacyFixtures(t)
	intermediatePEM, _ := selfSignedPEM(t, "intermediate")
	leafPEM, leafDER := selfSignedPEM(t, "leaf")
	// A real Rekor entry body from the virtual Rekor.
	var rb rekorBundle
	if err := json.Unmarshal([]byte(fx.keyless.annotations[annRekorBundle]), &rb); err != nil {
		t.Fatal(err)
	}
	goodBody := rb.Payload.Body
	logID := strings.Repeat("0a", 32)

	type check func(t *testing.T, e entity)
	keyedMaterial := func(t *testing.T, e entity) {
		if e.bundle.GetVerificationMaterial().GetPublicKey() == nil {
			t.Error("want public key verification material")
		}
	}
	cases := []struct {
		name      string
		mediaType string
		layer     []byte
		ann       map[string]string
		wantErr   string
		check     check
	}{
		{name: "unsupported media type", mediaType: "application/octet-stream", layer: fx.keyed.content, ann: fx.keyed.annotations, wantErr: "unsupported layer type"},
		{name: "empty media type", mediaType: "", layer: fx.keyed.content, ann: fx.keyed.annotations, wantErr: "unsupported layer type"},
		{name: "simplesigning without signature", mediaType: simpleSigningType, layer: fx.keyed.content, ann: nil, wantErr: "signature annotation"},
		{name: "simplesigning with empty signature", mediaType: simpleSigningType, layer: fx.keyed.content, ann: map[string]string{annSignature: ""}, wantErr: "signature annotation"},
		{name: "simplesigning with non-base64 signature", mediaType: simpleSigningType, layer: fx.keyed.content, ann: map[string]string{annSignature: "!!not base64!!"}, wantErr: "signature annotation"},
		{
			name: "keyed simplesigning", mediaType: simpleSigningType, layer: fx.keyed.content, ann: fx.keyed.annotations,
			check: func(t *testing.T, e entity) {
				if !bytes.Equal(e.payload, fx.keyed.content) {
					t.Error("payload is not the layer")
				}
				ms := e.bundle.GetMessageSignature()
				sum := sha256.Sum256(fx.keyed.content)
				if !bytes.Equal(ms.GetMessageDigest().GetDigest(), sum[:]) {
					t.Error("message digest is not sha256(layer)")
				}
				sig, _ := base64.StdEncoding.DecodeString(fx.keyed.annotations[annSignature])
				if !bytes.Equal(ms.GetSignature(), sig) {
					t.Error("signature is not the annotation")
				}
				keyedMaterial(t, e)
				if n := len(e.bundle.GetVerificationMaterial().GetTlogEntries()); n != 0 {
					t.Errorf("tlog entries = %d, want 0", n)
				}
			},
		},
		{name: "DSSE not JSON", mediaType: dsseLayerType, layer: []byte("{"), wantErr: "parse DSSE envelope"},
		{name: "DSSE without signatures", mediaType: dsseLayerType, layer: []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}`), wantErr: "no signatures"},
		{name: "DSSE with non-base64 payload", mediaType: dsseLayerType, layer: []byte(`{"payload":"!!","signatures":[{"sig":"AA=="}]}`), wantErr: "parse DSSE envelope"},
		{
			name: "keyed DSSE attestation", mediaType: dsseLayerType, layer: fx.att.content, ann: fx.att.annotations,
			check: func(t *testing.T, e entity) {
				if e.payload != nil {
					t.Error("DSSE entity must not carry a simplesigning payload")
				}
				env, err := e.bundle.Envelope()
				if err != nil {
					t.Fatal(err)
				}
				st, err := env.Statement()
				if err != nil || st.GetPredicateType() != spdxType {
					t.Errorf("statement = %v, %v", st, err)
				}
				keyedMaterial(t, e)
			},
		},
		{name: "certificate annotation without PEM", mediaType: simpleSigningType, layer: fx.keyless.content, ann: with(fx.keyless.annotations, annCertificate, "not pem"), wantErr: "invalid certificate annotation"},
		{
			name: "certificate with chain keeps only the leaf", mediaType: simpleSigningType, layer: fx.keyed.content,
			ann: with(fx.keyed.annotations, annCertificate, leafPEM, annChain, intermediatePEM),
			check: func(t *testing.T, e entity) {
				certs := e.bundle.GetVerificationMaterial().GetX509CertificateChain().GetCertificates()
				if len(certs) != 1 || !bytes.Equal(certs[0].GetRawBytes(), leafDER) {
					t.Errorf("chain = %d certs, want only the leaf", len(certs))
				}
			},
		},
		{
			name: "chain without certificate is ignored", mediaType: simpleSigningType, layer: fx.keyed.content,
			ann:   with(fx.keyed.annotations, annChain, intermediatePEM),
			check: keyedMaterial,
		},
		{name: "rekor bundle not JSON", mediaType: simpleSigningType, layer: fx.keyed.content, ann: with(fx.keyed.annotations, annRekorBundle, "{"), wantErr: "parse rekor bundle"},
		{name: "rekor body not base64", mediaType: simpleSigningType, layer: fx.keyed.content, ann: with(fx.keyed.annotations, annRekorBundle, rekorAnn(t, "!!", logID)), wantErr: "decode rekor body"},
		{name: "rekor log ID not hex", mediaType: simpleSigningType, layer: fx.keyed.content, ann: with(fx.keyed.annotations, annRekorBundle, rekorAnn(t, goodBody, "zz")), wantErr: "decode rekor log ID"},
		{name: "rekor body not JSON", mediaType: simpleSigningType, layer: fx.keyed.content, ann: with(fx.keyed.annotations, annRekorBundle, rekorAnn(t, base64.StdEncoding.EncodeToString([]byte("x")), logID)), wantErr: "no kind or apiVersion"},
		{name: "rekor body without kind", mediaType: simpleSigningType, layer: fx.keyed.content, ann: with(fx.keyed.annotations, annRekorBundle, rekorAnn(t, base64.StdEncoding.EncodeToString([]byte(`{"apiVersion":"0.0.1"}`)), logID)), wantErr: "no kind or apiVersion"},
		{name: "rekor body without apiVersion", mediaType: simpleSigningType, layer: fx.keyed.content, ann: with(fx.keyed.annotations, annRekorBundle, rekorAnn(t, base64.StdEncoding.EncodeToString([]byte(`{"kind":"hashedrekord"}`)), logID)), wantErr: "no kind or apiVersion"},
		{
			name: "keyed with rekor bundle", mediaType: simpleSigningType, layer: fx.keyed.content, ann: with(fx.keyed.annotations, annRekorBundle, rekorAnn(t, goodBody, logID)),
			check: func(t *testing.T, e entity) {
				tl := e.bundle.GetVerificationMaterial().GetTlogEntries()
				if len(tl) != 1 {
					t.Fatalf("tlog entries = %d, want 1", len(tl))
				}
				te := tl[0]
				if te.GetLogIndex() != 7 || te.GetIntegratedTime() != 1700000000 ||
					te.GetKindVersion().GetKind() != "hashedrekord" || te.GetKindVersion().GetVersion() == "" ||
					!bytes.Equal(te.GetInclusionPromise().GetSignedEntryTimestamp(), []byte("set")) ||
					len(te.GetLogId().GetKeyId()) != 32 {
					t.Errorf("tlog entry = %v", te)
				}
			},
		},
		{
			name: "keyless with certificate and rekor bundle", mediaType: simpleSigningType, layer: fx.keyless.content, ann: fx.keyless.annotations,
			check: func(t *testing.T, e entity) {
				vc, err := e.bundle.VerificationContent()
				if err != nil || vc.Certificate() == nil {
					t.Fatalf("verification content = %v, %v", vc, err)
				}
				if n := len(e.bundle.GetVerificationMaterial().GetTlogEntries()); n != 1 {
					t.Errorf("tlog entries = %d, want 1", n)
				}
			},
		},
		{
			name: "RFC 3161 timestamp", mediaType: simpleSigningType, layer: fx.keyed.content,
			ann: with(fx.keyed.annotations, annRFC3161, `{"SignedRFC3161Timestamp":"dHM="}`),
			check: func(t *testing.T, e entity) {
				ts := e.bundle.GetVerificationMaterial().GetTimestampVerificationData().GetRfc3161Timestamps()
				if len(ts) != 1 || string(ts[0].GetSignedTimestamp()) != "ts" {
					t.Errorf("timestamps = %v", ts)
				}
			},
		},
		{
			name: "malformed RFC 3161 annotation is ignored", mediaType: simpleSigningType, layer: fx.keyed.content,
			ann: with(fx.keyed.annotations, annRFC3161, `{"SignedRFC3161Timestamp":`),
			check: func(t *testing.T, e entity) {
				if e.bundle.GetVerificationMaterial().GetTimestampVerificationData() != nil {
					t.Error("malformed timestamp was kept")
				}
			},
		},
		{
			name: "empty RFC 3161 timestamp is ignored", mediaType: simpleSigningType, layer: fx.keyed.content,
			ann: with(fx.keyed.annotations, annRFC3161, `{"SignedRFC3161Timestamp":""}`),
			check: func(t *testing.T, e entity) {
				if e.bundle.GetVerificationMaterial().GetTimestampVerificationData() != nil {
					t.Error("empty timestamp was kept")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, err := legacyEntity(tc.mediaType, tc.layer, tc.ann)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				if e.bundle != nil || e.payload != nil {
					t.Error("error returned with a non-empty entity")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if e.bundle == nil {
				t.Fatal("nil bundle")
			}
			if !strings.Contains(e.bundle.GetMediaType(), "0.1") {
				t.Errorf("media type = %q, want a v0.1 bundle", e.bundle.GetMediaType())
			}
			tc.check(t, e)
		})
	}
}

func TestCheckSimpleSigning(t *testing.T) {
	t.Parallel()
	d := "sha256:" + strings.Repeat("ab", 32)
	other := "sha256:" + strings.Repeat("cd", 32)
	cases := []struct {
		name    string
		payload string
		digest  string
		wantErr string
	}{
		{name: "matches", payload: string(simpleSigningPayload("reg/app", d)), digest: d},
		{name: "other digest", payload: string(simpleSigningPayload("reg/app", other)), digest: d, wantErr: "signature is for " + other},
		{name: "empty digest in payload", payload: `{"critical":{"image":{},"type":"cosign container image signature"}}`, digest: d, wantErr: "not " + d},
		{name: "digest prefix only", payload: string(simpleSigningPayload("reg/app", d[:20])), digest: d, wantErr: "signature is for"},
		{name: "wrong type", payload: `{"critical":{"image":{"docker-manifest-digest":"` + d + `"},"type":"atomic container signature"}}`, digest: d, wantErr: "unexpected signed payload type"},
		{name: "missing type", payload: `{"critical":{"image":{"docker-manifest-digest":"` + d + `"}}}`, digest: d, wantErr: "unexpected signed payload type"},
		{name: "type with different case", payload: `{"critical":{"image":{"docker-manifest-digest":"` + d + `"},"type":"Cosign Container Image Signature"}}`, digest: d, wantErr: "unexpected signed payload type"},
		{name: "not JSON", payload: "nope", digest: d, wantErr: "parse signed payload"},
		{name: "empty", payload: "", digest: d, wantErr: "parse signed payload"},
		{name: "critical is not an object", payload: `{"critical":"x"}`, digest: d, wantErr: "parse signed payload"},
		{name: "digest is not a string", payload: `{"critical":{"image":{"docker-manifest-digest":1},"type":"cosign container image signature"}}`, digest: d, wantErr: "parse signed payload"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkSimpleSigning([]byte(tc.payload), tc.digest)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// FuzzLegacyEntity feeds attacker-controlled .sig/.att layers and
// annotations. Whatever is accepted must be exactly what was signed: the
// payload is the layer, the digest is its SHA-256, and the verification
// material comes only from the annotations given.
func FuzzLegacyEntity(f *testing.F) {
	_, fx := newLegacyFixtures(f)
	for _, l := range []legacyLayer{fx.keyed, fx.keyless, fx.att} {
		a := l.annotations
		f.Add(string(l.mediaType), l.content, a[annSignature], a[annCertificate], a[annChain], a[annRekorBundle], a[annRFC3161])
	}
	f.Add(simpleSigningType, fx.keyed.content, fx.keyed.annotations[annSignature], "", "", "", `{"SignedRFC3161Timestamp":"dHM="}`)
	f.Add("application/octet-stream", []byte("x"), "AA==", "", "", "", "")

	f.Fuzz(func(t *testing.T, mediaType string, layer []byte, sig, cert, chain, rekor, ts string) {
		ann := with(nil, annSignature, sig, annCertificate, cert, annChain, chain, annRekorBundle, rekor, annRFC3161, ts)
		e, err := legacyEntity(mediaType, layer, ann)
		if mediaType != simpleSigningType && mediaType != dsseLayerType {
			if err == nil {
				t.Fatalf("accepted media type %q", mediaType)
			}
			return
		}
		if err != nil {
			if e.bundle != nil || e.payload != nil {
				t.Fatal("error returned with a non-empty entity")
			}
			return
		}
		if e.bundle == nil || e.source != "" {
			t.Fatalf("bad entity %+v", e)
		}
		vm := e.bundle.GetVerificationMaterial()

		switch mediaType {
		case simpleSigningType:
			if !bytes.Equal(e.payload, layer) || (e.payload == nil) {
				t.Fatal("payload is not the layer")
			}
			ms := e.bundle.GetMessageSignature()
			sum := sha256.Sum256(layer)
			if !bytes.Equal(ms.GetMessageDigest().GetDigest(), sum[:]) {
				t.Fatal("message digest is not sha256(layer)")
			}
			want, derr := base64.StdEncoding.DecodeString(sig)
			if derr != nil || len(want) == 0 || !bytes.Equal(ms.GetSignature(), want) {
				t.Fatal("signature does not come from the annotation")
			}
		case dsseLayerType:
			if e.payload != nil {
				t.Fatal("DSSE entity carries a simplesigning payload")
			}
			if env := e.bundle.GetDsseEnvelope(); env == nil || len(env.GetSignatures()) == 0 {
				t.Fatal("DSSE entity without signatures")
			}
		}

		certs := vm.GetX509CertificateChain().GetCertificates()
		if cert == "" {
			if len(certs) != 0 || vm.GetPublicKey() == nil {
				t.Fatal("certificate material without a certificate annotation")
			}
		} else {
			// The leaf is the first PEM block of the certificate
			// annotation, or of the chain if the former has none.
			block, _ := pem.Decode([]byte(cert))
			if block == nil {
				block, _ = pem.Decode([]byte(chain))
			}
			if len(certs) != 1 || block == nil || !bytes.Equal(certs[0].GetRawBytes(), block.Bytes) {
				t.Fatalf("chain has %d certs, want exactly the leaf", len(certs))
			}
		}
		if n := len(vm.GetTlogEntries()); (rekor == "" && n != 0) || (rekor != "" && n != 1) {
			t.Fatalf("%d tlog entries for rekor annotation %q", n, rekor)
		}
	})
}

// FuzzCheckSimpleSigning asserts checkSimpleSigning accepts a signed
// payload only when it names exactly the digest being verified.
func FuzzCheckSimpleSigning(f *testing.F) {
	d := "sha256:" + strings.Repeat("ab", 32)
	other := "sha256:" + strings.Repeat("cd", 32)
	f.Add(simpleSigningPayload("reg/app", d), d, d, "cosign container image signature")
	f.Add(simpleSigningPayload("reg/app", other), d, other, "cosign container image signature")
	f.Add([]byte(`{"critical":{"image":{"docker-manifest-digest":""},"type":"cosign container image signature"}}`), "", "", "x")
	f.Add([]byte(`{"Critical":{"Image":{"Docker-Manifest-Digest":"`+d+`"},"TYPE":"cosign container image signature"}}`), d, d, "")
	f.Add([]byte(`{"critical":{"type":"cosign container image signature"},"critical":{"image":{"docker-manifest-digest":"`+d+`"}}}`), d, "", "")
	f.Add([]byte("null"), "", "", "")

	f.Fuzz(func(t *testing.T, payload []byte, digest, inDigest, typ string) {
		// Arbitrary bytes: accepted only if they decode (with the same
		// encoding/json semantics cosign uses) to the right type and
		// exactly this digest.
		if err := checkSimpleSigning(payload, digest); err == nil {
			var ss struct {
				Critical struct {
					Image struct {
						DockerManifestDigest string `json:"docker-manifest-digest"`
					} `json:"image"`
					Type string `json:"type"`
				} `json:"critical"`
			}
			if !json.Valid(payload) {
				t.Fatal("accepted invalid JSON")
			}
			if jerr := json.Unmarshal(payload, &ss); jerr != nil {
				t.Fatalf("accepted unparseable payload: %v", jerr)
			}
			if ss.Critical.Image.DockerManifestDigest != digest {
				t.Fatalf("accepted payload for %q when verifying %q", ss.Critical.Image.DockerManifestDigest, digest)
			}
			if ss.Critical.Type != "cosign container image signature" {
				t.Fatalf("accepted payload type %q", ss.Critical.Type)
			}
		}

		// A well-formed payload: accepted iff type and digest match.
		built, err := json.Marshal(map[string]any{
			"critical": map[string]any{
				"identity": map[string]string{"docker-reference": "reg/app"},
				"image":    map[string]string{"docker-manifest-digest": inDigest},
				"type":     typ,
			},
			"optional": nil,
		})
		if err != nil {
			t.Fatal(err)
		}
		want := inDigest == digest && typ == "cosign container image signature"
		if got := checkSimpleSigning(built, digest) == nil; got != want {
			t.Fatalf("checkSimpleSigning(digest %q, type %q) for %q = %v, want %v", inDigest, typ, digest, got, want)
		}
	})
}

func BenchmarkLegacyEntity(b *testing.B) {
	_, fx := newLegacyFixtures(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := legacyEntity(simpleSigningType, fx.keyless.content, fx.keyless.annotations); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckSimpleSigning(b *testing.B) {
	d := "sha256:" + strings.Repeat("ab", 32)
	payload := simpleSigningPayload("ghcr.io/acme/api", d)
	b.ReportAllocs()
	for b.Loop() {
		if err := checkSimpleSigning(payload, d); err != nil {
			b.Fatal(err)
		}
	}
}
