package verify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// Annotations cosign sets on legacy .sig and .att layers.
const (
	annSignature   = "dev.cosignproject.cosign/signature"
	annCertificate = "dev.sigstore.cosign/certificate"
	annChain       = "dev.sigstore.cosign/chain"
	annRekorBundle = "dev.sigstore.cosign/bundle"
	annRFC3161     = "dev.sigstore.cosign/rfc3161timestamp"
)

// rekorBundle is cosign's legacy "bundle" annotation: a Rekor entry plus its
// signed entry timestamp.
type rekorBundle struct {
	SignedEntryTimestamp []byte `json:"SignedEntryTimestamp"`
	Payload              struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
	} `json:"Payload"`
}

// legacyEntity converts a cosign .sig or .att layer into a Sigstore bundle
// so both layouts verify through the same sigstore-go path.
func legacyEntity(mediaType string, layer []byte, ann map[string]string) (entity, error) {
	pb := &protobundle.Bundle{VerificationMaterial: &protobundle.VerificationMaterial{}}
	var payload []byte

	switch mediaType {
	case simpleSigningType:
		sig, err := base64.StdEncoding.DecodeString(ann[annSignature])
		if err != nil || len(sig) == 0 {
			return entity{}, errors.New("missing or invalid signature annotation")
		}
		sum := sha256.Sum256(layer)
		pb.Content = &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{Algorithm: protocommon.HashAlgorithm_SHA2_256, Digest: sum[:]},
			Signature:     sig,
		}}
		payload = layer
	case dsseLayerType:
		var env struct {
			PayloadType string `json:"payloadType"`
			Payload     []byte `json:"payload"`
			Signatures  []struct {
				KeyID string `json:"keyid"`
				Sig   []byte `json:"sig"`
			} `json:"signatures"`
		}
		if err := json.Unmarshal(layer, &env); err != nil {
			return entity{}, fmt.Errorf("parse DSSE envelope: %w", err)
		}
		if len(env.Signatures) == 0 {
			return entity{}, errors.New("DSSE envelope has no signatures")
		}
		e := &protodsse.Envelope{Payload: env.Payload, PayloadType: env.PayloadType}
		for _, s := range env.Signatures {
			e.Signatures = append(e.Signatures, &protodsse.Signature{Sig: s.Sig, Keyid: s.KeyID})
		}
		pb.Content = &protobundle.Bundle_DsseEnvelope{DsseEnvelope: e}
	default:
		return entity{}, fmt.Errorf("unsupported layer type %s", mediaType)
	}

	// Verification material: a Fulcio certificate (keyless) or nothing,
	// in which case the policy's public keys are tried.
	if certPEM := ann[annCertificate]; certPEM != "" {
		chain := &protocommon.X509CertificateChain{}
		for _, p := range []string{certPEM, ann[annChain]} {
			rest := []byte(p)
			for {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}
				chain.Certificates = append(chain.Certificates, &protocommon.X509Certificate{RawBytes: block.Bytes})
			}
		}
		if len(chain.Certificates) == 0 {
			return entity{}, errors.New("invalid certificate annotation")
		}
		// The leaf alone: intermediates come from the trusted root.
		pb.VerificationMaterial.Content = &protobundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &protocommon.X509CertificateChain{Certificates: chain.Certificates[:1]},
		}
	} else {
		pb.VerificationMaterial.Content = &protobundle.VerificationMaterial_PublicKey{
			PublicKey: &protocommon.PublicKeyIdentifier{Hint: ""},
		}
	}

	if raw := ann[annRekorBundle]; raw != "" {
		var rb rekorBundle
		if err := json.Unmarshal([]byte(raw), &rb); err != nil {
			return entity{}, fmt.Errorf("parse rekor bundle: %w", err)
		}
		body, err := base64.StdEncoding.DecodeString(rb.Payload.Body)
		if err != nil {
			return entity{}, fmt.Errorf("decode rekor body: %w", err)
		}
		logID, err := hex.DecodeString(rb.Payload.LogID)
		if err != nil {
			return entity{}, fmt.Errorf("decode rekor log ID: %w", err)
		}
		var kv struct {
			Kind       string `json:"kind"`
			APIVersion string `json:"apiVersion"`
		}
		if err := json.Unmarshal(body, &kv); err != nil || kv.Kind == "" || kv.APIVersion == "" {
			return entity{}, errors.New("rekor body has no kind or apiVersion")
		}
		te := &protorekor.TransparencyLogEntry{
			LogIndex:          rb.Payload.LogIndex,
			LogId:             &protocommon.LogId{KeyId: logID},
			KindVersion:       &protorekor.KindVersion{Kind: kv.Kind, Version: kv.APIVersion},
			IntegratedTime:    rb.Payload.IntegratedTime,
			InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: rb.SignedEntryTimestamp},
			CanonicalizedBody: body,
		}
		pb.VerificationMaterial.TlogEntries = append(pb.VerificationMaterial.TlogEntries, te)
	}

	if raw := ann[annRFC3161]; raw != "" {
		var ts struct {
			SignedRFC3161Timestamp []byte `json:"SignedRFC3161Timestamp"`
		}
		if err := json.Unmarshal([]byte(raw), &ts); err == nil && len(ts.SignedRFC3161Timestamp) > 0 {
			pb.VerificationMaterial.TimestampVerificationData = &protobundle.TimestampVerificationData{
				Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{{SignedTimestamp: ts.SignedRFC3161Timestamp}},
			}
		}
	}

	// v0.1 is the bundle version that carries inclusion promises (SETs)
	// without inclusion proofs, which is what legacy cosign stores.
	mt, err := bundle.MediaTypeString("0.1")
	if err != nil {
		return entity{}, err
	}
	pb.MediaType = mt
	b, err := bundle.NewBundle(pb)
	if err != nil {
		return entity{}, err
	}
	return entity{bundle: b, payload: payload}, nil
}

// simpleSigning is the payload cosign signs for legacy image signatures.
type simpleSigning struct {
	Critical struct {
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

// checkSimpleSigning confirms a verified legacy payload names digest.
func checkSimpleSigning(payload []byte, digest string) error {
	var ss simpleSigning
	if err := json.Unmarshal(payload, &ss); err != nil {
		return fmt.Errorf("parse signed payload: %w", err)
	}
	if ss.Critical.Type != "cosign container image signature" {
		return fmt.Errorf("unexpected signed payload type %q", ss.Critical.Type)
	}
	if ss.Critical.Image.DockerManifestDigest != digest {
		return fmt.Errorf("signature is for %s, not %s", ss.Critical.Image.DockerManifestDigest, digest)
	}
	return nil
}
