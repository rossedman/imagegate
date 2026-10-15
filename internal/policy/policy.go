// Package policy loads, validates and hashes the imagegate policy file.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// APIVersion is the only policy apiVersion this build understands.
const APIVersion = "imagegate.dev/v1"

// Mode controls whether verdicts are enforced or only logged.
type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeAudit   Mode = "audit"
)

// Known SBOM predicate types, used when a rule does not list its own.
var DefaultPredicateTypes = []string{
	"https://spdx.dev/Document",
	"https://cyclonedx.org/bom",
}

// Policy is the parsed form of /etc/imagegate/policy.yaml.
type Policy struct {
	APIVersion  string              `yaml:"apiVersion"`
	Mode        Mode                `yaml:"mode"`
	Defaults    Defaults            `yaml:"defaults"`
	Trust       Trust               `yaml:"trust"`
	Identities  map[string]Identity `yaml:"identities"`
	LocalImages string              `yaml:"localImages"`
	Rules       []Rule              `yaml:"rules"`

	// Hash is the SHA-256 of the canonicalized file. It is part of every
	// cache key, so a policy change invalidates old verdicts.
	Hash string `yaml:"-"`
}

type Defaults struct {
	// FailClosed denies creates when verification cannot complete
	// (registry down, timeout). Defaults to true.
	FailClosed    *bool    `yaml:"failClosed"`
	VerifyTimeout Duration `yaml:"verifyTimeout"`
	Cache         Cache    `yaml:"cache"`
	// HelpURL, when set, is printed in every denial as <HelpURL>#<REASON>.
	HelpURL string `yaml:"helpURL"`
}

type Cache struct {
	AllowTTL Duration `yaml:"allowTTL"`
	DenyTTL  Duration `yaml:"denyTTL"`
}

type Trust struct {
	// Sigstore is "public-good" or a path to a private trusted_root.json.
	Sigstore string `yaml:"sigstore"`
	// RequireSCT requires an embedded certificate transparency SCT on
	// keyless certificates. Defaults to true; private Sigstore stacks
	// without a CT log set it to false.
	RequireSCT *bool `yaml:"requireSCT"`
}

// Identity is either keyless (issuer + subject) or keyed (publicKey).
type Identity struct {
	Issuer        string `yaml:"issuer"`
	IssuerRegExp  string `yaml:"issuerRegExp"`
	Subject       string `yaml:"subject"`
	SubjectRegExp string `yaml:"subjectRegExp"`
	PublicKey     string `yaml:"publicKey"`
}

// Keyed reports whether the identity is a public key rather than a
// Fulcio certificate identity.
func (i Identity) Keyed() bool { return i.PublicKey != "" }

type Rule struct {
	Name      string        `yaml:"name"`
	Images    []string      `yaml:"images"`
	Signature SignatureRule `yaml:"signature"`
	SBOM      SBOMRule      `yaml:"sbom"`

	globs []glob
}

type SignatureRule struct {
	Identities []string `yaml:"identities"`
}

type SBOMRule struct {
	// Required defaults to true.
	Required       *bool    `yaml:"required"`
	Identities     []string `yaml:"identities"`
	PredicateTypes []string `yaml:"predicateTypes"`
}

// IsRequired reports whether the rule requires a signed SBOM attestation.
func (s SBOMRule) IsRequired() bool { return s.Required == nil || *s.Required }

// Load reads, validates and hashes the policy at path.
func Load(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Parse validates and hashes a policy document.
func Parse(raw []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	hash, err := canonicalHash(raw)
	if err != nil {
		return nil, err
	}
	p.Hash = hash
	p.applyDefaults()
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) applyDefaults() {
	if p.Mode == "" {
		p.Mode = ModeEnforce
	}
	if p.Defaults.FailClosed == nil {
		t := true
		p.Defaults.FailClosed = &t
	}
	if p.Defaults.VerifyTimeout == 0 {
		p.Defaults.VerifyTimeout = Duration(10 * time.Second)
	}
	if p.Defaults.Cache.AllowTTL == 0 {
		p.Defaults.Cache.AllowTTL = Duration(24 * time.Hour)
	}
	if p.Defaults.Cache.DenyTTL == 0 {
		p.Defaults.Cache.DenyTTL = Duration(60 * time.Second)
	}
	if p.Trust.Sigstore == "" {
		p.Trust.Sigstore = "public-good"
	}
	if p.Trust.RequireSCT == nil {
		t := true
		p.Trust.RequireSCT = &t
	}
	if p.LocalImages == "" {
		p.LocalImages = "deny"
	}
	for i := range p.Rules {
		if len(p.Rules[i].SBOM.PredicateTypes) == 0 {
			p.Rules[i].SBOM.PredicateTypes = DefaultPredicateTypes
		}
	}
}

func (p *Policy) validate() error {
	var errs []error
	if p.APIVersion != APIVersion {
		errs = append(errs, fmt.Errorf("apiVersion must be %q, got %q", APIVersion, p.APIVersion))
	}
	if p.Mode != ModeEnforce && p.Mode != ModeAudit {
		errs = append(errs, fmt.Errorf("mode must be enforce or audit, got %q", p.Mode))
	}
	if p.LocalImages != "deny" && p.LocalImages != "allow" {
		errs = append(errs, fmt.Errorf("localImages must be deny or allow, got %q", p.LocalImages))
	}
	if p.Defaults.VerifyTimeout < 0 || p.Defaults.Cache.AllowTTL < 0 || p.Defaults.Cache.DenyTTL < 0 {
		errs = append(errs, errors.New("defaults: durations must be positive"))
	}
	for name, id := range p.Identities {
		if err := id.validate(); err != nil {
			errs = append(errs, fmt.Errorf("identities.%s: %w", name, err))
		}
	}
	if len(p.Rules) == 0 {
		errs = append(errs, errors.New("rules: at least one rule is required"))
	}
	seen := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		where := fmt.Sprintf("rules[%d]", i)
		if r.Name == "" {
			errs = append(errs, fmt.Errorf("%s: name is required", where))
		} else {
			where = fmt.Sprintf("rules[%d] (%s)", i, r.Name)
			if seen[r.Name] {
				errs = append(errs, fmt.Errorf("%s: duplicate rule name", where))
			}
			seen[r.Name] = true
		}
		if len(r.Images) == 0 {
			errs = append(errs, fmt.Errorf("%s: images must list at least one glob", where))
		}
		r.globs = nil
		for _, pat := range r.Images {
			g, err := compileGlob(pat)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", where, err))
				continue
			}
			r.globs = append(r.globs, g)
		}
		if len(r.Signature.Identities) == 0 {
			errs = append(errs, fmt.Errorf("%s: signature.identities must list at least one identity", where))
		}
		errs = append(errs, p.checkRefs(where+": signature.identities", r.Signature.Identities)...)
		if r.SBOM.IsRequired() && len(r.SBOM.Identities) == 0 {
			errs = append(errs, fmt.Errorf("%s: sbom.identities is required when sbom.required is true", where))
		}
		errs = append(errs, p.checkRefs(where+": sbom.identities", r.SBOM.Identities)...)
	}
	return errors.Join(errs...)
}

func (p *Policy) checkRefs(where string, names []string) []error {
	var errs []error
	for _, n := range names {
		if _, ok := p.Identities[n]; !ok {
			errs = append(errs, fmt.Errorf("%s: unknown identity %q", where, n))
		}
	}
	return errs
}

func (i Identity) validate() error {
	keyless := i.Issuer != "" || i.IssuerRegExp != "" || i.Subject != "" || i.SubjectRegExp != ""
	switch {
	case i.Keyed() && keyless:
		return errors.New("set either publicKey or issuer/subject, not both")
	case i.Keyed():
		return nil
	case !keyless:
		return errors.New("set publicKey, or issuer (or issuerRegExp) and subject (or subjectRegExp)")
	}
	if (i.Issuer == "") == (i.IssuerRegExp == "") {
		return errors.New("set exactly one of issuer or issuerRegExp")
	}
	if (i.Subject == "") == (i.SubjectRegExp == "") {
		return errors.New("set exactly one of subject or subjectRegExp")
	}
	return nil
}

// FailClosed reports whether transient verification failures deny.
func (p *Policy) FailClosed() bool { return *p.Defaults.FailClosed }

// Match returns the first rule whose images glob matches the normalized
// repository (no tag or digest), or nil when no rule matches.
func (p *Policy) Match(repo string) *Rule {
	for i := range p.Rules {
		for _, g := range p.Rules[i].globs {
			if g.match(repo) {
				return &p.Rules[i]
			}
		}
	}
	return nil
}

// canonicalHash returns the SHA-256 of the document re-encoded as JSON with
// sorted keys, so formatting and comment changes do not change the hash.
func canonicalHash(raw []byte) (string, error) {
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("parse policy: %w", err)
	}
	canon, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("canonicalize policy: %w", err)
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// Duration is a time.Duration that unmarshals from strings like "10s".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }
