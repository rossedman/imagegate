// Package gate decides whether a container create or start may proceed.
package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/sync/singleflight"

	"github.com/rossedman/image-gate/internal/audit"
	"github.com/rossedman/image-gate/internal/cache"
	"github.com/rossedman/image-gate/internal/docker"
	"github.com/rossedman/image-gate/internal/imageref"
	"github.com/rossedman/image-gate/internal/metrics"
	"github.com/rossedman/image-gate/internal/policy"
	"github.com/rossedman/image-gate/internal/verdict"
	"github.com/rossedman/image-gate/internal/verify"
)

// Docker is the subset of the dockerd API the gate uses.
type Docker interface {
	InspectImage(ctx context.Context, ref string) (*docker.Image, error)
	InspectContainer(ctx context.Context, id string) (*docker.Container, error)
}

// Verifier checks one image against one rule.
type Verifier interface {
	Verify(ctx context.Context, t verify.Target, rule *policy.Rule) verify.Result
}

// Compiler binds a verifier to a policy's identities.
type Compiler func(*policy.Policy) (Verifier, error)

// Resolver resolves a registry reference to a digest, for `imagegate warm`.
type Resolver interface {
	ResolveDigest(ctx context.Context, ref imageref.Ref) (string, error)
}

// Config wires a Gate.
type Config struct {
	PolicyPath   string
	OverridesDir string
	Docker       Docker
	Compile      Compiler
	Resolver     Resolver
	Cache        *cache.Cache
	Audit        *audit.Logger
	Metrics      *metrics.Metrics
	Log          *slog.Logger
	Now          func() time.Time
}

// Decision is the answer returned to dockerd.
type Decision struct {
	Allow bool
	Msg   string
}

type state struct {
	policy   *policy.Policy
	verifier Verifier
}

// Gate is safe for concurrent use.
type Gate struct {
	cfg       Config
	state     atomic.Pointer[state]
	overrides atomic.Pointer[policy.Overrides]
	sf        singleflight.Group
}

func New(cfg Config) *Gate {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Gate{cfg: cfg}
}

// Policy returns the active policy, or nil when none has loaded.
func (g *Gate) Policy() *policy.Policy {
	if st := g.state.Load(); st != nil {
		return st.policy
	}
	return nil
}

// ReloadPolicy loads and validates the policy file. An invalid file is
// rejected and the last good policy stays active.
func (g *Gate) ReloadPolicy() error {
	p, err := policy.Load(g.cfg.PolicyPath)
	var v Verifier
	if err == nil {
		v, err = g.cfg.Compile(p)
	}
	if err != nil {
		g.cfg.Metrics.PolicyReloadErrors.Inc()
		if g.state.Load() == nil {
			g.cfg.Log.Error("no valid policy; denying all container creates", "path", g.cfg.PolicyPath, "err", err)
		} else {
			g.cfg.Log.Error("policy rejected; keeping last good policy", "path", g.cfg.PolicyPath, "err", err)
		}
		return err
	}
	g.state.Store(&state{policy: p, verifier: v})
	g.cfg.Log.Info("policy loaded", "path", g.cfg.PolicyPath, "mode", p.Mode, "rules", len(p.Rules), "policyHash", p.Hash)
	return nil
}

// ReloadOverrides re-reads the break-glass directory.
func (g *Gate) ReloadOverrides() {
	ov, err := policy.LoadOverrides(g.cfg.OverridesDir, g.cfg.Now())
	if err != nil {
		g.cfg.Log.Error("invalid break-glass override entries were ignored", "dir", g.cfg.OverridesDir, "err", err)
	}
	g.overrides.Store(ov)
	g.cfg.Metrics.OverridesActive.Set(float64(ov.Active(g.cfg.Now())))
}

// input is one image to evaluate.
type input struct {
	endpoint string
	user     string
	image    string // as the client wrote it, for the audit record
	repo     string
	digest   string
	platform *v1.Platform
	start    time.Time
}

// Create gates POST /containers/create.
func (g *Gate) Create(ctx context.Context, user string, body []byte, query url.Values) Decision {
	const endpoint = "containers/create"
	t0 := time.Now()
	st := g.state.Load()
	if st == nil {
		return g.noPolicy(endpoint, user)
	}
	var req struct {
		Image string `json:"Image"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Image == "" {
		detail := "request body has no Image"
		if err != nil {
			detail = "malformed request body"
		}
		return g.early(st, input{endpoint: endpoint, user: user, start: t0}, verdict.BadRequest, detail)
	}
	in := input{endpoint: endpoint, user: user, image: req.Image, start: t0}
	if _, err := imageref.Parse(req.Image); err != nil && !imageref.LooksLikeID(req.Image) {
		return g.early(st, in, verdict.BadRequest, "invalid image reference")
	}
	platform, err := parsePlatform(query.Get("platform"))
	if err != nil {
		return g.early(st, in, verdict.BadRequest, err.Error())
	}

	img, err := g.cfg.Docker.InspectImage(ctx, req.Image)
	if errors.Is(err, docker.ErrNotFound) {
		// The image is not present yet. dockerd will answer "No such
		// image" and `docker run` will pull and retry the create,
		// which is checked then. If the image appears in between, the
		// re-check at start catches it.
		g.cfg.Log.Debug("image not present; letting dockerd answer", "image", req.Image)
		return Decision{Allow: true}
	}
	if err != nil {
		g.cfg.Metrics.UpstreamErrors.WithLabelValues("dockerd").Inc()
		return g.early(st, in, verdict.UpstreamUnavailable, "inspect image: "+err.Error())
	}
	if platform == nil {
		platform = &v1.Platform{OS: img.Os, Architecture: img.Architecture, Variant: img.Variant}
	}
	in.platform = platform
	return g.resolved(ctx, st, in, req.Image, img, true)
}

// Start gates POST /containers/{id}/start (and restart): the container's
// actual image ID is re-checked, closing the gap where a tag moved between
// create and the daemon resolving it, and covering containers created
// before imagegate was installed.
func (g *Gate) Start(ctx context.Context, user, endpoint, containerID string) Decision {
	t0 := time.Now()
	st := g.state.Load()
	if st == nil {
		return g.noPolicy(endpoint, user)
	}
	ct, err := g.cfg.Docker.InspectContainer(ctx, containerID)
	in := input{endpoint: endpoint, user: user, image: containerID, start: t0}
	if errors.Is(err, docker.ErrNotFound) {
		// Fail closed: a container dockerd is about to start must exist.
		// Not finding it means imagegate is asking the wrong daemon
		// (-docker-socket), and allowing would bypass every check.
		return g.early(st, in, verdict.BadRequest, "container not found via imagegate's dockerd socket; check -docker-socket")
	}
	if err != nil {
		g.cfg.Metrics.UpstreamErrors.WithLabelValues("dockerd").Inc()
		return g.early(st, in, verdict.UpstreamUnavailable, "inspect container: "+err.Error())
	}
	in.image = ct.Config.Image
	if m, ok := g.cfg.Cache.GetImage(ct.Image); ok {
		in.repo, in.digest = m.Repo, m.Digest
		return g.evaluate(ctx, st, in)
	}
	img, err := g.cfg.Docker.InspectImage(ctx, ct.Image)
	if errors.Is(err, docker.ErrNotFound) {
		return g.local(st, in)
	}
	if err != nil {
		g.cfg.Metrics.UpstreamErrors.WithLabelValues("dockerd").Inc()
		return g.early(st, in, verdict.UpstreamUnavailable, "inspect image: "+err.Error())
	}
	in.platform = &v1.Platform{OS: img.Os, Architecture: img.Architecture, Variant: img.Variant}
	return g.resolved(ctx, st, in, ct.Config.Image, img, false)
}

// resolved picks the registry digest for img and evaluates it.
func (g *Gate) resolved(ctx context.Context, st *state, in input, ref string, img *docker.Image, trustPinned bool) Decision {
	repo, digest, ok := pickDigest(ref, img, trustPinned)
	if !ok {
		return g.local(st, in)
	}
	in.repo, in.digest = repo, digest
	if err := g.cfg.Cache.PutImage(img.ID, cache.ImageDigest{Repo: repo, Digest: digest}); err != nil {
		g.cfg.Log.Warn("cache image mapping", "err", err)
	}
	return g.evaluate(ctx, st, in)
}

// pickDigest resolves the digest to verify. A reference that pins
// @sha256: uses that digest (at create; at start the image's own digests
// are used). Otherwise use the RepoDigests entry for the same repository.
// An image ID reference may use any RepoDigests entry.
func pickDigest(ref string, img *docker.Image, trustPinned bool) (repo, digest string, ok bool) {
	r, err := imageref.Parse(ref)
	if err == nil {
		if r.Digest != "" && trustPinned {
			return r.Repo, r.Digest, true
		}
		var sameRepo []string
		for _, rd := range img.RepoDigests {
			rr, d, err := imageref.SplitRepoDigest(rd)
			if err == nil && rr == r.Repo {
				if d == r.Digest {
					return rr, d, true
				}
				sameRepo = append(sameRepo, d)
			}
		}
		if len(sameRepo) > 0 {
			return r.Repo, sameRepo[0], true
		}
	}
	if imageref.LooksLikeID(ref) && strings.HasPrefix(strings.TrimPrefix(img.ID, "sha256:"), strings.TrimPrefix(ref, "sha256:")) {
		for _, rd := range img.RepoDigests {
			if rr, d, err := imageref.SplitRepoDigest(rd); err == nil {
				return rr, d, true
			}
		}
	}
	return "", "", false
}

// local applies the localImages rule to images with no registry digest
// (docker load, docker commit, local builds).
func (g *Gate) local(st *state, in input) Decision {
	if st.policy.LocalImages == "allow" {
		return g.finish(st, in, verdict.Verdict{Allow: true, Reason: verdict.LocalImage, Detail: "local image allowed by localImages: allow"}, "")
	}
	return g.early(st, in, verdict.LocalImage, "image has no registry digest (built, loaded or committed locally)")
}

// evaluate applies overrides, the cache and the matching rule.
func (g *Gate) evaluate(ctx context.Context, st *state, in input) Decision {
	d, _ := g.evaluateVerdict(ctx, st, in)
	return d
}

func (g *Gate) evaluateVerdict(ctx context.Context, st *state, in input) (Decision, verdict.Verdict) {
	now := g.cfg.Now()
	if ov, ok := g.overrides.Load().Lookup(in.digest, now); ok {
		g.cfg.Log.Warn("break-glass override used", "digest", in.digest, "image", in.image,
			"ticket", ov.Ticket, "expires", ov.Expires, "file", ov.File, "reason", ov.Reason)
		v := verdict.Verdict{Allow: true, Reason: verdict.Override, Detail: ov.Reason}
		return g.finishOverride(st, in, v, ov), v
	}

	key := cache.Key{Repo: in.repo, Digest: in.digest, PolicyHash: st.policy.Hash}
	if v, ok := g.cfg.Cache.Get(key); ok {
		g.cfg.Metrics.CacheRequests.WithLabelValues("hit").Inc()
		return g.finish(st, in, v, "hit"), v
	}
	g.cfg.Metrics.CacheRequests.WithLabelValues("miss").Inc()

	rule := st.policy.Match(in.repo)
	if rule == nil {
		v := verdict.Verdict{Reason: verdict.NoRule, Detail: fmt.Sprintf("no policy rule matches %s", in.repo)}
		return g.finish(st, in, v, "miss"), v
	}
	v := g.verifyShared(st, key, verify.Target{Repo: in.repo, Digest: in.digest, Platform: in.platform}, rule)
	return g.finish(st, in, v, "miss"), v
}

// verifyShared runs one verification per key no matter how many requests
// ask for it concurrently.
func (g *Gate) verifyShared(st *state, key cache.Key, t verify.Target, rule *policy.Rule) verdict.Verdict {
	ch := g.sf.DoChan(key.String(), func() (any, error) {
		// Not tied to any one request: the result is shared and cached.
		ctx, cancel := context.WithTimeout(context.Background(), st.policy.Defaults.VerifyTimeout.D())
		defer cancel()
		res := st.verifier.Verify(ctx, t, rule)
		for stage, d := range res.Stages {
			g.cfg.Metrics.VerifyDuration.WithLabelValues(stage).Observe(d.Seconds())
		}
		v := verdict.Verdict{
			Allow:  res.Reason == verdict.Allowed || res.Reason == verdict.LocalImage && st.policy.LocalImages == "allow",
			Reason: res.Reason,
			Rule:   rule.Name,
			Signer: res.Signer,
			Detail: res.Detail,
		}
		if res.Reason.Transient() {
			target := "registry"
			if strings.Contains(res.Detail, "trusted root") {
				target = "tuf"
			}
			g.cfg.Metrics.UpstreamErrors.WithLabelValues(target).Inc()
			return v, nil
		}
		ttl := st.policy.Defaults.Cache.DenyTTL.D()
		if res.Reason == verdict.Allowed {
			ttl = st.policy.Defaults.Cache.AllowTTL.D()
		}
		v.ExpiresAt = g.cfg.Now().Add(ttl)
		if err := g.cfg.Cache.Put(key, v); err != nil {
			g.cfg.Log.Warn("cache verdict", "err", err)
		}
		return v, nil
	})
	r := <-ch
	return r.Val.(verdict.Verdict)
}

// early records a verdict reached before verification.
func (g *Gate) early(st *state, in input, r verdict.Reason, detail string) Decision {
	return g.finish(st, in, verdict.Verdict{Reason: r, Detail: detail}, "")
}

func (g *Gate) noPolicy(endpoint, user string) Decision {
	v := verdict.Verdict{Reason: verdict.NoPolicy, Detail: "no valid policy is loaded"}
	g.cfg.Metrics.Decisions.WithLabelValues("deny", string(v.Reason), "", string(policy.ModeEnforce)).Inc()
	g.cfg.Audit.Log(audit.Record{
		Decision: "deny", Mode: string(policy.ModeEnforce), Reason: string(v.Reason),
		Endpoint: endpoint, User: user, Enforced: true, Detail: v.Detail,
	})
	return Decision{Msg: verdict.Message("container", v.Reason, v.Detail, "")}
}

func (g *Gate) finishOverride(st *state, in input, v verdict.Verdict, ov policy.Override) Decision {
	return g.record(st, in, v, "", func(r *audit.Record) {
		r.Ticket = ov.Ticket
		r.Severity = "high"
	})
}

func (g *Gate) finish(st *state, in input, v verdict.Verdict, cacheResult string) Decision {
	return g.record(st, in, v, cacheResult, nil)
}

// record turns a verdict into a decision: audit mode and failClosed: false
// downgrade denials to logged-only. Every decision is audited and counted.
func (g *Gate) record(st *state, in input, v verdict.Verdict, cacheResult string, extra func(*audit.Record)) Decision {
	p := st.policy
	enforced := true
	if !v.Allow && v.Reason.Transient() && !p.FailClosed() {
		enforced = false
	}
	if !v.Allow && p.Mode == policy.ModeAudit {
		enforced = false
	}
	decision := "allow"
	if !v.Allow {
		decision = "deny"
	}
	rec := audit.Record{
		Decision: decision, Mode: string(p.Mode), Reason: string(v.Reason),
		Image: in.image, Digest: in.digest, Rule: v.Rule, Signer: v.Signer, Cache: cacheResult,
		LatencyMs: latencyMs(in.start), Endpoint: in.endpoint, User: in.user, PolicyHash: p.Hash,
		Enforced: v.Allow || enforced, Detail: v.Detail,
	}
	if extra != nil {
		extra(&rec)
	}
	g.cfg.Metrics.Decisions.WithLabelValues(decision, string(v.Reason), v.Rule, string(p.Mode)).Inc()
	g.cfg.Audit.Log(rec)

	if v.Allow || !enforced {
		return Decision{Allow: true}
	}
	shown := in.image
	if in.repo != "" && in.digest != "" {
		shown = in.repo + "@" + in.digest
	}
	if shown == "" {
		shown = "container"
	}
	return Decision{Msg: verdict.Message(shown, v.Reason, v.Detail, p.Defaults.HelpURL)}
}

// Warm pre-verifies a registry reference so later creates are cache hits.
func (g *Gate) Warm(ctx context.Context, ref string) (verdict.Verdict, string, error) {
	st := g.state.Load()
	if st == nil {
		return verdict.Verdict{}, "", errors.New("no valid policy is loaded")
	}
	if g.cfg.Resolver == nil {
		return verdict.Verdict{}, "", errors.New("warm is not available")
	}
	r, err := imageref.Parse(ref)
	if err != nil {
		return verdict.Verdict{}, "", err
	}
	digest := r.Digest
	if digest == "" {
		if digest, err = g.cfg.Resolver.ResolveDigest(ctx, r); err != nil {
			return verdict.Verdict{}, "", fmt.Errorf("resolve %s: %w", ref, err)
		}
	}
	_, v := g.evaluateVerdict(ctx, st, input{endpoint: "warm", image: ref, repo: r.Repo, digest: digest, start: time.Now()})
	return v, r.Repo + "@" + digest, nil
}

// PurgeCache drops cached verdicts, all or for one digest.
func (g *Gate) PurgeCache(digest string) (int, error) { return g.cfg.Cache.Purge(digest) }

func parsePlatform(s string) (*v1.Platform, error) {
	if s == "" {
		return nil, nil
	}
	p, err := v1.ParsePlatform(s)
	if err != nil {
		return nil, fmt.Errorf("invalid platform %q", s)
	}
	return p, nil
}

func latencyMs(start time.Time) int64 {
	if start.IsZero() {
		return 0
	}
	return time.Since(start).Milliseconds()
}
