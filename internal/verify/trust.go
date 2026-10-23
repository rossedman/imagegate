package verify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// ErrNoTrustedRoot means keyless verification cannot run because no
// Sigstore trusted root has been loaded yet.
var ErrNoTrustedRoot = errors.New("sigstore trusted root unavailable")

// TrustSource provides the Sigstore trusted root (Fulcio CAs, Rekor and CT
// log keys, TSAs) used for keyless verification and transparency log
// checks.
type TrustSource interface {
	TrustedMaterial() (root.TrustedMaterial, error)
}

// StaticTrust is a fixed trusted root, e.g. a private Sigstore deployment's
// trusted_root.json.
type StaticTrust struct{ Material root.TrustedMaterial }

// TrustedMaterial returns the fixed root, or ErrNoTrustedRoot when unset.
func (s StaticTrust) TrustedMaterial() (root.TrustedMaterial, error) {
	if s.Material == nil {
		return nil, ErrNoTrustedRoot
	}
	return s.Material, nil
}

// TrustFromFile loads a trusted_root.json.
func TrustFromFile(path string) (StaticTrust, error) {
	tr, err := root.NewTrustedRootFromPath(path)
	if err != nil {
		return StaticTrust{}, fmt.Errorf("load trusted root %s: %w", path, err)
	}
	return StaticTrust{Material: tr}, nil
}

// TUFTrust fetches the public-good trusted root through TUF and refreshes it
// on a timer, never inline with a request. When the network is down it
// falls back to the last trusted root cached on disk.
type TUFTrust struct {
	opts    *tuf.Options
	refresh time.Duration
	log     *slog.Logger
	onError func()

	mu      sync.RWMutex
	current root.TrustedMaterial
}

// NewTUFTrust creates a TUF-backed trust source caching metadata in
// cacheDir. Call Run to load and keep it fresh.
func NewTUFTrust(cacheDir string, refresh time.Duration, log *slog.Logger, onError func()) *TUFTrust {
	opts := tuf.DefaultOptions()
	opts.CachePath = cacheDir
	if refresh <= 0 {
		refresh = 6 * time.Hour
	}
	if onError == nil {
		onError = func() {}
	}
	return &TUFTrust{opts: opts, refresh: refresh, log: log, onError: onError}
}

// TrustedMaterial returns the last loaded root, or ErrNoTrustedRoot before
// the first successful load.
func (t *TUFTrust) TrustedMaterial() (root.TrustedMaterial, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.current == nil {
		return nil, ErrNoTrustedRoot
	}
	return t.current, nil
}

// Run loads the trusted root, then refreshes it every refresh period until
// ctx is done. Failed loads retry every minute.
func (t *TUFTrust) Run(ctx context.Context) {
	for {
		wait := t.refresh
		if err := t.load(); err != nil {
			t.onError()
			t.log.Error("refresh sigstore trusted root", "err", err)
			wait = time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// load fetches the trusted root through TUF. With no root loaded yet, a
// failed fetch falls back to the on-disk cache.
func (t *TUFTrust) load() error {
	tr, err := root.FetchTrustedRootWithOptions(t.opts)
	if err != nil {
		// Offline: use the cached metadata even if it is past its
		// cache validity, so a network outage does not drop trust.
		t.mu.RLock()
		have := t.current != nil
		t.mu.RUnlock()
		if have {
			return err
		}
		cached := *t.opts
		cached.ForceCache = true
		var cerr error
		tr, cerr = root.FetchTrustedRootWithOptions(&cached)
		if cerr != nil {
			return errors.Join(err, cerr)
		}
		t.log.Warn("using cached sigstore trusted root; TUF refresh failed", "err", err)
	}
	t.mu.Lock()
	t.current = tr
	t.mu.Unlock()
	return nil
}
