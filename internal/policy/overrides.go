package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// MaxOverrideLifetime is the longest an override may stay valid.
const MaxOverrideLifetime = 7 * 24 * time.Hour

var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Override is a break-glass entry that allows exactly one digest until it
// expires.
type Override struct {
	Digest  string    `yaml:"digest"`
	Expires time.Time `yaml:"expires"`
	Ticket  string    `yaml:"ticket"`
	Reason  string    `yaml:"reason"`

	File string `yaml:"-"`
}

// Overrides is the set loaded from overrides.d, keyed by digest.
type Overrides struct {
	byDigest map[string]Override
}

// Lookup returns the override for digest if one exists and has not expired.
func (o *Overrides) Lookup(digest string, now time.Time) (Override, bool) {
	if o == nil {
		return Override{}, false
	}
	ov, ok := o.byDigest[digest]
	if !ok || !now.Before(ov.Expires) {
		return Override{}, false
	}
	return ov, true
}

// Active counts overrides that have not expired.
func (o *Overrides) Active(now time.Time) int {
	if o == nil {
		return 0
	}
	n := 0
	for _, ov := range o.byDigest {
		if now.Before(ov.Expires) {
			n++
		}
	}
	return n
}

// LoadOverrides reads every *.yaml file in dir. Invalid entries and files
// that are not root-owned (when running as root) are skipped and reported
// in the returned error; valid entries are still loaded. A missing
// directory yields an empty set.
func LoadOverrides(dir string, now time.Time) (*Overrides, error) {
	out := &Overrides{byDigest: map[string]Override{}}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return out, err
	}
	sort.Strings(files)
	var errs []error
	for _, f := range files {
		if err := checkOwnership(f); err != nil {
			errs = append(errs, err)
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var entries []Override
		if err := yaml.Unmarshal(raw, &entries); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f, err))
			continue
		}
		for i, e := range entries {
			e.File = f
			if err := e.validate(now); err != nil {
				errs = append(errs, fmt.Errorf("%s[%d]: %w", f, i, err))
				continue
			}
			// Keep the entry that expires last if a digest repeats.
			if cur, ok := out.byDigest[e.Digest]; !ok || e.Expires.After(cur.Expires) {
				out.byDigest[e.Digest] = e
			}
		}
	}
	return out, errors.Join(errs...)
}

func (o Override) validate(now time.Time) error {
	if !digestRE.MatchString(o.Digest) {
		return fmt.Errorf("digest must be sha256:<64 hex>, got %q", o.Digest)
	}
	if o.Expires.IsZero() {
		return errors.New("expires is required")
	}
	if o.Ticket == "" {
		return errors.New("ticket is required")
	}
	if o.Expires.Sub(now) > MaxOverrideLifetime {
		return fmt.Errorf("expires %s is more than 7 days away", o.Expires.Format(time.RFC3339))
	}
	return nil
}

// checkOwnership rejects override files that a non-root user could have
// written. It is a no-op when imagegate itself is not running as root
// (tests, development).
func checkOwnership(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if st.Uid != 0 {
		return fmt.Errorf("%s: must be owned by root", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: must not be group- or world-writable", path)
	}
	return nil
}
