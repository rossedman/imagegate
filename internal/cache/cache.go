// Package cache stores verdicts by (repository, digest, policyHash) in an
// in-memory LRU backed by a bbolt file, so a restart does not cause a burst
// of cold verifications. It also remembers which manifest digest each local
// image ID was resolved to, for the re-check at container start.
package cache

import (
	"encoding/json"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	bolt "go.etcd.io/bbolt"

	"github.com/rossedman/imagegate/internal/verdict"
)

var (
	bucketVerdicts = []byte("verdicts")
	bucketImages   = []byte("images")
)

// Key identifies one verification. The repository is part of the key
// because the matching rule, and the registry repository signatures are
// fetched from, depend on it.
type Key struct {
	Repo       string
	Digest     string
	PolicyHash string
}

func (k Key) String() string { return k.Repo + "@" + k.Digest + "|" + k.PolicyHash }

// ImageDigest records which repository digest a local image ID resolved to.
type ImageDigest struct {
	Repo   string `json:"repo"`
	Digest string `json:"digest"`
}

// Cache is safe for concurrent use.
type Cache struct {
	mem    *lru.Cache[string, verdict.Verdict]
	images *lru.Cache[string, ImageDigest]
	db     *bolt.DB
	now    func() time.Time
}

// Open creates a cache holding up to size verdicts in memory. path may be
// empty for a memory-only cache.
func Open(path string, size int) (*Cache, error) {
	if size <= 0 {
		size = 10000
	}
	mem, err := lru.New[string, verdict.Verdict](size)
	if err != nil {
		return nil, err
	}
	images, err := lru.New[string, ImageDigest](size)
	if err != nil {
		return nil, err
	}
	c := &Cache{mem: mem, images: images, now: time.Now}
	if path == "" {
		return c, nil
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketVerdicts); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketImages)
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	c.db = db
	c.compact()
	return c, nil
}

// SetClock replaces the clock used for expiry checks (tests).
func (c *Cache) SetClock(now func() time.Time) { c.now = now }

// Close flushes and closes the backing file.
func (c *Cache) Close() error {
	if c.db == nil {
		return nil
	}
	return c.db.Close()
}

// Get returns an unexpired verdict.
func (c *Cache) Get(k Key) (verdict.Verdict, bool) {
	ks := k.String()
	if v, ok := c.mem.Get(ks); ok {
		if c.now().Before(v.ExpiresAt) {
			return v, true
		}
		c.mem.Remove(ks)
		return verdict.Verdict{}, false
	}
	if c.db == nil {
		return verdict.Verdict{}, false
	}
	var v verdict.Verdict
	found := false
	_ = c.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketVerdicts).Get([]byte(ks))
		if raw != nil && json.Unmarshal(raw, &v) == nil {
			found = true
		}
		return nil
	})
	if !found || !c.now().Before(v.ExpiresAt) {
		return verdict.Verdict{}, false
	}
	c.mem.Add(ks, v)
	return v, true
}

// Put stores a verdict until v.ExpiresAt.
func (c *Cache) Put(k Key, v verdict.Verdict) error {
	ks := k.String()
	c.mem.Add(ks, v)
	if c.db == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketVerdicts).Put([]byte(ks), raw)
	})
}

// PutImage remembers that local image ID resolved to repo@digest.
func (c *Cache) PutImage(imageID string, d ImageDigest) error {
	if imageID == "" {
		return nil
	}
	if cur, ok := c.images.Get(imageID); ok && cur == d {
		return nil
	}
	c.images.Add(imageID, d)
	if c.db == nil {
		return nil
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return c.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketImages).Put([]byte(imageID), raw)
	})
}

// GetImage returns the digest a local image ID was last resolved to.
func (c *Cache) GetImage(imageID string) (ImageDigest, bool) {
	if d, ok := c.images.Get(imageID); ok {
		return d, true
	}
	if c.db == nil {
		return ImageDigest{}, false
	}
	var d ImageDigest
	found := false
	_ = c.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketImages).Get([]byte(imageID))
		if raw != nil && json.Unmarshal(raw, &d) == nil {
			found = true
		}
		return nil
	})
	if found {
		c.images.Add(imageID, d)
	}
	return d, found
}

// Purge removes every verdict, or only those for digest when it is set.
// It returns the number of verdicts removed.
func (c *Cache) Purge(digest string) (int, error) {
	n := 0
	for _, k := range c.mem.Keys() {
		if digest == "" || keyHasDigest(k, digest) {
			c.mem.Remove(k)
			n++
		}
	}
	if c.db == nil {
		return n, nil
	}
	dbN := 0
	err := c.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketVerdicts)
		var del [][]byte
		err := b.ForEach(func(k, _ []byte) error {
			if digest == "" || keyHasDigest(string(k), digest) {
				del = append(del, append([]byte(nil), k...))
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range del {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		dbN = len(del)
		return nil
	})
	return max(n, dbN), err
}

func keyHasDigest(k, digest string) bool {
	return strings.Contains(k, "@"+digest+"|")
}

// compact drops expired verdicts from the backing file at startup.
func (c *Cache) compact() {
	now := c.now()
	_ = c.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketVerdicts)
		var del [][]byte
		_ = b.ForEach(func(k, raw []byte) error {
			var v verdict.Verdict
			if json.Unmarshal(raw, &v) != nil || !now.Before(v.ExpiresAt) {
				del = append(del, append([]byte(nil), k...))
			}
			return nil
		})
		for _, k := range del {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}
