package cache

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/rossedman/imagegate/internal/verdict"
)

func open(t testing.TB, path string, size int) *Cache {
	t.Helper()
	c, err := Open(path, size)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c
}

func put(t testing.TB, c *Cache, k Key, v verdict.Verdict) {
	t.Helper()
	if err := c.Put(k, v); err != nil {
		t.Fatal(err)
	}
}

// clock is a settable test clock.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestKeyString(t *testing.T) {
	t.Parallel()
	k := Key{Repo: "ghcr.io/acme/api", Digest: "sha256:aa", PolicyHash: "p1"}
	if got, want := k.String(), "ghcr.io/acme/api@sha256:aa|p1"; got != want {
		t.Errorf("Key.String() = %q, want %q", got, want)
	}
	if !keyHasDigest(k.String(), "sha256:aa") || keyHasDigest(k.String(), "sha256:a") || keyHasDigest(k.String(), "p1") {
		t.Error("keyHasDigest must match the whole digest only")
	}
}

func TestGetPutExpiry(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"", "db"} {
		t.Run("path="+path, func(t *testing.T) {
			t.Parallel()
			if path != "" {
				path = filepath.Join(t.TempDir(), "cache.db")
			}
			c := open(t, path, 10)
			clk := &clock{t: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)}
			c.SetClock(clk.now)
			k := Key{Repo: "ghcr.io/acme/api", Digest: "sha256:aa", PolicyHash: "p1"}
			if _, ok := c.Get(k); ok {
				t.Fatal("empty cache hit")
			}
			want := verdict.Verdict{Allow: true, Reason: verdict.Allowed, Rule: "internal", ExpiresAt: clk.t.Add(time.Minute)}
			put(t, c, k, want)
			if v, ok := c.Get(k); !ok || v != want {
				t.Fatalf("Get = %+v %v, want %+v", v, ok, want)
			}
			for _, other := range []Key{
				{Repo: k.Repo, Digest: k.Digest, PolicyHash: "p2"},
				{Repo: "ghcr.io/acme/other", Digest: k.Digest, PolicyHash: k.PolicyHash},
				{Repo: k.Repo, Digest: "sha256:bb", PolicyHash: k.PolicyHash},
			} {
				if _, ok := c.Get(other); ok {
					t.Errorf("Get(%s) hit; every key field must matter", other)
				}
			}
			clk.t = want.ExpiresAt.Add(-time.Nanosecond)
			if _, ok := c.Get(k); !ok {
				t.Error("verdict missed before expiry")
			}
			// Expired at exactly ExpiresAt.
			clk.t = want.ExpiresAt
			if _, ok := c.Get(k); ok {
				t.Error("verdict served at its expiry")
			}
			if c.mem.Contains(k.String()) {
				t.Error("expired verdict kept in memory")
			}
			// Still expired when re-read from the backing file.
			if _, ok := c.Get(k); ok {
				t.Error("expired verdict served from the backing file")
			}
			if c.mem.Contains(k.String()) {
				t.Error("expired verdict from the file was cached in memory")
			}
		})
	}
}

func TestPersistenceAndPurge(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cache.db")
	c, err := Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	k1 := Key{Repo: "r", Digest: "sha256:aa", PolicyHash: "p"}
	k2 := Key{Repo: "r", Digest: "sha256:bb", PolicyHash: "p"}
	k3 := Key{Repo: "other", Digest: "sha256:aa", PolicyHash: "q"}
	put(t, c, k1, verdict.Verdict{Allow: true, Reason: verdict.Allowed, ExpiresAt: exp})
	put(t, c, k2, verdict.Verdict{Reason: verdict.NoSBOM, ExpiresAt: exp})
	put(t, c, k3, verdict.Verdict{Reason: verdict.NoSignature, ExpiresAt: exp})
	put(t, c, Key{Repo: "r", Digest: "sha256:cc", PolicyHash: "p"}, verdict.Verdict{ExpiresAt: time.Now().Add(-time.Second)})
	if err := c.PutImage("sha256:img", ImageDigest{Repo: "r", Digest: "sha256:aa"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	c = open(t, path, 10)
	if v, ok := c.Get(k1); !ok || v.Reason != verdict.Allowed || !v.Allow {
		t.Fatal("verdict lost across restart")
	}
	if !c.mem.Contains(k1.String()) {
		t.Error("verdict read from the file was not cached in memory")
	}
	if d, ok := c.GetImage("sha256:img"); !ok || d != (ImageDigest{Repo: "r", Digest: "sha256:aa"}) {
		t.Fatalf("image mapping lost across restart: %+v %v", d, ok)
	}
	if !c.images.Contains("sha256:img") {
		t.Error("image mapping read from the file was not cached in memory")
	}
	// k1 is in memory and the file; k3 only in the file. Both carry the
	// digest, and the count is the larger of the two stores.
	n, err := c.Purge("sha256:aa")
	if err != nil || n != 2 {
		t.Errorf("Purge(sha256:aa) = %d, %v; want 2", n, err)
	}
	if _, ok := c.Get(k1); ok {
		t.Error("purged verdict served")
	}
	if _, ok := c.Get(k3); ok {
		t.Error("purged verdict for another repository served")
	}
	if _, ok := c.Get(k2); !ok {
		t.Error("purge by digest removed another digest")
	}
	if n, err := c.Purge(""); err != nil || n != 1 {
		t.Errorf("Purge(\"\") = %d, %v; want 1", n, err)
	}
	if _, ok := c.Get(k2); ok {
		t.Error("purge all left a verdict")
	}
	if n, err := c.Purge(""); err != nil || n != 0 {
		t.Errorf("Purge on an empty cache = %d, %v", n, err)
	}
	// Image mappings are not verdicts and survive a purge.
	if _, ok := c.GetImage("sha256:img"); !ok {
		t.Error("purge removed an image mapping")
	}
}

func TestPurgeMemoryOnly(t *testing.T) {
	t.Parallel()
	c := open(t, "", 10)
	exp := time.Now().Add(time.Hour)
	for _, d := range []string{"sha256:aa", "sha256:aa", "sha256:bb"} {
		for _, p := range []string{"p1", "p2"} {
			put(t, c, Key{Repo: "r", Digest: d, PolicyHash: p}, verdict.Verdict{ExpiresAt: exp})
		}
	}
	if n, err := c.Purge("sha256:aa"); err != nil || n != 2 {
		t.Errorf("Purge(sha256:aa) = %d, %v; want 2", n, err)
	}
	if n, err := c.Purge("sha256:zz"); err != nil || n != 0 {
		t.Errorf("Purge(unknown) = %d, %v", n, err)
	}
	if n, err := c.Purge(""); err != nil || n != 2 {
		t.Errorf("Purge(all) = %d, %v; want 2", n, err)
	}
}

// Open drops expired and unreadable verdicts from the backing file.
func TestCompactOnOpen(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cache.db")
	c, err := Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	live := Key{Repo: "r", Digest: "sha256:live", PolicyHash: "p"}
	dead := Key{Repo: "r", Digest: "sha256:dead", PolicyHash: "p"}
	put(t, c, live, verdict.Verdict{Reason: verdict.Allowed, ExpiresAt: now.Add(time.Hour)})
	put(t, c, dead, verdict.Verdict{Reason: verdict.Allowed, ExpiresAt: now.Add(-time.Hour)})
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	writeRaw(t, path, bucketVerdicts, "garbage", "{not json")

	c = open(t, path, 10)
	if keys := rawKeys(t, c, bucketVerdicts); len(keys) != 1 || keys[0] != live.String() {
		t.Errorf("after compaction the file holds %q, want only %q", keys, live.String())
	}
	// Even with a clock before its expiry, the compacted verdict is gone.
	c.SetClock(func() time.Time { return now.Add(-2 * time.Hour) })
	if _, ok := c.Get(dead); ok {
		t.Error("compacted verdict served")
	}
	if _, ok := c.Get(live); !ok {
		t.Error("live verdict lost in compaction")
	}
}

// A record that does not decode is a miss, never a verdict.
func TestCorruptRecords(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cache.db")
	c := open(t, path, 10)
	k := Key{Repo: "r", Digest: "sha256:aa", PolicyHash: "p"}
	if err := c.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketVerdicts).Put([]byte(k.String()), []byte("{")); err != nil {
			return err
		}
		return tx.Bucket(bucketImages).Put([]byte("sha256:img"), []byte("["))
	}); err != nil {
		t.Fatal(err)
	}
	if v, ok := c.Get(k); ok {
		t.Errorf("corrupt verdict served: %+v", v)
	}
	if d, ok := c.GetImage("sha256:img"); ok {
		t.Errorf("corrupt image mapping served: %+v", d)
	}
}

func TestImages(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"", "db"} {
		t.Run("path="+path, func(t *testing.T) {
			t.Parallel()
			if path != "" {
				path = filepath.Join(t.TempDir(), "cache.db")
			}
			c := open(t, path, 10)
			if _, ok := c.GetImage("sha256:img"); ok {
				t.Fatal("empty cache hit")
			}
			if err := c.PutImage("", ImageDigest{Repo: "r", Digest: "sha256:aa"}); err != nil {
				t.Fatal(err)
			}
			if _, ok := c.GetImage(""); ok {
				t.Error("an empty image ID was stored")
			}
			a := ImageDigest{Repo: "r", Digest: "sha256:aa"}
			b := ImageDigest{Repo: "r", Digest: "sha256:bb"}
			for _, d := range []ImageDigest{a, a, b} {
				if err := c.PutImage("sha256:img", d); err != nil {
					t.Fatal(err)
				}
			}
			if d, ok := c.GetImage("sha256:img"); !ok || d != b {
				t.Errorf("GetImage = %+v %v, want the latest %+v", d, ok, b)
			}
			if c.db != nil {
				if keys := rawKeys(t, c, bucketImages); len(keys) != 1 || keys[0] != "sha256:img" {
					t.Errorf("image bucket = %q", keys)
				}
			}
		})
	}
}

// An unchanged mapping does not rewrite the file.
func TestPutImageUnchangedSkipsWrite(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cache.db")
	c, err := Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	d := ImageDigest{Repo: "r", Digest: "sha256:aa"}
	if err := c.PutImage("sha256:img", d); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// With the file closed, any write would fail.
	if err := c.PutImage("sha256:img", d); err != nil {
		t.Errorf("unchanged PutImage wrote to the file: %v", err)
	}
	if err := c.PutImage("sha256:img", ImageDigest{Repo: "r", Digest: "sha256:bb"}); err == nil {
		t.Error("changed PutImage on a closed file should fail")
	}
}

func TestClosedErrors(t *testing.T) {
	t.Parallel()
	c, err := Open(filepath.Join(t.TempDir(), "cache.db"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	k := Key{Repo: "r", Digest: "sha256:aa", PolicyHash: "p"}
	if err := c.Put(k, verdict.Verdict{ExpiresAt: time.Now().Add(time.Hour)}); err == nil {
		t.Error("Put on a closed file should fail")
	}
	if _, err := c.Purge(""); err == nil {
		t.Error("Purge on a closed file should fail")
	}
	if err := c.PutImage("sha256:img", ImageDigest{Repo: "r"}); err == nil {
		t.Error("PutImage on a closed file should fail")
	}
}

// A verdict that cannot be encoded is not written to the file.
func TestPutUnencodable(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cache.db")
	c := open(t, path, 10)
	k := Key{Repo: "r", Digest: "sha256:aa", PolicyHash: "p"}
	// encoding/json rejects years outside [0, 9999].
	if err := c.Put(k, verdict.Verdict{ExpiresAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("Put of an unencodable verdict should fail")
	}
	if keys := rawKeys(t, c, bucketVerdicts); len(keys) != 0 {
		t.Errorf("unencodable verdict written: %q", keys)
	}
}

func TestCloseMemoryOnly(t *testing.T) {
	t.Parallel()
	c, err := Open("", 0)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := c.Close(); err != nil {
			t.Errorf("Close = %v", err)
		}
	}
}

func TestOpenErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	notDB := filepath.Join(dir, "not.db")
	if err := os.WriteFile(notDB, bytes.Repeat([]byte("not a bbolt file "), 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing directory": filepath.Join(dir, "missing", "cache.db"),
		"directory":         dir,
		"not a database":    notDB,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, err := Open(path, 10)
			if err == nil {
				_ = c.Close()
				t.Fatalf("Open(%s) succeeded", path)
			}
			if c != nil {
				t.Error("Open returned a cache with an error")
			}
		})
	}
}

// The memory tier is bounded; evicted entries are re-read from the file.
func TestEviction(t *testing.T) {
	t.Parallel()
	exp := time.Now().Add(time.Hour)
	k1 := Key{Repo: "r", Digest: "sha256:aa", PolicyHash: "p"}
	k2 := Key{Repo: "r", Digest: "sha256:bb", PolicyHash: "p"}

	mem := open(t, "", 1)
	put(t, mem, k1, verdict.Verdict{ExpiresAt: exp})
	put(t, mem, k2, verdict.Verdict{ExpiresAt: exp})
	if _, ok := mem.Get(k1); ok {
		t.Error("size-1 memory cache kept two verdicts")
	}
	if _, ok := mem.Get(k2); !ok {
		t.Error("newest verdict evicted")
	}

	disk := open(t, filepath.Join(t.TempDir(), "cache.db"), 1)
	put(t, disk, k1, verdict.Verdict{ExpiresAt: exp})
	put(t, disk, k2, verdict.Verdict{ExpiresAt: exp})
	if _, ok := disk.Get(k1); !ok {
		t.Error("evicted verdict not re-read from the file")
	}
	if !disk.mem.Contains(k1.String()) || disk.mem.Contains(k2.String()) {
		t.Error("re-read verdict did not replace the LRU entry")
	}
}

func TestConcurrentUse(t *testing.T) {
	t.Parallel()
	c := open(t, filepath.Join(t.TempDir(), "cache.db"), 16)
	exp := time.Now().Add(time.Hour)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := range 8 {
		wg.Go(func() {
			for i := range 20 {
				k := Key{Repo: "r", Digest: fmt.Sprintf("sha256:%d-%d", g, i), PolicyHash: "p"}
				if err := c.Put(k, verdict.Verdict{Allow: true, ExpiresAt: exp}); err != nil {
					errs <- err
					return
				}
				if v, ok := c.Get(k); !ok || !v.Allow {
					errs <- fmt.Errorf("miss after put for %s", k)
					return
				}
				if err := c.PutImage(fmt.Sprintf("img-%d", g), ImageDigest{Repo: "r", Digest: k.Digest}); err != nil {
					errs <- err
					return
				}
				c.GetImage(fmt.Sprintf("img-%d", g))
			}
			if _, err := c.Purge(fmt.Sprintf("sha256:%d-0", g)); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func writeRaw(t *testing.T, path string, bucket []byte, k, v string) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Put([]byte(k), []byte(v))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func rawKeys(t *testing.T, c *Cache, bucket []byte) []string {
	t.Helper()
	var keys []string
	if err := c.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).ForEach(func(k, _ []byte) error {
			keys = append(keys, string(k))
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return keys
}

func BenchmarkCacheGet(b *testing.B) {
	c := open(b, filepath.Join(b.TempDir(), "cache.db"), 0)
	k := Key{Repo: "ghcr.io/acme/api", Digest: "sha256:3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c", PolicyHash: "4b1e541e8d356c9b1f915b0e09df1c25585b855f249839f95a22846c83b995af"}
	put(b, c, k, verdict.Verdict{Allow: true, Reason: verdict.Allowed, ExpiresAt: time.Now().Add(time.Hour)})
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := c.Get(k); !ok {
			b.Fatal("miss")
		}
	}
}

func BenchmarkCachePut(b *testing.B) {
	v := verdict.Verdict{Allow: true, Reason: verdict.Allowed, Rule: "internal", Signer: "ci-main", ExpiresAt: time.Now().Add(time.Hour)}
	k := Key{Repo: "ghcr.io/acme/api", Digest: "sha256:3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c3f9c", PolicyHash: "4b1e541e8d356c9b1f915b0e09df1c25585b855f249839f95a22846c83b995af"}
	b.Run("memory", func(b *testing.B) {
		c := open(b, "", 0)
		b.ReportAllocs()
		for b.Loop() {
			put(b, c, k, v)
		}
	})
	b.Run("bbolt", func(b *testing.B) {
		c := open(b, filepath.Join(b.TempDir(), "cache.db"), 0)
		b.ReportAllocs()
		for b.Loop() {
			put(b, c, k, v)
		}
	})
}
