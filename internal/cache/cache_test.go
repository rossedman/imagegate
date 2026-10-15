package cache

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/rossedman/image-gate/internal/verdict"
)

func TestGetPutExpiry(t *testing.T) {
	c, err := Open("", 10)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c.now = func() time.Time { return now }
	k := Key{Repo: "ghcr.io/acme/api", Digest: "sha256:aa", PolicyHash: "p1"}
	if _, ok := c.Get(k); ok {
		t.Fatal("empty cache hit")
	}
	c.Put(k, verdict.Verdict{Allow: true, Reason: verdict.Allowed, ExpiresAt: now.Add(time.Minute)})
	if v, ok := c.Get(k); !ok || !v.Allow {
		t.Fatal("miss after put")
	}
	if _, ok := c.Get(Key{Repo: k.Repo, Digest: k.Digest, PolicyHash: "p2"}); ok {
		t.Error("a policy change must miss")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := c.Get(k); ok {
		t.Error("expired verdict served")
	}
}

func TestPersistenceAndPurge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	c, err := Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	k1 := Key{Repo: "r", Digest: "sha256:aa", PolicyHash: "p"}
	k2 := Key{Repo: "r", Digest: "sha256:bb", PolicyHash: "p"}
	c.Put(k1, verdict.Verdict{Allow: true, Reason: verdict.Allowed, ExpiresAt: exp})
	c.Put(k2, verdict.Verdict{Reason: verdict.NoSBOM, ExpiresAt: exp})
	c.Put(Key{Repo: "r", Digest: "sha256:cc", PolicyHash: "p"}, verdict.Verdict{ExpiresAt: time.Now().Add(-time.Second)})
	c.PutImage("sha256:img", ImageDigest{Repo: "r", Digest: "sha256:aa"})
	c.Close()

	c, err = Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if v, ok := c.Get(k1); !ok || v.Reason != verdict.Allowed {
		t.Fatal("verdict lost across restart")
	}
	if d, ok := c.GetImage("sha256:img"); !ok || d.Digest != "sha256:aa" {
		t.Fatal("image mapping lost across restart")
	}
	if n, _ := c.Purge("sha256:aa"); n != 1 {
		t.Errorf("purge by digest removed %d", n)
	}
	if _, ok := c.Get(k1); ok {
		t.Error("purged verdict served")
	}
	if _, ok := c.Get(k2); !ok {
		t.Error("purge by digest removed another digest")
	}
	c.Purge("")
	if _, ok := c.Get(k2); ok {
		t.Error("purge all left a verdict")
	}
}
