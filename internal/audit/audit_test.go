package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// decode parses one JSON line into a generic map so the test checks the
// wire field names, not just the Go struct round trip.
func decode(t *testing.T, line []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatalf("not JSON: %v: %s", err, line)
	}
	return m
}

func TestLogRecordShape(t *testing.T) {
	t.Parallel()
	loc := time.FixedZone("UTC+5", 5*3600)
	ts := time.Date(2026, 3, 4, 10, 11, 12, 345678901, loc)
	cases := []struct {
		name string
		rec  Record
		want map[string]any
		// absent lists omitempty fields that must not appear.
		absent []string
	}{
		{
			name: "full deny with override fields",
			rec: Record{
				TS: ts, Decision: "deny", Mode: "enforce", Reason: "NO_SBOM",
				Image: "ghcr.io/acme/api:1", Digest: "sha256:aa", Rule: "internal", Signer: "ci-main",
				Cache: "miss", LatencyMs: 42, Endpoint: "containers/create", User: "alice",
				PolicyHash: "h1", Enforced: true, Detail: "no sbom", Ticket: "INC-1", Severity: "high",
			},
			want: map[string]any{
				"ts": "2026-03-04T05:11:12.345Z", "decision": "deny", "mode": "enforce", "reason": "NO_SBOM",
				"image": "ghcr.io/acme/api:1", "digest": "sha256:aa", "rule": "internal", "signer": "ci-main",
				"cache": "miss", "latencyMs": float64(42), "endpoint": "containers/create", "user": "alice",
				"policyHash": "h1", "enforced": true, "detail": "no sbom", "ticket": "INC-1", "severity": "high",
			},
		},
		{
			name: "minimal allow omits optional fields but keeps required ones",
			rec:  Record{TS: ts, Decision: "allow", Mode: "audit"},
			want: map[string]any{
				"ts": "2026-03-04T05:11:12.345Z", "decision": "allow", "mode": "audit", "reason": "",
				"image": "", "digest": "", "rule": "", "signer": "", "cache": "", "latencyMs": float64(0),
				"endpoint": "", "user": "", "policyHash": "", "enforced": false,
			},
			absent: []string{"detail", "ticket", "severity"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			New(&buf).Log(c.rec)
			out := buf.Bytes()
			if bytes.Count(out, []byte("\n")) != 1 || !bytes.HasSuffix(out, []byte("\n")) {
				t.Fatalf("want exactly one JSON line, got %q", out)
			}
			got := decode(t, out)
			for k, v := range c.want {
				if got[k] != v {
					t.Errorf("%s = %#v, want %#v", k, got[k], v)
				}
			}
			for _, k := range c.absent {
				if _, ok := got[k]; ok {
					t.Errorf("%s present, want omitted", k)
				}
			}
			if len(got) != len(c.want) {
				t.Errorf("record has %d fields, want %d: %v", len(got), len(c.want), got)
			}
		})
	}
}

func TestLogFillsZeroTimestamp(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	before := time.Now().UTC().Truncate(time.Millisecond)
	New(&buf).Log(Record{Decision: "allow"})
	after := time.Now().UTC()
	var r Record
	if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.TS.Before(before) || r.TS.After(after) {
		t.Errorf("ts %v not within [%v, %v]", r.TS, before, after)
	}
	if r.TS.Location() != time.UTC || r.TS.Nanosecond()%int(time.Millisecond) != 0 {
		t.Errorf("ts %v not UTC millisecond precision", r.TS)
	}
	if !strings.HasSuffix(decode(t, buf.Bytes())["ts"].(string), "Z") {
		t.Errorf("ts not serialized in UTC: %s", buf.String())
	}
}

// Concurrent Log calls must never interleave bytes within a line.
func TestLogConcurrent(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := New(&buf)
	const n = 64
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			l.Log(Record{Decision: "allow", LatencyMs: int64(i), Detail: strings.Repeat("x", 512)})
		})
	}
	wg.Wait()
	sc := bufio.NewScanner(&buf)
	sc.Buffer(nil, 1<<20)
	seen := map[int64]bool{}
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("interleaved line: %v", err)
		}
		seen[r.LatencyMs] = true
	}
	if len(seen) != n {
		t.Errorf("got %d distinct records, want %d", len(seen), n)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// A broken audit sink must not panic the decision path.
func TestLogWriteErrorIgnored(t *testing.T) {
	t.Parallel()
	New(failWriter{}).Log(Record{Decision: "deny"})
}

func BenchmarkLog(b *testing.B) {
	l := New(io.Discard)
	r := Record{TS: time.Now(), Decision: "allow", Mode: "enforce", Reason: "ALLOWED", Image: "ghcr.io/acme/api:1"}
	b.ReportAllocs()
	for b.Loop() {
		l.Log(r)
	}
}
