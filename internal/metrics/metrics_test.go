package metrics

import (
	"testing"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	// A second instance owns its own registry: no duplicate registration
	// panic, and values are independent.
	other := New()
	if m.Registry == other.Registry {
		t.Fatal("instances share a registry")
	}

	m.Decisions.WithLabelValues("deny", "NO_SBOM", "internal", "enforce").Inc()
	m.VerifyDuration.WithLabelValues("signature").Observe(0.2)
	m.CacheRequests.WithLabelValues("hit").Add(2)
	m.UpstreamErrors.WithLabelValues("registry").Inc()
	m.OverridesActive.Set(3)
	m.PolicyReloadErrors.Inc()

	fams, err := m.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]int{}
	for i, f := range fams {
		byName[f.GetName()] = i
	}

	cases := []struct {
		name   string
		typ    string
		labels []string
		value  float64
	}{
		{"imagegate_decisions_total", "COUNTER", []string{"decision", "mode", "reason", "rule"}, 1},
		{"imagegate_verify_duration_seconds", "HISTOGRAM", []string{"stage"}, 1},
		{"imagegate_cache_requests_total", "COUNTER", []string{"result"}, 2},
		{"imagegate_upstream_errors_total", "COUNTER", []string{"target"}, 1},
		{"imagegate_overrides_active", "GAUGE", nil, 3},
		{"imagegate_policy_reload_errors_total", "COUNTER", nil, 1},
	}
	for _, c := range cases {
		i, ok := byName[c.name]
		if !ok {
			t.Errorf("%s not registered", c.name)
			continue
		}
		f := fams[i]
		if f.GetType().String() != c.typ {
			t.Errorf("%s type = %v, want %v", c.name, f.GetType(), c.typ)
		}
		if len(f.GetMetric()) != 1 {
			t.Fatalf("%s has %d series", c.name, len(f.GetMetric()))
		}
		mt := f.GetMetric()[0]
		var names []string
		for _, l := range mt.GetLabel() {
			names = append(names, l.GetName())
		}
		if len(names) != len(c.labels) {
			t.Errorf("%s labels = %v, want %v", c.name, names, c.labels)
		} else {
			for i := range names {
				if names[i] != c.labels[i] {
					t.Errorf("%s labels = %v, want %v", c.name, names, c.labels)
				}
			}
		}
		var got float64
		switch c.typ {
		case "COUNTER":
			got = mt.GetCounter().GetValue()
		case "GAUGE":
			got = mt.GetGauge().GetValue()
		case "HISTOGRAM":
			got = float64(mt.GetHistogram().GetSampleCount())
			if n := len(mt.GetHistogram().GetBucket()); n != 12 {
				t.Errorf("histogram buckets = %d, want 12", n)
			}
		}
		if got != c.value {
			t.Errorf("%s = %v, want %v", c.name, got, c.value)
		}
	}

	// The Go and process collectors are registered too.
	if _, ok := byName["go_goroutines"]; !ok {
		t.Error("Go collector not registered")
	}

	// The other instance saw none of this.
	ofams, err := other.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range ofams {
		if f.GetName() == "imagegate_policy_reload_errors_total" && f.GetMetric()[0].GetCounter().GetValue() != 0 {
			t.Error("metrics leaked between instances")
		}
	}
}
