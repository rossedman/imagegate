// Package metrics defines imagegate's Prometheus metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics holds every collector imagegate exports, on its own registry.
type Metrics struct {
	Registry           *prometheus.Registry
	Decisions          *prometheus.CounterVec
	VerifyDuration     *prometheus.HistogramVec
	CacheRequests      *prometheus.CounterVec
	UpstreamErrors     *prometheus.CounterVec
	OverridesActive    prometheus.Gauge
	PolicyReloadErrors prometheus.Counter
}

// New creates the collectors and registers them, with the Go and process
// collectors, on a fresh registry.
func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		Decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "imagegate_decisions_total",
			Help: "Container create/start decisions.",
		}, []string{"decision", "reason", "rule", "mode"}),
		VerifyDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "imagegate_verify_duration_seconds",
			Help:    "Time spent in each cold verification stage.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 1.5, 2.5, 5, 10},
		}, []string{"stage"}),
		CacheRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "imagegate_cache_requests_total",
			Help: "Verdict cache lookups.",
		}, []string{"result"}),
		UpstreamErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "imagegate_upstream_errors_total",
			Help: "Errors talking to registries, Rekor, TUF or dockerd.",
		}, []string{"target"}),
		OverridesActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "imagegate_overrides_active",
			Help: "Break-glass overrides that have not expired.",
		}),
		PolicyReloadErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "imagegate_policy_reload_errors_total",
			Help: "Policy loads that failed validation.",
		}),
	}
	m.Registry.MustRegister(m.Decisions, m.VerifyDuration, m.CacheRequests, m.UpstreamErrors,
		m.OverridesActive, m.PolicyReloadErrors,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}
