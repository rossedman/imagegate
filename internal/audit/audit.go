// Package audit writes one structured JSON record per decision.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Record is one decision. Field names match the spec's audit format.
type Record struct {
	TS         time.Time `json:"ts"`
	Decision   string    `json:"decision"` // allow | deny
	Mode       string    `json:"mode"`     // enforce | audit
	Reason     string    `json:"reason"`
	Image      string    `json:"image"`
	Digest     string    `json:"digest"`
	Rule       string    `json:"rule"`
	Signer     string    `json:"signer"`
	Cache      string    `json:"cache"` // hit | miss | ""
	LatencyMs  int64     `json:"latencyMs"`
	Endpoint   string    `json:"endpoint"`
	User       string    `json:"user"`
	PolicyHash string    `json:"policyHash"`
	// Enforced is false when the decision was "deny" but the request was
	// allowed (audit mode, or failClosed: false).
	Enforced bool   `json:"enforced"`
	Detail   string `json:"detail,omitempty"`
	// Override fields are set when a break-glass override was used.
	Ticket   string `json:"ticket,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// Logger serializes records as JSON lines.
type Logger struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func New(w io.Writer) *Logger { return &Logger{enc: json.NewEncoder(w)} }

func (l *Logger) Log(r Record) {
	if r.TS.IsZero() {
		r.TS = time.Now().UTC()
	}
	r.TS = r.TS.UTC().Truncate(time.Millisecond)
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(r)
}
