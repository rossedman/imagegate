// Package admin serves root-only maintenance commands (warm, cache purge)
// on a Unix socket, and the client the CLI uses to call them.
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/rossedman/image-gate/internal/verdict"
)

// Gate is what the admin server needs from the decision engine.
type Gate interface {
	Warm(ctx context.Context, ref string) (verdict.Verdict, string, error)
	PurgeCache(digest string) (int, error)
}

// WarmResult reports one pre-verified reference.
type WarmResult struct {
	Ref    string `json:"ref"`
	Image  string `json:"image,omitempty"`
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Handler returns the admin HTTP handler.
func Handler(g Gate) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /warm", func(w http.ResponseWriter, r *http.Request) {
		var refs []string
		if err := json.NewDecoder(r.Body).Decode(&refs); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		out := make([]WarmResult, 0, len(refs))
		for _, ref := range refs {
			v, img, err := g.Warm(r.Context(), ref)
			res := WarmResult{Ref: ref, Image: img}
			if err != nil {
				res.Error = err.Error()
			} else {
				res.Allow, res.Reason, res.Detail = v.Allow, string(v.Reason), v.Detail
			}
			out = append(out, res)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /cache/purge", func(w http.ResponseWriter, r *http.Request) {
		n, err := g.PurgeCache(r.URL.Query().Get("digest"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]int{"purged": n})
	})
	return mux
}

// Client calls a running imagegate over its admin socket.
type Client struct{ http *http.Client }

func NewClient(socket string) *Client {
	return &Client{http: &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}},
	}}
}

func (c *Client) Warm(refs []string) ([]WarmResult, error) {
	body, _ := json.Marshal(refs)
	var out []WarmResult
	return out, c.post("/warm", body, &out)
}

func (c *Client) Purge(digest string) (int, error) {
	var out map[string]int
	err := c.post("/cache/purge?digest="+url.QueryEscape(digest), nil, &out)
	return out["purged"], err
}

func (c *Client) post(path string, body []byte, out any) error {
	resp, err := c.http.Post("http://imagegate"+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("is imagegate running? %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
