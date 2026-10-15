// Package authz implements Docker's authorization plugin protocol.
//
// dockerd calls AuthZPlugin.AuthZReq before every API request and
// AuthZPlugin.AuthZRes after it. imagegate gates only container create and
// start in the request phase; every other call, and every response, is
// allowed — including on internal errors — so a fault in imagegate never
// locks operators out of the daemon.
package authz

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/rossedman/image-gate/internal/gate"
	"github.com/rossedman/image-gate/internal/verdict"
)

const contentType = "application/vnd.docker.plugins.v1+json"

// Request is dockerd's authorization request (authorization.Request).
type Request struct {
	User            string            `json:"User,omitempty"`
	UserAuthNMethod string            `json:"UserAuthNMethod,omitempty"`
	RequestMethod   string            `json:"RequestMethod,omitempty"`
	RequestURI      string            `json:"RequestUri,omitempty"`
	RequestBody     []byte            `json:"RequestBody,omitempty"`
	RequestHeaders  map[string]string `json:"RequestHeaders,omitempty"`
}

// Response is the plugin's answer (authorization.Response).
type Response struct {
	Allow bool   `json:"Allow"`
	Msg   string `json:"Msg,omitempty"`
	Err   string `json:"Err,omitempty"`
}

// Gate is what the handler needs from the decision engine.
type Gate interface {
	Create(ctx context.Context, user string, body []byte, query url.Values) gate.Decision
	Start(ctx context.Context, user, endpoint, containerID string) gate.Decision
}

// Handler serves the plugin protocol.
type Handler struct {
	Gate Gate
	Log  *slog.Logger
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/Plugin.Activate":
		write(w, map[string][]string{"Implements": {"authz"}})
	case "/AuthZPlugin.AuthZReq":
		h.authzReq(w, r)
	case "/AuthZPlugin.AuthZRes":
		write(w, Response{Allow: true})
	default:
		http.NotFound(w, r)
	}
}

// gated classifies a request. Only these endpoints are ever denied.
type gated int

const (
	passThrough gated = iota
	create
	start
)

var (
	versionPrefix = regexp.MustCompile(`^/v[0-9]+(\.[0-9]+)?`)
	startPath     = regexp.MustCompile(`^/containers/([^/]+)/(start|restart)$`)
)

// Classify returns what kind of gated request this is, the container ID for
// start/restart, and the query.
func Classify(method, requestURI string) (kind gated, endpoint, containerID string, query url.Values) {
	if method != http.MethodPost {
		return passThrough, "", "", nil
	}
	u, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return passThrough, "", "", nil
	}
	p := versionPrefix.ReplaceAllString(u.Path, "")
	p = strings.TrimRight(p, "/")
	switch {
	case p == "/containers/create":
		return create, "containers/create", "", u.Query()
	case startPath.MatchString(p):
		m := startPath.FindStringSubmatch(p)
		id, err := url.PathUnescape(m[1])
		if err != nil {
			id = m[1]
		}
		return start, "containers/" + m[2], id, u.Query()
	}
	return passThrough, "", "", nil
}

func (h *Handler) authzReq(w http.ResponseWriter, r *http.Request) {
	var req Request
	raw, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err == nil {
		err = json.Unmarshal(raw, &req)
	}
	kind, endpoint, id, query := passThrough, "", "", url.Values(nil)
	if err == nil {
		kind, endpoint, id, query = Classify(req.RequestMethod, req.RequestURI)
	}
	if err != nil {
		// We cannot tell what this is. Denying would risk locking
		// out the daemon, but it could be a create: deny only if the
		// raw request plainly names the create endpoint.
		if strings.Contains(string(raw), "/containers/create") {
			write(w, Response{Msg: verdict.Message("container", verdict.BadRequest, "unreadable authorization request", "")})
			return
		}
		write(w, Response{Allow: true})
		return
	}
	if kind == passThrough {
		write(w, Response{Allow: true})
		return
	}

	resp := h.decide(r.Context(), kind, req, endpoint, id, query)
	write(w, resp)
}

// decide runs the gate, failing closed if it panics.
func (h *Handler) decide(ctx context.Context, kind gated, req Request, endpoint, id string, query url.Values) (resp Response) {
	defer func() {
		if p := recover(); p != nil {
			h.Log.Error("panic while deciding; denying", "endpoint", endpoint, "panic", p)
			resp = Response{Msg: verdict.Message("container", verdict.UpstreamUnavailable, "internal error in imagegate", "")}
		}
	}()
	var d gate.Decision
	switch kind {
	case create:
		d = h.Gate.Create(ctx, req.User, req.RequestBody, query)
	case start:
		d = h.Gate.Start(ctx, req.User, endpoint, id)
	}
	return Response{Allow: d.Allow, Msg: d.Msg}
}

func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", contentType)
	_ = json.NewEncoder(w).Encode(v)
}
