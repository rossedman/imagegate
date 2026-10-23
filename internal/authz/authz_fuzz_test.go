package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rossedman/imagegate/internal/gate"
)

// Real request URIs as dockerd forwards them (docker CLI, compose, SDKs),
// plus near misses.
var seedURIs = []string{
	"/v1.47/containers/create?name=web",
	"/v1.47/containers/create?platform=linux%2Farm64",
	"/containers/create",
	"/v1.45.0/containers/create",
	"/v1.47/containers/0123abcd/start",
	"/v1.47/containers/web/restart?t=5",
	"/v1.45/containers/web/db/start",
	"/v1.47/containers/abc/stop",
	"/v1.47/containers/abc/exec",
	"/v1.47/containers/abc/json",
	"/v1.47/images/create?fromImage=nginx&tag=latest",
	"/v1.47/images/nginx/json",
	"/v1.47/plugins/imagegate/disable",
	"/v1.47/build?t=x",
	"/_ping",
	"/v1.47/containers/creat%65",
	"/v1.47//containers/create",
	"//containers/create",
	"/vx/containers/create",
	"/v1.47/containers/create/",
	"/v1.47/containers/create%zz",
	"/v1.47/containers//start",
	"/v1.47/containers/x/start#frag",
	"containers/create",
	"",
}

var seedMethods = []string{"POST", "post", "GET", "HEAD", "PUT", "DELETE", ""}

// dockerdGated mirrors dockerd's create/start/restart routes on a decoded,
// trailing-slash-trimmed path: any POST whose path ends this way could
// reach a gated handler and must never pass through.
var dockerdGated = regexp.MustCompile(`/containers/(create|.+/(start|restart))$`)

// gatedShape is the set of paths a create/start classification may come
// from: an optional /v[0-9.]+ prefix and a create, start or restart path.
var (
	createShape = regexp.MustCompile(`^(/v[0-9.]+)?/+containers/create/*$`)
	startShape  = regexp.MustCompile(`^(/v[0-9.]+)?/+containers/(.+)/(start|restart)/*$`)
)

func checkClassify(t *testing.T, method, uri string) {
	t.Helper()
	kind, endpoint, id, query := Classify(method, uri)
	if !strings.EqualFold(method, http.MethodPost) {
		if kind != passThrough || endpoint != "" || id != "" || query != nil {
			t.Fatalf("Classify(%q, %q) = %v %q %q %v; non-POST must pass through", method, uri, kind, endpoint, id, query)
		}
		return
	}
	u, err := url.ParseRequestURI(uri)
	if err != nil {
		want := passThrough
		if strings.Contains(uri, "/containers/") {
			want = unrecognized
		}
		if kind != want {
			t.Fatalf("Classify(POST, %q) = %v, want %v for an unparseable URI", uri, kind, want)
		}
		return
	}
	switch kind {
	case create:
		if !createShape.MatchString(u.Path) || endpoint != "containers/create" || id != "" {
			t.Fatalf("Classify(POST, %q) = create %q %q for path %q", uri, endpoint, id, u.Path)
		}
	case start:
		m := startShape.FindStringSubmatch(u.Path)
		if m == nil || id == "" || endpoint != "containers/"+m[3] ||
			!strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/"+id+"/"+m[3]) {
			t.Fatalf("Classify(POST, %q) = start %q %q for path %q", uri, endpoint, id, u.Path)
		}
	case passThrough:
		if dockerdGated.MatchString(strings.TrimRight(u.Path, "/")) {
			t.Fatalf("Classify(POST, %q) passes through a path dockerd routes to a gated handler (%q)", uri, u.Path)
		}
	case unrecognized:
		if endpoint != "" || id != "" {
			t.Fatalf("unrecognized with endpoint %q id %q", endpoint, id)
		}
	default:
		t.Fatalf("unknown kind %v", kind)
	}
	if kind == create || kind == start {
		if query.Encode() != u.Query().Encode() {
			t.Fatalf("query = %v, want %v", query, u.Query())
		}
	}
}

func TestClassifyEdges(t *testing.T) {
	t.Parallel()
	cases := []struct {
		method, uri string
		kind        gated
	}{
		{"POST", "/v1.47/containers/create%zz", unrecognized}, // bad escape names a container path
		{"POST", "%zz", passThrough},
		{"POST", "containers/create", passThrough}, // not a request URI; dockerd's server rejects it too
		{"POST", "/v1.47/containers/creat%65", create},
		{"POST", "/v1.47//containers/create", create},
		{"POST", "//containers/create", unrecognized},
		{"POST", "/v1.47/containers//start", passThrough}, // empty name: dockerd redirects, never starts
		{"POST", "/v1.47/containers/a%2Fb/start", start},
		{"POST", "/v1.47", passThrough},
		{"PUT", "/v1.47/containers/create", passThrough},
		{"", "/v1.47/containers/create", passThrough},
	}
	for _, c := range cases {
		if kind, _, _, _ := Classify(c.method, c.uri); kind != c.kind {
			t.Errorf("Classify(%q, %q) = %v, want %v", c.method, c.uri, kind, c.kind)
		}
		checkClassify(t, c.method, c.uri)
	}
	if _, _, id, _ := Classify("POST", "/v1.47/containers/a%2Fb/start"); id != "a/b" {
		t.Errorf("decoded id = %q", id)
	}
}

func FuzzClassify(f *testing.F) {
	for _, m := range seedMethods {
		for _, u := range seedURIs {
			f.Add(m, u)
		}
	}
	f.Fuzz(func(t *testing.T, method, uri string) {
		checkClassify(t, method, uri)
	})
}

// stubGate denies every gated request so the tests can tell a gate
// decision from a pass-through.
type stubGate struct {
	allow   bool
	creates atomic.Int32
	starts  atomic.Int32
	lastEP  atomic.Value
	lastID  atomic.Value
	panics  bool
}

func (s *stubGate) Create(context.Context, string, []byte, url.Values) gate.Decision {
	s.creates.Add(1)
	if s.panics {
		panic("boom")
	}
	if s.allow {
		return gate.Decision{Allow: true}
	}
	return gate.Decision{Msg: "stub deny create"}
}

func (s *stubGate) Start(_ context.Context, _, endpoint, id string) gate.Decision {
	s.starts.Add(1)
	s.lastEP.Store(endpoint)
	s.lastID.Store(id)
	if s.panics {
		panic("boom")
	}
	if s.allow {
		return gate.Decision{Allow: true}
	}
	return gate.Decision{Msg: "stub deny start"}
}

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

// post sends body to path and decodes a strict Response.
func post(t *testing.T, h http.Handler, path string, body io.Reader) Response {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, body))
	if ct := rec.Header().Get("Content-Type"); ct != contentType {
		t.Fatalf("%s: content type %q", path, ct)
	}
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.DisallowUnknownFields()
	var r Response
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("%s: response is not valid JSON: %v: %q", path, err, rec.Body.String())
	}
	if !r.Allow && r.Msg == "" {
		t.Fatalf("%s: denial without a message", path)
	}
	return r
}

func TestHandlerStartAndUnrecognized(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		req          Request
		allow        bool
		msgHas       string
		creates      int32
		starts       int32
		endpoint, id string
		panics       bool
	}{
		{
			name: "restart", req: Request{RequestMethod: "POST", RequestURI: "/v1.47/containers/web/db/restart?t=1"},
			msgHas: "stub deny start", starts: 1, endpoint: "containers/restart", id: "web/db",
		},
		{
			name: "start", req: Request{RequestMethod: "POST", RequestURI: "/containers/abc/start"},
			msgHas: "stub deny start", starts: 1, endpoint: "containers/start", id: "abc",
		},
		{
			name: "unrecognized path denies without calling the gate",
			req:  Request{RequestMethod: "POST", RequestURI: "/vx/containers/create"}, msgHas: "BAD_REQUEST",
		},
		{
			name: "unparseable URI naming containers denies",
			req:  Request{RequestMethod: "POST", RequestURI: "/v1.47/containers/create%zz"}, msgHas: "BAD_REQUEST",
		},
		{name: "GET on create path passes", req: Request{RequestMethod: "GET", RequestURI: "/v1.47/containers/create"}, allow: true},
		{
			name: "panic in start denies", req: Request{RequestMethod: "POST", RequestURI: "/containers/abc/start"},
			panics: true, msgHas: "UPSTREAM_UNAVAILABLE", starts: 1, endpoint: "containers/start", id: "abc",
		},
		{
			name: "create through gate", req: Request{RequestMethod: "POST", RequestURI: "/v1.47/containers/create", RequestBody: []byte(`{"Image":"x"}`)},
			msgHas: "stub deny create", creates: 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			g := &stubGate{panics: c.panics}
			h := &Handler{Gate: g, Log: discard}
			raw, err := json.Marshal(c.req)
			if err != nil {
				t.Fatal(err)
			}
			r := post(t, h, "/AuthZPlugin.AuthZReq", bytes.NewReader(raw))
			if r.Allow != c.allow || !strings.Contains(r.Msg, c.msgHas) {
				t.Errorf("got %+v, want allow=%v msg containing %q", r, c.allow, c.msgHas)
			}
			if g.creates.Load() != c.creates || g.starts.Load() != c.starts {
				t.Errorf("gate calls create=%d start=%d, want %d %d", g.creates.Load(), g.starts.Load(), c.creates, c.starts)
			}
			if c.starts > 0 && (g.lastEP.Load() != c.endpoint || g.lastID.Load() != c.id) {
				t.Errorf("start(%v, %v), want (%q, %q)", g.lastEP.Load(), g.lastID.Load(), c.endpoint, c.id)
			}
		})
	}
}

func TestHandlerUnknownPath(t *testing.T) {
	t.Parallel()
	g := &stubGate{}
	h := &Handler{Gate: g, Log: discard}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/AuthZPlugin.Other", nil))
	if rec.Code != http.StatusNotFound || g.creates.Load()+g.starts.Load() != 0 {
		t.Errorf("unknown plugin path: %d", rec.Code)
	}
}

type errReader struct{ data string }

func (e *errReader) Read(p []byte) (int, error) {
	if e.data == "" {
		return 0, errors.New("connection reset")
	}
	n := copy(p, e.data)
	e.data = e.data[n:]
	return n, nil
}

// A body that cannot be read is treated like one that cannot be parsed.
func TestHandlerBodyReadError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		partial string
		allow   bool
	}{
		{`{"RequestMethod":"POST","RequestUri":"/v1.47/containers/create`, false},
		{`{"RequestMethod":"GET","RequestUri":"/v1.47/info`, true},
		{``, true},
	}
	for _, c := range cases {
		g := &stubGate{}
		r := post(t, &Handler{Gate: g, Log: discard}, "/AuthZPlugin.AuthZReq", &errReader{data: c.partial})
		if r.Allow != c.allow || g.creates.Load() != 0 {
			t.Errorf("%q: allow=%v, want %v", c.partial, r.Allow, c.allow)
		}
	}
}

// checkAuthZReq posts raw to both phases and checks the invariants.
func checkAuthZReq(t *testing.T, raw []byte) {
	t.Helper()
	g := &stubGate{}
	h := &Handler{Gate: g, Log: discard}

	if r := post(t, h, "/AuthZPlugin.AuthZRes", bytes.NewReader(raw)); !r.Allow {
		t.Fatalf("response phase denied: %q", raw)
	}

	r := post(t, h, "/AuthZPlugin.AuthZReq", bytes.NewReader(raw))
	calls := g.creates.Load() + g.starts.Load()
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		want := !strings.Contains(string(raw), "/containers/create")
		if r.Allow != want || calls != 0 {
			t.Fatalf("unparseable request %q: allow=%v calls=%d, want allow=%v", raw, r.Allow, calls, want)
		}
		return
	}
	kind, _, _, _ := Classify(req.RequestMethod, req.RequestURI)
	switch kind {
	case passThrough:
		if !r.Allow || calls != 0 {
			t.Fatalf("non-gated %s %q: allow=%v calls=%d", req.RequestMethod, req.RequestURI, r.Allow, calls)
		}
	case unrecognized:
		if r.Allow || calls != 0 {
			t.Fatalf("unrecognized POST %q allowed (calls=%d)", req.RequestURI, calls)
		}
	case create, start:
		if r.Allow || calls != 1 {
			t.Fatalf("gated %s %q: allow=%v calls=%d; the gate's deny must stand", req.RequestMethod, req.RequestURI, r.Allow, calls)
		}
	}
	if !strings.EqualFold(req.RequestMethod, http.MethodPost) && !r.Allow {
		t.Fatalf("non-POST %s %q denied", req.RequestMethod, req.RequestURI)
	}
}

func FuzzAuthZReq(f *testing.F) {
	for _, m := range seedMethods {
		for _, u := range seedURIs {
			raw, err := json.Marshal(Request{
				User: "alice", RequestMethod: m, RequestURI: u,
				RequestBody: []byte(`{"Image":"nginx"}`), RequestHeaders: map[string]string{"Content-Type": "application/json"},
			})
			if err != nil {
				f.Fatal(err)
			}
			f.Add(raw)
		}
	}
	for _, s := range []string{
		``, `null`, `[]`, `{}`, `not json`, `{"RequestUri": "/containers/create", "RequestBody": 5}`,
		`{"RequestMethod":"POST","RequestUri":"/containers/create","RequestBody":"!!"}`,
		`{"RequestMethod":"POST","RequestUri":"/containers/create"`,
		`{"RequestMethod":"POST","RequestUri":"/containers/x/start","RequestMethod":"GET"}`,
		`{"requestmethod":"POST","requesturi":"/containers/create"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		checkAuthZReq(t, raw)
	})
}

func FuzzServeHTTP(f *testing.F) {
	for _, m := range seedMethods {
		for _, u := range seedURIs {
			f.Add(m, u, []byte(`{"Image":"ghcr.io/acme/api:1"}`), "alice")
		}
	}
	f.Add("POST", "/v1.47/containers/create", []byte("\xff\xfe"), "\xff")
	f.Fuzz(func(t *testing.T, method, uri string, body []byte, user string) {
		raw, err := json.Marshal(Request{User: user, RequestMethod: method, RequestURI: uri, RequestBody: body})
		if err != nil {
			t.Fatal(err)
		}
		checkAuthZReq(t, raw)
	})
}

func BenchmarkClassify(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		for _, u := range seedURIs {
			Classify("POST", u)
		}
	}
}

func BenchmarkServeHTTP(b *testing.B) {
	h := &Handler{Gate: &stubGate{allow: true}, Log: discard}
	raw, err := json.Marshal(Request{
		User: "alice", RequestMethod: "POST", RequestURI: "/v1.47/containers/create?name=web",
		RequestBody: []byte(`{"Image":"ghcr.io/acme/api:1","Cmd":["serve"]}`),
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/AuthZPlugin.AuthZReq", bytes.NewReader(raw)))
		if !bytes.HasPrefix(rec.Body.Bytes(), []byte(`{"Allow":true`)) {
			b.Fatal(rec.Body.String())
		}
	}
}
