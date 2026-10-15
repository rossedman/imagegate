package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/rossedman/image-gate/internal/gate"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		method, uri string
		kind        gated
		endpoint    string
		id          string
	}{
		{"POST", "/v1.47/containers/create?name=web", create, "containers/create", ""},
		{"POST", "/containers/create", create, "containers/create", ""},
		{"POST", "/v1.47/containers/abc123/start", start, "containers/start", "abc123"},
		{"POST", "/v1.47/containers/web/restart?t=5", start, "containers/restart", "web"},
		{"GET", "/v1.47/containers/create", passThrough, "", ""},
		{"GET", "/v1.47/images/nginx/json", passThrough, "", ""},
		{"GET", "/_ping", passThrough, "", ""},
		{"POST", "/v1.47/plugins/imagegate/disable", passThrough, "", ""},
		{"POST", "/v1.47/containers/abc/stop", passThrough, "", ""},
		{"POST", "/v1.47/images/create?fromImage=nginx", passThrough, "", ""},
		{"POST", "/v1.47/containers/abc/exec", passThrough, "", ""},
		// dockerd accepts any [0-9.]+ version and names containing "/".
		{"POST", "/v1.45.0/containers/create", create, "containers/create", ""},
		{"POST", "/v1.45.0.1/containers/abc/start", start, "containers/start", "abc"},
		{"POST", "/v1/containers/create", create, "containers/create", ""},
		{"POST", "/v1.45/containers/web/db/start", start, "containers/start", "web/db"},
		{"POST", "/v1.45/containers/web/db/restart", start, "containers/restart", "web/db"},
		{"post", "/v1.45/containers/create", create, "containers/create", ""},
		{"POST", "/v1.45/containers/create/", create, "containers/create", ""},
		{"POST", "/vx/containers/create", unrecognized, "", ""},
		{"POST", "/foo/containers/create", unrecognized, "", ""},
		{"POST", "/v1.45/containers/start", passThrough, "", ""},
	}
	for _, c := range cases {
		kind, endpoint, id, _ := Classify(c.method, c.uri)
		if kind != c.kind || endpoint != c.endpoint || id != c.id {
			t.Errorf("Classify(%s %s) = %v %q %q", c.method, c.uri, kind, endpoint, id)
		}
	}
}

type fakeGate struct {
	panics bool
	calls  int
	query  url.Values
}

func (f *fakeGate) Create(_ context.Context, _ string, body []byte, q url.Values) gate.Decision {
	f.calls++
	f.query = q
	if f.panics {
		panic("boom")
	}
	return gate.Decision{Msg: "denied: " + string(body)}
}

func (f *fakeGate) Start(context.Context, string, string, string) gate.Decision {
	f.calls++
	return gate.Decision{Allow: true}
}

func call(t *testing.T, h http.Handler, path string, body any) Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", path, bytes.NewReader(raw)))
	var resp Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("%s: %v: %s", path, err, rec.Body.String())
	}
	return resp
}

func TestHandler(t *testing.T) {
	g := &fakeGate{}
	h := &Handler{Gate: g, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/Plugin.Activate", nil))
	if rec.Body.String() != `{"Implements":["authz"]}`+"\n" {
		t.Errorf("activate = %s", rec.Body.String())
	}

	if r := call(t, h, "/AuthZPlugin.AuthZReq", Request{RequestMethod: "GET", RequestURI: "/v1.47/info"}); !r.Allow || g.calls != 0 {
		t.Error("GET must pass through without calling the gate")
	}
	r := call(t, h, "/AuthZPlugin.AuthZReq", Request{RequestMethod: "POST", RequestURI: "/v1.47/containers/create?platform=linux/arm64", RequestBody: []byte(`{"Image":"x"}`)})
	if r.Allow || r.Msg != `denied: {"Image":"x"}` || g.query.Get("platform") != "linux/arm64" {
		t.Errorf("create: %+v %v", r, g.query)
	}
	if r := call(t, h, "/AuthZPlugin.AuthZRes", Request{RequestMethod: "POST", RequestURI: "/v1.47/containers/create"}); !r.Allow {
		t.Error("response phase must always allow")
	}

	g.panics = true
	if r := call(t, h, "/AuthZPlugin.AuthZReq", Request{RequestMethod: "POST", RequestURI: "/containers/create"}); r.Allow {
		t.Error("a panic while gating a create must deny")
	}
	if r := call(t, h, "/AuthZPlugin.AuthZReq", Request{RequestMethod: "POST", RequestURI: "/v1.47/plugins/imagegate/disable"}); !r.Allow {
		t.Error("plugin management must never be blocked")
	}
}

func TestUnreadableRequest(t *testing.T) {
	h := &Handler{Gate: &fakeGate{}, Log: slog.Default()}
	for body, allow := range map[string]bool{
		`not json`: true,
		`{"RequestUri": "/containers/create", "RequestBody": 5}`: false,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/AuthZPlugin.AuthZReq", bytes.NewBufferString(body)))
		var r Response
		json.Unmarshal(rec.Body.Bytes(), &r)
		if r.Allow != allow {
			t.Errorf("%s: allow = %v", body, r.Allow)
		}
	}
}
