package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// GET /v1/limits is the gateway's one route besides the model: it asks the provider (the model
// broker) for this workspace's limits with the provisioned credential, and passes back a small JSON
// object or a fixed 404. The worker names nothing: not the destination, not the credential.
func TestLimitsRouteForwardsOnlyTheFixedRequest(t *testing.T) {
	g, _ := gatewayV3Fixture(t, nil)
	var asked *http.Request
	answer := func(status int, body string) {
		g.client = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
			asked = r
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
	}
	get := func(method, path string, header map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		for k, v := range header {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w
	}
	answer(200, `{"steps":80,"context":null,"output":8192,"timeout_seconds":200}`)
	// A caller's own credential is never what the broker sees (LIM-07).
	w := get("GET", "/v1/limits", map[string]string{"Authorization": "Bearer bbt_someone_else", "X-Forwarded-Host": "evil.test"})
	if w.Code != 200 || w.Body.String() != `{"steps":80,"context":null,"output":8192,"timeout_seconds":200}` {
		t.Fatalf("served %d %q", w.Code, w.Body)
	}
	if asked.Method != "GET" || asked.URL.String() != "https://provider.test/v1/limits" || asked.Header.Get("Authorization") != "Bearer fixture-token" ||
		asked.Header.Get("X-Forwarded-Host") != "" || asked.Body != nil && asked.Body != http.NoBody {
		t.Fatalf("asked %s %s %v", asked.Method, asked.URL, asked.Header)
	}
	// The model's one slot is not taken: a limits read works while a model call runs.
	g.active <- struct{}{}
	if w := get("GET", "/v1/limits", nil); w.Code != 200 {
		t.Fatalf("while a model call runs: %d", w.Code)
	}
	<-g.active
	for name, reply := range map[string][2]any{"not a broker": {404, `not found`}, "refused": {401, `{}`},
		"not JSON": {200, `steps=999`}, "not an object": {200, `[1]`}, "too large": {200, `{"a":"` + strings.Repeat("x", 1100) + `"}`},
		"duplicate key": {200, `{"steps":1,"steps":999}`}} {
		answer(reply[0].(int), reply[1].(string))
		if w := get("GET", "/v1/limits", nil); w.Code != 404 || strings.Contains(w.Body.String(), "999") {
			t.Errorf("%s: %d %q, want the fixed 404", name, w.Code, w.Body)
		}
	}
	// Nothing else is reachable through it: no other method, no query, no admin path (LIM-06).
	asked = nil
	for _, c := range [][2]string{{"POST", "/v1/limits"}, {"GET", "/v1/limits?principal=bob"}, {"PUT", "/admin/v1/quotas"},
		{"GET", "/admin/v1/quotas"}, {"GET", "/v1/usage"}} {
		if w := get(c[0], c[1], nil); w.Code != 400 {
			t.Errorf("%s %s: %d", c[0], c[1], w.Code)
		}
	}
	if asked != nil {
		t.Fatal("a refused request reached the provider")
	}
	// Every one of them, served or not, is an audit record.
	entries, _ := os.ReadDir(g.config.Spool)
	if len(entries) < 13 {
		t.Fatalf("%d audit records", len(entries))
	}
}
