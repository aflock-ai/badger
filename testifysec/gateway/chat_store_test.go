package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// OpenCode 2.0 sends "store":false on every Chat Completions request. That is
// the no-retention value, so it is admitted and forwarded unchanged; any other
// value could ask the provider to retain the conversation and stays refused.
func TestChatStoreFalseAdmittedOtherValuesRefused(t *testing.T) {
	c := Config{Model: "approved", Spool: privateTemp(t), MaxRecords: 16, MaxOfflineSeconds: 60, DevelopmentLoopback: true, ProviderURL: "https://provider.test/v1/chat/completions", TimeoutSeconds: 5}
	_ = os.Chmod(c.Spool, 0700)
	s, err := openSpool(c)
	if err != nil {
		t.Fatal(err)
	}
	var forwarded []string
	g := &Gateway{config: c, spool: s, active: make(chan struct{}, 1), client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		forwarded = append(forwarded, string(b))
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))}, nil
	})}}
	run := func(body string) int {
		w := httptest.NewRecorder()
		g.ServeHTTP(w, httptest.NewRequest("POST", c.requestPath(), strings.NewReader(body)))
		return w.Code
	}
	for _, store := range []string{`true`, `null`, `"false"`, `0`, `{}`} {
		if code := run(`{"model":"approved","messages":[{"role":"user","content":"hi"}],"store":` + store + `}`); code != 400 {
			t.Fatalf("store:%s admitted with %d", store, code)
		}
	}
	if len(forwarded) != 0 {
		t.Fatal("refused store value reached the provider")
	}
	ok := `{"model":"approved","messages":[{"role":"user","content":"hi"}],"store":false,"max_completion_tokens":32,"stream_options":{"include_usage":true}}`
	if code := run(ok); code != 200 {
		t.Fatalf("store:false refused with %d", code)
	}
	if len(forwarded) != 1 || forwarded[0] != ok {
		t.Fatalf("store:false not forwarded unchanged: %q", forwarded)
	}
}
