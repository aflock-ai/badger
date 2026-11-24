package broker

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Reasoning models can take minutes before the first response byte; a 30 s header timeout
// turned slow answers into 502s. The timeouts are operator config, defaulted for that.

func TestUpstreamTimeoutDefaultsFitReasoningModels(t *testing.T) {
	f := newFixture(t, true)
	u := f.cfg.Upstream
	if u.ResponseHeaderSeconds != 180 || u.RequestSeconds != 240 || u.ServerWriteSeconds != 250 {
		t.Fatalf("defaults %+v", u)
	}
	up := newUpstream(f.cfg.Routes, 1, nil, f.cfg.Upstream)
	if up.client.Timeout != 240*time.Second {
		t.Fatalf("client timeout %s", up.client.Timeout)
	}
	if tr := up.client.Transport.(*http.Transport); tr.ResponseHeaderTimeout != 180*time.Second {
		t.Fatalf("header timeout %s", tr.ResponseHeaderTimeout)
	}
	if got := f.cfg.ServerWriteTimeout(); got != 250*time.Second {
		t.Fatalf("server write timeout %s", got)
	}
}

func TestUpstreamTimeoutsFromConfig(t *testing.T) {
	f := newFixture(t, true)
	raw, _ := os.ReadFile(filepath.Join(f.dir, "config.json"))
	s := strings.Replace(string(raw), `"seed_policy_file"`, `"upstream": {"response_header_seconds": 60, "request_seconds": 90, "server_write_seconds": 100}, "seed_policy_file"`, 1)
	p := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(p, []byte(s), 0o600)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	up := newUpstream(cfg.Routes, 1, nil, cfg.Upstream)
	if up.client.Timeout != 90*time.Second || up.client.Transport.(*http.Transport).ResponseHeaderTimeout != 60*time.Second ||
		cfg.ServerWriteTimeout() != 100*time.Second {
		t.Fatal("config not applied")
	}
}

func TestUpstreamTimeoutsMustNest(t *testing.T) {
	f := newFixture(t, true)
	raw, _ := os.ReadFile(filepath.Join(f.dir, "config.json"))
	for name, u := range map[string]string{
		"header over total": `{"response_header_seconds": 300, "request_seconds": 240, "server_write_seconds": 250}`,
		"write not above":   `{"response_header_seconds": 180, "request_seconds": 240, "server_write_seconds": 240}`,
		"negative":          `{"response_header_seconds": -1, "request_seconds": 240, "server_write_seconds": 250}`,
		"absurd":            `{"response_header_seconds": 180, "request_seconds": 240, "server_write_seconds": 4000}`,
		"unknown field":     `{"response_header": 180}`,
	} {
		s := strings.Replace(string(raw), `"seed_policy_file"`, `"upstream": `+u+`, "seed_policy_file"`, 1)
		p := filepath.Join(t.TempDir(), "c.json")
		os.WriteFile(p, []byte(s), 0o600)
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSlowUpstreamWithinTheHeaderTimeoutIsServed(t *testing.T) {
	slow := newSlowServer(t, 1500*time.Millisecond)
	routes := []RouteConfig{{Model: "m", UpstreamURL: slow, AuthHeader: "api-key", KeyFile: writeKey(t)}}
	if err := routes[0].check(); err != nil {
		t.Fatal(err)
	}
	ok := newUpstream(routes, 1, nil, UpstreamConfig{ResponseHeaderSeconds: 3, RequestSeconds: 5, ServerWriteSeconds: 6})
	if status := callUpstream(t, ok); status != http.StatusOK {
		t.Fatalf("slow answer within the timeout: %d", status)
	}
	short := newUpstream(routes, 1, nil, UpstreamConfig{ResponseHeaderSeconds: 1, RequestSeconds: 5, ServerWriteSeconds: 6})
	if status := callUpstream(t, short); status != http.StatusBadGateway {
		t.Fatalf("answer past the header timeout: %d, want 502", status)
	}
}

func newSlowServer(t *testing.T, delay time.Duration) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/v1/chat/completions"
}

func writeKey(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	os.WriteFile(p, []byte("k\n"), 0o600)
	return p
}

func callUpstream(t *testing.T, up *upstream) int {
	t.Helper()
	if up.usage.db == nil {
		up.usage = openUsage(testLedger(t), testCeiling, time.Now())
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[]}`))
	w := httptest.NewRecorder()
	up.forward(w, r, "alice@example.com", testCeiling, usageAttr{}, up.routes["m"], &chatRequest{payload: map[string]json.RawMessage{
		"model": json.RawMessage(`"m"`), "messages": json.RawMessage(`[]`)}}, admission{})
	return w.Code
}
