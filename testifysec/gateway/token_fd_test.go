// jade:ring local
package main

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

// waitFor polls cond for up to two seconds; the credential is updated by another goroutine.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A provider credential handed over a pipe lives only in the gateway's memory: each line replaces
// it, and when the pipe closes the gateway stops calling the provider.
func TestProviderTokenFromPipe(t *testing.T) {
	c := Config{Model: "approved", Spool: privateTemp(t), MaxRecords: 16, MaxOfflineSeconds: 60, DevelopmentLoopback: true,
		ProviderURL: "https://provider.test/v1/chat/completions", TimeoutSeconds: 5, ProviderTokenFD: 3}
	_ = os.Chmod(c.Spool, 0700)
	s, err := openSpool(c)
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	g := &Gateway{config: c, spool: s, active: make(chan struct{}, 1), client: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r.Header.Get("Authorization"))
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"choices":[]}`))}, nil
	})}}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go g.provider.follow(pr)
	call := func() int {
		w := httptest.NewRecorder()
		g.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"approved","messages":[{"role":"user","content":"hi"}]}`)))
		return w.Code
	}
	if code := call(); code != 503 || len(seen) != 0 {
		t.Fatalf("before any credential: %d, %d provider calls", code, len(seen))
	}
	io.WriteString(pw, "first-token\n")
	waitFor(t, func() bool { return g.provider.get() == "first-token" })
	if code := call(); code != 200 || seen[len(seen)-1] != "Bearer first-token" {
		t.Fatalf("first token: %d %v", code, seen)
	}
	io.WriteString(pw, "second-token\n")
	waitFor(t, func() bool { return g.provider.get() == "second-token" })
	if call(); seen[len(seen)-1] != "Bearer second-token" {
		t.Fatalf("rotated token: %v", seen)
	}
	io.WriteString(pw, "bad\x00token\n")
	waitFor(t, func() bool { return g.provider.get() == "" })
	io.WriteString(pw, "crlf-token\n")
	waitFor(t, func() bool { return g.provider.get() == "crlf-token" })
	io.WriteString(pw, "crlf-token\r\n")
	waitFor(t, func() bool { return g.provider.get() == "" })
	calls := len(seen)
	if code := call(); code != 503 || len(seen) != calls {
		t.Fatalf("after a CRLF line: %d, provider called %d times", code, len(seen)-calls)
	}
	io.WriteString(pw, "third-token\n")
	waitFor(t, func() bool { return g.provider.get() == "third-token" })
	pw.Close()
	waitFor(t, func() bool { return g.provider.get() == "" })
	calls = len(seen)
	if code := call(); code != 503 || len(seen) != calls {
		t.Fatalf("after the pipe closed: %d, provider called %d times", code, len(seen)-calls)
	}
	entries, _ := os.ReadDir(c.Spool)
	refused := false
	for _, e := range entries {
		raw, _ := os.ReadFile(filepath.Join(c.Spool, e.Name()))
		var rec Record
		_ = json.Unmarshal(raw, &rec)
		if rec.Outcome == "credential-unavailable" {
			refused = true
		}
		if strings.Contains(string(raw), "token") && strings.Contains(string(raw), "first-token") {
			t.Fatal("credential in the spool")
		}
	}
	if !refused {
		t.Fatal("the refusal was not recorded")
	}
}

func TestProviderTokenSourceIsExactlyOne(t *testing.T) {
	for name, set := range map[string]func(*Config){
		"file":     func(c *Config) {},
		"fd":       func(c *Config) { c.ProviderTokenFile, c.ProviderTokenFD = "", 3 },
		"both":     func(c *Config) { c.ProviderTokenFD = 3 },
		"neither":  func(c *Config) { c.ProviderTokenFile = "" },
		"stdio fd": func(c *Config) { c.ProviderTokenFile, c.ProviderTokenFD = "", 2 },
		"negative": func(c *Config) { c.ProviderTokenFile, c.ProviderTokenFD = "", -1 },
		"relative": func(c *Config) { c.ProviderTokenFile = "provider.token" },
	} {
		t.Run(name, func(t *testing.T) {
			c := v2ConfigFixture(t)
			set(&c)
			data, _ := json.Marshal(c)
			path := filepath.Join(filepath.Dir(c.Spool), "config.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := readConfig(path)
			if want := name == "file" || name == "fd"; (err == nil) != want {
				t.Fatalf("%s: %v", name, err)
			}
		})
	}
}
