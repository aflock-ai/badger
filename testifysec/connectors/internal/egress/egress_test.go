package egress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sentinel = "SENTINEL-TOKEN-7f3a9c"

func tokenFile(t *testing.T, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newClient(t *testing.T, base string, scheme AuthScheme, insecure bool) *Client {
	t.Helper()
	c, err := New(Config{BaseURL: base, Token: FileToken(tokenFile(t, sentinel)), Scheme: scheme, InsecureLoopbackHTTP: insecure})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConfigRefusals(t *testing.T) {
	tok := FileToken(tokenFile(t, sentinel))
	for _, tc := range []struct {
		name, base string
		insecure   bool
	}{
		{"http without the test flag", "http://127.0.0.1:8080", false},
		{"http to a non-loopback host even with the flag", "http://jira.example.invalid", true},
		{"other scheme", "ftp://jira.example.invalid", false},
		{"userinfo", "https://user:pw@jira.example.invalid", false},
		{"query", "https://jira.example.invalid/?x=1", false},
		{"relative", "/rest/api/2", false},
	} {
		if _, err := New(Config{BaseURL: tc.base, Token: tok, InsecureLoopbackHTTP: tc.insecure}); err == nil {
			t.Errorf("%s: New accepted %q", tc.name, tc.base)
		}
	}
	if _, err := New(Config{BaseURL: "https://jira.example.invalid/jira", Token: tok}); err != nil {
		t.Errorf("https base refused: %v", err)
	}
}

func TestHeaderSchemesAndTokenReadPerRequest(t *testing.T) {
	var got []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Clone())
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	path := tokenFile(t, "first")
	c, err := New(Config{BaseURL: srv.URL, Token: FileToken(path), Scheme: PrivateToken, InsecureLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), "/a", nil); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("second"), 0o600) // the broker rotated it
	if _, err := c.Get(context.Background(), "/a", nil); err != nil {
		t.Fatal(err)
	}
	if got[0].Get("PRIVATE-TOKEN") != "first" || got[1].Get("PRIVATE-TOKEN") != "second" || got[0].Get("Authorization") != "" {
		t.Errorf("headers: %v", got)
	}
	b := newClient(t, srv.URL, Bearer, true)
	b.Get(context.Background(), "/a", nil)
	if got[2].Get("Authorization") != "Bearer "+sentinel {
		t.Errorf("bearer header: %q", got[2].Get("Authorization"))
	}
}

func TestPathsCannotLeaveTheBase(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	c := newClient(t, srv.URL+"/rest/api/2", Bearer, true)
	for _, p := range []string{"//evil.example.invalid/x", "https://evil.example.invalid/", "/../admin", "/a/%2e%2e/%2e%2e/admin", "issue", "/a?x=1", "/a#f"} {
		if _, err := c.Get(context.Background(), p, nil); err == nil {
			t.Errorf("path %q was accepted", p)
		}
	}
	if hits != 0 {
		t.Errorf("%d refused requests reached the server", hits)
	}
	if _, err := c.Get(context.Background(), "/projects/a%2Fb", nil); err != nil {
		t.Errorf("an escaped slash inside a segment was refused: %v", err)
	}
}

func TestRedirectOffHostRefused(t *testing.T) {
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect followed to another host with headers %v", r.Header)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/same":
			http.Redirect(w, r, "/api/other", http.StatusFound)
		case "/api/other":
			w.Write([]byte("ok"))
		case "/api/outside":
			http.Redirect(w, r, "/login", http.StatusFound)
		default:
			http.Redirect(w, r, evil.URL+"/steal", http.StatusFound)
		}
	}))
	defer srv.Close()
	c := newClient(t, srv.URL+"/api", PrivateToken, true)
	if body, err := c.Get(context.Background(), "/same", nil); err != nil || string(body) != "ok" {
		t.Errorf("same-base redirect: %q %v", body, err)
	}
	for _, p := range []string{"/offhost", "/outside"} {
		if _, err := c.Get(context.Background(), p, nil); err == nil || strings.Contains(err.Error(), sentinel) {
			t.Errorf("%s: err %v", p, err)
		}
	}
}

func TestResponseCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", 2048)))
	}))
	defer srv.Close()
	c, _ := New(Config{BaseURL: srv.URL, Token: FileToken(tokenFile(t, sentinel)), InsecureLoopbackHTTP: true, MaxResponseBytes: 1024})
	if _, err := c.Get(context.Background(), "/", nil); err == nil || !strings.Contains(err.Error(), "1024") {
		t.Errorf("oversized response: %v", err)
	}
}

func TestStatusMappingNeverLeaksToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A hostile or careless service echoes the credential back.
		w.Header().Set("Retry-After", "17")
		w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/401":
			w.WriteHeader(401)
		case "/403":
			w.WriteHeader(403)
		case "/404":
			w.WriteHeader(404)
		case "/429":
			w.WriteHeader(429)
		case "/400":
			w.WriteHeader(400)
		default:
			w.WriteHeader(502)
		}
		w.Write([]byte(`{"errorMessages":["bad JQL near ` + r.Header.Get("Authorization") + `"]}`))
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, Bearer, true)
	want := map[string]string{"/401": "credential was rejected", "/403": "lacks permission", "/404": "not found", "/429": "retry after 17", "/400": "bad JQL", "/502": "HTTP 502"}
	for p, w := range want {
		_, err := c.Get(context.Background(), p, nil)
		var he *HTTPError
		if !errors.As(err, &he) {
			t.Fatalf("%s: %v is not an HTTPError", p, err)
		}
		if !strings.Contains(err.Error(), w) || strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), "X-Echo") {
			t.Errorf("%s: %q", p, err)
		}
	}
	if got := c.Redact("x " + sentinel + " y"); strings.Contains(got, sentinel) {
		t.Errorf("Redact left the token: %q", got)
	}
}

func TestMalformedTokenFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("request sent") }))
	defer srv.Close()
	for _, v := range []string{"", "a\r\nX-Injected: " + sentinel} {
		c, _ := New(Config{BaseURL: srv.URL, Token: FileToken(tokenFile(t, v)), InsecureLoopbackHTTP: true})
		if _, err := c.Get(context.Background(), "/", nil); err == nil || strings.Contains(err.Error(), sentinel) {
			t.Errorf("token %q: %v", v, err)
		}
	}
}

func TestPagingHeadersOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Next-Page", "3")
		w.Header().Set("Link", `<https://svc.example.invalid/x?page=3>; rel="next"`)
		w.Header().Set("Set-Cookie", "session="+sentinel)
		w.Write([]byte("[]"))
	}))
	defer srv.Close()
	_, h, err := newClient(t, srv.URL, Bearer, true).GetWithHeaders(context.Background(), "/x", nil)
	if err != nil || h.Get("X-Next-Page") != "3" || h.Get("Link") == "" || h.Get("Set-Cookie") != "" || len(h) != 2 {
		t.Errorf("headers %v %v", h, err)
	}
}

func TestHTTPErrorBodyScrubbedAndCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"errorMessages":["field x is required"],"echo":"` + r.Header.Get("Authorization") + `","pad":"` + strings.Repeat("p", 20000) + `"}`))
	}))
	defer srv.Close()
	_, err := newClient(t, srv.URL, Bearer, true).Get(context.Background(), "/x", nil)
	var he *HTTPError
	if !errors.As(err, &he) || !strings.Contains(he.Body, "field x is required") || strings.Contains(he.Body, sentinel) ||
		len(he.Body) != 16<<10 || len(he.Detail) > 303 || len(err.Error()) > 400 {
		t.Errorf("body %d detail %d: %v", len(he.Body), len(he.Detail), err)
	}
}

func TestTail(t *testing.T) {
	log := strings.Repeat("a", 3000) + "THE END"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ranged": // honours Range
			http.ServeContent(w, r, "log", time.Time{}, strings.NewReader(log))
		case "/empty":
			http.ServeContent(w, r, "log", time.Time{}, strings.NewReader(""))
		default: // ignores Range and streams more than the cap
			w.Write([]byte(log))
		}
	}))
	defer srv.Close()
	c, _ := New(Config{BaseURL: srv.URL, Token: FileToken(tokenFile(t, sentinel)), InsecureLoopbackHTTP: true, MaxResponseBytes: 1024})
	for _, p := range []string{"/ranged", "/streamed"} {
		b, dropped, err := c.Tail(context.Background(), p, nil, 100)
		if err != nil || len(b) != 100 || !strings.HasSuffix(string(b), "THE END") || !dropped {
			t.Errorf("%s: %q dropped=%v %v", p, b, dropped, err)
		}
		b, dropped, err = c.Tail(context.Background(), p, nil, 1024)
		if err != nil || len(b) != 1024 || !dropped {
			t.Errorf("%s at cap: %d dropped=%v %v", p, len(b), dropped, err)
		}
	}
	if b, dropped, err := c.Tail(context.Background(), "/empty", nil, 100); err != nil || len(b) != 0 || dropped {
		t.Errorf("empty: %q %v %v", b, dropped, err)
	}
	if _, _, err := c.Tail(context.Background(), "/ranged", nil, 2048); err == nil {
		t.Error("tail over the cap accepted")
	}
}

// Codex review on #166: a server that normalizes ";params" or backslashes before dot segments
// would let "/jira/..;/x" leave the base path.
func TestSemicolonAndBackslashSegmentsRefused(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jira/hop" {
			http.Redirect(w, r, "/jira/..;/other-app", http.StatusFound)
			return
		}
		hits++
	}))
	defer srv.Close()
	c := newClient(t, srv.URL+"/jira", Bearer, true)
	for _, p := range []string{"/..;/other-app", "/a/..%3B/x", "/a;jsessionid=1", "/a%5C..%5Cx", "/hop"} {
		if _, err := c.Get(context.Background(), p, nil); err == nil {
			t.Errorf("path %q was accepted", p)
		}
	}
	if hits != 0 {
		t.Errorf("%d refused requests reached a path outside the base", hits)
	}
}

// Codex review on #166: a tail cut inside the credential must not expose the rest of it.
func TestTailCutInsideCredential(t *testing.T) {
	body := strings.Repeat("x", 500) + "token=" + sentinel
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ranged" {
			http.ServeContent(w, r, "log", time.Time{}, strings.NewReader(body))
			return
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, Bearer, true)
	for _, p := range []string{"/ranged", "/streamed"} {
		for n := int64(1); n <= int64(len(sentinel))+8; n++ {
			b, _, err := c.Tail(context.Background(), p, nil, n)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(string(b), sentinel[len(sentinel)-1:]) || !strings.HasSuffix(string(b), "[redacted]") {
				t.Errorf("%s n=%d: credential bytes %q in tail", p, n, b)
			}
		}
	}
}

// Codex review on #166: a response buffered across many rotations is still scrubbed of the
// first credential.
func TestRedactAfterManyRotations(t *testing.T) {
	var echoes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.Header.Get("Authorization")))
	}))
	defer srv.Close()
	path := tokenFile(t, "rotation-0-"+sentinel)
	c, _ := New(Config{BaseURL: srv.URL, Token: FileToken(path), InsecureLoopbackHTTP: true})
	for i := range 10 {
		os.WriteFile(path, []byte(fmt.Sprintf("rotation-%d-%s", i, sentinel)), 0o600)
		b, err := c.Get(context.Background(), "/", nil)
		if err != nil {
			t.Fatal(err)
		}
		echoes = append(echoes, string(b))
	}
	if got := c.Redact(strings.Join(echoes, " ")); strings.Contains(got, sentinel) {
		t.Errorf("a rotated credential survived: %s", got)
	}
}

// Codex review on #166: an error body cut at a read limit inside an echoed credential keeps no
// piece of it.
func TestErrorBodyCutInsideCredential(t *testing.T) {
	for _, pad := range []int{16<<10 - 3, 32<<10 - 5, 1024 - 4} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			w.Write([]byte(strings.Repeat("e", pad) + strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") + strings.Repeat("z", 40<<10)))
		}))
		c, _ := New(Config{BaseURL: srv.URL, Token: FileToken(tokenFile(t, sentinel)), InsecureLoopbackHTTP: true, MaxResponseBytes: 1024})
		_, err1 := c.Get(context.Background(), "/", nil)
		_, _, err2 := c.Tail(context.Background(), "/", nil, 100)
		for _, err := range []error{err1, err2} {
			var he *HTTPError
			if !errors.As(err, &he) || strings.Contains(he.Body, sentinel[:3]) {
				t.Errorf("pad %d: body keeps part of the credential: ...%q", pad, he.Body[max(0, len(he.Body)-40):])
			}
		}
		srv.Close()
	}
}

// Codex review on #166: a 206 longer than the requested range is refused, not cut (a cut at
// its end could split a credential).
func TestTailOversizedRangeRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes 0-99/100")
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte(strings.Repeat("x", 95) + strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
	}))
	defer srv.Close()
	b, _, err := newClient(t, srv.URL, Bearer, true).Tail(context.Background(), "/", nil, 100)
	if err == nil || strings.Contains(string(b), sentinel[:3]) {
		t.Errorf("oversized range: %q %v", b, err)
	}
}

// Codex review on #166, fourth round: credentials that overlap are replaced whole, and the client
// keeps every credential of a session (refusing to send past its bound rather than forget one).
func TestRedactOverlappingAndManyRotations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	path := tokenFile(t, "abc123")
	c, _ := New(Config{BaseURL: srv.URL, Token: FileToken(path), InsecureLoopbackHTTP: true})
	for i := range 300 {
		if i > 0 {
			os.WriteFile(path, []byte(fmt.Sprintf("abc123XYZ%d", i)), 0o600)
		}
		if _, err := c.Get(context.Background(), "/", nil); err != nil {
			t.Fatal(err)
		}
	}
	if got := c.Redact("a abc123XYZ299 b abc123XYZ1 c abc123 d"); got != "a [redacted] b [redacted] c [redacted] d" {
		t.Errorf("Redact: %q", got)
	}
	c.recent = c.recent[:0]
	for i := range maxCredentials {
		c.recent = append(c.recent, fmt.Sprint("t", i))
	}
	os.WriteFile(path, []byte("one-more"), 0o600)
	if _, err := c.Get(context.Background(), "/", nil); err == nil || !strings.Contains(err.Error(), "rotations") {
		t.Errorf("past the bound: %v", err)
	}
}

// Codex review on #166, fifth round: rotation, overlap and truncation together leave no piece of
// any credential.
func TestRedactOverlapAtCuts(t *testing.T) {
	c := &Client{recent: []string{"abc123", "abc123XYZ"}}
	for in, want := range map[string]string{
		"123XYZ tail":        "[redacted] tail",
		"XYZ tail":           "[redacted] tail",
		"head abc123XY":      "head [redacted]",
		"head abc1":          "head [redacted]",
		"x abc123XYZ abc123": "x [redacted] [redacted]",
	} {
		got := c.redact(in, !strings.HasPrefix(in, "head") && !strings.HasPrefix(in, "x "), strings.HasPrefix(in, "head"))
		if got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if got := string(c.redactTail([]byte("123XYZ end"), true)); got != "[redacted] end" {
		t.Errorf("redactTail: %q", got)
	}
	if got := c.redactCut("start abc123XY"); got != "start [redacted]" {
		t.Errorf("redactCut: %q", got)
	}
}

// Codex review on #166, sixth round: bytes a server sends after a response (here the echoed
// credential after a zero-length body) never reach the process log.
func TestUnsolicitedBytesNotLogged(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" + r.Header.Get("Authorization"))
		buf.Flush()
		time.Sleep(200 * time.Millisecond)
		conn.Close()
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, Bearer, true)
	for range 3 {
		c.Get(context.Background(), "/", nil)
	}
	time.Sleep(300 * time.Millisecond)
	if strings.Contains(logged.String(), sentinel) {
		t.Errorf("credential logged: %s", logged.String())
	}
}

func TestContainsCredentialIgnoresCase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := newClient(t, srv.URL, Bearer, true)
	if c.ContainsCredential("x " + strings.ToUpper(sentinel)) {
		t.Error("credential reported before one was sent")
	}
	c.Get(context.Background(), "/", nil)
	if !c.ContainsCredential("x "+strings.ToUpper(sentinel)) || c.ContainsCredential("nothing here") {
		t.Error("ContainsCredential")
	}
}
