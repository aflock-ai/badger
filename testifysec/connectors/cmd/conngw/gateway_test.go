package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/bundle"
	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// levels returns the classification levels' banners, lowest first, from the marking token table,
// so the test names no marking itself.
func levels(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("../../internal/marking/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	var tokens struct {
		Levels []struct {
			Banner string `json:"banner"`
		} `json:"levels"`
	}
	if err := json.Unmarshal(b, &tokens); err != nil || len(tokens.Levels) < 3 {
		t.Fatal("tokens.json levels unreadable")
	}
	out := make([]string, len(tokens.Levels))
	for i, l := range tokens.Levels {
		out[i] = l.Banner
	}
	return out
}

func mustSource(t *testing.T, name, banner string) source {
	t.Helper()
	m, err := marking.Parse(banner)
	if err != nil {
		t.Fatal(err)
	}
	return source{Name: name, BaseURL: "https://" + name + ".example.invalid", Grants: []grant{{Workspaces: []string{"ns/a"}}},
		TokenPath: "/tokens/" + name, UID: 61000, GID: 61000, Classification: banner, marking: m, scheme: marking.Current(), manifest: &bundle.Manifest{Schema: 1, Name: name, Version: "1.0.0", Tools: testTools}}
}

// fake is a connector: it answers every request that has an id and records the methods it saw.
type fake struct {
	mu   sync.Mutex
	seen []string
	id   []string
}

func (f *fake) serve(in io.Reader, out io.WriteCloser) {
	defer out.Close()
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		var m message
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		f.mu.Lock()
		f.seen = append(f.seen, m.Method)
		if len(m.ID) > 0 {
			f.id = append(f.id, string(m.ID))
		}
		f.mu.Unlock()
		if len(m.ID) == 0 {
			continue
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"content": []any{}}})
		if _, err := out.Write(append(b, '\n')); err != nil {
			return
		}
	}
}

func (f *fake) ids() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.id...)
}

func (f *fake) methods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.seen...)
}

func (f *fake) start(source) (*process, error) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go f.serve(inR, outW)
	return &process{in: inW, out: outR, stop: func() { _ = inR.Close(); _ = outR.Close() }}, nil
}

// session runs one stream in memory and returns a function that sends a line and reads the reply.
func session(t *testing.T, l *labels, ws string, src source, f *fake) (call func(line string) string, closeFn func()) {
	t.Helper()
	p, _ := f.start(src)
	clientR, clientW := io.Pipe() // caller -> gateway
	replyR, replyW := io.Pipe()   // gateway -> caller
	s := &stream{ws: ws, conn: src, labels: l, log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
	go func() { _ = s.answers(p.out, replyW) }()
	go func() { _ = s.requests(clientR, replyW, p.in); _ = p.in.Close() }()
	r := bufio.NewReader(replyR)
	call = func(line string) string {
		if _, err := clientW.Write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
		reply, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	return call, func() { _ = clientW.Close(); p.stop() }
}

const toolCall = `{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"x_get","arguments":{}}}`

func callID(id string) string { return strings.Replace(toolCall, "%s", id, 1) }

func TestReadingHighContentRefusesCallsToLowerConnectors(t *testing.T) {
	lv := levels(t)
	low, high := mustSource(t, "low", lv[0]), mustSource(t, "high", lv[2])
	l := newLabels()
	fLow, fHigh := &fake{}, &fake{}

	// Nothing read yet: the low connector answers, and the label is its marking.
	callLow, closeLow := session(t, l, "ws/a", low, fLow)
	defer closeLow()
	if got := callLow(callID("1")); strings.Contains(got, "refused") {
		t.Fatalf("first low call refused: %s", got)
	}
	// Reading the high connector raises the workspace's label.
	callHigh, closeHigh := session(t, l, "ws/a", high, fHigh)
	defer closeHigh()
	if got := callHigh(callID(`"h1"`)); strings.Contains(got, "refused") {
		t.Fatalf("high call refused: %s", got)
	}
	if label, _ := l.allows("ws/a", high.marking); marking.Banner(label) != lv[2] {
		t.Fatalf("label %q, want %q", marking.Banner(label), lv[2])
	}

	// Now a call to the low connector is answered by the gateway, and never reaches it.
	before := len(fLow.methods())
	got := callLow(callID("2"))
	if !strings.Contains(got, `"isError":true`) || !strings.Contains(got, "refused by the connector gateway") || !strings.Contains(got, `"id":2`) {
		t.Fatalf("low call after high read not refused: %s", got)
	}
	// Content-free requests still pass.
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":5,"method":"initialize","params":{}}`,
	} {
		if got := callLow(line); strings.Contains(got, "refused") {
			t.Fatalf("content-free request refused: %s", got)
		}
	}
	// Any other method with an id is checked like a tool call.
	if got := callLow(`{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{}}`); !strings.Contains(got, `"code":-32001`) {
		t.Fatalf("other method not checked: %s", got)
	}
	if seen := fLow.methods()[before:]; strings.Join(seen, ",") != "tools/list,ping,initialize" {
		t.Fatalf("low connector saw %v", seen)
	}

	// Another workspace has its own label.
	callOther, closeOther := session(t, l, "ws/b", low, &fake{})
	defer closeOther()
	if got := callOther(callID("1")); strings.Contains(got, "refused") {
		t.Fatalf("other workspace refused: %s", got)
	}
}

func TestLinesTheConnectorWouldMisreadNeverReachIt(t *testing.T) {
	lv := levels(t)
	f := &fake{}
	call, closeFn := session(t, newLabels(), "ws/a", mustSource(t, "low", lv[0]), f)
	defer closeFn()
	// Dropped: a batch, a line that is not JSON, and a request without a method. A later request
	// still works, so nothing was left half-read.
	got := call(strings.Join([]string{`[` + callID("7") + `]`, `not json`, `{"jsonrpc":"2.0","id":8}`, `{"jsonrpc":"2.0","id":9,"method":"ping"}`}, "\n"))
	if !strings.Contains(got, `"id":9`) {
		t.Fatalf("got %s", got)
	}
	if seen := f.methods(); strings.Join(seen, ",") != "ping" {
		t.Fatalf("connector saw %v", seen)
	}
	// A request without an id, or with a null one, is dropped unless it is a notification, so a call
	// cannot skip the check by leaving its id out.
	call(`{"jsonrpc":"2.0","method":"tools/call","params":{}}` + "\n" + `{"jsonrpc":"2.0","id":null,"method":"tools/call"}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" + `{"jsonrpc":"2.0","id":10,"method":"ping"}`)
	if seen := f.methods(); strings.Join(seen, ",") != "ping,notifications/initialized,ping" {
		t.Fatalf("connector saw %v", seen)
	}
	// An id that is not a string or a number, and an id already waiting for its answer, are refused.
	if got := call(`{"jsonrpc":"2.0","id":{"a":1},"method":"tools/call"}`); !strings.Contains(got, "must be a string or a number") {
		t.Fatalf("object id: %s", got)
	}
}

func TestAnIDInUseIsRefused(t *testing.T) {
	s := &stream{ws: "ws/a", conn: mustSource(t, "low", levels(t)[0]), labels: newLabels(), log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
	var forwarded, reply strings.Builder
	in := callID("1") + "\n" + callID("1") + "\n"
	if err := s.requests(strings.NewReader(in), &reply, &forwarded); err != nil {
		t.Fatal(err)
	}
	if strings.Count(forwarded.String(), "\n") != 1 || !strings.Contains(reply.String(), "already in use") {
		t.Fatalf("forwarded %q, replied %q", forwarded.String(), reply.String())
	}
}

// Anything the connector says that is not the answer to a content-free request raises the label:
// an answer to an id the gateway never saw, a notification, a line that is not JSON.
func TestUnattributedConnectorOutputRaisesTheLabel(t *testing.T) {
	lv := levels(t)
	for _, line := range []string{`{"jsonrpc":"2.0","id":42,"result":{}}`, `{"jsonrpc":"2.0","method":"notifications/message"}`, `garbage`} {
		l := newLabels()
		s := &stream{ws: "ws/a", conn: mustSource(t, "high", lv[2]), labels: l, log: slog.New(slog.DiscardHandler), pending: map[string]bool{"1": false}, perm: testPermit()}
		var out strings.Builder
		if err := s.answers(strings.NewReader(line+"\n"), &out); err != nil {
			t.Fatal(err)
		}
		if _, ok := l.allows("ws/a", mustSource(t, "low", lv[0]).marking); ok {
			t.Fatalf("%s did not raise the label", line)
		}
	}
	// The answer to a content-free request does not.
	l := newLabels()
	s := &stream{ws: "ws/a", conn: mustSource(t, "high", lv[2]), labels: l, log: slog.New(slog.DiscardHandler), pending: map[string]bool{"1": false}, perm: testPermit()}
	var out strings.Builder
	_ = s.answers(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{}}`+"\n"), &out)
	if _, ok := l.allows("ws/a", mustSource(t, "low", lv[0]).marking); !ok {
		t.Fatal("tools/list answer raised the label")
	}
}

type review struct {
	ws      string
	err     error
	adminID string
}

func (r review) workspace(context.Context, string) (string, error) { return r.ws, r.err }

func TestUpgradeChecksIdentityAndDeclarationFirst(t *testing.T) {
	lv := levels(t)
	src := mustSource(t, "jira", lv[1])
	src.Flags = map[string]string{"label-prefix": "x"}
	f := &fake{}
	g := &gateway{sources: map[string]source{"jira": src}, labels: newLabels(), log: slog.New(slog.DiscardHandler), start: f.start, maxStreams: 4, maxPerWorkspace: 4, idle: time.Hour}
	srv := httptest.NewServer(g)
	defer srv.Close()
	good := `{"classification":"` + lv[1] + `","writes":false,"flags":{"label-prefix":"x"}}`

	for _, tc := range []struct {
		name, path, upgrade, auth, decl string
		review                          review
		want                            int
	}{
		{"unknown connector", "/connectors/nope", "badger-mcp", "Bearer t", good, review{ws: "ns/a"}, 404},
		{"no upgrade", "/connectors/jira", "", "Bearer t", good, review{ws: "ns/a"}, 404},
		{"no token", "/connectors/jira", "badger-mcp", "", good, review{ws: "ns/a"}, 401},
		{"token refused", "/connectors/jira", "badger-mcp", "Bearer t", good, review{err: errUnauthenticated}, 401},
		{"not a workspace", "/connectors/jira", "badger-mcp", "Bearer t", good, review{err: errNotWorkspace}, 403},
		{"review down", "/connectors/jira", "badger-mcp", "Bearer t", good, review{err: errors.New("down")}, 503},
		// A workspace the connector is not granted to is refused however well it declares: the
		// declaration is not authorization.
		{"not granted", "/connectors/jira", "badger-mcp", "Bearer t", good, review{ws: "ns/b"}, 403},
		{"not granted, forged writes", "/connectors/jira", "badger-mcp", "Bearer t", `{"classification":"` + lv[1] + `","writes":true,"flags":{"label-prefix":"x"}}`, review{ws: "ns/b"}, 403},
		{"no declaration", "/connectors/jira", "badger-mcp", "Bearer t", "", review{ws: "ns/a"}, 409},
		{"other marking", "/connectors/jira", "badger-mcp", "Bearer t", `{"classification":"` + lv[0] + `","flags":{"label-prefix":"x"}}`, review{ws: "ns/a"}, 409},
		{"writes on", "/connectors/jira", "badger-mcp", "Bearer t", `{"classification":"` + lv[1] + `","writes":true,"flags":{"label-prefix":"x"}}`, review{ws: "ns/a"}, 409},
		{"other flags", "/connectors/jira", "badger-mcp", "Bearer t", `{"classification":"` + lv[1] + `"}`, review{ws: "ns/a"}, 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g.review = tc.review
			req, _ := http.NewRequest("GET", srv.URL+tc.path, nil)
			req.Header.Set("Upgrade", tc.upgrade)
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Authorization", tc.auth)
			req.Header.Set("Badger-Connector", tc.decl)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != tc.want {
				t.Fatalf("status %d, want %d", res.StatusCode, tc.want)
			}
		})
	}
	if len(f.methods()) != 0 {
		t.Fatalf("a refused upgrade reached the connector: %v", f.methods())
	}

	// A good upgrade switches protocols and carries the MCP stream.
	g.review = review{ws: "ns/a"}
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET /connectors/jira HTTP/1.1\r\nHost: x\r\nUpgrade: badger-mcp\r\nConnection: Upgrade\r\nAuthorization: Bearer t\r\nBadger-Connector: "+good+"\r\n\r\n")
	r := bufio.NewReader(c)
	res, err := http.ReadResponse(r, nil)
	if err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", res, err)
	}
	_, _ = io.WriteString(c, callID("1")+"\n")
	line, err := r.ReadString('\n')
	if err != nil || !strings.Contains(line, `"id":1`) {
		t.Fatalf("stream answer %q %v", line, err)
	}
}

func TestConfigRefusesAnyInvalidEntry(t *testing.T) {
	lv := levels(t)
	dir := t.TempDir()
	write := func(c string) string {
		p := dir + "/c.json"
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	key := strings.Repeat("A", 43) + "="
	digest := "sha256:" + strings.Repeat("0", 64)
	base := `"listen":":8443","certFile":"/c","keyFile":"/k","audience":"a","namespaces":["ws","team-b"],"labelsFile":"/var/lib/conngw/labels","hostDigest":"` + hostDigest + `","signers":{"vendor":"` + key + `"}`
	entry := func(extra string) string {
		return `{` + base + `,"connectors":[{"name":"jira","bundle":"/plugins/jira","digest":"` + digest + `","signer":"vendor","baseUrl":"https://j.example.invalid","tokenPath":"/t","socket":"/run/conngw/p.sock","uid":61000,"gid":61000,"grants":[{"workspaces":["ws/alice"]}],"classification":"` + lv[1] + `"` + extra + `}]}`
	}
	c, err := load(write(entry("")))
	if err != nil || len(c.Sources) != 1 || marking.Banner(c.Sources[0].marking) != lv[1] || c.MaxStreams != 64 || c.MaxStreamsPerWorkspace != 8 || *c.IdleMinutes != 30 {
		t.Fatalf("valid config: %v %+v", err, c)
	}
	if c, err := load(write(strings.Replace(entry(""), `"audience":"a"`, `"audience":"a","floor":"`+lv[0]+`","admins":["ctl/controller"],"inboxDir":"/var/lib/conngw/inbox"`, 1))); err != nil || c.floor == nil || marking.Banner(*c.floor) != lv[0] {
		t.Fatalf("valid controller config: %v", err)
	}
	if _, err := load(write(strings.Replace(entry(`,"writes":true`), `["ws/alice"]}`, `["ws/alice"],"writeTools":["jira_add"]},{"workspaces":["ws/*","team-b/bob"]}`, 1))); err != nil {
		t.Fatalf("valid grants: %v", err)
	}
	for name, bad := range map[string]string{
		"unknown field":      entry(`,"extra":1`),
		"executable field":   entry(`,"executable":"/x/jira"`),
		"workspaces list":    entry(`,"workspaces":["alice"]`),
		"relative bundle":    strings.Replace(entry(""), `"/plugins/jira"`, `"plugins/jira"`, 1),
		"no digest":          strings.Replace(entry(""), `"digest":"`+digest+`",`, "", 1),
		"bad digest":         strings.Replace(entry(""), digest, "sha256:abc", 1),
		"no host digest":     strings.Replace(entry(""), `"hostDigest":"`+hostDigest+`",`, "", 1),
		"bad host digest":    strings.Replace(entry(""), hostDigest, "sha256:abc", 1),
		"plugin is the host": strings.Replace(entry(""), digest, hostDigest, 1),
		"unknown signer":     strings.Replace(entry(""), `"signer":"vendor"`, `"signer":"other"`, 1),
		"bad signer key":     strings.Replace(entry(""), key, "not-a-key", 1),
		"bad marking":        strings.Replace(entry(""), lv[1], lv[1]+"//NOT A TOKEN", 1),
		"bad flag":           entry(`,"flags":{"Bad Flag":"x"}`),
		"writes by flag":     entry(`,"flags":{"enable-writes":"true"}`),
		"base by flag":       entry(`,"flags":{"base-url":"https://elsewhere.example.invalid"}`),
		"token by flag":      entry(`,"flags":{"token-file":"/other"}`),
		"marking by flag":    entry(`,"flags":{"classification":"x"}`),
		"ca by flag":         entry(`,"flags":{"ca-file":"/other"}`),
		"loopback by flag":   entry(`,"flags":{"insecure-loopback-http":"true"}`),
		"manifest by flag":   entry(`,"flags":{"manifest":"x"}`),
		"no audience":        strings.Replace(entry(""), `"audience":"a"`, `"audience":""`, 1),
		"repeated name":      strings.Replace(entry(""), `"connectors":[{`, `"connectors":[{"name":"jira","bundle":"/b","digest":"`+digest+`","signer":"vendor","tokenPath":"/t","socket":"/run/conngw/p.sock","uid":61001,"gid":61001,"grants":[{"workspaces":["ws/x"]}],"classification":"`+lv[0]+`"},{`, 1),
		"single namespace":   strings.Replace(entry(""), `"namespaces":["ws","team-b"]`, `"namespace":"ws"`, 1),
		"no namespaces":      strings.Replace(entry(""), `["ws","team-b"]`, `[]`, 1),
		"namespace format":   strings.Replace(entry(""), `["ws","team-b"]`, `["ws/x"]`, 1),
		"repeated namespace": strings.Replace(entry(""), `["ws","team-b"]`, `["ws","ws"]`, 1),
		"no grant":           strings.Replace(entry(""), `"grants":[{"workspaces":["ws/alice"]}],`, "", 1),
		"empty grant":        strings.Replace(entry(""), `["ws/alice"]`, `[]`, 1),
		"bare account":       strings.Replace(entry(""), `["ws/alice"]`, `["alice"]`, 1),
		"unknown namespace":  strings.Replace(entry(""), `["ws/alice"]`, `["other/alice"]`, 1),
		"bad account":        strings.Replace(entry(""), `["ws/alice"]`, `["ws/Alice"]`, 1),
		"repeated subject":   strings.Replace(entry(""), `["ws/alice"]}`, `["ws/alice"]},{"workspaces":["ws/alice"]}`, 1),
		"writes not allowed": strings.Replace(entry(""), `["ws/alice"]}`, `["ws/alice"],"writeTools":["jira_add"]}`, 1),
		"no labels file":     strings.Replace(entry(""), `,"labelsFile":"/var/lib/conngw/labels"`, "", 1),
		"relative labels":    strings.Replace(entry(""), `"/var/lib/conngw/labels"`, `"labels"`, 1),
		"negative bound":     strings.Replace(entry(""), `"audience":"a"`, `"audience":"a","maxStreams":-1`, 1),
		"floor, no admins":   strings.Replace(entry(""), `"audience":"a"`, `"audience":"a","floor":"`+lv[0]+`"`, 1),
		"admins, no floor":   strings.Replace(entry(""), `"audience":"a"`, `"audience":"a","admins":["ctl/controller"]`, 1),
		"bad floor":          strings.Replace(entry(""), `"audience":"a"`, `"audience":"a","floor":"`+lv[0]+`//ZZ","admins":["ctl/controller"]`, 1),
		"admin a workspace":  strings.Replace(entry(""), `"audience":"a"`, `"audience":"a","floor":"`+lv[0]+`","admins":["ws/controller"]`, 1),
		"inbox, no floor":    strings.Replace(entry(""), `"audience":"a"`, `"audience":"a","inboxDir":"/var/lib/conngw/inbox"`, 1),
		"relative inbox":     strings.Replace(entry(""), `"audience":"a"`, `"audience":"a","floor":"`+lv[0]+`","admins":["ctl/controller"],"inboxDir":"inbox"`, 1),
	} {
		if _, err := load(write(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// An id is one id however it is escaped: the connector writes "<" back as "<", so a call and a
// content-free request under the two spellings would otherwise let the call's answer pass as the
// content-free one, without raising the label.
func TestEscapedSpellingsOfOneIDAreOneID(t *testing.T) {
	lv := levels(t)
	l := newLabels()
	s := &stream{ws: "ws/a", conn: mustSource(t, "high", lv[2]), labels: l, log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
	var forwarded, reply strings.Builder
	in := `{"jsonrpc":"2.0","id":"<","method":"tools/call","params":{"name":"x_get"}}` + "\n" + `{"jsonrpc":"2.0","id":"\u003c","method":"ping"}` + "\n"
	if err := s.requests(strings.NewReader(in), &reply, &forwarded); err != nil {
		t.Fatal(err)
	}
	if strings.Count(forwarded.String(), "\n") != 1 || !strings.Contains(reply.String(), "already in use") {
		t.Fatalf("forwarded %q, replied %q", forwarded.String(), reply.String())
	}
	// The connector's answer, in its own spelling, is the call's: it raises the label.
	var out strings.Builder
	if err := s.answers(strings.NewReader(`{"jsonrpc":"2.0","id":"\u003c","result":{}}`+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.allows("ws/a", mustSource(t, "low", lv[0]).marking); ok {
		t.Fatal("the call's answer did not raise the label")
	}
}

// When the connector side ends (its output too long to read, say) while a request is blocked writing
// to it, the connector is stopped and the relay returns; nothing is left running.
func TestRelayStopsTheConnectorWhenItsSideEnds(t *testing.T) {
	inR, inW := io.Pipe() // nobody reads the connector's input: a write blocks
	var stopped sync.Once
	stops := make(chan struct{})
	p := &process{in: inW, out: strings.NewReader(""), stop: func() {
		stopped.Do(func() { _ = inR.CloseWithError(io.ErrClosedPipe); close(stops) })
	}}
	callerR, callerW := io.Pipe()
	go func() { _, _ = callerW.Write([]byte(callID("1") + "\n")) }()
	s := &stream{ws: "ws/a", conn: mustSource(t, "low", levels(t)[0]), labels: newLabels(), log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
	returned := make(chan struct{})
	go func() { s.relay(callerR, nopCloser{io.Discard}, p, time.Hour, time.Hour); close(returned) }()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not return")
	}
	select {
	case <-stops:
	default:
		t.Fatal("connector not stopped")
	}
}

// The key itself: both spellings of one id are one key, whatever the decoder hands over.
func TestCanonicalID(t *testing.T) {
	if canonical(json.RawMessage(`"<"`)) != canonical(json.RawMessage(`"\u003c"`)) ||
		canonical(json.RawMessage(`"a"`)) != canonical(json.RawMessage(`"\u0061"`)) ||
		canonical(json.RawMessage(`1`)) == canonical(json.RawMessage(`"1"`)) {
		t.Fatal("ids not canonical")
	}
}

// A caller that stops sending but never reads again cannot hold the relay open: after the grace the
// connection is closed, which unblocks an answer stuck writing to it.
func TestRelayEndsWhenTheCallerStopsReading(t *testing.T) {
	reply := &stuck{closed: make(chan struct{})}
	stops := make(chan struct{})
	var once sync.Once
	p := &process{in: nopCloser{io.Discard}, out: strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{}}` + "\n"),
		stop: func() { once.Do(func() { close(stops) }) }}
	s := &stream{ws: "ws/a", conn: mustSource(t, "low", levels(t)[0]), labels: newLabels(), log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
	returned := make(chan struct{})
	go func() { s.relay(strings.NewReader(""), reply, p, 50*time.Millisecond, time.Hour); close(returned) }()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not return")
	}
	<-stops
}

// stuck is a caller connection that never accepts a write until it is closed.
type stuck struct{ closed chan struct{} }

func (s *stuck) Write([]byte) (int, error) { <-s.closed; return 0, io.ErrClosedPipe }
func (s *stuck) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}

// When the caller stops sending and the connector never finishes, it is stopped after the grace.
func TestRelayStopsAConnectorThatOutlivesTheCaller(t *testing.T) {
	outR, outW := io.Pipe() // the connector never answers or exits
	stops := make(chan struct{})
	var once sync.Once
	p := &process{in: nopCloser{io.Discard}, out: outR, stop: func() { once.Do(func() { _ = outW.Close(); close(stops) }) }}
	s := &stream{ws: "ws/a", conn: mustSource(t, "low", levels(t)[0]), labels: newLabels(), log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
	returned := make(chan struct{})
	go func() {
		s.relay(strings.NewReader(""), nopCloser{io.Discard}, p, 50*time.Millisecond, time.Hour)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not return")
	}
	<-stops
}

// A caller that floods refusals, stops reading and stops sending cannot hold the relay: the write
// deadline fails the stuck refusal, and the connector, still waiting for input, is stopped after
// the grace.
func TestRelayEndsWhenARefusalCannotBeWritten(t *testing.T) {
	lv := levels(t)
	l := newLabels()
	l.raise("ws/a", mustSource(t, "high", lv[2]).marking)
	var lines strings.Builder
	for i := range 64 {
		lines.WriteString(callID(fmt.Sprint(i)) + "\n")
	}
	callerSide, gatewaySide := net.Pipe() // nobody reads callerSide
	defer callerSide.Close()
	outR, outW := io.Pipe() // the connector waits for input and never answers
	stops := make(chan struct{})
	var once sync.Once
	p := &process{in: nopCloser{io.Discard}, out: outR, stop: func() { once.Do(func() { _ = outW.Close(); close(stops) }) }}
	s := &stream{ws: "ws/a", conn: mustSource(t, "low", lv[0]), labels: l, log: slog.New(slog.DiscardHandler),
		pending: map[string]bool{}, perm: testPermit(), writeTimeout: 50 * time.Millisecond}
	returned := make(chan struct{})
	go func() {
		s.relay(strings.NewReader(lines.String()), gatewaySide, p, 50*time.Millisecond, time.Hour)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not return")
	}
	<-stops
}

// Nothing the caller sends reaches the gateway's log: only fixed reasons, the reviewed workspace
// and configured names are logged, whatever the caller puts in a method, an id, a parameter or a
// line that is not JSON, and whether the request is dropped, refused or forwarded.
func TestCallerTextNeverReachesTheLog(t *testing.T) {
	lv := levels(t)
	const leak = "LEAKED-CONTENT-7f3a"
	var log bytes.Buffer
	l := newLabels()
	l.raise("ws/a", mustSource(t, "high", lv[2]).marking)
	s := &stream{ws: "ws/a", conn: mustSource(t, "low", lv[0]), labels: l, log: slog.New(slog.NewTextHandler(&log, nil)), pending: map[string]bool{}, perm: testPermit()}
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","method":"` + leak + `"}`,
		`{"jsonrpc":"2.0","id":null,"method":"tools/call ` + leak + `"}`,
		leak + ` not json`,
		`{"jsonrpc":"2.0","id":"` + leak + `","method":"tools/call","params":{"arguments":{"q":"` + leak + `"}}}`,
		`{"jsonrpc":"2.0","id":{"x":"` + leak + `"},"method":"ping"}`,
		`{"jsonrpc":"2.0","id":"` + leak + `-2","method":"` + leak + `"}`,
	}, "\n") + "\n"
	var forwarded, reply strings.Builder
	if err := s.requests(strings.NewReader(in), &reply, &forwarded); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	_ = s.answers(strings.NewReader(`{"jsonrpc":"2.0","id":"`+leak+`-2","result":{"text":"`+leak+`"}}`+"\n"+leak+"\n"), &out)
	if log.Len() == 0 || strings.Contains(log.String(), leak) {
		t.Fatalf("log: %s", log.String())
	}

	// The upgrade handler logs no caller text either: path, headers and declaration included.
	log.Reset()
	g := &gateway{sources: map[string]source{"jira": mustSource(t, "jira", lv[1])}, labels: newLabels(),
		log: slog.New(slog.NewTextHandler(&log, nil)), start: (&fake{}).start, maxStreams: 4, maxPerWorkspace: 4, idle: time.Hour}
	for _, tc := range []struct {
		path string
		rev  review
	}{{"/connectors/" + leak, review{ws: "ns/a"}}, {"/connectors/jira", review{ws: "ns/b"}}, {"/connectors/jira", review{ws: "ns/a"}}, {"/connectors/jira", review{err: errors.New("down")}}} {
		g.review = tc.rev
		req := httptest.NewRequest("GET", tc.path, nil)
		req.Header.Set("Upgrade", "badger-mcp")
		req.Header.Set("Authorization", "Bearer "+leak)
		req.Header.Set("Badger-Connector", `{"classification":"`+leak+`"}`)
		g.ServeHTTP(httptest.NewRecorder(), req)
	}
	if log.Len() == 0 || strings.Contains(log.String(), leak) {
		t.Fatalf("handler log: %s", log.String())
	}
}

// A request the connector sends under the id of a pending content-free request is output like any
// other: it raises the label and leaves the pending entry alone.
func TestAConnectorRequestUnderAPendingIDRaisesTheLabel(t *testing.T) {
	lv := levels(t)
	l := newLabels()
	s := &stream{ws: "ws/a", conn: mustSource(t, "high", lv[2]), labels: l, log: slog.New(slog.DiscardHandler), pending: map[string]bool{"1": false}, perm: testPermit()}
	var out strings.Builder
	if err := s.answers(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{"x":"content"}}`+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.allows("ws/a", mustSource(t, "low", lv[0]).marking); ok {
		t.Fatal("a connector request under a pending ping id did not raise the label")
	}
	if _, ok := s.pending["1"]; !ok {
		t.Fatal("the request consumed the ping's pending entry")
	}
}

// Streams are bounded before a connector starts: per workspace and per pod.
func TestStreamsAreBoundedBeforeTheConnectorStarts(t *testing.T) { testStreamBounds(t, time.Hour) }

func testStreamBounds(t *testing.T, idle time.Duration) {
	lv := levels(t)
	src := mustSource(t, "jira", lv[1])
	src.Grants = []grant{{Workspaces: []string{"ns/a", "ns/b"}}}
	starts := 0
	var mu sync.Mutex
	g := &gateway{sources: map[string]source{"jira": src}, labels: newLabels(), log: slog.New(slog.DiscardHandler),
		maxStreams: 3, maxPerWorkspace: 2, idle: idle,
		start: func(s source) (*process, error) { mu.Lock(); starts++; mu.Unlock(); return (&fake{}).start(s) }}
	srv := httptest.NewServer(g)
	defer srv.Close()
	decl := `{"classification":"` + lv[1] + `","writes":false,"flags":{}}`
	open := func(ws string) (net.Conn, int) {
		g.review = review{ws: "ns/" + ws}
		c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(c, "GET /connectors/jira HTTP/1.1\r\nHost: x\r\nUpgrade: badger-mcp\r\nConnection: Upgrade\r\nAuthorization: Bearer t\r\nBadger-Connector: "+decl+"\r\n\r\n")
		res, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		return c, res.StatusCode
	}
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for _, tc := range []struct {
		ws   string
		want int
	}{{"a", 101}, {"a", 101}, {"a", 429}, {"b", 101}, {"b", 429}} {
		c, code := open(tc.ws)
		conns = append(conns, c)
		if code != tc.want {
			t.Fatalf("%s: %d, want %d", tc.ws, code, tc.want)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if starts != 3 {
		t.Fatalf("%d connectors started, want 3", starts)
	}
}

// A stream with no traffic either way is closed after the idle timeout, connector and caller both.
func TestAnIdleStreamIsClosed(t *testing.T) {
	outR, outW := io.Pipe()
	stops := make(chan struct{})
	var once sync.Once
	p := &process{in: nopCloser{io.Discard}, out: outR, stop: func() { once.Do(func() { _ = outW.Close(); close(stops) }) }}
	callerR, callerW := io.Pipe() // the caller keeps the stream open and says nothing
	defer callerW.Close()
	s := &stream{ws: "ws/a", conn: mustSource(t, "low", levels(t)[0]), labels: newLabels(), log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
	reply := closer{close: func() { _ = callerR.Close() }}
	returned := make(chan struct{})
	go func() { s.relay(callerR, reply, p, time.Hour, 80*time.Millisecond); close(returned) }()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("idle stream not closed")
	}
	<-stops
}

type closer struct {
	io.Writer
	close func()
}

func (c closer) Write(b []byte) (int, error) { return len(b), nil }
func (c closer) Close() error                { c.close(); return nil }

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
