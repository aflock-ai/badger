package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/bundle"
	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// The plugin's tools as its signed manifest lists them: x_get reads, x_put writes.
var testTools = []bundle.Tool{
	{Name: "x_get", Description: "Get.", InputSchema: json.RawMessage(`{"type":"object"}`)},
	{Name: "x_put", Description: "Put.", Write: true, InputSchema: json.RawMessage(`{"type":"object"}`)},
}

func testPermit() *permit {
	return &permit{tools: map[string]bundle.Tool{"x_get": testTools[0]}}
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func b64(k ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(k) }

// packBundle writes a bundle the way plugintool pack does: a manifest naming the plugin image's
// digest (here the digest of image, which stands for one) and the signer's signature. extra is
// spliced into the manifest's object.
func packBundle(t *testing.T, image []byte, extra string, priv ed25519.PrivateKey) (dir, digest string) {
	t.Helper()
	dir = t.TempDir()
	digest = bundle.Digest(image)
	tools, _ := json.Marshal(testTools)
	m := `{"schema":1,"name":"x","version":"1.0.0","digest":"` + digest + `","tools":` + string(tools) + extra + `}`
	for name, b := range map[string][]byte{bundle.ManifestFile: []byte(m), bundle.SigFile: bundle.Sign(priv, []byte(m))} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir, digest
}

const script = "#!/bin/sh\ncat >/dev/null\n"

// profileJSON is a whole signed-profile body with one connector entry.
func profileJSON(signerKey, bundleDir, digest, classification, extra string) string {
	return `{"listen":":8443","certFile":"/c","keyFile":"/k","audience":"a","namespaces":["team-a","team-b"],"labelsFile":"/var/lib/conngw/labels",` +
		`"hostDigest":"` + hostDigest + `","signers":{"vendor":"` + signerKey + `"},` +
		`"connectors":[{"name":"x","bundle":"` + bundleDir + `","digest":"` + digest + `","signer":"vendor","baseUrl":"https://x.example.invalid",` +
		`"tokenPath":"/tokens/x","classification":"` + classification + `"` + extra + `}]}`
}

// withUser gives a profileJSON extra the plugin socket and user every connector needs.
func withUser(extra string) string {
	return plugin + extra
}

const plugin = `,"socket":"/run/conngw/x/plugin.sock","uid":61000,"gid":61000`

const readGrant = `,"grants":[{"workspaces":["team-a/*"]}]`

const userGrant = plugin + readGrant

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The profile is the gateway's whole configuration and only the administrator's signature makes it
// one: unsigned, signed by another key, or edited after signing, the gateway does not start.
func TestTheProfileMustBeSignedByTheAdministrator(t *testing.T) {
	lv := levels(t)
	vendor, vendorPriv := newKey(t)
	admin, adminPriv := newKey(t)
	_, otherPriv := newKey(t)
	dir, digest := packBundle(t, []byte(script), "", vendorPriv)
	body := profileJSON(b64(vendor), dir, digest, lv[1], userGrant)
	path := writeFile(t, "profile.json", body)
	adminKey := writeFile(t, "admin.pub", b64(admin))

	if _, err := loadProfile(path, path+".sig", adminKey); err == nil {
		t.Fatal("unsigned profile accepted")
	}
	_ = os.WriteFile(path+".sig", bundle.Sign(otherPriv, []byte(body)), 0o600)
	if _, err := loadProfile(path, path+".sig", adminKey); err == nil {
		t.Fatal("profile signed by another key accepted")
	}
	_ = os.WriteFile(path+".sig", bundle.Sign(adminPriv, []byte(body)), 0o600)
	c, err := loadProfile(path, path+".sig", adminKey)
	if err != nil || len(c.Sources) != 1 {
		t.Fatalf("signed profile: %v", err)
	}
	_ = os.WriteFile(path, []byte(strings.Replace(body, lv[1], lv[0], 1)), 0o600)
	if _, err := loadProfile(path, path+".sig", adminKey); err == nil {
		t.Fatal("profile edited after signing accepted")
	}
}

// A plugin is admitted only if its manifest is signed by the signer the profile names for it and
// names the image the profile pins by digest.
func TestAdmissionRefusesUnsignedOrUnknownPlugins(t *testing.T) {
	lv := levels(t)
	vendor, vendorPriv := newKey(t)
	_, strangerPriv := newKey(t)
	good, digest := packBundle(t, []byte(script), "", vendorPriv)
	admitOne := func(body string) (config, error) {
		c, err := load(writeFile(t, "p.json", body))
		if err != nil {
			return c, err
		}
		return c, admit(&c)
	}

	c, err := admitOne(profileJSON(b64(vendor), good, digest, lv[1], userGrant))
	if err != nil {
		t.Fatalf("good plugin: %v", err)
	}
	if s := c.Sources[0]; s.manifest == nil || s.manifest.Digest != digest {
		t.Fatalf("admitted plugin %+v", s)
	}

	stranger, _ := packBundle(t, []byte(script), "", strangerPriv)
	unsigned, _ := packBundle(t, []byte(script), "", vendorPriv)
	_ = os.Remove(filepath.Join(unsigned, bundle.SigFile))
	other, otherDigest := packBundle(t, []byte(script+"# another build\n"), "", vendorPriv)

	for name, body := range map[string]string{
		"signed by a stranger":      profileJSON(b64(vendor), stranger, digest, lv[1], userGrant),
		"unsigned manifest":         profileJSON(b64(vendor), unsigned, digest, lv[1], userGrant),
		"digest not the pinned one": profileJSON(b64(vendor), other, digest, lv[1], userGrant),
		"grant names unknown tool":  profileJSON(b64(vendor), good, digest, lv[1], withUser(`,"grants":[{"workspaces":["team-a/*"],"tools":["x_nope"]}]`)),
		"read list names a write":   profileJSON(b64(vendor), good, digest, lv[1], withUser(`,"grants":[{"workspaces":["team-a/*"],"tools":["x_put"]}]`)),
		"write list names a read":   profileJSON(b64(vendor), good, digest, lv[1], withUser(`,"writes":true,"grants":[{"workspaces":["team-a/*"],"writeTools":["x_get"]}]`)),
	} {
		if _, err := admitOne(body); err == nil {
			t.Errorf("%s: admitted", name)
		}
	}
	_ = otherDigest
}

// The marking is the profile's. A manifest that claims one changes nothing: the gateway parses the
// profile's banner, raises labels with it and passes it to the plugin.
func TestTheMarkingComesOnlyFromTheProfile(t *testing.T) {
	lv := levels(t)
	vendor, vendorPriv := newKey(t)
	dir, digest := packBundle(t, []byte(script), `,"classification":"`+lv[0]+`"`, vendorPriv)
	c, err := load(writeFile(t, "p.json", profileJSON(b64(vendor), dir, digest, lv[2], userGrant)))
	if err != nil {
		t.Fatal(err)
	}
	if err := admit(&c); err != nil {
		t.Fatal(err)
	}
	s := c.Sources[0]
	if marking.Banner(s.marking) != lv[2] {
		t.Fatalf("marking %q, want the profile's %q", marking.Banner(s.marking), lv[2])
	}
	if h := s.hello(); h.Classification != lv[2] {
		t.Fatalf("hello %+v", h)
	}
}

// answer runs one plugin line through the answer side of a stream whose request id 1 is a pending
// tools/call, and returns what the caller sees.
func answer(t *testing.T, l *labels, src source, line string) map[string]any {
	t.Helper()
	s := &stream{ws: "team-a/alice", conn: src, labels: l, log: slog.New(slog.DiscardHandler), pending: map[string]bool{"1": true}, perm: testPermit()}
	var out strings.Builder
	if err := s.answers(strings.NewReader(line+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil {
		t.Fatalf("caller got %q", out.String())
	}
	return got
}

func callAnswer(banner, text, metaBanner string) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{
		"isError": false, "content": []any{map[string]any{"type": "text", "text": banner + "\n" + text + "\n" + banner}},
		"_meta": map[string]any{"com.testifysec/classification": map[string]any{"schema": 1, "banner": metaBanner}}}})
	return string(b)
}

func metaBanner(got map[string]any) string {
	r, _ := got["result"].(map[string]any)
	m, _ := r["_meta"].(map[string]any)
	c, _ := m["com.testifysec/classification"].(map[string]any)
	s, _ := c["banner"].(string)
	return s
}

// A plugin that claims a marking in its answer is ignored: the caller sees the profile's marking in
// _meta, an answer not framed by the profile's banner is refused, and the label rises to the
// profile's marking either way.
func TestAPluginClaimingAMarkingIsIgnored(t *testing.T) {
	lv := levels(t)
	src := mustSource(t, "x", lv[2])
	low := mustSource(t, "low", lv[0]).marking

	// Right banner in the text, a lower one claimed in _meta: _meta is the profile's.
	l := newLabels()
	got := answer(t, l, src, callAnswer(lv[2], "data", lv[0]))
	if metaBanner(got) != lv[2] || strings.Contains(mustJSON(got), `"isError":true`) {
		t.Fatalf("caller got %s", mustJSON(got))
	}
	if _, ok := l.allows("team-a/alice", low); ok {
		t.Fatal("label did not rise to the profile's marking")
	}

	// A lower banner in the text and in _meta: the answer is refused, still under the profile's marking.
	l = newLabels()
	got = answer(t, l, src, callAnswer(lv[0], "data", lv[0]))
	if metaBanner(got) != lv[2] || !strings.Contains(mustJSON(got), "did not carry") || strings.Contains(mustJSON(got), "data\\n") {
		t.Fatalf("caller got %s", mustJSON(got))
	}
	if _, ok := l.allows("team-a/alice", low); ok {
		t.Fatal("label did not rise")
	}

	// Content that is not text is refused: it carries no banner.
	l = newLabels()
	got = answer(t, l, src, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"image","data":"AAAA","mimeType":"image/png"}]}}`)
	if !strings.Contains(mustJSON(got), "did not carry") || strings.Contains(mustJSON(got), "AAAA") {
		t.Fatalf("caller got %s", mustJSON(got))
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// A tool outside the workspace's grant, a write tool for a read-only grant, or a method the gateway
// does not carry, is answered by the gateway and never reaches the plugin.
func TestCallsOutsideTheGrantNeverReachThePlugin(t *testing.T) {
	lv := levels(t)
	f := &fake{}
	call, closeFn := session(t, newLabels(), "team-a/alice", mustSource(t, "x", lv[1]), f)
	defer closeFn()
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x_put","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"y_other","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call"}`,
		`{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{}}`,
		`{"jsonrpc":"2.0","id":6,"method":"sampling/createMessage","params":{}}`,
	} {
		if got := call(line); !strings.Contains(got, "refused by the connector gateway") {
			t.Fatalf("%s: %s", line, got)
		}
	}
	if len(f.methods()) != 0 {
		t.Fatalf("plugin saw %v", f.methods())
	}
	if got := call(callID("7")); strings.Contains(got, "refused") {
		t.Fatalf("granted tool refused: %s", got)
	}
}

// What the caller sees as the tool list is the grant, built from the signed manifest: a tool the
// plugin adds at runtime does not appear, and neither does a write tool a read-only grant lacks.
func TestToolsListIsTheGrantNotThePlugin(t *testing.T) {
	lv := levels(t)
	s := &stream{ws: "team-a/alice", conn: mustSource(t, "x", lv[1]), labels: newLabels(), log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
	var forwarded, reply strings.Builder
	if err := s.requests(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n"), &reply, &forwarded); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	plugin := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"x_get"},{"name":"x_put"},{"name":"evil_exfiltrate","description":"SECRET CONTENT"}]}}`
	if err := s.answers(strings.NewReader(plugin+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Result struct {
			Tools []struct {
				Name        string
				Annotations struct{ ReadOnlyHint bool }
			}
		}
	}
	if err := json.Unmarshal([]byte(out.String()), &got); err != nil || len(got.Result.Tools) != 1 || got.Result.Tools[0].Name != "x_get" || !got.Result.Tools[0].Annotations.ReadOnlyHint {
		t.Fatalf("caller got %s", out.String())
	}
	if strings.Contains(out.String(), "SECRET") {
		t.Fatal("plugin text passed as a content-free answer")
	}
}

// What reaches the plugin is the gateway's own encoding of what it checked, so a plugin that reads
// duplicate keys first-wins cannot run something else.
func TestForwardedRequestsAreReencoded(t *testing.T) {
	lv := levels(t)
	s := &stream{ws: "team-a/alice", conn: mustSource(t, "x", lv[1]), labels: newLabels(), log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
	in := `{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"ping"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x_put","name":"x_get","arguments":{"a":1}}}` + "\n" +
		`{"jsonrpc":"2.0","method":"tools/call","method":"notifications/initialized"}` + "\n"
	var forwarded, reply strings.Builder
	if err := s.requests(strings.NewReader(in), &reply, &forwarded); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(forwarded.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("forwarded %q, replied %q", forwarded.String(), reply.String())
	}
	for _, l := range lines {
		if strings.Count(l, `"method"`) != 1 || strings.Count(l, `"name"`) > 1 || strings.Contains(l, "x_put") {
			t.Fatalf("forwarded %q", l)
		}
	}
	if !strings.Contains(lines[0], `"ping"`) || !strings.Contains(lines[1], `"x_get"`) || !strings.Contains(lines[1], `{"a":1}`) {
		t.Fatalf("forwarded %q", forwarded.String())
	}
}

// Grants: an exact workspace beats its namespace's wildcard; write tools are opt-in per grant; a
// workspace in a namespace the grant does not name is not granted.
func TestGrantsResolvePerWorkspace(t *testing.T) {
	lv := levels(t)
	s := mustSource(t, "x", lv[1])
	s.Writes = true
	s.Grants = []grant{{Workspaces: []string{"team-a/*"}}, {Workspaces: []string{"team-a/alice"}, WriteTools: []string{"x_put"}}}
	bob, ok := s.permitFor("team-a/bob")
	if !ok || bob.writes || bob.tools["x_put"].Name != "" || bob.tools["x_get"].Name != "x_get" {
		t.Fatalf("bob: %v %+v", ok, bob)
	}
	alice, ok := s.permitFor("team-a/alice")
	if !ok || !alice.writes || alice.tools["x_put"].Name != "x_put" || alice.tools["x_get"].Name != "x_get" {
		t.Fatalf("alice: %v %+v", ok, alice)
	}
	if _, ok := s.permitFor("team-b/alice"); ok {
		t.Fatal("another namespace's alice granted")
	}
	// A connector whose profile does not allow writes never gives a write tool, whatever a grant says.
	s.Writes = false
	if alice, _ := s.permitFor("team-a/alice"); alice.writes || alice.tools["x_put"].Name != "" {
		t.Fatalf("writes off, alice: %+v", alice)
	}
}

// The plugin starts with writes only for a workspace whose grant has write tools, and the caller's
// declaration must say the same.
func TestWritesAreStartedOnlyForAWriteGrant(t *testing.T) {
	lv := levels(t)
	src := mustSource(t, "x", lv[1])
	src.Writes = true
	src.Grants = []grant{{Workspaces: []string{"team-a/*"}}, {Workspaces: []string{"team-a/alice"}, WriteTools: []string{"x_put"}}}
	var mu sync.Mutex
	var started []bool
	g := &gateway{sources: map[string]source{"x": src}, labels: newLabels(), log: slog.New(slog.DiscardHandler), maxStreams: 8, maxPerWorkspace: 8, idle: time.Hour,
		start: func(s source) (*process, error) {
			mu.Lock()
			started = append(started, s.Writes)
			mu.Unlock()
			return (&fake{}).start(s)
		}}
	srv := httptest.NewServer(g)
	defer srv.Close()
	open := func(ws string, writes bool) int {
		g.review = review{ws: ws}
		c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		decl, _ := json.Marshal(map[string]any{"classification": lv[1], "writes": writes, "flags": map[string]string{}})
		_, _ = io.WriteString(c, "GET /connectors/x HTTP/1.1\r\nHost: x\r\nUpgrade: badger-mcp\r\nConnection: Upgrade\r\nAuthorization: Bearer t\r\nBadger-Connector: "+string(decl)+"\r\n\r\n")
		res, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode
	}
	for _, tc := range []struct {
		ws     string
		writes bool
		want   int
	}{{"team-a/alice", true, 101}, {"team-a/alice", false, 409}, {"team-a/bob", false, 101}, {"team-a/bob", true, 409}} {
		if got := open(tc.ws, tc.writes); got != tc.want {
			t.Fatalf("%s writes=%v: %d, want %d", tc.ws, tc.writes, got, tc.want)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(started) != 2 || !started[0] || started[1] {
		t.Fatalf("started with writes %v, want [true false]", started)
	}
}

// One gateway serves workspaces in every configured namespace; each is its own workspace.
func TestOneGatewayServesManyNamespaces(t *testing.T) {
	own := writeFile(t, "token", "pod-token\n")
	var user string
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":{"authenticated":true,"audiences":["aud"],"user":{"username":"` + user + `"}}}`))
	}))
	defer api.Close()
	r := &reviewer{url: api.URL, client: api.Client(), tokenFile: own, audience: "aud", namespaces: []string{"team-a", "team-b"}}
	long := "w" + strings.Repeat("x", 61) + "z" // 63 characters, a DNS label
	for _, tc := range []struct {
		user, ws string
	}{
		{"system:serviceaccount:team-a:alice", "team-a/alice"},
		{"system:serviceaccount:team-b:alice", "team-b/alice"},
		{"system:serviceaccount:team-b:" + long, "team-b/" + long},
		{"system:serviceaccount:team-c:alice", ""},
		{"system:serviceaccount:team-a:" + long + "q", ""},
		{"system:serviceaccount:team-a:al:ice", ""},
		{"system:serviceaccount:team-a:Alice", ""},
		{"system:serviceaccount::alice", ""},
	} {
		user = tc.user
		ws, err := r.workspace(context.Background(), "t")
		if tc.ws != "" && (err != nil || ws != tc.ws) {
			t.Fatalf("%s: %q %v", tc.user, ws, err)
		}
		if tc.ws == "" && err != errNotWorkspace {
			t.Fatalf("%s: %q %v, want not a workspace", tc.user, ws, err)
		}
	}
}

// Labels written for long workspace names (up to the 63-character DNS label) read back.
func TestLabelsHoldLongWorkspaceNames(t *testing.T) {
	lv := levels(t)
	long := "w" + strings.Repeat("x", 62)
	path := writeFile(t, "labels", labelsHeader+"\n"+`{"workspace":"team-a/`+long+`","label":"`+lv[1]+`"}`+"\n"+`{"workspace":"ns/a-","label":"`+lv[1]+`"}`+"\n")
	l, err := openLabels(path, marking.Current())
	if err != nil {
		t.Fatal(err)
	}
	defer l.file.Close()
	if _, ok := l.allows("team-a/"+long, mustSource(t, "low", lv[0]).marking); ok {
		t.Fatal("long workspace's label lost")
	}
}

// The same account name in two namespaces is two workspaces: reading under one leaves the other's
// label alone.
func TestTwoNamespacesNeverShareALabel(t *testing.T) {
	lv := levels(t)
	l := newLabels()
	if _, err := l.raise("team-a/alice", mustSource(t, "high", lv[2]).marking); err != nil {
		t.Fatal(err)
	}
	low := mustSource(t, "low", lv[0]).marking
	if _, ok := l.allows("team-a/alice", low); ok {
		t.Fatal("label did not rise")
	}
	if _, ok := l.allows("team-b/alice", low); !ok {
		t.Fatal("another namespace's workspace shares the label")
	}
}

// A null result, null _meta or null content is the plugin's text like any other: it never stops
// the gateway, and the caller still gets the profile's marking.
func TestNullsInAnAnswerAreStampedNotFatal(t *testing.T) {
	lv := levels(t)
	src := mustSource(t, "x", lv[2])
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":1,"result":null}`,
		`{"jsonrpc":"2.0","id":1,"result":{"_meta":null}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":null,"_meta":null}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"_meta":{"com.testifysec/classification":null}}}`,
	} {
		got := answer(t, newLabels(), src, line)
		if metaBanner(got) != lv[2] {
			t.Fatalf("%s: caller got %s", line, mustJSON(got))
		}
	}
}

// Only the parts of an answer the gateway marks reach the caller: structured content, other _meta
// keys, an error's text and data, and output that answers no request are the plugin's words with no
// banner, so they are dropped or replaced, and the label still rises.
func TestOnlyMarkedPartsOfAnAnswerReachTheCaller(t *testing.T) {
	lv := levels(t)
	src := mustSource(t, "x", lv[2])
	low := mustSource(t, "low", lv[0]).marking
	framed, _ := json.Marshal(lv[2] + "\nok\n" + lv[2])
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + string(framed) + `}],"structuredContent":{"text":"LEAKED"}}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"text":"LEAKED"}}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + string(framed) + `,"annotations":{"x":"LEAKED"}}]}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + string(framed) + `}],"_meta":{"other":"LEAKED"}}}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"LEAKED","data":{"x":"LEAKED"}}}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":"LEAKED","message":"x"}}`,
	} {
		l := newLabels()
		got := mustJSON(answer(t, l, src, line))
		if strings.Contains(got, "LEAKED") {
			t.Fatalf("%s: caller got %s", line, got)
		}
		if _, ok := l.allows("team-a/alice", low); ok {
			t.Fatalf("%s: label did not rise", line)
		}
	}
	// A notification or a line that answers no request is not passed on at all.
	for _, line := range []string{`{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"LEAKED"}}`, `LEAKED`} {
		l := newLabels()
		s := &stream{ws: "team-a/alice", conn: src, labels: l, log: slog.New(slog.DiscardHandler), pending: map[string]bool{}}
		var out strings.Builder
		if err := s.answers(strings.NewReader(line+"\n"), &out); err != nil {
			t.Fatal(err)
		}
		if out.Len() != 0 {
			t.Fatalf("%s: caller got %q", line, out.String())
		}
		if _, ok := l.allows("team-a/alice", low); ok {
			t.Fatalf("%s: label did not rise", line)
		}
	}
}

// A content-free answer is the gateway's own: tools/list is the signed manifest (write tools only
// when the connector has writes), initialize answers the version the caller asked for, and a
// plugin's error and result give the same answer. None of it raises the label. The plugin answers
// under the gateway's id, 1 for a stream's first request.
func TestContentFreeAnswersCarryNothingFromThePlugin(t *testing.T) {
	lv := levels(t)
	ask := func(req, plugin string) string {
		l := newLabels()
		s := &stream{ws: "team-a/alice", conn: mustSource(t, "x", lv[1]), labels: l, log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
		var forwarded, reply, out strings.Builder
		if err := s.requests(strings.NewReader(req+"\n"), &reply, &forwarded); err != nil {
			t.Fatal(err)
		}
		if err := s.answers(strings.NewReader(plugin+"\n"), &out); err != nil {
			t.Fatal(err)
		}
		if _, ok := l.allows("team-a/alice", mustSource(t, "low", lv[0]).marking); !ok {
			t.Fatalf("%s raised the label", req)
		}
		if strings.Contains(out.String(), "LEAKED") {
			t.Fatalf("%s: caller got %s", req, out.String())
		}
		return out.String()
	}
	const initReq = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`
	a := ask(initReq, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"1234-56-78","serverInfo":{"name":"LEAKED"}}}`)
	b := ask(initReq, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}`)
	c := ask(initReq, `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"LEAKED"}}`)
	if a != b || a != c || !strings.Contains(a, `"protocolVersion":"2025-06-18"`) {
		t.Fatalf("initialize answers differ:\n%s%s%s", a, b, c)
	}
	if got := ask(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"9999-99-99"}}`, `{"jsonrpc":"2.0","id":1,"result":{}}`); !strings.Contains(got, `"protocolVersion":"2025-11-25"`) {
		t.Fatalf("unknown version: %s", got)
	}
	if ask(`{"jsonrpc":"2.0","id":2,"method":"ping"}`, `{"jsonrpc":"2.0","id":1,"result":{"x":"LEAKED"}}`) != ask(`{"jsonrpc":"2.0","id":2,"method":"ping"}`, `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"LEAKED"}}`) {
		t.Fatal("ping answers differ")
	}
	list := ask(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"evil","description":"LEAKED"}]}}`)
	if !strings.Contains(list, `"x_get"`) || strings.Contains(list, `"x_put"`) || strings.Contains(list, "evil") {
		t.Fatalf("tools/list: %s", list)
	}
}

// A response whose id no request is waiting for is the plugin's text, not an answer: it is not
// passed on, and the label rises.
func TestAnUnsolicitedResponseIsNotPassedOn(t *testing.T) {
	lv := levels(t)
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":"LEAKED","error":{"code":-1,"message":"x"}}`,
		`{"jsonrpc":"2.0","id":"LEAKED","result":{"content":[]}}`,
	} {
		l := newLabels()
		s := &stream{ws: "team-a/alice", conn: mustSource(t, "x", lv[2]), labels: l, log: slog.New(slog.DiscardHandler), pending: map[string]bool{}}
		var out strings.Builder
		if err := s.answers(strings.NewReader(line+"\n"), &out); err != nil {
			t.Fatal(err)
		}
		if out.Len() != 0 {
			t.Fatalf("%s: caller got %q", line, out.String())
		}
		if _, ok := l.allows("team-a/alice", mustSource(t, "low", lv[0]).marking); ok {
			t.Fatalf("%s: label did not rise", line)
		}
	}
}

// The caller gets its own spelling of a request id back, never the plugin's: the plugin answers under
// the gateway's id (1 for a stream's first request), content-free answers included.
func TestAnswersCarryTheCallersID(t *testing.T) {
	lv := levels(t)
	for _, tc := range []struct{ req, plugin string }{
		{`{"jsonrpc":"2.0","id":"aa","method":"ping"}`, `{"jsonrpc":"2.0","id":1,"result":{}}`},
		{`{"jsonrpc":"2.0","id":"aa","method":"tools/list"}`, `{"jsonrpc":"2.0","id":1,"result":{}}`},
		{`{"jsonrpc":"2.0","id":"aa","method":"tools/call","params":{"name":"x_get"}}`, `{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"x"}}`},
	} {
		s := &stream{ws: "team-a/alice", conn: mustSource(t, "x", lv[1]), labels: newLabels(), log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
		var forwarded, reply, out strings.Builder
		if err := s.requests(strings.NewReader(tc.req+"\n"), &reply, &forwarded); err != nil {
			t.Fatal(err)
		}
		if err := s.answers(strings.NewReader(tc.plugin+"\n"), &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), `"id":"aa"`) {
			t.Fatalf("%s: caller got %s", tc.req, out.String())
		}
	}
}

// An empty read allowlist grants no read tool; only a grant that leaves tools out gets every read
// tool. From the profile's JSON too: "tools": [] is not "tools" omitted.
func TestAnEmptyReadAllowlistGrantsNoReadTool(t *testing.T) {
	lv := levels(t)
	s := mustSource(t, "x", lv[1])
	s.Writes = true
	if err := json.Unmarshal([]byte(`[{"workspaces":["team-a/alice"],"tools":[],"writeTools":["x_put"]},{"workspaces":["team-a/*"]}]`), &s.Grants); err != nil {
		t.Fatal(err)
	}
	alice, _ := s.permitFor("team-a/alice")
	if alice.allows("x_get") || !alice.allows("x_put") {
		t.Fatalf("alice: %+v", alice)
	}
	bob, _ := s.permitFor("team-a/bob")
	if !bob.allows("x_get") || bob.allows("x_put") {
		t.Fatalf("bob: %+v", bob)
	}
}

// Requests that pass without the high-water check carry no caller text to the plugin: initialize,
// ping and tools/list reach it as the gateway's own fixed requests, and a notification other than
// notifications/initialized does not reach it at all. A workspace that has read higher content cannot
// send it down inside their params.
func TestContentFreeRequestsCarryNoCallerText(t *testing.T) {
	lv := levels(t)
	l := newLabels()
	if _, err := l.raise("team-a/alice", mustSource(t, "high", lv[2]).marking); err != nil {
		t.Fatal(err)
	}
	s := &stream{ws: "team-a/alice", conn: mustSource(t, "low", lv[0]), labels: l, log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"LEAKED"},"capabilities":{"x":"LEAKED"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping","params":{"secret":"LEAKED"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"cursor":"LEAKED"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized","params":{"x":"LEAKED"}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":"LEAKED"}}`,
	}, "\n") + "\n"
	var forwarded, reply strings.Builder
	if err := s.requests(strings.NewReader(in), &reply, &forwarded); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(forwarded.String(), "LEAKED") || strings.Count(forwarded.String(), "\n") != 4 {
		t.Fatalf("forwarded %q", forwarded.String())
	}
	if !strings.Contains(forwarded.String(), `"protocolVersion":"2025-06-18"`) {
		t.Fatalf("initialize lost its version: %q", forwarded.String())
	}
}

// Each plugin's container has its own user, never root, and the gateway is not root either: a
// profile without a uid and gid for each connector, with root, a shared uid or a value that is not
// a 31-bit id, is refused, and so is a gateway running as root or as a plugin's user.
func TestEachPluginHasItsOwnUser(t *testing.T) {
	lv := levels(t)
	vendor, _ := newKey(t)
	digest := "sha256:" + strings.Repeat("0", 64)
	sock := `,"socket":"/run/conngw/x/plugin.sock"`
	for name, extra := range map[string]string{
		"no uid":       sock + `,"gid":61000` + readGrant,
		"no gid":       sock + `,"uid":61000` + readGrant,
		"root uid":     sock + `,"uid":0,"gid":61000` + readGrant,
		"root gid":     sock + `,"uid":61000,"gid":0` + readGrant,
		"uid wraps":    sock + `,"uid":4294967296,"gid":61000` + readGrant,
		"uid too big":  sock + `,"uid":2147483648,"gid":61000` + readGrant,
		"negative gid": sock + `,"uid":61000,"gid":-1` + readGrant,
		"no socket":    `,"uid":61000,"gid":61000` + readGrant,
		"rel socket":   `,"socket":"plugin.sock","uid":61000,"gid":61000` + readGrant,
	} {
		if _, err := load(writeFile(t, "p.json", profileJSON(b64(vendor), "/plugins/x", digest, lv[1], extra))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	two := strings.Replace(profileJSON(b64(vendor), "/plugins/x", digest, lv[1], userGrant), `"connectors":[{`,
		`"connectors":[{"name":"y","bundle":"/plugins/y","digest":"`+digest+`","signer":"vendor","tokenPath":"/tokens/y","socket":"/run/conngw/y/plugin.sock","uid":61000,"gid":61001,"grants":[{"workspaces":["team-a/*"]}],"classification":"`+lv[1]+`"},{`, 1)
	if _, err := load(writeFile(t, "p.json", two)); err == nil {
		t.Error("two connectors sharing a uid accepted")
	}
	shared := strings.Replace(strings.Replace(two, `"uid":61000,"gid":61001`, `"uid":61001,"gid":61001`, 1), "/run/conngw/y/", "/run/conngw/x/", 1)
	if _, err := load(writeFile(t, "p.json", shared)); err == nil {
		t.Error("two connectors sharing a socket accepted")
	}

	srcs := []source{mustSource(t, "x", lv[1])}
	for name, ids := range map[string][2]int{"root": {0, 65532}, "root group": {65532, 0}, "a plugin's uid": {61000, 65532}} {
		if checkGatewayUser(ids[0], ids[1], srcs) == nil {
			t.Errorf("gateway as %s accepted", name)
		}
	}
	if err := checkGatewayUser(65532, 65532, srcs); err != nil {
		t.Fatal(err)
	}
}

// Request ids are the gateway's own: the caller's id, whatever text it carries, never reaches the
// plugin, on a content-free request or a call, and each answer goes back under the caller's id.
func TestCallerIDsNeverReachThePlugin(t *testing.T) {
	lv := levels(t)
	l := newLabels()
	if _, err := l.raise("team-a/alice", mustSource(t, "high", lv[2]).marking); err != nil {
		t.Fatal(err)
	}
	// A plugin at the workspace's own level, so the call passes too.
	f := &fake{}
	call, done := session(t, l, "team-a/alice", mustSource(t, "x", lv[2]), f)
	defer done()
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":"LEAKED-1","method":"ping"}`,
		`{"jsonrpc":"2.0","id":"LEAKED-2","method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":"LEAKED-3","method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		callID(`"LEAKED-4"`),
	} {
		var sent, got struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal([]byte(line), &sent)
		if err := json.Unmarshal([]byte(call(line)), &got); err != nil || string(got.ID) != string(sent.ID) {
			t.Fatalf("answer id %s, want %s", got.ID, sent.ID)
		}
	}
	if ids := f.ids(); strings.Contains(strings.Join(ids, " "), "LEAKED") || len(ids) != 4 {
		t.Fatalf("plugin saw ids %q", ids)
	}
}
