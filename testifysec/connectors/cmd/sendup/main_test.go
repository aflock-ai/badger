package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// listing is the pod's GET /inbox answer.
var listing = `{"items":[{"id":"00000000000000000001","from":"ws/low","fromLabel":"X","name":"a.txt","size":2}]}`

// pod stands in for conngw's send-up endpoints and records what it was sent.
func pod(t *testing.T, answer int) (config string, got *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization")+" "+string(b))
		switch {
		case r.URL.Path == "/sendup" && answer == 200:
			_, _ = io.WriteString(w, `{"status":"delivered"}`)
		case r.URL.Path == "/sendup":
			w.WriteHeader(answer)
			_, _ = io.WriteString(w, `{"status":"refused"}`)
		case r.URL.Path == "/inbox":
			_, _ = io.WriteString(w, listing)
		case strings.HasPrefix(r.URL.Path, "/inbox/") && r.Method == http.MethodGet:
			_, _ = io.WriteString(w, `{"id":"00000000000000000001","name":"a.txt","data":"`+base64.StdEncoding.EncodeToString([]byte("hi"))+`"}`)
		default:
			_, _ = io.WriteString(w, `{"status":"removed"}`)
		}
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	token := filepath.Join(dir, "token")
	_ = os.WriteFile(token, []byte("tok\n"), 0o600)
	b, _ := json.Marshal(map[string]string{"url": srv.URL, "caFile": ca, "tokenFile": token})
	config = filepath.Join(dir, "sendup.json")
	_ = os.WriteFile(config, b, 0o600)
	return config, &seen
}

func runIt(config string, args []string, stdin string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(config, args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestSendPostsTheFileWithTheWorkspaceToken(t *testing.T) {
	config, seen := pod(t, 200)
	code, out, errOut := runIt(config, []string{"send", "--to=ws/high", "--name=notes.md", "-"}, "draft")
	if code != 0 || strings.TrimSpace(out) != "delivered" {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
	var body struct {
		To, Name string
		Data     []byte
	}
	parts := strings.SplitN((*seen)[0], " ", 4)
	if parts[0] != "POST" || parts[1] != "/sendup" || parts[2]+" "+strings.SplitN(parts[3], " ", 2)[0] != "Bearer tok" {
		t.Fatalf("request %q", (*seen)[0])
	}
	_ = json.Unmarshal([]byte(strings.SplitN(parts[3], " ", 2)[1]), &body)
	if body.To != "ws/high" || body.Name != "notes.md" || string(body.Data) != "draft" {
		t.Fatalf("body %+v", body)
	}
}

func TestARefusalExitsNonZeroAndSaysOnlyRefused(t *testing.T) {
	config, _ := pod(t, 403)
	code, out, _ := runIt(config, []string{"send", "--to=ws/low", "--name=a", "-"}, "x")
	if code == 0 || strings.TrimSpace(out) != "refused" {
		t.Fatalf("%d %q", code, out)
	}
}

func TestListGetAndAck(t *testing.T) {
	config, seen := pod(t, 200)
	if code, out, _ := runIt(config, []string{"list"}, ""); code != 0 || !strings.Contains(out, "00000000000000000001\tws/low\tX\ta.txt") {
		t.Fatalf("list %d %q", code, out)
	}
	if code, out, _ := runIt(config, []string{"get", "00000000000000000001"}, ""); code != 0 || out != "hi" {
		t.Fatalf("get %d %q", code, out)
	}
	if code, _, _ := runIt(config, []string{"ack", "00000000000000000001"}, ""); code != 0 || !strings.HasPrefix((*seen)[2], "DELETE /inbox/00000000000000000001") {
		t.Fatalf("ack %d %v", code, *seen)
	}
	if code, _, _ := runIt(config, []string{"get", "../x"}, ""); code == 0 {
		t.Fatal("a malformed id was sent")
	}
}

// The destination and its trust roots come only from the administrator's mounted configuration: a
// caller cannot point the client, and the workspace token it carries, anywhere else.
func TestTheDestinationIsNotTheCallers(t *testing.T) {
	config, seen := pod(t, 200)
	for _, args := range [][]string{
		{"--url=https://elsewhere.example.invalid", "list"},
		{"--ca-file=/tmp/other.pem", "list"},
		{"--token-file=/tmp/t", "list"},
	} {
		if code, _, _ := runIt(config, args, ""); code != 2 {
			t.Errorf("%v accepted", args)
		}
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"plain http":    `{"url":"http://pod:8443","caFile":"/x","tokenFile":"/y"}`,
		"a path":        `{"url":"https://pod:8443/elsewhere","caFile":"/x","tokenFile":"/y"}`,
		"unknown field": `{"url":"https://pod:8443","caFile":"/x","tokenFile":"/y","insecure":true}`,
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		_ = os.WriteFile(p, []byte(content), 0o600)
		if code, _, _ := runIt(p, []string{"list"}, ""); code != 2 {
			t.Errorf("%s: accepted", name)
		}
	}
	if code, _, _ := runIt(filepath.Join(dir, "absent"), []string{"list"}, ""); code != 2 {
		t.Error("a missing configuration was accepted")
	}
	if len(*seen) != 0 {
		t.Fatalf("a refused run sent %v", *seen)
	}
}

// failing is an output that cannot be written (a full disk).
type failing struct{}

func (failing) Write([]byte) (int, error) { return 0, io.ErrShortWrite }

// get fails when its output cannot be written, so "get > file && ack" never removes an item that
// was not saved.
func TestGetFailsWhenItsOutputCannotBeWritten(t *testing.T) {
	config, _ := pod(t, 200)
	var errOut bytes.Buffer
	if code := run(config, []string{"get", "00000000000000000001"}, strings.NewReader(""), failing{}, &errOut); code == 0 {
		t.Fatal("get succeeded with its output lost")
	}
}

// A file over the limit is refused without being read whole or sent.
func TestAnOversizedFileIsNotReadOrSent(t *testing.T) {
	config, seen := pod(t, 200)
	big := filepath.Join(t.TempDir(), "big")
	f, _ := os.Create(big)
	_ = f.Truncate(64 << 20) // sparse: 64 MiB of zeros
	f.Close()
	if code, _, _ := runIt(config, []string{"send", "--to=ws/high", "--name=big", big}, ""); code != 2 || len(*seen) != 0 {
		t.Fatalf("oversized file: %d, sent %v", code, *seen)
	}
}

// A listing shows each item on one line whatever the pod sends: a newline, tab, escape sequence or
// other control or format character in a field is shown escaped, so it cannot fake a row or drive
// the terminal.
func TestAListingCannotFakeRowsOrDriveTheTerminal(t *testing.T) {
	hostile := []string{"a\n00000000000000000002\tws/x\tLOW\tfaked.txt", "\u001b[2J\u001b]0;title\u0007", "b\u202etxt.exe", "c\rd", "bad\xff"}
	var items []map[string]string
	for i, h := range hostile {
		items = append(items, map[string]string{"id": "0000000000000000000" + string(rune('1'+i)), "from": "ws/low\tz", "fromLabel": "X\u001b[0m", "name": h})
	}
	b, _ := json.Marshal(map[string]any{"items": items})
	old := listing
	listing = string(b)
	t.Cleanup(func() { listing = old })
	config, _ := pod(t, 200)
	code, out, _ := runIt(config, []string{"list"}, "")
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if code != 0 || len(lines) != len(hostile) {
		t.Fatalf("list %d %q", code, out)
	}
	for _, l := range lines {
		if strings.Count(l, "\t") != 3 || strings.ContainsAny(l, "\x1b\r\x07\u202e") {
			t.Fatalf("unescaped line %q", l)
		}
	}
	if !strings.Contains(out, `"a\n00000000000000000002\tws/x\tLOW\tfaked.txt"`) {
		t.Fatalf("escaped name not shown: %q", out)
	}
	// An ordinary name is shown as it is.
	listing = old
	if _, out, _ := runIt(config, []string{"list"}, ""); !strings.Contains(out, "\tws/low\tX\ta.txt\n") {
		t.Fatalf("plain listing %q", out)
	}
}
