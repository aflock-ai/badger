package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

type sendUpEnv struct {
	t   *testing.T
	srv *httptest.Server
	g   *gateway
	l   *labels
	dir string
}

// sendUpServer has three workspaces of owner o1: low (read the lowest level), high (a fork, read
// the next level) and fresh (read nothing), and one of owner o2.
func sendUpServer(t *testing.T) *sendUpEnv {
	t.Helper()
	lv := levels(t)
	l := newLabels()
	floor := parsed(t, lv[0])
	for ws, owner := range map[string]string{"ws/low": "o1", "ws/fresh": "o1", "ws/other": "o2"} {
		if _, err := l.register(ws, owner, floor); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.raise("ws/low", floor); err != nil {
		t.Fatal(err)
	}
	if _, err := l.raise("ws/other", floor); err != nil {
		t.Fatal(err)
	}
	if _, err := l.fork("ws/low", "ws/high", "o1", parsed(t, lv[1])); err != nil {
		t.Fatal(err)
	}
	if _, err := l.raise("ws/high", parsed(t, lv[1])); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	in, err := openInbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	g := &gateway{sources: map[string]source{}, labels: l, log: slog.New(slog.DiscardHandler), maxStreams: 4, maxPerWorkspace: 4,
		idle: time.Hour, namespaces: []string{"ws"}, floor: &floor, inbox: in}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return &sendUpEnv{t: t, srv: srv, g: g, l: l, dir: dir}
}

// as sends a request with the given workspace's token.
func (e *sendUpEnv) as(ws, method, path, body string) (int, string) {
	e.t.Helper()
	e.g.review = review{ws: ws}
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer t")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func sendBody(to, name, text string) string {
	b, _ := json.Marshal(map[string]string{"to": to, "name": name, "data": base64.StdEncoding.EncodeToString([]byte(text))})
	return string(b)
}

type listed struct {
	Items []struct {
		ID, From, FromLabel, Name string
	} `json:"items"`
}

func (e *sendUpEnv) list(ws string) listed {
	e.t.Helper()
	code, body := e.as(ws, http.MethodGet, "/inbox", "")
	if code != 200 {
		e.t.Fatalf("inbox %s: %d %s", ws, code, body)
	}
	var l listed
	if err := json.Unmarshal([]byte(body), &l); err != nil {
		e.t.Fatal(err)
	}
	return l
}

// A lower workspace sends up to its fork; the fork receives the file with its source and the
// source's label; the sender learns only "delivered".
func TestSendUpDeliversToAHigherWorkspaceOfTheSameUser(t *testing.T) {
	lv := levels(t)
	e := sendUpServer(t)
	code, body := e.as("ws/low", http.MethodPost, "/sendup", sendBody("ws/high", "notes.md", "draft text"))
	if code != 200 || strings.TrimSpace(body) != `{"status":"delivered"}` {
		t.Fatalf("send: %d %s", code, body)
	}
	// Read nothing is lowest of all: it may send to anything of its owner's.
	if code, body := e.as("ws/fresh", http.MethodPost, "/sendup", sendBody("ws/low", "a.txt", "x")); code != 200 {
		t.Fatalf("fresh send: %d %s", code, body)
	}
	got := e.list("ws/high")
	if len(got.Items) != 1 || got.Items[0].From != "ws/low" || got.Items[0].FromLabel != lv[0] || got.Items[0].Name != "notes.md" {
		t.Fatalf("received: %+v", got)
	}
	code, body = e.as("ws/high", http.MethodGet, "/inbox/"+got.Items[0].ID, "")
	var item struct{ Data []byte }
	if code != 200 || json.Unmarshal([]byte(body), &item) != nil || string(item.Data) != "draft text" {
		t.Fatalf("item: %d %s", code, body)
	}
	// It survives a restart of the pod.
	again, err := openInbox(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	e.g.inbox = again
	if got := e.list("ws/high"); len(got.Items) != 1 {
		t.Fatalf("after restart: %+v", got)
	}
	if code, _ := e.as("ws/high", http.MethodDelete, "/inbox/"+got.Items[0].ID, ""); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if got := e.list("ws/high"); len(got.Items) != 0 {
		t.Fatalf("after delete: %+v", got)
	}
}

// Nothing flows down or sideways: higher to lower, to another owner, to an unregistered or unknown
// workspace, or to itself is refused, and nothing is stored.
func TestSendUpRefusesEverythingButUp(t *testing.T) {
	e := sendUpServer(t)
	for name, tc := range map[string]struct{ from, to string }{
		"higher to lower":     {"ws/high", "ws/low"},
		"higher to fresh":     {"ws/high", "ws/fresh"},
		"lower to fresh":      {"ws/low", "ws/fresh"},
		"another owner":       {"ws/low", "ws/other"},
		"unregistered target": {"ws/low", "ws/nobody"},
		"unregistered sender": {"ws/nobody", "ws/high"},
		"itself":              {"ws/low", "ws/low"},
		"another namespace":   {"ws/low", "other/high"},
	} {
		code, body := e.as(tc.from, http.MethodPost, "/sendup", sendBody(tc.to, "f.txt", "secret-ish"))
		if code != 403 || strings.TrimSpace(body) != `{"status":"refused"}` {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	for _, ws := range []string{"ws/low", "ws/fresh", "ws/other", "ws/high"} {
		if got := e.list(ws); len(got.Items) != 0 {
			t.Errorf("%s holds %+v", ws, got)
		}
	}
	for name, body := range map[string]string{
		"bad name":      sendBody("ws/high", "../x", "y"),
		"empty name":    sendBody("ws/high", "", "y"),
		"unknown field": `{"to":"ws/high","name":"a","data":"","x":1}`,
	} {
		if code, _ := e.as("ws/low", http.MethodPost, "/sendup", body); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
}

// A fork cannot read its parent's data through the inbox: each workspace sees only what was sent to
// it, and an item id of another workspace is not found.
func TestAForkCannotReadItsParentsInbox(t *testing.T) {
	e := sendUpServer(t)
	if code, _ := e.as("ws/fresh", http.MethodPost, "/sendup", sendBody("ws/low", "parent.txt", "parent data")); code != 200 {
		t.Fatal("send to parent")
	}
	parent := e.list("ws/low")
	if len(parent.Items) != 1 {
		t.Fatalf("parent inbox: %+v", parent)
	}
	if got := e.list("ws/high"); len(got.Items) != 0 {
		t.Fatalf("fork sees %+v", got)
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		if code, body := e.as("ws/high", method, "/inbox/"+parent.Items[0].ID, ""); code != 404 || strings.Contains(body, "parent data") {
			t.Fatalf("fork %s parent's item: %d %s", method, code, body)
		}
	}
	if got := e.list("ws/low"); len(got.Items) != 1 {
		t.Fatal("parent's item was removed by the fork")
	}
}

// Without an inbox directory in the profile, send-up does not exist.
func TestSendUpIsOffWithoutAnInbox(t *testing.T) {
	e := sendUpServer(t)
	e.g.inbox = nil
	if code, _ := e.as("ws/low", http.MethodPost, "/sendup", sendBody("ws/high", "a", "b")); code != 404 {
		t.Fatalf("send-up without an inbox: %d", code)
	}
	if entries, _ := os.ReadDir(e.dir); len(entries) != 0 {
		t.Fatal("something was stored")
	}
}

// Nothing the receiver does changes what a sender is told: the only capacity limit is the sender's
// own quota, so a higher workspace cannot signal a lower one by filling or emptying its inbox.
func TestTheReceiverCannotSignalTheSender(t *testing.T) {
	e := sendUpServer(t)
	e.g.inbox.perSender = 3
	answers := func() []int {
		var out []int
		for i := 0; i < 5; i++ {
			code, _ := e.as("ws/low", http.MethodPost, "/sendup", sendBody("ws/high", "f.txt", "x"))
			out = append(out, code)
		}
		return out
	}
	first := answers()
	if !slices.Equal(first, []int{200, 200, 200, 403, 403}) {
		t.Fatalf("quota: %v", first)
	}
	// The receiver empties its inbox; the sender's answers do not change.
	for _, it := range e.list("ws/high").Items {
		if code, _ := e.as("ws/high", http.MethodDelete, "/inbox/"+it.ID, ""); code != 200 {
			t.Fatal("delete")
		}
	}
	if again := answers(); !slices.Equal(again, []int{403, 403, 403, 403, 403}) {
		t.Fatalf("the receiver's deletes changed the sender's answers: %v", again)
	}
	// Another sender has its own quota.
	if code, _ := e.as("ws/fresh", http.MethodPost, "/sendup", sendBody("ws/high", "g.txt", "y")); code != 200 {
		t.Fatalf("other sender: %d", code)
	}
}

// Items appear whole or not at all: a file left half written (a crash mid-delivery) is never
// listed, never breaks the listing, and is removed when the pod starts.
func TestAHalfWrittenItemIsNeverSeen(t *testing.T) {
	e := sendUpServer(t)
	if code, _ := e.as("ws/low", http.MethodPost, "/sendup", sendBody("ws/high", "a.txt", "whole")); code != 200 {
		t.Fatal("send")
	}
	dir := e.g.inbox.path("ws/high")
	stray := filepath.Join(dir, ".tmp-00000000000000000099")
	if err := os.WriteFile(stray, []byte(`{"id":"0000`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := e.list("ws/high"); len(got.Items) != 1 || got.Items[0].Name != "a.txt" {
		t.Fatalf("listing: %+v", got)
	}
	again, err := openInbox(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	e.g.inbox = again
	if _, err := os.Stat(stray); !os.IsNotExist(err) {
		t.Fatal("the half-written file survived a start")
	}
	if got := e.list("ws/high"); len(got.Items) != 1 {
		t.Fatalf("after start: %+v", got)
	}
}

// After an administrator lowers a receiver's label, an item above it is hidden from every inbox
// request, delete included: a delete answers as for an item that does not exist and removes
// nothing.
func TestAnItemAboveTheReceiverCannotBeDeletedOrProbed(t *testing.T) {
	lv := levels(t)
	e := sendUpServer(t)
	if _, err := e.l.fork("ws/high", "ws/top", "o1", parsed(t, lv[1])); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.as("ws/high", http.MethodPost, "/sendup", sendBody("ws/top", "h.txt", "high data")); code != 200 {
		t.Fatal("send")
	}
	id := e.list("ws/top").Items[0].ID
	// The administrator resets ws/top to the lowest level.
	e.l.mu.Lock()
	e.l.set["ws/top"] = parsed(t, lv[0])
	e.l.mu.Unlock()
	missing := "00000000000000000001"
	for _, path := range []string{"/inbox/" + id, "/inbox/" + missing} {
		if code, body := e.as("ws/top", http.MethodDelete, path, ""); code != 404 || strings.Contains(body, "high data") {
			t.Fatalf("delete %s after a reset: %d %s", path, code, body)
		}
	}
	if _, err := os.Stat(filepath.Join(e.g.inbox.path("ws/top"), id+".json")); err != nil {
		t.Fatalf("the hidden item was removed: %v", err)
	}
}

// A store that fails (a full volume) is refused like any other send and stops send-up until a restart: deleting items, which frees the
// space, does not make a later send succeed, so a receiver cannot signal a sender through space.
func TestAFullVolumeCannotBeUsedToSignalTheSender(t *testing.T) {
	e := sendUpServer(t)
	full := false
	e.g.inbox.write = func(path string, b []byte) error {
		if full {
			return syscall.ENOSPC
		}
		return writeSynced(path, b)
	}
	if code, _ := e.as("ws/low", http.MethodPost, "/sendup", sendBody("ws/high", "a.txt", "one")); code != 200 {
		t.Fatal("first send")
	}
	full = true
	if code, body := e.as("ws/low", http.MethodPost, "/sendup", sendBody("ws/high", "b.txt", "two")); code != 403 || strings.TrimSpace(body) != `{"status":"refused"}` {
		t.Fatalf("send on a full volume: %d %s", code, body)
	}
	// The receiver frees the space.
	for _, it := range e.list("ws/high").Items {
		if code, _ := e.as("ws/high", http.MethodDelete, "/inbox/"+it.ID, ""); code != 200 {
			t.Fatal("delete")
		}
	}
	full = false
	for _, from := range []string{"ws/low", "ws/fresh"} {
		if code, body := e.as(from, http.MethodPost, "/sendup", sendBody("ws/high", "c.txt", "three")); code != 403 || strings.TrimSpace(body) != `{"status":"refused"}` {
			t.Fatalf("%s: send after the receiver freed space: %d %s", from, code, body)
		}
	}
	if got := e.list("ws/high"); len(got.Items) != 0 {
		t.Fatalf("stored after the failure: %+v", got)
	}
	// A restart, an administrator's act, restores send-up.
	again, err := openInbox(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	e.g.inbox = again
	if code, _ := e.as("ws/low", http.MethodPost, "/sendup", sendBody("ws/high", "d.txt", "four")); code != 200 {
		t.Fatalf("after a restart: %d", code)
	}
}

// An item acknowledged while the inbox is being listed is left out of that listing; the others are
// still listed. (A name whose file is gone between reading the directory and reading the file
// stands in for the race: a dangling link.)
func TestAnItemDeletedDuringAListingIsSkipped(t *testing.T) {
	e := sendUpServer(t)
	for _, f := range []string{"a.txt", "b.txt"} {
		if code, _ := e.as("ws/low", http.MethodPost, "/sendup", sendBody("ws/high", f, f)); code != 200 {
			t.Fatal("send")
		}
	}
	dir := e.g.inbox.path("ws/high")
	if err := os.Symlink(filepath.Join(dir, "gone"), filepath.Join(dir, "00000000000000000002.json")); err != nil {
		t.Fatal(err)
	}
	if got := e.list("ws/high"); len(got.Items) != 2 || got.Items[0].Name != "a.txt" || got.Items[1].Name != "b.txt" {
		t.Fatalf("listing during a delete: %+v", got)
	}
	// Any other failure to read an item still fails the listing.
	if err := os.WriteFile(filepath.Join(dir, "00000000000000000003.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.as("ws/high", http.MethodGet, "/inbox", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("an unreadable item: %d", code)
	}
}

// The inbox directory's own entry is durable before any send is accepted: a missing inbox is created
// in an existing parent (the labels volume), every start syncs the parent and the inbox (so a sync an
// interrupted start missed is made up), and a missing parent is refused, not created unsynced.
func TestANewInboxDirectoryIsDurable(t *testing.T) {
	var synced []string
	old := syncDir
	syncDir = func(p string) error { synced = append(synced, p); return old(p) }
	t.Cleanup(func() { syncDir = old })
	vol := t.TempDir()
	dir := filepath.Join(vol, "inbox")
	if _, err := openInbox(dir); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(synced, vol) {
		t.Fatalf("parent not synced after creating the inbox: %v", synced)
	}
	// A start syncs again whatever an earlier start created (its sync may never have happened): the
	// inbox's entry in the volume and every receiver directory's entry in the inbox.
	synced = nil
	if _, err := openInbox(dir); err != nil || !slices.Contains(synced, vol) || !slices.Contains(synced, dir) {
		t.Fatalf("existing inbox: %v %v", err, synced)
	}
	// A start whose sync fails does not open the inbox.
	syncDir = func(string) error { return syscall.EIO }
	if _, err := openInbox(dir); err == nil {
		t.Fatal("an inbox whose entries could not be synced was opened")
	}
	syncDir = old
	if _, err := openInbox(filepath.Join(vol, "missing", "inbox")); err == nil {
		t.Fatal("an inbox under a missing parent was created")
	}
}

// An acknowledgement is durable before "removed" is answered: the receiver's directory is synced,
// so a crash cannot bring an acknowledged item back.
func TestAnAcknowledgementIsDurable(t *testing.T) {
	e := sendUpServer(t)
	if code, _ := e.as("ws/low", http.MethodPost, "/sendup", sendBody("ws/high", "a.txt", "x")); code != 200 {
		t.Fatal("send")
	}
	id := e.list("ws/high").Items[0].ID
	var synced []string
	old := syncDir
	syncDir = func(p string) error { synced = append(synced, p); return old(p) }
	t.Cleanup(func() { syncDir = old })
	if code, _ := e.as("ws/high", http.MethodDelete, "/inbox/"+id, ""); code != 200 {
		t.Fatal("delete")
	}
	if !slices.Equal(synced, []string{e.g.inbox.path("ws/high")}) {
		t.Fatalf("synced %v after an acknowledgement", synced)
	}
	// A directory that cannot be synced is not answered "removed".
	if code, _ := e.as("ws/low", http.MethodPost, "/sendup", sendBody("ws/high", "b.txt", "y")); code != 200 {
		t.Fatal("send")
	}
	id = e.list("ws/high").Items[0].ID
	syncDir = func(string) error { return syscall.EIO }
	if code, body := e.as("ws/high", http.MethodDelete, "/inbox/"+id, ""); code == 200 {
		t.Fatalf("an unsynced delete answered %d %s", code, body)
	}
}
