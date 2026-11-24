package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// admin is the fake reviewer's answer for an administrator token: r.admin names the identity, and
// errNotAdmin is any other caller.
func (r review) admin(context.Context, string) (string, error) {
	if r.adminID == "" {
		return "", errNotAdmin
	}
	return r.adminID, nil
}

// A call whose answer would lift a registered workspace above its ceiling is refused before it
// reaches the connector, with a message that says a copy is the way up. The label does not move.
func TestARaisingCallIsRefusedBeforeTheConnector(t *testing.T) {
	lv := levels(t)
	l := newLabels()
	if _, err := l.register("ws/a", "o", parsed(t, lv[0])); err != nil {
		t.Fatal(err)
	}
	low, high := mustSource(t, "low", lv[0]), mustSource(t, "high", lv[1])
	fHigh := &fake{}
	callHigh, closeHigh := session(t, l, "ws/a", high, fHigh)
	defer closeHigh()
	got := callHigh(callID("1"))
	if !strings.Contains(got, `"isError":true`) || !strings.Contains(got, "continue in a copy") || !strings.Contains(got, lv[1]) {
		t.Fatalf("raising call not refused: %s", got)
	}
	if len(fHigh.methods()) != 0 {
		t.Fatalf("the connector saw %v", fHigh.methods())
	}
	if _, labelled, _, _, _ := l.describe("ws/a"); labelled {
		t.Fatal("a refused call raised the label")
	}
	// Content-free requests still work, so the app can list the tools it would warn about.
	if got := callHigh(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`); strings.Contains(got, "refused") {
		t.Fatalf("tools/list refused: %s", got)
	}
	callLow, closeLow := session(t, l, "ws/a", low, &fake{})
	defer closeLow()
	if got := callLow(callID("1")); strings.Contains(got, "refused") {
		t.Fatalf("a call within the ceiling refused: %s", got)
	}
}

func adminServer(t *testing.T, l *labels, adminID string) (*httptest.Server, *gateway) {
	t.Helper()
	lv := levels(t)
	floor := parsed(t, lv[0])
	g := &gateway{sources: map[string]source{}, labels: l, log: slog.New(slog.DiscardHandler), maxStreams: 4, maxPerWorkspace: 4,
		idle: time.Hour, namespaces: []string{"ws"}, floor: &floor, review: review{adminID: adminID}}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return srv, g
}

func post(t *testing.T, url, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer t")
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(res.Body)
	_ = json.Unmarshal(b, &out)
	return res.StatusCode, out
}

// Only the configured controller may register and fork; the fork is seeded at the parent's label.
func TestTheAdminAPIRegistersAndForks(t *testing.T) {
	lv := levels(t)
	l := newLabels()
	srv, g := adminServer(t, l, "ctl/controller")

	if code, out := post(t, srv.URL+"/admin/register", `{"workspace":"ws/p","owner":"o1"}`); code != 200 || out["ceiling"] != lv[0] {
		t.Fatalf("register: %d %v", code, out)
	}
	if _, err := l.raise("ws/p", parsed(t, lv[0])); err != nil {
		t.Fatal(err)
	}
	code, out := post(t, srv.URL+"/admin/fork", `{"parent":"ws/p","child":"ws/c","owner":"o1","ceiling":"`+lv[1]+`"}`)
	if code != 200 || out["label"] != lv[0] || out["ceiling"] != lv[1] {
		t.Fatalf("fork: %d %v", code, out)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin/workspace?workspace=ws/c", nil)
	req.Header.Set("Authorization", "Bearer t")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var info map[string]any
	_ = json.NewDecoder(res.Body).Decode(&info)
	res.Body.Close()
	if res.StatusCode != 200 || info["label"] != lv[0] || info["ceiling"] != lv[1] || info["owner"] != "o1" {
		t.Fatalf("describe: %d %v", res.StatusCode, info)
	}

	for name, tc := range map[string]struct {
		path, body string
		want       int
	}{
		"another owner's parent": {"/admin/fork", `{"parent":"ws/p","child":"ws/d","owner":"o2","ceiling":"` + lv[1] + `"}`, 409},
		"fork onto a used child": {"/admin/fork", `{"parent":"ws/p","child":"ws/c","owner":"o1","ceiling":"` + lv[1] + `"}`, 409},
		"unknown namespace":      {"/admin/fork", `{"parent":"ws/p","child":"other/d","owner":"o1","ceiling":"` + lv[1] + `"}`, 400},
		"bad ceiling":            {"/admin/fork", `{"parent":"ws/p","child":"ws/d","owner":"o1","ceiling":"` + lv[1] + `//ZZ"}`, 400},
		"unknown field":          {"/admin/register", `{"workspace":"ws/q","owner":"o1","ceiling":"` + lv[2] + `"}`, 400},
		"second owner":           {"/admin/register", `{"workspace":"ws/p","owner":"o2"}`, 409},
	} {
		if code, _ := post(t, srv.URL+tc.path, tc.body); code != tc.want {
			t.Errorf("%s: %d, want %d", name, code, tc.want)
		}
	}

	// A workspace's own token is not an administrator's.
	g.review = review{ws: "ws/p"}
	if code, _ := post(t, srv.URL+"/admin/fork", `{"parent":"ws/p","child":"ws/e","owner":"o1","ceiling":"`+lv[2]+`"}`); code != 403 {
		t.Fatalf("a workspace forked itself: %d", code)
	}
	if _, _, _, _, registered := l.describe("ws/e"); registered {
		t.Fatal("refused fork left a record")
	}
}

// Without a floor in the profile the admin API does not exist, and nothing is registered.
func TestTheAdminAPIIsOffWithoutAFloor(t *testing.T) {
	l := newLabels()
	srv, g := adminServer(t, l, "ctl/controller")
	g.floor = nil
	if code, _ := post(t, srv.URL+"/admin/register", `{"workspace":"ws/p","owner":"o1"}`); code != 404 {
		t.Fatalf("register without a floor: %d", code)
	}
}
