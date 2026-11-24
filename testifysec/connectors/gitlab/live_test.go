package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/fakeserver"
)

// liveRoutes replays exchanges recorded from a real GitLab CE 19.5.1 (hosts and tokens
// scrubbed): each file holds the request the connector sent and the response it got back.
// Routes match the recorded path and query exactly, so a change in what the connector asks
// for fails here as well.
func liveRoutes(t *testing.T) []fakeserver.Route {
	t.Helper()
	files, _ := filepath.Glob("testdata/live/*.json")
	if len(files) == 0 {
		t.Fatal("no live fixtures")
	}
	var rs []fakeserver.Route
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var ex struct {
			Request struct {
				Method, Path string
				Query        url.Values
			}
			Status  int
			Headers map[string]string
			Body    json.RawMessage
		}
		if err := json.Unmarshal(raw, &ex); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		h := map[string]string{}
		for k, v := range ex.Headers {
			if strings.HasPrefix(k, "X-") {
				h[k] = v
			}
		}
		rs = append(rs, fakeserver.Route{Method: ex.Request.Method, Path: ex.Request.Path, Query: ex.Request.Query.Encode(),
			Status: ex.Status, Body: string(ex.Body), Header: h})
	}
	return rs
}

func TestLiveExchanges(t *testing.T) {
	h := newHarness(t, "UNCLASSIFIED", nil, liveRoutes(t)...)
	cases := []struct {
		tool, args string
		want       []string
	}{
		{"gitlab_get_project", `{"project":"1"}`, []string{"# lvb-top/sub1/sub2/widget (id 1)", "default branch: main"}},
		{"gitlab_search_issues", `{"project":"1","labels":"bug"}`, []string{"#18 [opened] qa upper", "#1 [opened] lvb-seed-1 plain issue", "[end of results]"}},
		{"gitlab_get_issue", `{"project":"1","iid":1}`, []string{"# #1: lvb-seed-1 plain issue", "dev1 (", "thread start", "  reply: root (", "a reply"}},
		{"gitlab_list_merge_requests", `{"project":"1"}`, []string{"!1 [opened] lvb-seed MR", "lvb-change -> main", "[end of results]"}},
		{"gitlab_get_merge_request", `{"project":"1","iid":1}`, []string{"merge status: mergeable", " on src/app.go:4 [resolved]:\non an added line",
			"  reply: root (", " on src/app.go:5 (old):\non a deleted line", " on src/app.go:3:\non an unchanged line", " on src/new.go:3:", "general MR thread"}},
		{"gitlab_get_merge_request_diff", `{"project":"1","iid":1}`, []string{"### docs/plus+sign.txt (deleted)",
			"### docs/a..b.txt -> docs/renamed.txt\n[no content change]", "### src/new.go (new file)", "[end of results]"}},
		{"gitlab_list_pipelines", `{"project":"1"}`, []string{"4 [success] lvb-change 8823c5099c50 push", "1 [success] feature/@alice"}},
		{"gitlab_list_pipelines", `{"project":"1","pipeline_id":4}`, []string{"8 [success] test/noisy 6s", "7 [success] test/quiet 2s"}},
	}
	for _, c := range cases {
		r := h.call(c.tool, c.args)
		// The project's topic looks like a marking; the banner is still the connector's own.
		if r.IsError || r.Banner != "UNCLASSIFIED" || strings.Contains(r.Text, "restored source branch") {
			t.Errorf("%s %s: banner %q\n%s", c.tool, c.args, r.Banner, r.Text)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(r.Text, w) {
				t.Errorf("%s %s: missing %q in\n%s", c.tool, c.args, w, r.Text)
			}
		}
	}
}
