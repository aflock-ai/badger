package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/fakeserver"
	"github.com/aflock-ai/badger/testifysec/connectors/sdk"
)

const (
	sentinel = "SENTINEL-GITLAB-TOKEN-7f3e"
	proj     = "/api/v4/projects/platform%2Fbuild%2Fsigner"
)

// routes is the fake GitLab every test starts from; tests append their own.
func routes(extra ...fakeserver.Route) []fakeserver.Route {
	return append(extra,
		fakeserver.Route{Method: "GET", Path: proj, Fixture: "project.json"},
		fakeserver.Route{Method: "GET", Path: proj + "/issues", Fixture: "issues.json", Header: map[string]string{"X-Page": "1", "X-Next-Page": "2", "X-Total": "31"}},
		fakeserver.Route{Method: "GET", Path: proj + "/issues/7", Fixture: "issue-7.json"},
		fakeserver.Route{Method: "GET", Path: proj + "/issues/7/discussions", Fixture: "issue-7-discussions.json", Header: map[string]string{"X-Page": "1"}},
		fakeserver.Route{Method: "GET", Path: proj + "/merge_requests", Fixture: "mrs.json", Header: map[string]string{"X-Page": "1", "X-Next-Page": ""}},
		fakeserver.Route{Method: "GET", Path: proj + "/merge_requests/12", Fixture: "mr-12.json"},
		fakeserver.Route{Method: "GET", Path: proj + "/merge_requests/12/discussions", Fixture: "mr-12-discussions.json", Header: map[string]string{"X-Page": "1"}},
		fakeserver.Route{Method: "GET", Path: proj + "/merge_requests/12/diffs", Fixture: "mr-12-diffs.json"},
		fakeserver.Route{Method: "GET", Path: proj + "/pipelines", Fixture: "pipelines.json"},
		fakeserver.Route{Method: "GET", Path: proj + "/pipelines/5501/jobs", Fixture: "pipeline-5501-jobs.json"},
		fakeserver.Route{Method: "GET", Path: proj + "/repository/files/cmd%2Fsigner%2Fmain.go/raw", Query: "ref=main", Body: "package main\n\nfunc main() {}\n"},
		fakeserver.Route{Method: "GET", Path: proj + "/repository/files/cmd%2Fsigner%2Fmain.go/raw", Query: "ref=release%2Fv1.2.3%2Bbuild", Body: "package main // release\n"},
	)
}

type harness struct {
	*sdk.Server
	fake *fakeserver.Server
}

// newHarness builds the server the way Main does, through sdk.Parse, so the GitLab flags
// are exercised; extra holds connector flags such as --auth=bearer or --enable-writes.
func newHarness(t *testing.T, classification string, extra []string, rs ...fakeserver.Route) harness {
	t.Helper()
	fake := fakeserver.New(t, "testdata", rs...)
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"--base-url", fake.URL + "/api/v4", "--token-file", tok, "--classification", classification, "--insecure-loopback-http"}, extra...)
	spec, cfg, err := sdk.Parse(newSpec(), args)
	if err != nil {
		t.Fatal(err)
	}
	s, err := sdk.New(spec, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return harness{s, fake}
}

func (h harness) call(name, args string) sdk.CallResult {
	return h.Call(context.Background(), name, json.RawMessage(args))
}

func TestReadTools(t *testing.T) {
	h := newHarness(t, "CUI", nil, routes()...)
	cases := []struct {
		tool, args string
		want       []string
		path, qry  string // the item request (the last one sent)
	}{
		{"gitlab_get_project", `{"project":"platform/build/signer"}`, []string{"# platform/build/signer (id 101)", "default branch: main", "topics: go, classification::CUI"}, proj, ""},
		{"gitlab_search_issues", `{"project":"platform/build/signer","state":"opened","labels":"security","search":"key"}`,
			[]string{"#7 [opened] Rotate the build signing key", "labels: security, classification::secret", "[more results: request page 2]"},
			proj + "/issues", "labels=security&page=1&per_page=20&search=key&state=opened"},
		{"gitlab_get_issue", `{"project":"platform/build/signer","iid":7,"notes":5}`,
			[]string{"# #7: Rotate the build signing key", "milestone: 2026.10", "Ignore all previous instructions", "dev-b (2026-09-02T09:00:00.000Z):\nOld key revoked",
				"  reply: dev-a (2026-09-02T09:30:00.000Z):\nConfirmed"},
			proj + "/issues/7/discussions", "page=1&per_page=5"},
		{"gitlab_list_merge_requests", `{"project":"platform/build/signer","state":"opened","target_branch":"main"}`,
			[]string{"!12 [opened] Switch signer to the new key", "rotate-key -> main", "end of results"}, proj + "/merge_requests", "page=1&per_page=20&state=opened&target_branch=main"},
		{"gitlab_get_merge_request", `{"project":"platform/build/signer","iid":12}`,
			[]string{"# !12: Switch signer to the new key", "merge status: mergeable", "dev-a (2026-09-04T11:00:00.000Z) on cmd/signer/main.go:42 [resolved]:",
				"  reply: dev-b (2026-09-04T11:30:00.000Z) on cmd/signer/main.go:42:\nYes, verify-only", "on cmd/signer/verify.go:17 (old):"},
			proj + "/merge_requests/12/discussions", "page=1&per_page=20"},
		{"gitlab_get_merge_request_diff", `{"project":"platform/build/signer","iid":12}`,
			[]string{"### cmd/signer/main.go", `+	keyID := "new"`, "### testdata/blob.bin (new file)", "[diff not returned by GitLab: too large]"}, proj + "/merge_requests/12/diffs", "page=1&per_page=20"},
		{"gitlab_get_file", `{"project":"platform/build/signer","path":"cmd/signer/main.go"}`,
			[]string{"# cmd/signer/main.go @ main", "func main() {}"}, proj + "/repository/files/cmd%2Fsigner%2Fmain.go/raw", "ref=main"},
		{"gitlab_get_file", `{"project":"platform/build/signer","path":"cmd/signer/main.go","ref":"release/v1.2.3+build"}`,
			[]string{"# cmd/signer/main.go @ release/v1.2.3+build", "package main // release"}, proj + "/repository/files/cmd%2Fsigner%2Fmain.go/raw", "ref=release%2Fv1.2.3%2Bbuild"},
		{"gitlab_list_pipelines", `{"project":"platform/build/signer","ref":"main"}`,
			[]string{"5501 [failed] main 8f3a2c1d9e0b push"}, proj + "/pipelines", "page=1&per_page=20&ref=main"},
		{"gitlab_list_pipelines", `{"project":"platform/build/signer","pipeline_id":5501}`,
			[]string{"77001 [failed] test/unit 61s"}, proj + "/pipelines/5501/jobs", "page=1&per_page=20"},
	}
	for _, c := range cases {
		before := len(h.fake.Requests())
		r := h.call(c.tool, c.args)
		if r.IsError {
			t.Errorf("%s: %s", c.tool, r.Text)
			continue
		}
		if strings.Contains(r.Text, "changed the description") {
			t.Errorf("%s: system note shown", c.tool)
		}
		for _, w := range c.want {
			if !strings.Contains(r.Text, w) {
				t.Errorf("%s: missing %q in\n%s", c.tool, w, r.Text)
			}
		}
		reqs := h.fake.Requests()[before:]
		last := reqs[len(reqs)-1]
		if reqs[0].Path != proj || last.Path != c.path || c.qry != "" && last.RawQuery != c.qry {
			t.Errorf("%s: requests %v, last %s?%s", c.tool, len(reqs), last.Path, last.RawQuery)
		}
		if last.Header.Get("PRIVATE-TOKEN") != sentinel || last.Header.Get("Authorization") != "" {
			t.Errorf("%s: wrong auth header", c.tool)
		}
	}
}

// An explicit notes:0 sends no discussions request; omitting it fetches 20.
func TestNotesZero(t *testing.T) {
	h := newHarness(t, "CONFIDENTIAL", nil, routes()...)
	for _, c := range []struct{ tool, args, item string }{
		{"gitlab_get_issue", `{"project":"platform/build/signer","iid":7,"notes":0}`, proj + "/issues/7"},
		{"gitlab_get_merge_request", `{"project":"platform/build/signer","iid":12,"notes":0}`, proj + "/merge_requests/12"},
	} {
		before := len(h.fake.Requests())
		r := h.call(c.tool, c.args)
		reqs := h.fake.Requests()[before:]
		if r.IsError || strings.Contains(r.Text, "## Discussions") || len(reqs) != 2 || reqs[1].Path != c.item {
			t.Errorf("%s: %d requests, last %s\n%s", c.tool, len(reqs), reqs[len(reqs)-1].Path, r.Text)
		}
	}
	before := len(h.fake.Requests())
	h.call("gitlab_get_issue", `{"project":"platform/build/signer","iid":7}`)
	if reqs := h.fake.Requests()[before:]; len(reqs) != 3 || reqs[2].RawQuery != "page=1&per_page=20" {
		t.Errorf("omitted notes: %+v", reqs)
	}
	if r := h.call("gitlab_get_issue", `{"project":"platform/build/signer","iid":7,"notes":-1}`); !r.IsError {
		t.Error("notes:-1 accepted")
	}
}

func TestNumericProjectAndPagination(t *testing.T) {
	h := newHarness(t, "CUI", nil, routes(
		fakeserver.Route{Method: "GET", Path: "/api/v4/projects/101", Fixture: "project.json"},
		fakeserver.Route{Method: "GET", Path: "/api/v4/projects/101/issues", Query: "page=3&per_page=5", Fixture: "issues.json", Header: map[string]string{"X-Page": "3"}},
		fakeserver.Route{Method: "GET", Path: "/api/v4/projects/101/issues", Query: "page=3&per_page=2", Fixture: "issues.json"},
	)...)
	r := h.call("gitlab_search_issues", `{"project":"101","page":3,"per_page":5}`)
	if r.IsError || !strings.Contains(r.Text, "end of results") || strings.Contains(r.Text, "request page") {
		t.Errorf("short page: %s", r.Text)
	}
	// No paging headers at all (a proxy stripped them): a full page is the only hint.
	r = h.call("gitlab_search_issues", `{"project":"101","page":3,"per_page":2}`)
	if r.IsError || !strings.Contains(r.Text, "sent no paging headers; more may exist: request page 4") {
		t.Errorf("headerless full page: %s", r.Text)
	}
	for _, bad := range []string{`{"project":"101","per_page":101}`, `{"project":"101","page":0,"per_page":-1}`, `{"project":"101","state":"bogus"}`} {
		if r := h.call("gitlab_search_issues", bad); !r.IsError {
			t.Errorf("%s accepted", bad)
		}
	}
}

// An empty diff means different things: GitLab omitted it (too large, or collapsed with
// too_large false), or the file was only renamed. Only the last is "no content change".
func TestEmptyDiffs(t *testing.T) {
	body := `[{"old_path":"big.go","new_path":"big.go","diff":"","too_large":true,"collapsed":false},` +
		`{"old_path":"gen.go","new_path":"gen.go","diff":"","too_large":false,"collapsed":true},` +
		`{"old_path":"old.go","new_path":"new.go","diff":"","renamed_file":true,"too_large":false,"collapsed":false},` +
		`{"old_path":"lib.go","new_path":"lib.go","diff":""},{"old_path":"a.go","new_path":"b.go","diff":"","renamed_file":true,"too_large":false}]`
	h := newHarness(t, "UNCLASSIFIED", nil, routes(fakeserver.Route{Method: "GET", Path: proj + "/merge_requests/17", Body: `{"iid":17,"labels":[]}`},
		fakeserver.Route{Method: "GET", Path: proj + "/merge_requests/17/diffs", Body: body})...)
	r := h.call("gitlab_get_merge_request_diff", `{"project":"platform/build/signer","iid":17}`)
	for _, w := range []string{"### big.go\n[diff not returned by GitLab: too large]", "### gen.go\n[diff not returned by GitLab: collapsed;",
		"### old.go -> new.go\n[no content change]", "### lib.go\n[diff not available from GitLab; the file may have changes",
		"### a.go -> b.go\n[diff not available from GitLab;"} {
		if r.IsError || !strings.Contains(r.Text, w) {
			t.Errorf("missing %q in\n%s", w, r.Text)
		}
	}
	if strings.Count(r.Text, "[no content change]") != 1 {
		t.Errorf("no content change claimed for an omitted diff:\n%s", r.Text)
	}
}

func TestDiffCaps(t *testing.T) {
	var files []map[string]any
	for i := range 8 {
		files = append(files, map[string]any{"old_path": fmt.Sprintf("f%d.go", i), "new_path": fmt.Sprintf("f%d.go", i), "diff": strings.Repeat("+line\n", 3000)})
	}
	body, _ := json.Marshal(files)
	h := newHarness(t, "UNCLASSIFIED", nil, routes(fakeserver.Route{Method: "GET", Path: proj + "/merge_requests/13", Body: `{"iid":13,"labels":[]}`},
		fakeserver.Route{Method: "GET", Path: proj + "/merge_requests/13/diffs", Body: string(body)})...)
	r := h.call("gitlab_get_merge_request_diff", `{"project":"platform/build/signer","iid":13}`)
	if r.IsError || !strings.Contains(r.Text, "[diff truncated: showed") || !strings.Contains(r.Text, "[total diff budget reached; not shown: f5.go, f6.go, f7.go]") {
		t.Errorf("caps: %s", r.Text[max(0, len(r.Text)-600):])
	}
	if len(r.Text) > diffTotalCap+8<<10 {
		t.Errorf("diff output %d bytes", len(r.Text))
	}
}

func TestJobLogTail(t *testing.T) {
	var b strings.Builder
	b.WriteString("\x1b[0Ksection_start:1790000000:step_script\r\x1b[0K\x1b[32;1mRunning\x1b[0;m\n")
	for i := range 500 {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	b.WriteString("progress 10%\rprogress 100%\n")
	big := strings.Repeat("x", 1000) + "\n"
	huge := strings.Repeat("y", 1000) + "\n"
	h := newHarness(t, "CUI", nil, routes(
		fakeserver.Route{Method: "GET", Path: proj + "/jobs/77001/trace", Body: b.String()},
		fakeserver.Route{Method: "GET", Path: proj + "/jobs/77002/trace", Body: strings.Repeat(big, 100)},
		fakeserver.Route{Method: "GET", Path: proj + "/jobs/77005/trace", Body: "\x1b]52;c;ZXZpbA==\x07copied \x1b]8;;https://link.example.invalid\x1b\\link\x1b]8;;\x1b\\ \x1bPq#0\x1b\\dcs \u009b31mred\x1b(B \x1b]0;title-unterminated\n"},
		fakeserver.Route{Method: "GET", Path: proj + "/jobs/77003/trace", Body: strings.Repeat(huge, 9000) + "build finished\n"},
		fakeserver.Route{Method: "GET", Path: proj + "/jobs/77004/trace", Status: 206, Header: map[string]string{"Content-Range": "bytes 900-917/918"},
			Body: "rtial first\nlast\n"},
	)...)
	r := h.call("gitlab_get_job_log", `{"project":"platform/build/signer","job_id":77005}`)
	if !strings.Contains(r.Text, "copied link dcs 31mred \n") || strings.ContainsAny(r.Text, "\x1b\x07\u009b") || strings.Contains(r.Text, "ZXZpbA") || strings.Contains(r.Text, "title-unterminated") {
		t.Errorf("terminal escapes survived: %q", r.Text)
	}
	r = h.call("gitlab_get_job_log", `{"project":"platform/build/signer","job_id":77001,"tail_lines":3}`)
	if r.IsError || !strings.Contains(r.Text, "line 498\nline 499\nprogress 100%\n") || strings.Contains(r.Text, "line 497") || strings.Contains(r.Text, "\x1b") {
		t.Errorf("tail: %q", r.Text)
	}
	r = h.call("gitlab_get_job_log", `{"project":"platform/build/signer","job_id":77002,"tail_lines":2000}`)
	if r.IsError || !strings.Contains(r.Text, "[log truncated to the last") || strings.Count(r.Text, "x") > logCap+200 {
		t.Errorf("byte cap: %d bytes", len(r.Text))
	}
	// 9 MB, over the egress client's 8 MiB body cap: Tail still returns the end.
	r = h.call("gitlab_get_job_log", `{"project":"platform/build/signer","job_id":77003,"tail_lines":5}`)
	if r.IsError || !strings.HasSuffix(strings.TrimSpace(strings.Split(r.Text, "```")[1]), "build finished") {
		t.Errorf("over-cap log: %s", r.Text[max(0, len(r.Text)-400):])
	}
	tr := h.fake.Requests()
	if tr[len(tr)-1].Header.Get("Range") != fmt.Sprintf("bytes=-%d", logFetch) {
		t.Errorf("no suffix range: %v", tr[len(tr)-1].Header)
	}
	r = h.call("gitlab_get_job_log", `{"project":"platform/build/signer","job_id":77004}`)
	if r.IsError || strings.Contains(r.Text, "rtial first") || !strings.Contains(r.Text, "```\nlast\n```") {
		t.Errorf("partial range: %s", r.Text)
	}
	if r := h.call("gitlab_get_job_log", `{"project":"platform/build/signer","job_id":77001,"tail_lines":5000}`); !r.IsError {
		t.Error("tail_lines over the limit accepted")
	}
}

func TestFileBinaryAndCap(t *testing.T) {
	h := newHarness(t, "CUI", nil, routes(
		fakeserver.Route{Method: "GET", Path: proj + "/repository/files/logo.png/raw", Body: "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"},
		fakeserver.Route{Method: "GET", Path: proj + "/repository/files/big.txt/raw", Query: "ref=v1.2.0", Body: strings.Repeat("abcdefghi\n", 10000)},
	)...)
	r := h.call("gitlab_get_file", `{"project":"platform/build/signer","path":"logo.png","ref":"main"}`)
	if !r.IsError || !strings.Contains(r.Text, "binary") || strings.Contains(r.Text, "IHDR") {
		t.Errorf("binary: %s", r.Text)
	}
	r = h.call("gitlab_get_file", `{"project":"platform/build/signer","path":"big.txt","ref":"v1.2.0"}`)
	if r.IsError || !strings.Contains(r.Text, "[file truncated: showed") {
		t.Errorf("cap: %s", r.Text[len(r.Text)-300:])
	}
}

// Every bad identifier is refused before the connector sends anything.
func TestValidationBeforeRequest(t *testing.T) {
	h := newHarness(t, "CUI", nil, routes()...)
	bad := map[string][]string{
		"gitlab_get_file": {
			`{"project":"platform/build/signer","path":"../etc/passwd"}`, `{"project":"platform/build/signer","path":"a/../b"}`,
			`{"project":"platform/build/signer","path":"/etc/passwd"}`, `{"project":"platform/build/signer","path":"a//b"}`,
			`{"project":"platform/build/signer","path":"a\\..\\b"}`, `{"project":"platform/build/signer","path":"./a"}`,
			`{"project":"platform/build/signer","path":"a","ref":"main..evil"}`, `{"project":"platform/build/signer","path":"a","ref":"-x"}`,
			`{"project":"platform/build/signer","path":"a","ref":"a b"}`, `{"project":"platform/build/signer","path":"a","ref":"x.lock"}`,
		},
		"gitlab_get_project":    {`{"project":"../admin"}`, `{"project":"/platform/build"}`, `{"project":"platform/../x"}`, `{"project":"group%2Fx"}`, `{"project":""}`, `{"project":"a?b"}`},
		"gitlab_get_issue":      {`{"project":"platform/build/signer","iid":0}`, `{"project":"platform/build/signer","iid":-3}`, `{"project":"platform/build/signer","iid":"7"}`},
		"gitlab_list_pipelines": {`{"project":"platform/build/signer","ref":"../main"}`, `{"project":"platform/build/signer","status":"exploded"}`},
	}
	for tool, argsList := range bad {
		for _, args := range argsList {
			if r := h.call(tool, args); !r.IsError {
				t.Errorf("%s %s accepted", tool, args)
			}
		}
	}
	if n := len(h.fake.Requests()); n != 0 {
		t.Errorf("%d requests sent for invalid input: %+v", n, h.fake.Requests())
	}
}

func TestToolNames(t *testing.T) {
	h := newHarness(t, "CUI", nil, routes()...)
	want := []string{"gitlab_get_file", "gitlab_get_issue", "gitlab_get_job_log", "gitlab_get_merge_request", "gitlab_get_merge_request_diff",
		"gitlab_get_project", "gitlab_list_merge_requests", "gitlab_list_pipelines", "gitlab_search_issues"}
	if got := h.ToolNames(); !slices.Equal(got, want) {
		t.Errorf("tools: %v", got)
	}
}

func TestErrors(t *testing.T) {
	h := newHarness(t, "CUI", nil, routes(
		fakeserver.Route{Method: "GET", Path: proj + "/issues/401", Status: 401, Body: `{"message":"401 Unauthorized"}`},
		fakeserver.Route{Method: "GET", Path: proj + "/issues/403", Status: 403, Body: `{"message":"403 Forbidden"}`},
		fakeserver.Route{Method: "GET", Path: proj + "/issues/404", Status: 404, Body: `{"message":"404 Issue Not Found"}`},
		fakeserver.Route{Method: "GET", Path: proj + "/issues/429", Status: 429, Body: `Retry later`, Header: map[string]string{"Retry-After": "30"}},
		fakeserver.Route{Method: "GET", Path: proj + "/issues", Query: "labels=echo&page=1&per_page=20", Status: 400, EchoAuth: true},
		fakeserver.Route{Method: "GET", Path: proj + "/issues", Query: "search=x&page=1&per_page=20", Status: 400, Body: `{"error":"search is too short"}`},
		// GitLab's array form of message, seen live on 409 and 422.
		fakeserver.Route{Method: "GET", Path: proj + "/merge_requests", Query: "source_branch=dup&page=1&per_page=20", Status: 409,
			Body: `{"message":["Another open merge request already exists for this source branch: !1"]}`},
		fakeserver.Route{Method: "GET", Path: proj + "/issues", Query: "search=xx&page=1&per_page=20", Status: 400, Body: `{"error":"` + strings.Repeat("q", 2000) + `"}`},
		// The message sits after 400 bytes of other fields: only HTTPError.Body still has it.
		fakeserver.Route{Method: "GET", Path: proj + "/merge_requests", Query: "labels=long&page=1&per_page=20", Status: 422,
			Body: `{"trace":"` + strings.Repeat("z", 400) + `","message":{"target_branch":["is invalid"],"labels":["is too long"]}}`},
	)...)
	want := map[string]string{
		"401": "credential was rejected or lacks permission (HTTP 401)", "403": "credential was rejected or lacks permission (HTTP 403)",
		"404": "not found, or not visible to you (HTTP 404)", "429": "retry after 30 seconds",
	}
	for iid, w := range want {
		r := h.call("gitlab_get_issue", `{"project":"platform/build/signer","iid":`+iid+`}`)
		if !r.IsError || !strings.Contains(r.Text, w) {
			t.Errorf("%s: %s", iid, r.Text)
		}
	}
	r := h.call("gitlab_list_merge_requests", `{"project":"platform/build/signer","labels":"long"}`)
	if !r.IsError || !strings.Contains(r.Text, "GitLab rejected the request (HTTP 422): labels is too long; target_branch is invalid") || strings.Contains(r.Text, "zzz") {
		t.Errorf("422: %s", r.Text)
	}
	r = h.call("gitlab_list_merge_requests", `{"project":"platform/build/signer","source_branch":"dup"}`)
	if !r.IsError || !strings.Contains(r.Text, "GitLab rejected the request (HTTP 409): Another open merge request already exists for this source branch: !1") || strings.Contains(r.Text, `["`) {
		t.Errorf("409 array message: %s", r.Text)
	}
	r = h.call("gitlab_search_issues", `{"project":"platform/build/signer","search":"x"}`)
	if !r.IsError || !strings.Contains(r.Text, "(HTTP 400): search is too short") {
		t.Errorf("400: %s", r.Text)
	}
	r = h.call("gitlab_search_issues", `{"project":"platform/build/signer","search":"xx"}`)
	if n := strings.Count(r.Text, "q"); !r.IsError || n < 290 || n > 310 {
		t.Errorf("long message not cut to 300 bytes: %d", n)
	}
	r = h.call("gitlab_search_issues", `{"project":"platform/build/signer","labels":"echo"}`)
	if !r.IsError || strings.Contains(r.Text, sentinel) || !strings.Contains(r.Text, "[redacted]") {
		t.Errorf("400 echo: %s", r.Text)
	}
}

// A GitLab instance holds one classification: content that looks like a marking (a label, a
// topic, a file's first line) never changes the banner, which is always the connector's own.
func TestContentNeverChangesBanner(t *testing.T) {
	marked := `{"id":102,"path_with_namespace":"platform/vault","default_branch":"main","topics":["classification::TOP SECRET"]}`
	rs := routes(
		fakeserver.Route{Method: "GET", Path: "/api/v4/projects/platform%2Fvault", Body: marked},
		fakeserver.Route{Method: "GET", Path: "/api/v4/projects/platform%2Fvault/repository/files/README.md/raw", Query: "ref=main", Body: "// TOP SECRET//SI\nhello\n"},
		fakeserver.Route{Method: "GET", Path: proj + "/issues/9", Body: `{"iid":9,"title":"t","labels":["classification::bogus-level"]}`},
		fakeserver.Route{Method: "GET", Path: proj + "/issues/9/discussions", Body: `[]`},
		fakeserver.Route{Method: "GET", Path: proj + "/merge_requests/14/diffs", Body: `[{"old_path":"a.go","new_path":"a.go","diff":"@@ -1 +1 @@\n-a\n+b\n"}]`},
		fakeserver.Route{Method: "GET", Path: "/api/v4/projects/platform%2Fnull", Body: "null"},
		fakeserver.Route{Method: "GET", Path: proj + "/issues/16", Body: "null"},
		fakeserver.Route{Method: "GET", Path: "/api/v4/projects/platform%2Fempty", Body: "{}"},
	)
	h := newHarness(t, "CONFIDENTIAL", nil, rs...)
	for _, c := range [][2]string{
		{"gitlab_get_project", `{"project":"platform/vault"}`},
		{"gitlab_get_file", `{"project":"platform/vault","path":"README.md"}`},
		{"gitlab_get_issue", `{"project":"platform/build/signer","iid":7}`},
		{"gitlab_get_issue", `{"project":"platform/build/signer","iid":9}`},
		{"gitlab_search_issues", `{"project":"platform/build/signer"}`},
		{"gitlab_get_merge_request_diff", `{"project":"platform/build/signer","iid":14}`},
	} {
		r := h.call(c[0], c[1])
		if r.IsError || r.Banner != "CONFIDENTIAL" || !strings.HasPrefix(r.Text, "CONFIDENTIAL\n") || !strings.HasSuffix(r.Text, "\nCONFIDENTIAL") {
			t.Errorf("%s %s: banner %q\n%s", c[0], c[1], r.Banner, r.Text)
		}
	}
	// A malformed response is still refused, whatever it carries.
	for _, c := range [][2]string{
		{"gitlab_get_project", `{"project":"platform/null"}`},
		{"gitlab_get_project", `{"project":"platform/empty"}`},
		{"gitlab_get_issue", `{"project":"platform/build/signer","iid":16}`},
	} {
		if r := h.call(c[0], c[1]); !r.IsError || r.Banner != "CONFIDENTIAL" {
			t.Errorf("%s %s: malformed response accepted: %s", c[0], c[1], r.Text)
		}
	}
}

// The credential never reaches tool output under either scheme, even when the service echoes it.
func TestSentinelNeverInOutput(t *testing.T) {
	for _, auth := range []string{"--auth=private-token", "--auth=bearer"} {
		h := newHarness(t, "CUI", []string{auth}, routes(fakeserver.Route{Method: "GET", Path: proj + "/repository/files/echo.txt/raw", EchoAuth: true},
			fakeserver.Route{Method: "GET", Path: proj + "/issues/99", Status: 403, EchoAuth: true})...)
		for _, args := range []string{`{"project":"platform/build/signer","path":"echo.txt","ref":"main"}`} {
			r := h.call("gitlab_get_file", args)
			if r.IsError || strings.Contains(r.Text, sentinel) || !strings.Contains(r.Text, "[redacted]") {
				t.Errorf("%s: %s", auth, r.Text)
			}
		}
		if r := h.call("gitlab_get_issue", `{"project":"platform/build/signer","iid":99}`); strings.Contains(r.Text, sentinel) {
			t.Errorf("%s: %s", auth, r.Text)
		}
		got := h.fake.Requests()[0].Header
		bearer := auth == "--auth=bearer"
		if bearer && (got.Get("Authorization") != "Bearer "+sentinel || got.Get("PRIVATE-TOKEN") != "") ||
			!bearer && (got.Get("PRIVATE-TOKEN") != sentinel || got.Get("Authorization") != "") {
			t.Errorf("%s header: %v", auth, got)
		}
	}
}

func TestCheckRef(t *testing.T) {
	for _, ok := range []string{"", "main", "release/v1.2.3+build", "feature/@alice", "fix/\u00fcmlaut", "v1.0-rc.1", "8f3a2c1d9e0b", "a,b=c", "user/name#1"} {
		if err := checkRef(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"main..evil", "-x", "a b", "x.lock", "a.lock/b", ".hidden/x", "a/.b", "a@{1}", "@", "x~1", "x^", "a:b", "a?b", "a*b", "a[b",
		"a\\b", "/a", "a/", "a//b", "a.", "a\tb", "a\u007fb"} {
		if checkRef(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFlags(t *testing.T) {
	base := []string{"--base-url", "https://gitlab.example.invalid/api/v4", "--token-file", "/run/token", "--classification", "CUI"}
	spec, _, err := sdk.Parse(newSpec(), base)
	if err != nil || spec.Scheme != sdk.PrivateToken {
		t.Errorf("default: %v %v", spec.Scheme, err)
	}
	spec, cfg, err := sdk.Parse(newSpec(), append(base, "--auth", "bearer", "--enable-writes"))
	if err != nil || spec.Scheme != sdk.Bearer || !cfg.EnableWrites {
		t.Errorf("flags: %v %+v %v", spec.Scheme, cfg, err)
	}
	t.Setenv("BADGER_CONNECTOR_GITLAB_AUTH", "bearer")
	if spec, _, err := sdk.Parse(newSpec(), base); err != nil || spec.Scheme != sdk.Bearer {
		t.Errorf("env: %v %v", spec.Scheme, err)
	}
	if spec, _, err := sdk.Parse(newSpec(), append(base, "--auth=private-token")); err != nil || spec.Scheme != sdk.PrivateToken {
		t.Errorf("flag over env: %v %v", spec.Scheme, err)
	}
	if _, _, err := sdk.Parse(newSpec(), append(base, "--auth=basic")); err == nil {
		t.Error("unknown auth scheme accepted")
	}
}

// Codex suggestion on #185/#186: a 200 response that is {} or names another item is refused, not
// shown as #0 or !0.
func TestItemMustBeTheOneRequested(t *testing.T) {
	h := newHarness(t, "CONFIDENTIAL", nil, routes(
		fakeserver.Route{Method: "GET", Path: proj + "/issues/31", Body: `{}`},
		fakeserver.Route{Method: "GET", Path: proj + "/merge_requests/32", Body: `{"iid":33,"title":"other"}`},
	)...)
	for _, c := range [][2]string{
		{"gitlab_get_issue", `{"project":"platform/build/signer","iid":31,"notes":0}`},
		{"gitlab_get_merge_request", `{"project":"platform/build/signer","iid":32,"notes":0}`},
	} {
		if r := h.call(c[0], c[1]); !r.IsError || !strings.Contains(r.Text, "not the one requested") || strings.Contains(r.Text, "other") {
			t.Errorf("%s %s: %s", c[0], c[1], r.Text)
		}
	}
}
