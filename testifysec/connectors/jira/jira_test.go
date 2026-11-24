package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/sdk"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/fakeserver"
)

const sentinel = "SENTINEL-JIRA-TOKEN-7e11"

const api = "/jira/rest/api/2"

type setup struct {
	writes         bool
	classification string
}

func start(t *testing.T, st setup, routes ...fakeserver.Route) (*sdk.Server, *fakeserver.Server) {
	t.Helper()
	fake := fakeserver.New(t, "testdata", routes...)
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	if st.classification == "" {
		st.classification = "UNCLASSIFIED"
	}
	s, err := sdk.New(spec, sdk.Config{BaseURL: fake.URL + "/jira", TokenFile: tok,
		EnableWrites: st.writes, InsecureLoopbackHTTP: true, Classification: st.classification})
	if err != nil {
		t.Fatal(err)
	}
	return s, fake
}

func call(s *sdk.Server, tool, args string) sdk.CallResult {
	return s.Call(context.Background(), tool, json.RawMessage(args))
}

func q(kv ...string) string {
	v := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v.Encode()
}

func want(t *testing.T, r sdk.CallResult, isErr bool, subs ...string) {
	t.Helper()
	if r.IsError != isErr {
		t.Errorf("IsError=%v, want %v:\n%s", r.IsError, isErr, r.Text)
	}
	for _, s := range subs {
		if !strings.Contains(r.Text, s) {
			t.Errorf("missing %q in:\n%s", s, r.Text)
		}
	}
	if strings.Contains(r.Text, sentinel) {
		t.Errorf("credential in output:\n%s", r.Text)
	}
}

func TestToolsAndWriteGate(t *testing.T) {
	s, _ := start(t, setup{})
	read := []string{"jira_get_issue", "jira_list_comments", "jira_search"}
	if got := s.ToolNames(); !reflect.DeepEqual(got, read) {
		t.Errorf("read-only tools: %v", got)
	}
	want(t, call(s, "jira_add_comment", `{"key":"OPS-42","body":"x"}`), true, "unknown tool")
	w, _ := start(t, setup{writes: true})
	all := []string{"jira_add_comment", "jira_create_issue", "jira_get_issue", "jira_list_comments", "jira_search", "jira_transition_issue"}
	if got := w.ToolNames(); !reflect.DeepEqual(got, all) {
		t.Errorf("with writes: %v", got)
	}
}

func TestSearchPaging(t *testing.T) {
	jql := "project = OPS ORDER BY updated DESC"
	fields := "summary,status,issuetype,priority,assignee,updated"
	s, fake := start(t, setup{},
		fakeserver.Route{Method: "GET", Path: api + "/search", Query: q("jql", jql, "startAt", "0", "maxResults", "2", "fields", fields), Fixture: "search-page1.json"},
		fakeserver.Route{Method: "GET", Path: api + "/search", Query: q("jql", jql, "startAt", "2", "maxResults", "2", "fields", fields), Fixture: "search-page2.json"},
	)
	r := call(s, "jira_search", `{"jql":"project = OPS ORDER BY updated DESC","max_results":2}`)
	want(t, r, false, "issues 1-2 of 3", "next page: start_at=2", "**OPS-42** [In Progress] Rotate the build signing key",
		"Task, High, Dana Example, updated 2026-10-01", "**OPS-41** [To Do] Document the release checklist", "unassigned")
	r = call(s, "jira_search", `{"jql":"project = OPS ORDER BY updated DESC","max_results":2,"start_at":2}`)
	want(t, r, false, "issues 3-3 of 3", "**OPS-40** [Done]")
	if strings.Contains(r.Text, "next page") {
		t.Errorf("last page offers a next page:\n%s", r.Text)
	}
	if n := len(fake.Requests()); n != 2 {
		t.Errorf("%d requests", n)
	}
	if got := fake.Requests()[0].Header.Get("Authorization"); got != "Bearer "+sentinel {
		t.Errorf("auth header %q", got)
	}
}

func TestSearchFieldsAndCap(t *testing.T) {
	s, fake := start(t, setup{},
		fakeserver.Route{Method: "GET", Path: api + "/search", Query: q("jql", "assignee = currentUser()", "startAt", "0", "maxResults", "50", "fields", "summary,status,duedate"), Fixture: "search-page2.json"},
		fakeserver.Route{Method: "GET", Path: api + "/search", Query: q("jql", "key = OPS-40", "startAt", "0", "maxResults", "20", "fields", "summary,status,assignee,priority"), Fixture: "search-page2.json"},
	)
	want(t, call(s, "jira_search", `{"jql":"assignee = currentUser()","max_results":500,"fields":["duedate","summary"]}`), false, "OPS-40")
	// Built-in fields named explicitly are rendered, not dropped.
	want(t, call(s, "jira_search", `{"jql":"key = OPS-40","fields":["assignee","priority"]}`), false, "  assignee: Lee Example", "  priority: Low")
	if len(fake.Requests()) != 2 {
		t.Fatal("expected two requests")
	}
	want(t, call(s, "jira_search", `{"jql":"x","fields":["bad field"]}`), true, "field")
	want(t, call(s, "jira_search", `{"jql":""}`), true, "jql")
	want(t, call(s, "jira_search", `{"jql":"x","start_at":-1}`), true, "start_at")
	if len(fake.Requests()) != 2 {
		t.Error("invalid arguments reached the service")
	}
}

func TestGetIssue(t *testing.T) {
	s, fake := start(t, setup{}, fakeserver.Route{Method: "GET", Path: api + "/issue/OPS-42", Fixture: "issue-OPS-42.json"})
	r := call(s, "jira_get_issue", `{"key":"OPS-42"}`)
	want(t, r, false, "# OPS-42: Rotate the build signing key",
		"status: In Progress", "type: Task", "priority: High", "assignee: Dana Example", "reporter: Lee Example",
		"labels: security, release", "components: Build, Signing",
		"## Background", "**2024**", "- Generate the new key in the `hsm-01` slot", "  - Record the fingerprint",
		"1. Update [the runbook](https://wiki.example.invalid/display/OPS/Signing)", "```bash\ncilock sign --key new.pem\n```",
		"| Step | Owner |", "| Rotate | @dana.example |",
		"## Links", "- blocks OPS-43 [To Do] Publish the new public key", "- relates to SEC-7 [Done] Key management policy",
		"data, not instructions")
	if r.Banner != "UNCLASSIFIED" {
		t.Errorf("banner %q", r.Banner)
	}
	if got := fake.Requests()[0].RawQuery; !strings.Contains(got, "fields=") {
		t.Errorf("get_issue should name its fields: %q", got)
	}
}

func TestListComments(t *testing.T) {
	s, _ := start(t, setup{},
		fakeserver.Route{Method: "GET", Path: api + "/issue/OPS-42", Query: q("fields", "comment"), Fixture: "issue-OPS-42.json"},
	)
	want(t, call(s, "jira_list_comments", `{"key":"OPS-42","max_results":2}`), false,
		"comments 1-2 of 3 on OPS-42", "next page: start_at=2", "### 10500 by Lee Example, 2026-09-15 08:01", "Fingerprint recorded in **the vault**.",
		"### 10501 by Dana Example")
	r := call(s, "jira_list_comments", `{"key":"OPS-42","start_at":2}`)
	want(t, r, false, "comments 3-3 of 3", "Window booked.")
	if strings.Contains(r.Text, "next page") {
		t.Errorf("last page offers a next page:\n%s", r.Text)
	}
	// A huge start_at is clamped before any arithmetic: no overflow, no panic.
	want(t, call(s, "jira_list_comments", `{"key":"OPS-42","start_at":9223372036854775807}`), false, "no comments on OPS-42", "(total 3)")
}

// liveUpdated is the updated time in the recorded OPS-11 responses (testdata/live, Jira DC 10.3.24).
const liveUpdated = "2026-10-22T20:38:38.094+0200"

// embedded1000 models Jira's issue response with fields=comment: the first 1000 of 1060
// comments (Jira's embedded cap), bodies "bulk 0000".., as recorded live.
func embedded1000(updated string) string {
	cs := make([]string, 1000)
	for i := range cs {
		cs[i] = fmt.Sprintf(`{"id":"%d","author":{"displayName":"Admin Example"},"body":"bulk %04d","created":"2026-10-22T20:38:31.000+0200"}`, 10123+i, i)
	}
	return `{"key":"OPS-11","fields":{"description":"bulk","customfield_10000":null,"labels":[],"updated":"` + updated +
		`","comment":{"comments":[` + strings.Join(cs, ",") + `],"maxResults":1000,"total":1060,"startAt":0}}}`
}

// Jira embeds at most 1000 comments. Pages within them come from the issue response; pages past
// or across the cap come from the comment endpoint (live recordings). A comment that opens with
// something banner-shaped changes nothing: the banner is the connector's.
func TestListCommentsServerPaging(t *testing.T) {
	page := func(fixture, startAt, max string) fakeserver.Route {
		return fakeserver.Route{Method: "GET", Path: api + "/issue/OPS-11/comment", Query: q("startAt", startAt, "maxResults", max, "orderBy", "created"), Fixture: fixture}
	}
	issue := fakeserver.Route{Method: "GET", Path: api + "/issue/OPS-11", Body: embedded1000(liveUpdated)}
	s, fake := start(t, setup{}, issue)
	want(t, call(s, "jira_list_comments", `{"key":"OPS-11","start_at":980}`), false,
		"comments 981-1000 of 1060 on OPS-11", "bulk 0980", "bulk 0999", "next page: start_at=1000")
	if n := len(fake.Requests()); n != 1 {
		t.Errorf("a page inside the cap took %d requests", n)
	}
	for _, c := range []struct{ args, page, startAt, max, first, last string }{
		{`{"key":"OPS-11","start_at":990}`, "live/straddle-page.json", "990", "20", "bulk 0990", "bulk 1009"},
		{`{"key":"OPS-11","start_at":1000,"max_results":50}`, "live/beyond-page.json", "1000", "50", "bulk 1000", "bulk 1049"},
	} {
		s, fake := start(t, setup{}, issue, page(c.page, c.startAt, c.max))
		r := call(s, "jira_list_comments", c.args)
		want(t, r, false, "of 1060 on OPS-11", c.first, c.last)
		if r.Banner != "UNCLASSIFIED" {
			t.Errorf("%s: banner %q", c.args, r.Banner)
		}
		if n := len(fake.Requests()); n != 2 {
			t.Errorf("%s: %d requests, want issue, page", c.args, n)
		}
	}
}

// Live recordings from Jira DC 10.3.24: errors as the server sends them.
func TestLiveRecordings(t *testing.T) {
	s, _ := start(t, setup{writes: true},
		fakeserver.Route{Method: "GET", Path: api + "/issue/HID-1", Status: 403, Fixture: "live/hidden-403.json"},
		fakeserver.Route{Method: "POST", Path: api + "/issue/HID-1/comment", Status: 403, Fixture: "live/comment-hidden-403.json"},
		fakeserver.Route{Method: "GET", Path: api + "/issue/OPS-99999", Status: 404, Fixture: "live/missing-404.json"},
		fakeserver.Route{Method: "GET", Path: api + "/search", Status: 400, Fixture: "live/bad-jql-400.json"},
		fakeserver.Route{Method: "POST", Path: api + "/issue", Status: 400, Fixture: "live/create-bad-type-400.json"},
	)
	// Jira answers 403 for an issue the user cannot see; that is not a credential problem.
	for _, r := range []sdk.CallResult{call(s, "jira_get_issue", `{"key":"HID-1"}`), call(s, "jira_add_comment", `{"key":"HID-1","body":"x"}`)} {
		want(t, r, true, "not visible to this credential, or does not exist (HTTP 403)")
		if strings.Contains(r.Text, "credential was rejected") {
			t.Errorf("403 worded as a bad credential:\n%s", r.Text)
		}
	}
	want(t, call(s, "jira_get_issue", `{"key":"OPS-99999"}`), true, "not found, or not visible to you (HTTP 404)")
	want(t, call(s, "jira_search", `{"jql":"project = = OPS"}`), true, "(HTTP 400): Error in JQL Query: Expecting either a value, list or function but got '='.")
	want(t, call(s, "jira_create_issue", `{"project":"OPS","issue_type":"Nope","summary":"x"}`), true, "(HTTP 400): issuetype: issue type is required")
}

func TestInvalidKeysNeverReachTheService(t *testing.T) {
	s, fake := start(t, setup{writes: true})
	for _, key := range []string{"OPS-42/../../admin", "ops-42", "OPS 42", "OPS-0", "OPS-", "-42", "OPS-42?x=1", "OPS-42%2F", "../OPS-1", ""} {
		arg, _ := json.Marshal(map[string]string{"key": key})
		want(t, call(s, "jira_get_issue", string(arg)), true, "issue key")
		want(t, call(s, "jira_list_comments", string(arg)), true, "issue key")
		arg, _ = json.Marshal(map[string]string{"key": key, "body": "x"})
		want(t, call(s, "jira_add_comment", string(arg)), true, "issue key")
		arg, _ = json.Marshal(map[string]string{"key": key, "transition": "Done"})
		want(t, call(s, "jira_transition_issue", string(arg)), true, "issue key")
	}
	for _, p := range []string{"ops", "O", "OPS/../X", "OPS-1"} {
		arg, _ := json.Marshal(map[string]string{"project": p, "issue_type": "Task", "summary": "s"})
		want(t, call(s, "jira_create_issue", string(arg)), true, "project key")
	}
	want(t, call(s, "jira_get_issue", `{"key":"OPS-1","extra":1}`), true, "invalid arguments")
	if n := len(fake.Requests()); n != 0 {
		t.Errorf("%d requests sent for invalid input: %+v", n, fake.Requests())
	}
}

func TestWriteTools(t *testing.T) {
	s, fake := start(t, setup{writes: true},
		fakeserver.Route{Method: "POST", Path: api + "/issue/OPS-42/comment", Status: 201, Fixture: "comment-added.json"},
		fakeserver.Route{Method: "POST", Path: api + "/issue", Status: 201, Fixture: "created.json"},
		fakeserver.Route{Method: "GET", Path: api + "/issue/OPS-42/transitions", Fixture: "transitions-OPS-42.json"},
		fakeserver.Route{Method: "POST", Path: api + "/issue/OPS-42/transitions", Status: 204},
	)
	want(t, call(s, "jira_add_comment", `{"key":"OPS-42","body":"done"}`), false, "comment 10502 added to OPS-42")
	want(t, call(s, "jira_create_issue", `{"project":"OPS","issue_type":"Task","summary":"Rotate the CI key","description":"Steps follow."}`), false, "created OPS-44")
	want(t, call(s, "jira_transition_issue", `{"key":"OPS-42","transition":"start progress"}`), false, "OPS-42: applied transition Start Progress (21)")
	want(t, call(s, "jira_transition_issue", `{"key":"OPS-42","transition":"31"}`), false, "applied transition Done (31)")
	want(t, call(s, "jira_transition_issue", `{"key":"OPS-42","transition":"Reopen"}`), true,
		`no transition "Reopen" on OPS-42`, "available: 11 To Do, 21 Start Progress, 31 Done")
	reqs := fake.Requests()
	bodies := []string{}
	for _, r := range reqs {
		if r.Method == "POST" {
			bodies = append(bodies, string(r.Body))
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("content type %q", r.Header.Get("Content-Type"))
			}
		}
	}
	wantBodies := []string{
		`{"body":"done"}`,
		`{"fields":{"description":"Steps follow.","issuetype":{"name":"Task"},"project":{"key":"OPS"},"summary":"Rotate the CI key"}}`,
		`{"transition":{"id":"21"}}`,
		`{"transition":{"id":"31"}}`,
	}
	if !reflect.DeepEqual(bodies, wantBodies) {
		t.Errorf("bodies:\n%v\nwant\n%v", bodies, wantBodies)
	}
	want(t, call(s, "jira_create_issue", `{"project":"OPS","issue_type":"Task","summary":"two\nlines"}`), true, "summary")
	// The limit counts characters, not bytes: 255 two-byte characters pass, 256 do not.
	want(t, call(s, "jira_create_issue", `{"project":"OPS","issue_type":"Task","summary":"`+strings.Repeat("é", 255)+`"}`), false, "created OPS-44")
	want(t, call(s, "jira_create_issue", `{"project":"OPS","issue_type":"Task","summary":"`+strings.Repeat("é", 256)+`"}`), true, "summary")
	want(t, call(s, "jira_add_comment", `{"key":"OPS-42","body":"  "}`), true, "body")
}

// sdk.Decode does not enforce "required"; every write tool checks its own arguments, and a
// missing or empty one never reaches the service.
// A transition id is matched exactly across the whole list before any name is tried, so a
// transition named like another's id cannot capture it; a name matching two transitions is refused.
func TestTransitionIDBeforeName(t *testing.T) {
	s, fake := start(t, setup{writes: true},
		fakeserver.Route{Method: "GET", Path: api + "/issue/OPS-43/transitions", Fixture: "transitions-OPS-43.json"},
		fakeserver.Route{Method: "POST", Path: api + "/issue/OPS-43/transitions", Status: 204})
	want(t, call(s, "jira_transition_issue", `{"key":"OPS-43","transition":"31"}`), false, "applied transition Done (31)")
	want(t, call(s, "jira_transition_issue", `{"key":"OPS-43","transition":"close"}`), true, `"close" matches more than one transition`, "41 Close", "51 close")
	var posts []string
	for _, r := range fake.Requests() {
		if r.Method == "POST" {
			posts = append(posts, string(r.Body))
		}
	}
	if !reflect.DeepEqual(posts, []string{`{"transition":{"id":"31"}}`}) {
		t.Errorf("posted %v", posts)
	}
}

func TestWriteToolsRequireArguments(t *testing.T) {
	s, fake := start(t, setup{writes: true})
	for _, c := range []struct{ tool, args, msg string }{
		{"jira_add_comment", `{"key":"OPS-42"}`, "body"},
		{"jira_add_comment", `{"key":"OPS-42","body":" \n "}`, "body"},
		{"jira_add_comment", `{"body":"x"}`, `"key" is required`},
		{"jira_create_issue", `{"issue_type":"Task","summary":"s"}`, `"project" is required`},
		{"jira_create_issue", `{"project":"OPS","summary":"s"}`, "issue_type"},
		{"jira_create_issue", `{"project":"OPS","issue_type":" ","summary":"s"}`, "issue_type"},
		{"jira_create_issue", `{"project":"OPS","issue_type":"Task"}`, "summary"},
		{"jira_create_issue", `{"project":"OPS","issue_type":"Task","summary":"  "}`, "summary"},
		{"jira_transition_issue", `{"key":"OPS-42"}`, "transition"},
		{"jira_transition_issue", `{"key":"OPS-42","transition":"  "}`, "transition"},
		{"jira_transition_issue", `{"transition":"Done"}`, `"key" is required`},
		{"jira_search", `{}`, "jql"},
		{"jira_get_issue", `{}`, `"key" is required`},
		{"jira_list_comments", `{}`, `"key" is required`},
	} {
		want(t, call(s, c.tool, c.args), true, c.msg)
	}
	if n := len(fake.Requests()); n != 0 {
		t.Errorf("%d requests sent with missing arguments: %+v", n, fake.Requests())
	}
}

func TestErrorMapping(t *testing.T) {
	s, _ := start(t, setup{writes: true},
		fakeserver.Route{Method: "GET", Path: api + "/issue/OPS-1", Status: 401, Body: `{"errorMessages":["You are not authenticated."],"errors":{}}`},
		fakeserver.Route{Method: "GET", Path: api + "/issue/OPS-2", Status: 403, EchoAuth: true},
		fakeserver.Route{Method: "GET", Path: api + "/issue/OPS-3", Status: 404, Fixture: "error-404.json"},
		fakeserver.Route{Method: "GET", Path: api + "/issue/OPS-4", Status: 429, Header: map[string]string{"Retry-After": "30"}, Body: `{}`},
		fakeserver.Route{Method: "GET", Path: api + "/issue/OPS-5", Status: 400, EchoAuth: true},
		fakeserver.Route{Method: "GET", Path: api + "/issue/OPS-6", EchoAuth: true},
		fakeserver.Route{Method: "GET", Path: api + "/search", Status: 400, Fixture: "error-jql.json"},
		fakeserver.Route{Method: "POST", Path: api + "/issue", Status: 400, Fixture: "error-create.json"},
		fakeserver.Route{Method: "POST", Path: api + "/issue/OPS-42/comment", Status: 400, Body: `{"errorMessages":["Comment body ` + strings.Repeat("is far too long ", 30) + `"],"errors":{}}`},
	)
	want(t, call(s, "jira_get_issue", `{"key":"OPS-1"}`), true, "credential was rejected or lacks permission (HTTP 401)")
	want(t, call(s, "jira_get_issue", `{"key":"OPS-2"}`), true, "not visible to this credential, or does not exist (HTTP 403)")
	want(t, call(s, "jira_get_issue", `{"key":"OPS-3"}`), true, "not found, or not visible to you (HTTP 404)")
	want(t, call(s, "jira_get_issue", `{"key":"OPS-4"}`), true, "retry after 30 seconds")
	want(t, call(s, "jira_get_issue", `{"key":"OPS-5"}`), true, "HTTP 400")
	want(t, call(s, "jira_get_issue", `{"key":"OPS-6"}`), true, "unexpected response from the service")
	r := call(s, "jira_search", `{"jql":"project garbage"}`)
	want(t, r, true, "(HTTP 400): Error in the JQL Query: Expecting operator but got 'garbage'.")
	if strings.Contains(r.Text, "errorMessages") {
		t.Errorf("raw Jira error JSON in output:\n%s", r.Text)
	}
	want(t, call(s, "jira_create_issue", `{"project":"OPS","issue_type":"Nope","summary":"x"}`), true,
		"(HTTP 400): issuetype: The issue type selected is invalid.; summary: You must specify a summary of the issue.")
	// A long message is parsed from the full body and capped.
	r = call(s, "jira_add_comment", `{"key":"OPS-42","body":"x"}`)
	want(t, r, true, "(HTTP 400): Comment body is far too long")
	if strings.Contains(r.Text, "errorMessages") {
		t.Errorf("raw Jira error JSON in output:\n%s", r.Text)
	}
}
