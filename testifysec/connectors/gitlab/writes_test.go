package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/fakeserver"
)

func writeRoutes(extra ...fakeserver.Route) []fakeserver.Route {
	return routes(append(extra,
		fakeserver.Route{Method: "POST", Path: proj + "/issues", Status: 201, Fixture: "created-issue.json"},
		fakeserver.Route{Method: "POST", Path: proj + "/merge_requests/12/notes", Status: 201, Fixture: "note.json"},
	)...)
}

func TestWrites(t *testing.T) {
	off := newHarness(t, "CUI", nil, writeRoutes()...)
	if names := off.ToolNames(); slices.Contains(names, "gitlab_create_issue") || slices.Contains(names, "gitlab_add_note") || len(names) != 9 {
		t.Errorf("tools with writes off: %v", names)
	}
	if r := off.call("gitlab_create_issue", `{"project":"platform/build/signer","title":"x"}`); !r.IsError || !strings.Contains(r.Text, "unknown tool") {
		t.Errorf("write tool callable with writes off: %s", r.Text)
	}
	on := newHarness(t, "CUI", []string{"--enable-writes"}, writeRoutes()...)
	if names := on.ToolNames(); len(names) != 11 || !slices.Contains(names, "gitlab_add_note") {
		t.Errorf("tools with writes on: %v", names)
	}
	r := on.call("gitlab_create_issue", `{"project":"platform/build/signer","title":"Document key rotation","description":"See #7.","labels":["docs"]}`)
	reqs := on.fake.Requests()
	if r.IsError || !strings.Contains(r.Text, "created issue #10") || len(reqs) != 1 || reqs[0].Method != "POST" ||
		string(reqs[0].Body) != `{"description":"See #7.","labels":"docs","title":"Document key rotation"}` || reqs[0].Header.Get("PRIVATE-TOKEN") != sentinel {
		t.Errorf("create: %s %+v", r.Text, reqs)
	}
	r = on.call("gitlab_add_note", `{"project":"platform/build/signer","target":"merge_request","iid":12,"body":"Looks good."}`)
	reqs = on.fake.Requests()
	if r.IsError || !strings.Contains(r.Text, "note 610 added to merge request !12") || string(reqs[1].Body) != `{"body":"Looks good."}` {
		t.Errorf("note: %s %+v", r.Text, reqs)
	}
	// The title limit is 255 characters: 255 three-byte characters pass, 256 do not.
	title := strings.Repeat("\u7b7e", 255)
	if r := on.call("gitlab_create_issue", `{"project":"platform/build/signer","title":"`+title+`"}`); r.IsError {
		t.Errorf("255-character multibyte title refused: %s", r.Text)
	}
	if last := on.fake.Requests(); string(last[len(last)-1].Body) != `{"title":"`+title+`"}` {
		t.Errorf("title body: %s", last[len(last)-1].Body)
	}
	n := len(on.fake.Requests())
	if r := on.call("gitlab_create_issue", `{"project":"platform/build/signer","title":"`+title+`\u7b7e"}`); !r.IsError || len(on.fake.Requests()) != n {
		t.Errorf("256-character title accepted: %s", r.Text)
	}
	// A slash inside a line or in backticks is not a quick action.
	if r := on.call("gitlab_add_note", `{"project":"platform/build/signer","target":"merge_request","iid":12,"body":"Ran a/b and `+"`/usr/bin/env go test`"+`."}`); r.IsError {
		t.Errorf("ordinary slashes refused: %s", r.Text)
	}
}

// A label that is empty once trimmed of whitespace and invisible characters, holds a comma or is
// too long is refused before any request; any other label, whatever it says, is sent trimmed.
func TestCreateIssueLabels(t *testing.T) {
	h := newHarness(t, "CONFIDENTIAL", []string{"--enable-writes"}, writeRoutes()...)
	for _, l := range []string{"", "   ", "\u200b", "\ufeff\u00a0", "\u0000", "a,b", strings.Repeat("l", 256)} {
		args, _ := json.Marshal(map[string]any{"project": "platform/build/signer", "title": "x", "labels": []string{"docs", l}})
		if r := h.call("gitlab_create_issue", string(args)); !r.IsError || !strings.Contains(r.Text, "refused") {
			t.Errorf("label %q accepted: %s", l, r.Text)
		}
	}
	if n := len(h.fake.Requests()); n != 0 {
		t.Errorf("%d requests sent for refused labels", n)
	}
	r := h.call("gitlab_create_issue", `{"project":"platform/build/signer","title":"Document key rotation","labels":[" docs ","\u200bteam::alpha","classification::example"]}`)
	if reqs := h.fake.Requests(); r.IsError || len(reqs) != 1 || string(reqs[0].Body) != `{"labels":"docs,team::alpha,classification::example","title":"Document key rotation"}` {
		t.Errorf("labels: %s %+v", r.Text, reqs)
	}
}

func TestWriteValidationAndErrors(t *testing.T) {
	h := newHarness(t, "CUI", []string{"--enable-writes"}, writeRoutes(
		fakeserver.Route{Method: "POST", Path: "/api/v4/projects/platform%2Fbad/issues", Status: 422,
			Body: `{"message":{"title":["is too long (maximum is 255 characters)"],"labels":["is invalid"]}}`},
	)...)
	bad := map[string][]string{
		"gitlab_add_note": {`{"project":"platform/build/signer","target":"commit","iid":7,"body":"x"}`, `{"project":"platform/build/signer","target":"issue","iid":7,"body":""}`,
			`{"project":"platform/build/signer","target":"issue","iid":0,"body":"x"}`, `{"project":"../x","target":"issue","iid":7,"body":"x"}`,
			`{"project":"platform/build/signer","target":"issue","iid":7}`, `{"project":"platform/build/signer","iid":7,"body":"x"}`,
			`{"project":"platform/build/signer","target":"issue","body":"x"}`, `{"target":"issue","iid":7,"body":"x"}`, `{"id":42}`, `{}`,
			// GitLab quick actions would act with the connector's credential.
			`{"project":"platform/build/signer","target":"merge_request","iid":12,"body":"/label ~\"classification::SECRET\""}`,
			`{"project":"platform/build/signer","target":"issue","iid":7,"body":"done\n  /close"}`,
			`{"project":"platform/build/signer","target":"issue","iid":7,"body":"ok\r/assign @dev-a"}`},
		"gitlab_create_issue": {`{"project":"platform/build/signer","title":""}`,
			`{"project":"platform/build/signer","title":"x","extra":1}`, `{"project":"platform/build/signer","title":"x","labels":["a,b"]}`,
			`{"project":"platform/build/signer","title":"x","description":"` + strings.Repeat("d", maxWriteBytes+1) + `"}`,
			`{"project":"platform/build/signer","title":"x","description":"See below.\n/relabel ~docs"}`,
			// Required arguments missing: refused before any request.
			`{"title":"x"}`, `{"project":"platform/build/signer"}`, `{}`, `{"id":42}`},
	}
	for tool, list := range bad {
		for _, args := range list {
			if r := h.call(tool, args); !r.IsError {
				t.Errorf("%s %.80s accepted", tool, args)
			}
		}
	}
	if n := len(h.fake.Requests()); n != 0 {
		t.Errorf("%d requests sent for invalid writes", n)
	}
	r := h.call("gitlab_create_issue", `{"project":"platform/bad","title":"x"}`)
	if !r.IsError || !strings.Contains(r.Text, "GitLab rejected the request (HTTP 422): labels is invalid; title is too long (maximum is 255 characters)") {
		t.Errorf("422: %s", r.Text)
	}
}

// Codex review on #186: a write is reported done only when the service confirms the created
// resource; null, {} or a missing id is an error, not "created issue #0".
func TestWriteNeedsConfirmation(t *testing.T) {
	for _, body := range []string{"null", "{}", `{"iid":0}`, `{"id":0}`} {
		h := newHarness(t, "CONFIDENTIAL", []string{"--enable-writes"}, routes(
			fakeserver.Route{Method: "POST", Path: proj + "/issues", Status: 201, Body: body},
			fakeserver.Route{Method: "POST", Path: proj + "/merge_requests/12/notes", Status: 201, Body: body},
		)...)
		for _, c := range [][2]string{
			{"gitlab_create_issue", `{"project":"platform/build/signer","title":"x"}`},
			{"gitlab_add_note", `{"project":"platform/build/signer","target":"merge_request","iid":12,"body":"x"}`},
		} {
			if r := h.call(c[0], c[1]); !r.IsError || !strings.Contains(r.Text, "not confirmed") {
				t.Errorf("%s with response %s: %s", c[0], body, r.Text)
			}
		}
	}
}
