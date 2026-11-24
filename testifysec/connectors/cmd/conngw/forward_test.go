package main

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// canary is what a hostile plugin puts in a field to carry a token out. It must never reach the
// caller except inside text framed by the profile's banner.
const canary = "7613470213"

// forwardOnce sends one caller request through a stream on a connector marked lv[1], answers it
// with the plugin's line, and returns what the caller got and the profile's banner.
func forwardOnce(t *testing.T, req, plugin string) (string, string) {
	t.Helper()
	src := mustSource(t, "x", levels(t)[1])
	s := &stream{ws: "team-a/alice", conn: src, labels: newLabels(), log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
	var forwarded, reply, out strings.Builder
	if err := s.requests(strings.NewReader(req+"\n"), &reply, &forwarded); err != nil || reply.Len() != 0 {
		t.Fatalf("request %s: %v %q", req, err, reply.String())
	}
	if err := s.answers(strings.NewReader(plugin+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	return out.String(), marking.Banner(src.marking)
}

const callReq = `{"jsonrpc":"2.0","id":"aa","method":"tools/call","params":{"name":"x_get"}}`

// Every field of a plugin's answer is either dropped, replaced by the gateway's fixed value, or
// carried inside text framed by the profile's banner. One case per field (DEPLOY 5c table): the
// canary never reaches the caller.
func TestEachPluginFieldIsDroppedFixedOrMarked(t *testing.T) {
	framed := func(banner, text string) string {
		b, _ := json.Marshal(banner + "\n" + text + "\n" + banner)
		return string(b)
	}
	lv1 := marking.Banner(mustSource(t, "x", levels(t)[1]).marking)
	ok := `{"type":"text","text":` + framed(lv1, "ok") + `}`
	for _, tc := range []struct {
		field, req, plugin string
		want               []string // must appear in what the caller gets
	}{
		// An error answer: fixed code and message, the profile's marking in data.
		{"error.code number", callReq, `{"jsonrpc":"2.0","id":1,"error":{"code":` + canary + `,"message":"x"}}`, []string{`"code":-32603`, `"id":"aa"`}},
		{"error.code negative", callReq, `{"jsonrpc":"2.0","id":1,"error":{"code":-` + canary + `,"message":"x"}}`, []string{`"code":-32603`}},
		{"error.code string", callReq, `{"jsonrpc":"2.0","id":1,"error":{"code":"` + canary + `","message":"x"}}`, []string{`"code":-32603`}},
		{"error.code fraction", callReq, `{"jsonrpc":"2.0","id":1,"error":{"code":1.` + canary + `,"message":"x"}}`, []string{`"code":-32603`}},
		{"error.message", callReq, `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"` + canary + `"}}`, []string{`"message":"the connector answered with an error"`}},
		{"error.data", callReq, `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"x","data":{"x":"` + canary + `"}}}`, []string{`"banner":"` + lv1 + `"`}},
		{"error.data._meta", callReq, `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"x","data":{"_meta":{"com.testifysec/classification":{"schema":1,"banner":"` + canary + `"}}}}}`, []string{`"banner":"` + lv1 + `"`}},
		{"error other member", callReq, `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"x","x` + canary + `":1}}`, []string{`"code":-32603`}},
		{"error not an object", callReq, `{"jsonrpc":"2.0","id":1,"error":"` + canary + `"}`, []string{`"code":-32603`}},
		// A result: only content (banner-framed text), isError and the gateway's _meta.
		{"result._meta other key", callReq, `{"jsonrpc":"2.0","id":1,"result":{"content":[` + ok + `],"_meta":{"x":"` + canary + `"}}}`, []string{`"banner":"` + lv1 + `"`}},
		{"result._meta marking", callReq, `{"jsonrpc":"2.0","id":1,"result":{"content":[` + ok + `],"_meta":{"com.testifysec/classification":{"schema":1,"banner":"` + canary + `"}}}}`, []string{`"banner":"` + lv1 + `"`}},
		{"result.structuredContent", callReq, `{"jsonrpc":"2.0","id":1,"result":{"content":[` + ok + `],"structuredContent":{"x":"` + canary + `"}}}`, nil},
		{"result.nextCursor", callReq, `{"jsonrpc":"2.0","id":1,"result":{"content":[` + ok + `],"nextCursor":"` + canary + `"}}`, nil},
		{"result other key", callReq, `{"jsonrpc":"2.0","id":1,"result":{"content":[` + ok + `],"x` + canary + `":1}}`, nil},
		{"result.isError not a boolean", callReq, `{"jsonrpc":"2.0","id":1,"result":{"content":[` + ok + `],"isError":` + canary + `}}`, nil},
		{"result not an object", callReq, `{"jsonrpc":"2.0","id":1,"result":"` + canary + `"}`, []string{`"banner":"` + lv1 + `"`}},
		{"content item annotations", callReq, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + framed(lv1, "ok") + `,"annotations":{"x":"` + canary + `"}}]}}`, nil},
		{"content item _meta", callReq, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + framed(lv1, "ok") + `,"_meta":{"x":"` + canary + `"}}]}}`, nil},
		{"content item mimeType", callReq, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + framed(lv1, "ok") + `,"mimeType":"` + canary + `"}]}}`, nil},
		{"content item not text", callReq, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"image","data":"` + canary + `","mimeType":"image/png"}]}}`, []string{`"isError":true`}},
		{"content item text unframed", callReq, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"` + canary + `"}]}}`, []string{`"isError":true`}},
		{"content not a list", callReq, `{"jsonrpc":"2.0","id":1,"result":{"content":"` + canary + `"}}`, []string{`"isError":true`}},
		// The envelope: jsonrpc and id are the gateway's, other members are dropped.
		{"jsonrpc", callReq, `{"jsonrpc":"` + canary + `","id":1,"result":{"content":[` + ok + `]}}`, []string{`"jsonrpc":"2.0"`}},
		{"envelope other member", callReq, `{"jsonrpc":"2.0","id":1,"_meta":{"x":"` + canary + `"},"result":{"content":[` + ok + `]}}`, nil},
		{"id spelling", callReq, `{"jsonrpc":"2.0","id":  1  ,"result":{"content":[` + ok + `]}}`, []string{`"id":"aa"`}},
		{"id unsolicited", callReq, `{"jsonrpc":"2.0","id":"` + canary + `","result":{"content":[` + ok + `]}}`, nil},
		// Output that answers no request is not passed on.
		{"notification progressToken", callReq, `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"` + canary + `","progress":1}}`, nil},
		{"notification message", callReq, `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"` + canary + `"}}`, nil},
		{"notification list_changed", callReq, `{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"_meta":{"x":"` + canary + `"}}}`, nil},
		{"request sampling", callReq, `{"jsonrpc":"2.0","id":99,"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"` + canary + `"}}]}}`, nil},
		{"request elicitation", callReq, `{"jsonrpc":"2.0","id":98,"method":"elicitation/create","params":{"message":"` + canary + `"}}`, nil},
		{"request under a pending id", callReq, `{"jsonrpc":"2.0","id":1,"method":"roots/list","params":{"x":"` + canary + `"}}`, nil},
		{"line not JSON", callReq, canary, nil},
		// Content-free answers are the gateway's own.
		{"initialize instructions", `{"jsonrpc":"2.0","id":"aa","method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","instructions":"` + canary + `","capabilities":{"x":"` + canary + `"}}}`, []string{`"serverInfo"`}},
		{"tools/list nextCursor", `{"jsonrpc":"2.0","id":"aa","method":"tools/list"}`, `{"jsonrpc":"2.0","id":1,"result":{"tools":[],"nextCursor":"` + canary + `"}}`, []string{`"x_get"`}},
		{"ping result", `{"jsonrpc":"2.0","id":"aa","method":"ping"}`, `{"jsonrpc":"2.0","id":1,"result":{"x":"` + canary + `"}}`, []string{`"result":{}`}},
	} {
		t.Run(tc.field, func(t *testing.T) {
			got, _ := forwardOnce(t, tc.req, tc.plugin)
			if strings.Contains(got, canary) {
				t.Fatalf("caller got the canary: %s", got)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Fatalf("caller got %s, want %s in it", got, w)
				}
			}
		})
	}
}

// The one place a plugin's bytes reach the caller is text framed by the profile's banner, under the
// gateway's marking in _meta: it is marked exactly as the profile says.
func TestPluginTextReachesTheCallerOnlyMarked(t *testing.T) {
	src := mustSource(t, "x", levels(t)[1])
	banner := marking.Banner(src.marking)
	text, _ := json.Marshal(banner + "\n" + canary + "\n" + banner)
	got, _ := forwardOnce(t, callReq, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":`+string(text)+`}]}}`)
	var answer struct {
		Result struct {
			Content []struct{ Type, Text string }
			Meta    map[string]struct{ Banner string } `json:"_meta"`
		}
	}
	if err := json.Unmarshal([]byte(got), &answer); err != nil || len(answer.Result.Content) != 1 {
		t.Fatalf("caller got %s", got)
	}
	if c := answer.Result.Content[0]; c.Text != banner+"\n"+canary+"\n"+banner || answer.Result.Meta[metaKey].Banner != banner {
		t.Fatalf("caller got %s", got)
	}
	if strings.Count(got, canary) != 1 {
		t.Fatalf("the text was not the only place: %s", got)
	}
}
