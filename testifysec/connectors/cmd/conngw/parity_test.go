package main

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/launch"
	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// The gateway and the plugin host's scrub read a plugin frame the same way: a frame with a repeated
// key, at any depth, is refused by both (the stream ends, nothing passes), and for every frame both
// accept, each string the gateway forwards to the caller is one the scrub inspected.
func TestTheScrubSeesEveryStringTheGatewayForwards(t *testing.T) {
	src := mustSource(t, "x", levels(t)[1])
	banner := marking.Banner(src.marking)
	framed := func(s string) string { b, _ := json.Marshal(banner + "\n" + s + "\n" + banner); return string(b) }
	frames := []string{
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + framed("plain") + `}]}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + framed(`a\/b & <c>`) + `}]}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + framed("one") + `},{"type":"text","text":` + framed("two") + `}],"isError":true}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + framed("x") + `,"text":null}]}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":null,"text":` + framed("y") + `}]}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + framed("z") + `}],"content":[]}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + framed("w") + `}]},"result":null}`,
		`{"jsonrpc":"2.0","id":1,"id":2,"result":{"content":[{"type":"text","text":` + framed("v") + `}]}}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"m","message":"n"}}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"m"}}`,
	}
	for _, frame := range frames {
		var seen []string
		valid, refuse := launch.JSONStrings([]byte(frame), func(s string) { seen = append(seen, s) })
		if !valid {
			t.Fatalf("not one JSON value: %s", frame)
		}
		s := &stream{ws: "team-a/alice", conn: src, labels: newLabels(), log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
		var forwarded, reply, out strings.Builder
		if err := s.requests(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x_get"}}`+"\n"), &reply, &forwarded); err != nil {
			t.Fatal(err)
		}
		err := s.answers(strings.NewReader(frame+"\n"), &out)
		if refuse != nil {
			if err != errRefusedFrame || out.Len() != 0 {
				t.Errorf("repeated key accepted by the gateway: %s -> %v %q", frame, err, out.String())
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", frame, err)
		}
		var answer struct {
			Result struct {
				Content []struct{ Text string }
			}
		}
		_ = json.Unmarshal([]byte(out.String()), &answer)
		for _, c := range answer.Result.Content {
			if !strings.Contains(c.Text, "refused by the connector gateway") && !contains(seen, c.Text) {
				t.Errorf("%s: the gateway forwarded %q, which the scrub never saw (it saw %q)", frame, c.Text, seen)
			}
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
