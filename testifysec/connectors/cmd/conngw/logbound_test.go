package main

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// What the gateway logs about a plugin's output does not follow it line by line: output that answers
// no request, and answers without the connector's marking, are logged once per stream however many
// there are, and the high-water once per label. The plugin's signal in the log is then a few bits
// per stream, not one line per line it writes.
func TestPluginOutputIsLoggedOncePerStream(t *testing.T) {
	var logged bytes.Buffer
	src := mustSource(t, "low", levels(t)[0])
	s := &stream{ws: "ws/a", conn: src, labels: newLabels(), log: slog.New(slog.NewTextHandler(&logged, nil)), pending: map[string]bool{"1": true, "2": true}, perm: testPermit()}
	junk := strings.Repeat("not json\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/x\"}\n", 50)
	unmarked := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"plain"}]}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"plain"}]}}` + "\n"
	if err := s.answers(strings.NewReader(junk+unmarked+junk), io.Discard); err != nil {
		t.Fatal(err)
	}
	for msg, want := range map[string]int{"dropped connector output": 1, "without this connector's marking": 1, "high-water": 1} {
		if got := strings.Count(logged.String(), msg); got != want {
			t.Errorf("%q logged %d times, want %d:\n%s", msg, got, want, logged.String())
		}
	}
}
