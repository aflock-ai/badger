package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// foreign returns an unclassified banner carrying foreign government information, built from the
// token table so the test spells no marking itself. Joined with the controlled-unclassified level
// it makes a marking no banner prints (marking.ErrNoBanner).
func foreign(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../internal/marking/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	var tokens struct {
		Levels []struct{ Banner string }
		FGI    struct{ Token string }
	}
	if err := json.Unmarshal(b, &tokens); err != nil || tokens.FGI.Token == "" {
		t.Fatal("tokens.json unreadable")
	}
	return tokens.Levels[0].Banner + "//" + tokens.FGI.Token + " GBR"
}

// A call whose answer would raise the label to a marking no banner prints is refused before it
// reaches the connector, by the dominance check (a connector that dominates the label joins to its
// own marking); the label is unchanged.
func TestACallWhoseJoinHasNoBannerIsRefused(t *testing.T) {
	lv := levels(t)
	fgi := mustSource(t, "fgi", foreign(t))
	if _, err := marking.Join(mustSource(t, "c", lv[1]).marking, fgi.marking); err == nil {
		t.Fatal("fixture: the join prints a banner")
	}
	l := newLabels()
	if _, err := l.raise("ws/a", mustSource(t, "c", lv[1]).marking); err != nil {
		t.Fatal(err)
	}
	f := &fake{}
	call, closeFn := session(t, l, "ws/a", fgi, f)
	defer closeFn()
	if got := call(callID("1")); !strings.Contains(got, "refused by the connector gateway") {
		t.Fatalf("not refused: %s", got)
	}
	if len(f.methods()) != 0 {
		t.Fatalf("connector saw %v", f.methods())
	}
}

// An answer whose join has no banner is not passed on and nothing is recorded.
func TestAnAnswerWhoseJoinHasNoBannerIsWithheld(t *testing.T) {
	lv := levels(t)
	path := filepath.Join(t.TempDir(), "labels")
	if err := initLabels(path, marking.Current()); err != nil {
		t.Fatal(err)
	}
	l, err := openLabels(path, marking.Current())
	if err != nil {
		t.Fatal(err)
	}
	defer l.file.Close()
	if _, err := l.raise("ws/a", mustSource(t, "c", lv[1]).marking); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	s := &stream{ws: "ws/a", conn: mustSource(t, "fgi", foreign(t)), labels: l, log: slog.New(slog.DiscardHandler), pending: map[string]bool{}, perm: testPermit()}
	var out strings.Builder
	if err := s.answers(strings.NewReader(`{"jsonrpc":"2.0","id":7,"result":{}}`+"\n"), &out); err == nil || out.Len() != 0 {
		t.Fatalf("answer passed on: err %v, out %q", err, out.String())
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatalf("recorded: %q", after)
	}
	// It is not a write failure: later answers that do print a banner still go through.
	if _, err := l.raise("ws/a", mustSource(t, "c", lv[1]).marking); err != nil {
		t.Fatalf("a printable raise after the refusal: %v", err)
	}
}

// A labels file whose records for one workspace join to no banner refuses start.
func TestReplayOfAnUnprintableJoinRefusesStart(t *testing.T) {
	lv := levels(t)
	path := filepath.Join(t.TempDir(), "labels")
	content := labelsHeader + "\n" + `{"workspace":"ns/a","label":"` + lv[1] + `"}` + "\n" + `{"workspace":"ns/a","label":"` + foreign(t) + `"}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openLabels(path, marking.Current()); err == nil {
		t.Fatal("started with an unprintable label")
	}
}
