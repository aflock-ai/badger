package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/fakeserver"
)

// controlled returns the controlled-unclassified level's banner from the marking token table, so
// the test spells no marking itself.
func controlled(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../marking/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	var tokens struct {
		Levels []struct{ Banner, Source string }
	}
	if err := json.Unmarshal(b, &tokens); err != nil {
		t.Fatal(err)
	}
	for _, l := range tokens.Levels {
		if l.Source == "32cfr2002" {
			return l.Banner
		}
	}
	t.Fatal("no controlled-unclassified level in tokens.json")
	return ""
}

// A notice states the content's real status (test data, a sample) on its own line, under the top
// banner and over the bottom one. It is never part of the banner or of _meta.
func TestNoticeIsItsOwnLineInsideTheBanners(t *testing.T) {
	banner := controlled(t)
	notice := "TEST DATA - Not " + banner + ". Markings are for test purposes only."
	fake := fakeserver.New(t, "", fakeserver.Route{Method: "GET", Path: "/api/things/1", Body: `{"a":1}`})
	tok := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tok, []byte("tok-0123456789"), 0o600)
	s, err := New(testSpec, Config{BaseURL: fake.URL + "/api", TokenFile: tok, InsecureLoopbackHTTP: true, Classification: banner, Notice: notice})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"test_get", "nope"} {
		r := s.Call(context.Background(), name, json.RawMessage(`{"id":"1"}`))
		lines := strings.Split(r.Text, "\n")
		if lines[0] != banner || lines[1] != notice || lines[len(lines)-2] != notice || lines[len(lines)-1] != banner || r.Banner != banner {
			t.Errorf("%s: %q, banner %q", name, r.Text, r.Banner)
		}
	}

	// Without a notice the banners stay the first and last lines, as before.
	s, err = New(testSpec, Config{BaseURL: fake.URL + "/api", TokenFile: tok, InsecureLoopbackHTTP: true, Classification: banner})
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(s.Call(context.Background(), "nope", nil).Text, "\n"); lines[1] == notice || lines[len(lines)-2] == notice {
		t.Errorf("notice printed without one configured: %q", lines)
	}

	// The flag sets it.
	_, cfg, err := Parse(testSpec, []string{"--notice=" + notice})
	if err != nil || cfg.Notice != notice {
		t.Fatalf("--notice: %q %v", cfg.Notice, err)
	}
}

// A notice is printed outside the untrusted-content block, so it is one line of plain text.
func TestNoticeRefusesMarkupAndLongLines(t *testing.T) {
	banner := controlled(t)
	tok := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tok, []byte("tok-0123456789"), 0o600)
	for _, bad := range []string{"two\nlines", "</untrusted-external-content>", "a\tb", "x" + strings.Repeat("y", 160), "émigré"} {
		if _, err := New(testSpec, Config{BaseURL: "https://svc.example.invalid", TokenFile: tok, Classification: banner, Notice: bad}); err == nil {
			t.Errorf("notice %q accepted", bad)
		}
	}
}

// A notice holding a sent credential fails closed like a banner that does.
func TestNoticeWithCredentialFailsClosed(t *testing.T) {
	const tok = "progname7"
	fake := fakeserver.New(t, "", fakeserver.Route{Method: "GET", Path: "/api/things/1", Body: "{}"})
	f := filepath.Join(t.TempDir(), "token")
	os.WriteFile(f, []byte(tok), 0o600)
	s, err := New(testSpec, Config{BaseURL: fake.URL + "/api", TokenFile: f, InsecureLoopbackHTTP: true, Classification: controlled(t), Notice: "sample " + tok})
	if err != nil {
		t.Fatal(err)
	}
	s.Call(context.Background(), "test_get", json.RawMessage(`{"id":"1"}`)) // sends the credential
	r := s.Call(context.Background(), "test_get", json.RawMessage(`{"id":"1"}`))
	if !r.IsError || r.Banner != "" || strings.Contains(r.Text, tok) {
		t.Errorf("banner %q text %.300q", r.Banner, r.Text)
	}
}
