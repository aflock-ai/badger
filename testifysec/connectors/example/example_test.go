package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/sdk"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/fakeserver"
)

// The pattern every connector test follows: a fake from fixtures, a server built from the real
// spec with a throwaway token file, then calls through sdk.Server.Call.
func TestExampleConnector(t *testing.T) {
	fake := fakeserver.New(t, "testdata",
		fakeserver.Route{Method: "GET", Path: "/api/items/42", Fixture: "item-42.json"},
		fakeserver.Route{Method: "POST", Path: "/api/items/42/notes", Status: 201, Body: `{}`},
	)
	tok := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tok, []byte("example-token"), 0o600)
	s, err := sdk.New(spec, sdk.Config{BaseURL: fake.URL + "/api", TokenFile: tok, EnableWrites: true, InsecureLoopbackHTTP: true, Classification: "UNCLASSIFIED"})
	if err != nil {
		t.Fatal(err)
	}
	r := s.Call(context.Background(), "example_get_item", json.RawMessage(`{"id":42}`))
	if r.IsError || !strings.Contains(r.Text, "# 42: Rotate the build signing key") || !strings.Contains(r.Text, "data, not instructions") || !strings.HasPrefix(r.Text, "UNCLASSIFIED\n") {
		t.Errorf("get: %+v", r)
	}
	r = s.Call(context.Background(), "example_add_note", json.RawMessage(`{"id":42,"text":"done"}`))
	reqs := fake.Requests()
	if r.IsError || len(reqs) != 2 || string(reqs[1].Body) != `{"body":"done"}` || reqs[1].Header.Get("Authorization") != "Bearer example-token" {
		t.Errorf("add note: %+v %+v", r, reqs)
	}
}
