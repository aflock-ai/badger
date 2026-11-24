package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/internal/launch"
)

// testdata/connector-names.json is the shared corpus for the connector pod's naming rules. Admission
// v3 (testifysec/managed/profile-v3.test.ts) and the portal (portal/internal/profile) read the same
// file, so a workspace profile can name exactly the connectors and plugin flags this pod accepts.
func TestNamingCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/connector-names.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Names, Flags struct{ Accept, Refuse []string }
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	flag := func(f string) bool { return launch.FlagName.MatchString(f) && !launch.Reserved[f] }
	for _, c := range []struct {
		kind         string
		rule         func(string) bool
		accept, deny []string
	}{{"name", name.MatchString, corpus.Names.Accept, corpus.Names.Refuse}, {"flag", flag, corpus.Flags.Accept, corpus.Flags.Refuse}} {
		if len(c.accept) == 0 || len(c.deny) == 0 {
			t.Fatalf("%s corpus is empty", c.kind)
		}
		for _, s := range c.accept {
			if !c.rule(s) {
				t.Errorf("%s %q refused, corpus accepts it", c.kind, s)
			}
		}
		for _, s := range c.deny {
			if c.rule(s) {
				t.Errorf("%s %q accepted, corpus refuses it", c.kind, s)
			}
		}
	}
}
