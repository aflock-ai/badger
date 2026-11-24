package broker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A user principal name is case-insensitive: the identity provider may hand the broker
// "alice@example.com" for a person configured as "Alice@Example.com", or the other way round. Every
// match against human_principals ignores case; what is stored is the configured spelling, so a
// person's tokens, usage and ownership stay under one key whichever case a token carries, and
// records written before are found as they are.
func TestAPrincipalMatchesItsConfiguredSpellingInAnyCase(t *testing.T) {
	f := newFixture(t, true) // human_principals: alice@example.com, bob@example.com

	// Provisioning: a workspace token for the person in another case is issued, and its owner is the
	// configured spelling.
	tok := f.issue("ws-case", "ALICE@Example.COM")
	if p, ok := f.b.tokens.Auth(tok, f.cfg.HumanPrincipals, testNow); !ok || p != "alice@example.com" {
		t.Fatalf("token owner %q %v, want the configured spelling", p, ok)
	}
	// The token keeps working if the configuration's spelling of the same person changes case.
	recased := []string{"Alice@Example.com", "bob@example.com"}
	if p, ok := f.b.tokens.Auth(tok, recased, testNow); !ok || p != "alice@example.com" {
		t.Fatalf("after a case-only config change: %q %v", p, ok)
	}

	// The edge: a person the edge signed in, in another case, is the configured person.
	w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-principal": "Bob@EXAMPLE.com"}, chatA)
	if w.Code == 401 {
		t.Fatalf("edge person in another case: %d %s", w.Code, w.Body)
	}
	if got := w.Header().Get("X-Broker-Usage-Principal"); got != "" && got != "bob@example.com" {
		t.Fatalf("usage recorded under %q, want the configured spelling", got)
	}

	// Device sign-in: the consent page is the configured person's.
	if w := edgeReq(f.edge, "GET", "/device/authorize?"+authorizeQuery(nil), "ALICE@EXAMPLE.COM", nil, ""); w.Code == 401 {
		t.Fatalf("device consent in another case: %d", w.Code)
	}

	// Ownership: an owner written in another case is accepted and still owns the entry.
	version, _, entries := ownersView(t, f)
	owners := map[string]string{}
	for _, e := range entries {
		owners[e["id"].(string)] = "Bob@Example.com"
	}
	body, _ := json.Marshal(map[string]any{"owners": owners, "comment": "case"})
	if c := do(f.admin, "PUT", "/admin/v1/owners", with(admin("u1"), "If-Match", fmt.Sprintf("%q", fmt.Sprint(version))), string(body)).Code; c != 200 {
		t.Fatalf("owners in another case: %d", c)
	}
	if _, stored, _ := ownersView(t, f); len(stored) == 0 || stored[entries[0]["id"].(string)] != "bob@example.com" {
		t.Fatalf("owners stored as %v, want the configured spelling", stored)
	}
	for id := range owners {
		if h, ok := f.b.ownerOf(id); !ok || h != "bob@example.com" {
			t.Fatalf("owner of %s: %q %v", id, h, ok)
		}
	}

	// Exact case is unchanged, and a person not configured in any case is still refused.
	f.issue("ws-exact", "bob@example.com")
	for _, p := range []string{"carol@example.com", "ci:group/alpha", "alice@example.co", "alice@example.com "} {
		w := do(f.provision, "POST", "/provision/v1/tokens", map[string]string{"Authorization": "Bearer prov-key"},
			`{"workspace":"ws-x","principal":"`+p+`"}`)
		if w.Code != 422 {
			t.Errorf("%q: %d", p, w.Code)
		}
	}
	if w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-principal": "Carol@example.com"}, chatA); w.Code != 401 {
		t.Fatalf("unconfigured person: %d", w.Code)
	}
}

// Two configured principals equal but for case are one person configured twice: the load is
// refused with a message that says so.
func TestPrincipalsEqualButForCaseAreRefused(t *testing.T) {
	raw, err := os.ReadFile("examples/config.json")
	if err != nil {
		t.Fatal(err)
	}
	load := func(people ...string) error {
		var c map[string]any
		json.Unmarshal(raw, &c)
		c["human_principals"] = people
		out, _ := json.Marshal(c)
		path := filepath.Join(t.TempDir(), "config.json")
		os.WriteFile(path, out, 0o600)
		_, err := LoadConfig(path)
		return err
	}
	if err := load("Dana.Kirk@example.com", "dana.kirk@example.com"); err == nil ||
		!strings.Contains(err.Error(), "differ only in case") {
		t.Fatalf("duplicate by case: %v", err)
	}
	if err := load("a@example.com", "a@example.com"); err == nil {
		t.Fatal("exact duplicate accepted")
	}
	if err := load("Dana.Kirk@example.com", "alice@example.com"); err != nil {
		t.Fatalf("distinct people: %v", err)
	}
}

// Only ASCII is folded: a look-alike that Unicode folding would equate (the Kelvin sign and "k")
// is a different principal.
func TestOnlyASCIICaseIsFolded(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"dana.kirk@example.com", "Dana.Kirk@EXAMPLE.com", true},
		{"dana.kirk@example.com", "dana.kirk@example.com", true},
		{"dana.kirk@example.com", "dana.\u212airk@example.com", false},
		{"dana.kirk@example.com", "dana.kirk@example.co", false},
	} {
		if got := samePrincipal(c.a, c.b); got != c.same {
			t.Errorf("samePrincipal(%q, %q) = %v", c.a, c.b, got)
		}
	}
	if p, ok := configuredPrincipal([]string{"Alice@Example.com"}, "ci:alice@example.com"); ok {
		t.Fatalf("a pipeline principal matched a person: %q", p)
	}
}
