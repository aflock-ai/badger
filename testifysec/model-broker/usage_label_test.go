package broker

import (
	"encoding/json"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
)

// Each ledger row records the session label its call was accounted at: a workspace below the
// ceiling is accounted at its own label (it never runs a transaction above it), a pipeline at the
// ceiling, and a person the edge signed in at the lowest label.
func TestCallsAreAccountedAtTheCallersLabel(t *testing.T) {
	f := newFixture(t, true)
	bottom := pgdb.LabelOf(marking.Marking{})
	tok := f.issue("ws-low", "alice@example.com")
	if w := do(f.internal, "POST", "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + tok}, chatA); w.Code != 200 {
		t.Fatalf("workspace call: %d %s", w.Code, w.Body)
	}
	if w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA); w.Code != 200 {
		t.Fatalf("pipeline call: %d %s", w.Code, w.Body)
	}
	if w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-principal": "bob@example.com"}, chatA); w.Code != 200 {
		t.Fatalf("person call: %d %s", w.Code, w.Body)
	}
	for principal, want := range map[string]pgdb.Label{
		"alice@example.com": bottom,
		"bob@example.com":   bottom,
		"ci:group/alpha":    f.cfg.Ceiling(),
	} {
		got := f.pg.SuperQuery(t, `SELECT string_agg((label = badger.label_of($2::jsonb))::text, ',')
			FROM broker.usage_calls WHERE principal = $1`, principal, want.Lattice())
		if got != "true" {
			t.Errorf("%s: calls accounted at the wrong label (matches: %q)", principal, got)
		}
	}
	if bottom.Banner == f.cfg.Ceiling().Banner {
		t.Fatal("the test needs a workspace below the ceiling")
	}
}

// The provisioner gives a workspace a label at or below the ceiling, never above it and never one
// the marking package cannot read.
func TestProvisionedMarkingStaysUnderTheCeiling(t *testing.T) {
	f := newFixture(t, true)
	for marking, want := range map[string]int{"TOP SECRET": 422, "NOT A BANNER": 422, "SECRET": 201, "UNCLASSIFIED": 201} {
		w := do(f.provision, "POST", "/provision/v1/tokens", map[string]string{"Authorization": "Bearer prov-key"},
			`{"workspace":"ws-m","principal":"alice@example.com","marking":"`+marking+`"}`)
		if w.Code != want {
			t.Errorf("marking %q: %d, want %d", marking, w.Code, want)
		}
	}
}

// A workspace token whose stored label no longer parses, or sits above the ceiling (the database
// edited, or the ceiling lowered since it was issued), is refused: its requests never run above
// the deployment's ceiling, and none reaches the model.
func TestWorkspaceAboveTheCeilingIsRefused(t *testing.T) {
	for name, marking := range map[string]string{"above the ceiling": "TOP SECRET", "unreadable": "NOT A BANNER"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, true)
			tok := f.issue("ws-x", "alice@example.com")
			f.pg.Super(t, `UPDATE broker.tokens SET marking = $1 WHERE workspace = 'ws-x'`, marking)
			calls := f.calls.Load()
			if w := do(f.internal, "POST", "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + tok}, chatA); w.Code != 403 {
				t.Fatalf("workspace at %q: %d", marking, w.Code)
			}
			if f.calls.Load() != calls {
				t.Fatal("a call above the ceiling reached the model")
			}
		})
	}
}

// A principal's quota counts its spend at every label: charges made in a workspace above the
// lowest label are seen by a check made at the lowest (usage_calls carries no row-level security,
// so a session label never hides a row of it).
func TestQuotaCountsSpendAcrossLabels(t *testing.T) {
	f := newFixture(t, true)
	priced(f)
	if c := putQuotas(f, `"0"`, `{"default_usd":null,"principals":{"alice@example.com":0.0004}}`); c != 200 {
		t.Fatal(c)
	}
	w := do(f.provision, "POST", "/provision/v1/tokens", map[string]string{"Authorization": "Bearer prov-key"},
		`{"workspace":"ws-s","principal":"alice@example.com","marking":"SECRET"}`)
	var out struct{ Token string }
	json.Unmarshal(w.Body.Bytes(), &out)
	if w := do(f.internal, "POST", "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + out.Token}, chatA); w.Code != 200 {
		t.Fatalf("SECRET workspace call: %d", w.Code)
	}
	if w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-principal": "alice@example.com"}, chatA); w.Code != 429 {
		t.Fatalf("the same person at the lowest label after spending the quota at SECRET: %d", w.Code)
	}
}
