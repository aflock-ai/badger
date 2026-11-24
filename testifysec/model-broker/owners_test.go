package broker

import (
	"encoding/json"
	"strings"
	"testing"
)

func unowned(t *testing.T, f *fixture) {
	t.Helper()
	f.pg.Super(t, `DELETE FROM broker.documents WHERE name = 'owners'`)
	f.open()
}

func ownersView(t *testing.T, f *fixture) (int64, map[string]string, []map[string]any) {
	t.Helper()
	w := do(f.admin, "GET", "/admin/v1/owners", admin("u1"), "")
	var v struct {
		Version int64             `json:"version"`
		Owners  map[string]string `json:"owners"`
		Entries []map[string]any  `json:"entries"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatalf("get owners: %d %s", w.Code, w.Body)
	}
	return v.Version, v.Owners, v.Entries
}

func TestUnownedPipelineIsRefused(t *testing.T) {
	f := newFixture(t, true)
	unowned(t, f)
	calls := f.calls.Load()
	w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA)
	if w.Code != 403 || f.calls.Load() != calls {
		t.Fatalf("unowned pipeline: %d, upstream calls %d -> %d", w.Code, calls, f.calls.Load())
	}
	recs, _ := f.b.store.AuditAfter(0, 500)
	for _, r := range recs {
		if r.Kind == "decision" && r.Decision == "allow" {
			t.Fatalf("an unowned pipeline was recorded as allowed: %+v", r)
		}
	}
	// Assign it; the same call now goes through and names its owner.
	_, _, entries := ownersView(t, f)
	owners := map[string]string{}
	for _, e := range entries {
		owners[e["id"].(string)] = "bob@example.com"
	}
	body, _ := json.Marshal(map[string]any{"owners": owners, "comment": "assign to bob"})
	if c := do(f.admin, "PUT", "/admin/v1/owners", with(admin("u1"), "If-Match", `"0"`), string(body)).Code; c != 200 {
		t.Fatalf("assign: %d", c)
	}
	w = do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA)
	if w.Code != 200 || w.Header().Get("X-Broker-Owner") != "bob@example.com" {
		t.Fatalf("owned pipeline: %d %v", w.Code, w.Header())
	}
	recs, _ = f.b.store.AuditAfter(0, 500)
	last := recs[len(recs)-1]
	if last.Kind != "decision" || last.Owner != "bob@example.com" {
		t.Fatalf("decision record %+v", last)
	}
}

func TestPipelineUsageNamesOwnerAndTrigger(t *testing.T) {
	f := newFixture(t, true)
	claims := payload(map[string]any{"user_login": "carol"})
	if w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": claims}, chatA); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	raw := f.superText(`SELECT string_agg(owner || '/' || triggered_by, ' ') FROM broker.usage_calls WHERE NOT pending`)
	if !strings.Contains(raw, "alice@example.com/carol") {
		t.Fatalf("ledger %s", raw)
	}
	w := do(f.admin, "GET", "/admin/v1/usage", admin("u1"), "")
	var rep struct {
		Owners map[string]string `json:"owners"`
	}
	json.Unmarshal(w.Body.Bytes(), &rep)
	if rep.Owners["ci:group/alpha"] != "alice@example.com" {
		t.Fatalf("report owners %s", w.Body)
	}
}

func TestOwnerWritesAreValidatedVersionedAndAudited(t *testing.T) {
	f := newFixture(t, true)
	v, owners, entries := ownersView(t, f)
	if v != 1 || len(entries) == 0 || owners[entries[0]["id"].(string)] != "alice@example.com" {
		t.Fatalf("v%d %v %v", v, owners, entries)
	}
	if entries[0]["principal"] == "" || entries[0]["owner"] != "alice@example.com" {
		t.Fatalf("entry view %v", entries[0])
	}
	put := func(version, body string, h map[string]string) int {
		return do(f.admin, "PUT", "/admin/v1/owners", with(h, "If-Match", version), body).Code
	}
	for _, bad := range []string{`{"owners":{"x":"mallory@example.com"}}`, `{"owners":{"x":"ci:group/alpha"}}`,
		`{"owners":{"bad id\n":"bob@example.com"}}`, `{"owners":{},"extra":1}`} {
		if c := put(`"1"`, bad, admin("u1")); c/100 != 4 || c == 412 {
			t.Errorf("%s: %d", bad, c)
		}
	}
	if c := put(`"0"`, `{"owners":{}}`, admin("u1")); c != 412 {
		t.Fatalf("stale: %d", c)
	}
	if c := put(`"1"`, `{"owners":{}}`, with(admin("u1"), "x-broker-role", "user")); c != 403 {
		t.Fatalf("as user: %d", c)
	}
	if c := put(`"1"`, `{"owners":{"`+entries[0]["id"].(string)+`":"bob@example.com"},"comment":"handover"}`, admin("u1")); c != 200 {
		t.Fatalf("write: %d", c)
	}
	f.open()
	if v, owners, _ := ownersView(t, f); v != 2 || owners[entries[0]["id"].(string)] != "bob@example.com" {
		t.Fatalf("after restart v%d %v", v, owners)
	}
	recs, _ := f.b.store.AuditAfter(0, 500)
	found := false
	for _, r := range recs {
		if r.Kind == "owner" && r.Actor == "u1" && strings.Contains(r.Comment, "bob@example.com") {
			found = true
		}
	}
	if !found {
		t.Fatal("no owner audit record")
	}
}

func TestOwnerMustStillBeAConfiguredPerson(t *testing.T) {
	for name, who := range map[string]string{"removed person": "mallory@example.com", "empty": ""} {
		f := newFixture(t, true)
		owners := map[string]string{}
		for _, e := range f.b.store.Active().Entries {
			owners[e.ID] = who
		}
		raw, _ := json.Marshal(OwnerSet{Version: 1, Owners: owners})
		f.setDoc("owners", string(raw))
		f.open()
		w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA)
		if w.Code != 403 {
			t.Errorf("%s owner: %d", name, w.Code)
		}
	}
}
