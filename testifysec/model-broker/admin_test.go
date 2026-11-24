package broker

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func admin(id string) map[string]string {
	return map[string]string{"x-broker-user-id": id, "x-broker-user": id + "@example.com", "x-broker-role": "superAdmin"}
}

func with(h map[string]string, k, v string) map[string]string {
	out := map[string]string{k: v}
	for a, b := range h {
		if a != k {
			out[a] = b
		}
	}
	return out
}

func policyBody(t *testing.T, f *fixture, mutate func([]Entry) []Entry) string {
	t.Helper()
	es := mutate(append([]Entry(nil), f.b.store.Active().Entries...))
	b, _ := json.Marshal(map[string]any{"entries": es, "comment": "test"})
	return string(b)
}

// TestPipelineCannotAdminister: pipeline_cannot_administer, payload_makes_pipeline. A request
// with a pipeline payload is refused on every admin endpoint, even with an admin's headers.
func TestPipelineCannotAdminister(t *testing.T) {
	f := newFixture(t, true)
	h := with(admin("u1"), "x-broker-ci-claims", payload(nil))
	body := policyBody(t, f, func(es []Entry) []Entry { return es[:1] })
	for _, rq := range [][2]string{{"GET", "/admin/v1/policy"}, {"PUT", "/admin/v1/policy"}, {"GET", "/admin/v1/audit"},
		{"GET", "/admin/v1/usage"}, {"GET", "/admin/v1/config"}, {"POST", "/admin/v1/proposals/1/approve"}} {
		hh := h
		if rq[0] == "PUT" {
			hh = with(h, "If-Match", `"1"`)
		}
		if w := do(f.admin, rq[0], rq[1], hh, body); w.Code != 403 || !strings.Contains(w.Body.String(), "pipeline_forbidden") {
			t.Errorf("%v: %d %s", rq, w.Code, w.Body)
		}
	}
	if len(f.b.store.Versions()) != 1 {
		t.Fatal("policy changed")
	}
}

// TestOnlyAdminChangesPolicy: only_admin_changes_policy.
func TestOnlyAdminChangesPolicy(t *testing.T) {
	f := newFixture(t, true)
	body := policyBody(t, f, func(es []Entry) []Entry { return es[:1] })
	for name, h := range map[string]map[string]string{
		"user role":   with(admin("u1"), "x-broker-role", "user"),
		"admin role":  with(admin("u1"), "x-broker-role", "admin"),
		"no identity": {"x-broker-role": "superAdmin"},
		"no role":     {"x-broker-user-id": "u1"},
		"bad origin":  with(admin("u1"), "Origin", "https://evil.example"),
	} {
		if w := do(f.admin, "PUT", "/admin/v1/policy", with(h, "If-Match", `"1"`), body); w.Code/100 != 4 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if len(f.b.store.Versions()) != 1 {
		t.Fatal("policy changed")
	}
}

// TestWriteVersionedAuditedHotReloaded: change_is_admin_versioned_audited, versions_append_only.
func TestWriteVersionedAuditedHotReloaded(t *testing.T) {
	f := newFixture(t, true)
	// Remove alpha: its pipeline is denied on the very next request, no restart.
	if w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA); w.Code != 200 {
		t.Fatal(w.Code)
	}
	body := policyBody(t, f, func(es []Entry) []Entry { return es[1:] })
	w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), body)
	if w.Code != 201 || w.Header().Get("ETag") != `"2"` {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA); w.Code != 403 {
		t.Fatalf("after removal: %d", w.Code)
	}
	recs, _ := f.b.store.AuditAfter(0, 500)
	var write *AuditRecord
	for i := range recs {
		if recs[i].Kind == "write" && recs[i].Version == 2 {
			write = &recs[i]
		}
	}
	if write == nil || write.Actor != "u1" || len(write.Removed) != 1 || write.Removed[0].ID != "alpha" || len(write.Added) != 0 {
		t.Fatalf("audit %+v", write)
	}
	// Version 1 is still on disk, unchanged and read-only.
	v1, err := f.b.store.Version(1)
	if err != nil || len(v1.Entries) != 4 || v1.Author != "operator:seed" {
		t.Fatalf("v1 %+v %v", v1, err)
	}
	// Restart: the store reloads version 2 and the chain verifies.
	f.open()
	if v := f.b.store.Active(); v == nil || v.N != 2 {
		t.Fatalf("after restart %+v", v)
	}
}

// TestStaleWriteRefused: stale_put_refused, If-Match required.
func TestStaleWriteRefused(t *testing.T) {
	f := newFixture(t, true)
	body := policyBody(t, f, func(es []Entry) []Entry { return es[:2] })
	if w := do(f.admin, "PUT", "/admin/v1/policy", admin("u1"), body); w.Code != http.StatusPreconditionRequired {
		t.Fatalf("no If-Match: %d", w.Code)
	}
	if w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), body); w.Code != 201 {
		t.Fatal(w.Code)
	}
	w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u2"), "If-Match", `"1"`), body)
	if w.Code != http.StatusPreconditionFailed || !strings.Contains(w.Body.String(), `"current_version":2`) {
		t.Fatalf("stale: %d %s", w.Code, w.Body)
	}
	if w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"2"`), `{"entries":[{"id":"x"}]}`); w.Code != 422 {
		t.Fatalf("invalid: %d %s", w.Code, w.Body)
	}
	if w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"2"`), `{"entries":[],"issuer":"x"}`); w.Code != 400 {
		t.Fatalf("operator field in body: %d", w.Code)
	}
	if len(f.b.store.Versions()) != 2 {
		t.Fatal("versions")
	}
}

// TestOperatorConfigNotWritable: operator_immutable. The policy document has no field for
// issuer, audience, upstreams or keys; a body that names one is refused, and nothing an admin
// does changes the operator view.
func TestOperatorConfigNotWritable(t *testing.T) {
	f := newFixture(t, true)
	before := do(f.admin, "GET", "/admin/v1/config", admin("u1"), "").Body.String()
	for _, field := range []string{"issuer", "audience", "routes", "jwks", "two_person_rule", "admin_roles"} {
		body := `{"entries":[],"` + field + `":"x"}`
		if w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), body); w.Code != 400 {
			t.Errorf("%s: %d", field, w.Code)
		}
	}
	do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), `{"entries":[]}`)
	if after := do(f.admin, "GET", "/admin/v1/config", admin("u1"), "").Body.String(); after != before {
		t.Fatalf("operator view changed:\n%s\n%s", before, after)
	}
	if !strings.Contains(before, testIssuer) || strings.Contains(before, "test-key") || strings.Contains(before, f.upstream.URL) {
		t.Fatalf("config view: %s", before)
	}
}

// TestTwoPersonRule: two_person_rule. Adding a named-branch entry needs a second admin; the
// author cannot approve; removing access does not need a second admin.
func TestTwoPersonRule(t *testing.T) {
	f := newFixture(t, true)
	exp := testNow.Add(48 * time.Hour)
	body := policyBody(t, f, func(es []Entry) []Entry {
		return append(es, Entry{ID: "alpha-feature", Kind: KindNamed, ProjectPath: "group/alpha", Ref: "feat/y",
			Sources: []string{"web"}, Models: []string{"model-a"}, TriggerUsers: []string{"alice"}, ExpiresAt: &exp, Enabled: true})
	})
	w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), body)
	if w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if len(f.b.store.Versions()) != 1 {
		t.Fatal("committed without a second admin")
	}
	if w := do(f.admin, "POST", "/admin/v1/proposals/1/approve", admin("u1"), ""); w.Code != 403 || !strings.Contains(w.Body.String(), "same_author") {
		t.Fatalf("self approval: %d %s", w.Code, w.Body)
	}
	if w := do(f.admin, "POST", "/admin/v1/proposals/1/approve", with(admin("u2"), "x-broker-role", "user"), ""); w.Code != 403 {
		t.Fatalf("non-admin approval: %d", w.Code)
	}
	// Restart in between: the proposal survives (rebuilt from the audit log).
	f.open()
	w = do(f.admin, "POST", "/admin/v1/proposals/1/approve", admin("u2"), "")
	if w.Code != 201 {
		t.Fatalf("approval: %d %s", w.Code, w.Body)
	}
	v := f.b.store.Active()
	if v.N != 2 || v.Author != "u1" || v.Approver != "u2" {
		t.Fatalf("%+v", v)
	}
	if w := do(f.admin, "POST", "/admin/v1/proposals/1/approve", admin("u3"), ""); w.Code != 404 {
		t.Fatalf("approved twice: %d", w.Code)
	}
	// Disabling it is a reduction: one admin is enough.
	body = policyBody(t, f, func(es []Entry) []Entry { es[len(es)-1].Enabled = false; return es })
	if w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"2"`), body); w.Code != 201 {
		t.Fatalf("disable: %d %s", w.Code, w.Body)
	}
}

func TestTwoPersonStaleAndOff(t *testing.T) {
	f := newFixture(t, true)
	exp := testNow.Add(48 * time.Hour)
	named := func(es []Entry) []Entry {
		return append(es, Entry{ID: "n", Kind: KindNamed, ProjectPath: "group/alpha", Ref: "feat/y",
			Sources: []string{"web"}, Models: []string{"model-a"}, TriggerUsers: []string{"alice"}, ExpiresAt: &exp, Enabled: true})
	}
	do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), policyBody(t, f, named))
	do(f.admin, "PUT", "/admin/v1/policy", with(admin("u3"), "If-Match", `"1"`), policyBody(t, f, func(es []Entry) []Entry { return es[:3] }))
	if w := do(f.admin, "POST", "/admin/v1/proposals/1/approve", admin("u2"), ""); w.Code != 412 {
		t.Fatalf("approving a proposal on an old base: %d", w.Code)
	}
	if w := do(f.admin, "POST", "/admin/v1/proposals/1/reject", admin("u2"), ""); w.Code != 200 {
		t.Fatalf("reject: %d", w.Code)
	}
	g := newFixture(t, false)
	if w := do(g.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), policyBody(t, g, named)); w.Code != 201 {
		t.Fatalf("rule off: %d", w.Code)
	}
}

func TestAdminReads(t *testing.T) {
	f := newFixture(t, true)
	w := do(f.admin, "GET", "/admin/v1/policy", admin("u1"), "")
	var got struct {
		Version int64 `json:"version"`
		Entries []struct {
			ID        string `json:"id"`
			Principal string `json:"principal"`
		} `json:"entries"`
	}
	json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != 200 || w.Header().Get("ETag") != `"1"` || got.Version != 1 || got.Entries[2].Principal != "ci:group/sub/beta@feat/x-1" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for _, p := range []string{"/admin/v1/policy/versions", "/admin/v1/policy/versions/1", "/admin/v1/proposals",
		"/admin/v1/audit?after=0&limit=5", "/admin/v1/usage", "/admin/v1/config"} {
		if w := do(f.admin, "GET", p, admin("u1"), ""); w.Code != 200 {
			t.Errorf("%s: %d", p, w.Code)
		}
		if w := do(f.admin, "GET", p, with(admin("u1"), "x-broker-role", "user"), ""); w.Code != 403 {
			t.Errorf("%s as user: %d", p, w.Code)
		}
	}
	if w := do(f.admin, "GET", "/admin/v1/policy/versions/9", admin("u1"), ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
}

// The console's script reads and writes through the admin API beside it, sending If-Match on
// every write, and never parses a name as markup.
func TestConsoleUsesTheAdminAPI(t *testing.T) {
	f := newFixture(t, true)
	js := do(f.admin, "GET", "/admin/v1/ui/console.js", admin("u1"), "").Body.String()
	for _, want := range []string{`"usage/principals?"`, `"usage?"`, `api("quotas"`, `api("owners"`, `api("policy"`, `api("config")`, `"If-Match"`, `"proposals/"`, "cost_usd", "cached_prompt_tokens"} {
		if !strings.Contains(js, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if strings.Contains(js, "innerHTML") || strings.Contains(js, "insertAdjacentHTML") || strings.Contains(js, "document.write") {
		t.Error("script writes markup; principal names must go in as text")
	}
	if w := do(f.admin, "GET", "/admin/v1/ui/", map[string]string{"x-broker-ci-claims": payload(nil)}, ""); w.Code != 403 {
		t.Fatalf("as pipeline: %d", w.Code)
	}
}
