package broker

import (
	"encoding/json"
	"strings"
	"testing"
)

// consoleUsage plants a person's call and a pipeline's call (owned by alice, started by carol) on
// the fixture's day, and returns that day.
func consoleUsage(t *testing.T, f *fixture) string {
	t.Helper()
	priced(f)
	u := f.b.up.usage
	u.addFor("bob@example.com", "model-a", usageAttr{}, tokens{Prompt: 10, Completion: 5}, testNow)
	u.addFor("bob@example.com", "model-b", usageAttr{}, tokens{Prompt: 1, Completion: 1}, testNow)
	u.addFor("ci:group/alpha", "model-a", usageAttr{Owner: "alice@example.com", TriggeredBy: "carol"}, tokens{Prompt: 3, Completion: 2}, testNow)
	u.addFor("ci:group/alpha", "model-a", usageAttr{Owner: "alice@example.com", TriggeredBy: "carol"}, tokens{Prompt: 3, Completion: 2}, testNow)
	return testNow.UTC().Format("2006-01-02")
}

// The day map of GET usage narrows to one kind of principal or one model; without a filter it is
// what it was before.
func TestUsageHistoryFilters(t *testing.T) {
	f := newFixture(t, false)
	day := consoleUsage(t, f)
	get := func(q string) map[string]map[string]map[string]usageCount {
		t.Helper()
		w := do(f.admin, "GET", "/admin/v1/usage?from="+day+"&to="+day+q, admin("u1"), "")
		var v struct {
			Days map[string]map[string]map[string]usageCount `json:"days"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil {
			t.Fatalf("%s: %d %s", q, w.Code, w.Body)
		}
		return v.Days
	}
	if d := get("")[day]; len(d) != 2 || len(d["bob@example.com"]) != 2 {
		t.Fatalf("unfiltered %+v", d)
	}
	if d := get("&kind=pipeline")[day]; len(d) != 1 || d["ci:group/alpha"]["model-a"].Requests != 2 {
		t.Fatalf("pipelines %+v", d)
	}
	if d := get("&kind=person")[day]; len(d) != 1 || d["bob@example.com"] == nil {
		t.Fatalf("people %+v", d)
	}
	if d := get("&model=model-b")[day]; len(d) != 1 || len(d["bob@example.com"]) != 1 || d["bob@example.com"]["model-b"].Requests != 1 {
		t.Fatalf("model-b %+v", d)
	}
	if w := do(f.admin, "GET", "/admin/v1/usage?from="+day+"&to="+day+"&kind=robot", admin("u1"), ""); w.Code != 400 || !strings.Contains(w.Body.String(), "bad_filter") {
		t.Fatalf("unknown kind: %d %s", w.Code, w.Body)
	}
}

type principalRow struct {
	Principal   string   `json:"principal"`
	Kind        string   `json:"kind"`
	Model       string   `json:"model"`
	Owner       string   `json:"owner"`
	TriggeredBy string   `json:"triggered_by"`
	Requests    int64    `json:"requests"`
	Prompt      int64    `json:"prompt_tokens"`
	Completion  int64    `json:"completion_tokens"`
	CostUSD     *float64 `json:"cost_usd"`
	LastUsed    string   `json:"last_used"`
}

// The Usage tab's rows: per principal and model, with the pipeline's owner and who started it,
// its cost and when it was last used.
func TestUsagePrincipals(t *testing.T) {
	f := newFixture(t, false)
	day := consoleUsage(t, f)
	get := func(q string) []principalRow {
		t.Helper()
		w := do(f.admin, "GET", "/admin/v1/usage/principals?from="+day+"&to="+day+q, admin("u1"), "")
		var v struct {
			Rows []principalRow `json:"rows"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil {
			t.Fatalf("%s: %d %s", q, w.Code, w.Body)
		}
		return v.Rows
	}
	rows := get("")
	if len(rows) != 3 {
		t.Fatalf("rows %+v", rows)
	}
	var pipe *principalRow
	for i := range rows {
		if rows[i].Principal == "ci:group/alpha" {
			pipe = &rows[i]
		}
	}
	if pipe == nil || pipe.Kind != "pipeline" || pipe.Owner != "alice@example.com" || pipe.TriggeredBy != "carol" ||
		pipe.Requests != 2 || pipe.Prompt != 6 || pipe.Completion != 4 || pipe.CostUSD == nil || *pipe.CostUSD != 0.001 ||
		!strings.HasPrefix(pipe.LastUsed, day) {
		t.Fatalf("pipeline row %+v", pipe)
	}
	if r := get("&kind=person&model=model-a"); len(r) != 1 || r[0].Principal != "bob@example.com" || r[0].Kind != "person" || r[0].Owner != "" {
		t.Fatalf("filtered %+v", r)
	}
	for q, want := range map[string]string{"&kind=robot": "bad_filter", "&to=2020-01-01": "bad_range"} {
		path := "/admin/v1/usage/principals?from=" + day + "&to=" + day + q
		if q == "&to=2020-01-01" {
			path = "/admin/v1/usage/principals?from=" + day + q
		}
		if w := do(f.admin, "GET", path, admin("u1"), ""); w.Code != 400 || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d %s", q, w.Code, w.Body)
		}
	}
	if w := do(f.admin, "GET", "/admin/v1/usage/principals?from="+day+"&to="+day, with(admin("u2"), "x-broker-role", "user"), ""); w.Code != 403 {
		t.Fatalf("non-admin: %d", w.Code)
	}
	unreadableLedger(t, f)
	if w := do(f.admin, "GET", "/admin/v1/usage/principals?from="+day+"&to="+day, admin("u1"), ""); w.Code != 503 {
		t.Fatalf("unreadable ledger: %d, want 503", w.Code)
	}
}

// A browser write from another site is refused before it reaches any handler, whatever it
// carries; a same-origin write and a non-browser client (no fetch metadata) are served.
func TestAdminWritesRefuseCrossSite(t *testing.T) {
	f := newFixture(t, true)
	body := `{"default_usd":5,"principals":{},"comment":"x"}`
	for _, site := range []string{"cross-site", "same-site", "none"} {
		w := do(f.admin, "PUT", "/admin/v1/quotas", with(with(admin("u1"), "If-Match", `"0"`), "Sec-Fetch-Site", site), body)
		if w.Code != 403 || !strings.Contains(w.Body.String(), "cross_site") {
			t.Errorf("PUT with Sec-Fetch-Site %s: %d %s", site, w.Code, w.Body)
		}
		w = do(f.admin, "POST", "/admin/v1/proposals/1/approve", with(admin("u2"), "Sec-Fetch-Site", site), "")
		if w.Code != 403 || !strings.Contains(w.Body.String(), "cross_site") {
			t.Errorf("approve with Sec-Fetch-Site %s: %d %s", site, w.Code, w.Body)
		}
	}
	// A form a hostile page could post: text/plain, no If-Match, foreign origin.
	w := do(f.admin, "PUT", "/admin/v1/quotas", with(with(admin("u1"), "Content-Type", "text/plain"), "Origin", "https://evil.example"), body)
	if w.Code != 403 {
		t.Fatalf("foreign-origin form: %d %s", w.Code, w.Body)
	}
	w = do(f.admin, "PUT", "/admin/v1/quotas", with(admin("u1"), "Content-Type", "text/plain"), body)
	if w.Code == 200 {
		t.Fatalf("a write without If-Match or JSON was saved: %s", w.Body)
	}
	if v := getQuotas(t, f); v.Version != 0 {
		t.Fatalf("a refused write changed the quotas: %+v", v)
	}
	// Reads are not writes: a cross-site navigation to the page still gets it (the CSP stops framing).
	if w := do(f.admin, "GET", "/admin/v1/quotas", with(admin("u1"), "Sec-Fetch-Site", "cross-site"), ""); w.Code != 200 {
		t.Fatalf("GET with fetch metadata: %d", w.Code)
	}
	if w := do(f.admin, "PUT", "/admin/v1/quotas", with(with(admin("u1"), "If-Match", `"0"`), "Sec-Fetch-Site", "same-origin"), body); w.Code != 200 {
		t.Fatalf("same-origin write: %d %s", w.Code, w.Body)
	}
	if w := do(f.admin, "PUT", "/admin/v1/quotas", with(admin("u1"), "If-Match", `"1"`), body); w.Code != 200 {
		t.Fatalf("non-browser write: %d %s", w.Code, w.Body)
	}
	// Two admins edit the same version: the second is refused and nothing of it is kept.
	if w := do(f.admin, "PUT", "/admin/v1/quotas", with(admin("u1"), "If-Match", `"1"`), `{"default_usd":9,"principals":{}}`); w.Code != 412 {
		t.Fatalf("stale If-Match: %d %s", w.Code, w.Body)
	}
	if v := getQuotas(t, f); *v.DefaultUSD != 5 {
		t.Fatalf("a stale write changed the default: %+v", v)
	}
}
