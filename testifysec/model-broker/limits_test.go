package broker

import (
	"encoding/json"
	"strings"
	"testing"
)

type limitsView struct {
	quotaView
	Defaults Limits             `json:"defaults"`
	People   map[string]Limits  `json:"people"`
	Seeded   []string           `json:"seeded"`
	TodayUSD map[string]float64 `json:"today_usd"`
}

func getLimits(t *testing.T, f *fixture) limitsView {
	t.Helper()
	w := do(f.admin, "GET", "/admin/v1/quotas", admin("u1"), "")
	var v limitsView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
	return v
}

func put(t *testing.T, f *fixture, version, body string) string {
	t.Helper()
	w := do(f.admin, "PUT", "/admin/v1/quotas", with(admin("u1"), "If-Match", version), body)
	if w.Code != 200 {
		t.Fatalf("put %s: %d %s", body, w.Code, w.Body)
	}
	return w.Body.String()
}

func num(v float64) *float64 { return &v }
func count(v int) *int       { return &v }

// The operator's seed fills a field only the first time the broker sees it; an admin's value,
// including "no limit", is never overwritten by a later start with the same or another seed.
func TestLimitsSeedOnceThenPortalIsTheSource(t *testing.T) {
	f := newFixture(t, false)
	f.cfg.SeedLimits = &SeedLimits{DefaultUSD: num(1000), Defaults: Limits{DailyUSD: num(100), CallUSD: num(1.5)}}
	f.open()
	v := getLimits(t, f)
	if v.DefaultUSD == nil || *v.DefaultUSD != 1000 || *v.Defaults.DailyUSD != 100 || *v.Defaults.CallUSD != 1.5 || len(v.Seeded) != 3 {
		t.Fatalf("seeded: %+v", v)
	}
	put(t, f, `"1"`, `{"default_usd":500,"principals":{},"defaults":{"call_usd":1.5},"people":{}}`)
	f.open() // the same config applied again
	f.cfg.SeedLimits = &SeedLimits{DefaultUSD: num(2000), Defaults: Limits{DailyUSD: num(200), Steps: count(50)}}
	f.open() // a changed seed, with one field never seeded before
	v = getLimits(t, f)
	if *v.DefaultUSD != 500 || v.Defaults.DailyUSD != nil || v.Defaults.Steps == nil || *v.Defaults.Steps != 50 {
		t.Fatalf("an admin's value was overwritten, or a new field was not seeded: %+v %+v", v.quotaView, v.Defaults)
	}
	recs, _ := f.b.store.AuditAfter(0, 500)
	seeds := 0
	for _, r := range recs {
		if r.Kind == "quota" && r.Actor == "operator:seed" {
			seeds++
		}
	}
	if seeds != 2 {
		t.Fatalf("%d seed records, want 2 (first start and the new field)", seeds)
	}
}

// What the system cannot physically do is refused with the reason; nothing is clamped silently.
func TestLimitsRefuseTechnicalLimits(t *testing.T) {
	f := newFixture(t, false)
	for body, want := range map[string]string{
		`{"default_usd":null,"principals":{},"defaults":{"timeout_seconds":240},"people":{}}`:                "240 s",
		`{"default_usd":null,"principals":{},"defaults":{"context":300000},"people":{}}`:                     "1 MiB",
		`{"default_usd":null,"principals":{},"defaults":{"context":8192,"output":8192},"people":{}}`:         "smaller than context",
		`{"default_usd":null,"principals":{},"defaults":{"steps":0},"people":{}}`:                            "steps",
		`{"default_usd":null,"principals":{},"defaults":{},"people":{"alice@example.com":{"daily_usd":-1}}}`: "not negative",
		`{"default_usd":null,"principals":{},"defaults":{},"people":{"bad name\n":{"steps":3}}}`:             "plain name",
	} {
		w := do(f.admin, "PUT", "/admin/v1/quotas", with(admin("u1"), "If-Match", `"0"`), body)
		if w.Code != 422 || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d %s, want 422 naming %q", body, w.Code, w.Body, want)
		}
	}
	put(t, f, `"0"`, `{"default_usd":null,"principals":{},"defaults":{"timeout_seconds":239,"context":262144,"output":32768},"people":{"alice@example.com":{"timeout_seconds":120}}}`)
}

// Every write records, per target and field, the old and the new value, and marks a change an
// admin made to their own limits.
func TestLimitsAuditOldNewAndSelf(t *testing.T) {
	f := newFixture(t, false)
	put(t, f, `"0"`, `{"default_usd":1000,"principals":{},"defaults":{"steps":40},"people":{}}`)
	put(t, f, `"1"`, `{"default_usd":1000,"principals":{"u1@example.com":2000},"defaults":{"steps":40},"people":{"u1@example.com":{"steps":80}},"comment":"own limit, reason given"}`)
	recs, _ := f.b.store.AuditAfter(0, 500)
	last := recs[len(recs)-1]
	if last.Kind != "quota" || last.Actor != "u1" || !last.Self {
		t.Fatalf("last record %+v", last)
	}
	got := map[string]LimitChange{}
	for _, c := range last.Changes {
		got[c.Target+" "+c.Field] = c
	}
	steps, monthly := got["u1@example.com steps"], got["u1@example.com monthly_usd"]
	if len(last.Changes) != 2 || steps.Old != nil || *steps.New != 80 || monthly.Old != nil || *monthly.New != 2000 {
		t.Fatalf("changes %+v", last.Changes)
	}
	first := recs[len(recs)-2]
	if first.Self || len(first.Changes) != 2 || first.Changes[0].Target != "default" {
		t.Fatalf("first record %+v", first)
	}
}

// The daily limit stops calls the same way the monthly quota does, and says which limit it was.
func TestDailyLimitStops(t *testing.T) {
	f := newFixture(t, false)
	priced(f)
	put(t, f, `"0"`, `{"default_usd":null,"principals":{},"defaults":{},"people":{"ci:group/alpha":{"daily_usd":0.0006}}}`)
	if code, warn := pipelineCall(f); code != 200 || warn != "" {
		t.Fatalf("first %d %q", code, warn)
	}
	if code, warn := pipelineCall(f); code != 200 || !strings.Contains(warn, "daily") {
		t.Fatalf("second %d %q", code, warn)
	}
	w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA)
	if w.Code != 429 || !strings.Contains(w.Body.String(), "quota_exceeded") || !strings.Contains(w.Body.String(), "daily") {
		t.Fatalf("over the daily limit: %d %s", w.Code, w.Body)
	}
	if v := getLimits(t, f); v.TodayUSD["ci:group/alpha"] != 0.001 {
		t.Fatalf("today %+v", v.TodayUSD)
	}
}

// The output limit is what the provider is asked for, whatever the caller sent; the per-call cap
// bounds it too, at the model's output price, and is the call's reservation while it runs.
func TestOutputClampAndCallCap(t *testing.T) {
	f := newFixture(t, false)
	sent := func(body string) string {
		t.Helper()
		if w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, body); w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		var p struct {
			Max *int `json:"max_completion_tokens"`
		}
		last, _ := f.lastBody.Load().(string)
		json.Unmarshal([]byte(last), &p)
		if p.Max == nil {
			return "none"
		}
		return itoa(*p.Max)
	}
	withMax := func(n string) string {
		return `{"model":"model-a","messages":[{"role":"user","content":"hi"}],"max_tokens":` + n + `}`
	}
	if got := sent(withMax("5000")); got != "5000" {
		t.Fatalf("no limit set: %s", got)
	}
	put(t, f, `"0"`, `{"default_usd":null,"principals":{},"defaults":{"output":4096},"people":{"ci:group/alpha":{"output":100}}}`)
	for body, want := range map[string]string{withMax("5000"): "100", withMax("50"): "50", chatA: "100"} {
		if got := sent(body); got != want {
			t.Errorf("%s: sent %s, want %s", body, got, want)
		}
	}
	priced(f) // $100 per million output tokens: a $0.001 cap buys 10
	put(t, f, `"1"`, `{"default_usd":null,"principals":{},"defaults":{},"people":{"ci:group/alpha":{"output":100,"call_usd":0.001}}}`)
	if got := sent(withMax("5000")); got != "10" {
		t.Fatalf("call cap: %s", got)
	}
	if r := f.superText(`SELECT string_agg(DISTINCT reserved_usd::text, ',') FROM broker.usage_calls WHERE reserved_usd IS NOT NULL`); r != "0.001" {
		t.Fatalf("reservations %q", r)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// GET /v1/limits answers a workspace with its owner's four agent limits, by the token alone; a
// field nobody set is null, which the managed agent reads as its compiled value.
func TestWorkspaceReadsItsOwnersLimits(t *testing.T) {
	f := newFixture(t, false)
	alice, bob := f.issue("ws-alice", "alice@example.com"), f.issue("ws-bob", "bob@example.com")
	read := func(token string, extra map[string]string) string {
		t.Helper()
		h := map[string]string{"Authorization": "Bearer " + token}
		for k, v := range extra {
			h[k] = v
		}
		w := do(f.internal, "GET", "/v1/limits", h, "")
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		return strings.TrimSpace(w.Body.String())
	}
	if got := read(alice, nil); got != `{"context":null,"output":null,"steps":null,"timeout_seconds":null}` {
		t.Fatalf("nothing set: %s", got)
	}
	put(t, f, `"0"`, `{"default_usd":5,"principals":{},"defaults":{"steps":40,"output":16384,"daily_usd":1},"people":{"alice@example.com":{"steps":80,"timeout_seconds":200}}}`)
	if got := read(alice, map[string]string{"x-broker-principal": "bob@example.com"}); got != `{"context":null,"output":16384,"steps":80,"timeout_seconds":200}` {
		t.Fatalf("alice: %s", got)
	}
	if got := read(bob, nil); got != `{"context":null,"output":16384,"steps":40,"timeout_seconds":null}` {
		t.Fatalf("bob: %s", got)
	}
	for _, c := range []struct{ method, path string }{{"POST", "/v1/limits"}, {"GET", "/v1/limits?principal=bob@example.com"}} {
		if w := do(f.internal, c.method, c.path, map[string]string{"Authorization": "Bearer " + alice}, ""); w.Code/100 != 4 {
			t.Errorf("%s %s: %d", c.method, c.path, w.Code)
		}
	}
	if w := do(f.internal, "GET", "/v1/limits", nil, ""); w.Code != 401 {
		t.Fatalf("no token: %d", w.Code)
	}
}

// A change to the caller's own limits, or to a pipeline they own, is flagged in the audit record
// and needs a reason; a change to someone else's does not.
func TestSelfChangeNeedsReasonAndIsFlagged(t *testing.T) {
	f := newFixture(t, false)
	// alice owns every seeded pipeline entry (newFixture); she signs in as admin "alice".
	alice := admin("alice")
	for name, body := range map[string]string{
		"own limit":       `{"default_usd":null,"principals":{"alice@example.com":500}}`,
		"owned pipeline":  `{"default_usd":null,"principals":{"ci:group/alpha":500}}`,
		"own agent limit": `{"default_usd":null,"principals":{},"people":{"Alice@Example.com":{"steps":200}}}`,
	} {
		w := do(f.admin, "PUT", "/admin/v1/quotas", with(alice, "If-Match", `"0"`), body)
		if w.Code != 422 || !strings.Contains(w.Body.String(), "reason_required") {
			t.Errorf("%s without a reason: %d %s", name, w.Code, w.Body)
		}
	}
	if v := getQuotas(t, f); v.Version != 0 {
		t.Fatalf("a refused self change was saved: %+v", v)
	}
	w := do(f.admin, "PUT", "/admin/v1/quotas", with(alice, "If-Match", `"0"`), `{"default_usd":null,"principals":{"ci:group/alpha":500},"comment":"release week"}`)
	if w.Code != 200 {
		t.Fatalf("with a reason: %d %s", w.Code, w.Body)
	}
	recs, _ := f.b.store.AuditAfter(0, 500)
	last := recs[len(recs)-1]
	if last.Kind != "quota" || !last.Self || !strings.Contains(last.Comment, "release week") {
		t.Fatalf("audit %+v", last)
	}
	// Someone else's limit: no reason needed, not flagged.
	if w := do(f.admin, "PUT", "/admin/v1/quotas", with(alice, "If-Match", `"1"`), `{"default_usd":null,"principals":{"ci:group/alpha":500,"bob@example.com":5}}`); w.Code != 200 {
		t.Fatalf("other's limit: %d %s", w.Code, w.Body)
	}
	recs, _ = f.b.store.AuditAfter(0, 500)
	if last := recs[len(recs)-1]; last.Self {
		t.Fatalf("a change to another person's limit was flagged self: %+v", last)
	}
}
