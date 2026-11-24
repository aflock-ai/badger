package broker

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

type quotaView struct {
	Version    int64              `json:"version"`
	DefaultUSD *float64           `json:"default_usd"`
	Principals map[string]float64 `json:"principals"`
	Month      string             `json:"month"`
	UsedUSD    map[string]float64 `json:"used_usd"`
}

func getQuotas(t *testing.T, f *fixture) quotaView {
	t.Helper()
	w := do(f.admin, "GET", "/admin/v1/quotas", admin("u1"), "")
	var q quotaView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &q) != nil {
		t.Fatalf("get quotas: %d %s", w.Code, w.Body)
	}
	if w.Header().Get("ETag") == "" {
		t.Fatal("no ETag")
	}
	return q
}

func putQuotas(f *fixture, version, body string) int {
	return do(f.admin, "PUT", "/admin/v1/quotas", with(admin("u1"), "If-Match", version), body).Code
}

// priced makes every model-a call cost $0.0005: the fixture upstream reports 3 prompt and 2
// completion tokens, at $100 per million each.
func priced(f *fixture) {
	f.b.up.usage.prices = map[string]Price{"model-a": {Input: 100, CachedInput: 100, Output: 100}}
}

func pipelineCall(f *fixture) (int, string) {
	w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA)
	return w.Code, w.Header().Get("X-Broker-Quota-Warning")
}

func TestQuotaWarnsThenStops(t *testing.T) {
	f := newFixture(t, true)
	priced(f)
	if c := putQuotas(f, `"0"`, `{"default_usd":null,"principals":{"ci:group/alpha":0.0006},"comment":"pilot cap"}`); c != 200 {
		t.Fatalf("put: %d", c)
	}
	if code, warn := pipelineCall(f); code != 200 || warn != "" { // used $0 of $0.0006
		t.Fatalf("first call %d warn %q", code, warn)
	}
	if code, warn := pipelineCall(f); code != 200 || warn == "" { // used $0.0005: 83%
		t.Fatalf("second call %d warn %q", code, warn)
	}
	calls := f.calls.Load()
	w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA)
	if w.Code != 429 || !strings.Contains(w.Body.String(), "quota_exceeded") {
		t.Fatalf("over quota: %d %s", w.Code, w.Body)
	}
	if f.calls.Load() != calls {
		t.Fatal("an over-quota call reached the model")
	}
	if q := getQuotas(t, f); q.UsedUSD["ci:group/alpha"] != 0.001 {
		t.Fatalf("used %+v", q.UsedUSD)
	}
}

func TestQuotaDefaultAndOverride(t *testing.T) {
	f := newFixture(t, true)
	priced(f)
	// A default of zero blocks everyone without an override; the override lets this principal through.
	if c := putQuotas(f, `"0"`, `{"default_usd":0,"principals":{}}`); c != 200 {
		t.Fatal(c)
	}
	if code, _ := pipelineCall(f); code != 429 {
		t.Fatalf("default zero: %d", code)
	}
	if c := putQuotas(f, `"1"`, `{"default_usd":0,"principals":{"ci:group/alpha":5}}`); c != 200 {
		t.Fatal(c)
	}
	if code, _ := pipelineCall(f); code != 200 {
		t.Fatalf("override: %d", code)
	}
	// No default and no override: unlimited.
	if c := putQuotas(f, `"2"`, `{"default_usd":null,"principals":{}}`); c != 200 {
		t.Fatal(c)
	}
	if code, _ := pipelineCall(f); code != 200 {
		t.Fatalf("unlimited: %d", code)
	}
}

func TestQuotaWritesAreVersionedValidatedAndAudited(t *testing.T) {
	f := newFixture(t, true)
	if c := putQuotas(f, `"0"`, `{"default_usd":25,"principals":{"alice@example.com":100}}`); c != 200 {
		t.Fatal(c)
	}
	if c := putQuotas(f, `"0"`, `{"default_usd":30,"principals":{}}`); c != 412 {
		t.Fatalf("stale version: %d", c)
	}
	if c := do(f.admin, "PUT", "/admin/v1/quotas", admin("u1"), `{"default_usd":30,"principals":{}}`).Code; c != 428 {
		t.Fatalf("no If-Match: %d", c)
	}
	for _, bad := range []string{`{"default_usd":-1,"principals":{}}`, `{"default_usd":null,"principals":{"a":-5}}`,
		`{"default_usd":null,"principals":{"bad name\n":5}}`, `{"default_usd":"10","principals":{}}`, `{"extra":1}`} {
		if c := putQuotas(f, `"1"`, bad); c/100 != 4 || c == 412 {
			t.Errorf("%s: %d", bad, c)
		}
	}
	if c := do(f.admin, "PUT", "/admin/v1/quotas", with(with(admin("u1"), "x-broker-role", "user"), "If-Match", `"1"`),
		`{"default_usd":1,"principals":{}}`).Code; c != 403 {
		t.Fatalf("as user: %d", c)
	}
	q := getQuotas(t, f)
	if q.Version != 1 || q.DefaultUSD == nil || *q.DefaultUSD != 25 || q.Principals["alice@example.com"] != 100 ||
		q.Month != time.Now().UTC().Format("2006-01") {
		t.Fatalf("%+v", q)
	}
	recs, _ := f.b.store.AuditAfter(0, 500)
	found := false
	for _, r := range recs {
		if r.Kind == "quota" && r.Actor == "u1" && strings.Contains(r.Comment, "default_usd=25") {
			found = true
		}
	}
	if !found {
		t.Fatal("no quota audit record")
	}
}

func TestQuotaAndSpendSurviveRestart(t *testing.T) {
	f := newFixture(t, true)
	priced(f)
	if c := putQuotas(f, `"0"`, `{"default_usd":null,"principals":{"ci:group/alpha":0.0004}}`); c != 200 {
		t.Fatal(c)
	}
	if code, _ := pipelineCall(f); code != 200 {
		t.Fatal(code)
	}
	f.open()
	priced(f)
	if q := getQuotas(t, f); q.Version != 1 || q.UsedUSD["ci:group/alpha"] != 0.0005 {
		t.Fatalf("after restart %+v", q)
	}
	if code, _ := pipelineCall(f); code != 429 {
		t.Fatalf("spend forgotten across restart: %d", code)
	}
}

func TestMonthSpendCountsEarlierDays(t *testing.T) {
	dir := testLedger(t)
	u := openUsage(dir, testCeiling, day1)
	u.prices = map[string]Price{"m": {Input: 1e6, Output: 0}}    // $1 per prompt token
	u.add("p", "m", tokens{Prompt: 2}, day1.AddDate(0, 0, -18))  // 1 Oct: same month
	u.add("p", "m", tokens{Prompt: 3}, day1)                     // 19 Oct
	u.add("p", "m", tokens{Prompt: 100}, day1.AddDate(0, -1, 0)) // September: not counted
	again := openUsage(dir, testCeiling, day1.Add(time.Hour))
	again.prices = u.prices
	if got := again.monthSpent("p", day1.Add(time.Hour)); got != 5 {
		t.Fatalf("month spend %v", got)
	}
}

func TestQuotaRefusesWhenSpendCannotBeRebuilt(t *testing.T) {
	f := newFixture(t, true)
	priced(f)
	if c := putQuotas(f, `"0"`, `{"default_usd":null,"principals":{"ci:group/alpha":1}}`); c != 200 {
		t.Fatal(c)
	}
	if code, _ := pipelineCall(f); code != 200 {
		t.Fatal(code)
	}
	// A call whose result was never recorded (a crash between the call and its record): once the
	// longest a call can run has passed, its spend is unknown.
	f.pg.Super(t, `INSERT INTO broker.usage_calls (id, day, t, principal, model, pending, label)
		VALUES ('lost', (now() - interval '10 minutes')::date, now() - interval '10 minutes', 'ci:group/alpha', 'model-a', true,
		badger.label_of($1::jsonb))`, f.cfg.Ceiling().Lattice())
	f.open()
	priced(f)
	if code, _ := pipelineCall(f); code != 503 {
		t.Fatalf("limited call with unknown spend: %d", code)
	}
}

func TestNullQuotasAndOwnersFileRefuse(t *testing.T) {
	for _, file := range []string{"quotas.json", "owners.json"} {
		f := newFixture(t, true)
		f.setDoc(strings.TrimSuffix(file, ".json"), "null")
		f.open()
		if code, _ := pipelineCall(f); code/100 == 2 {
			t.Errorf("%s holding null: call allowed (%d)", file, code)
		}
	}
}

func TestConcurrentCallsCannotShareOneBalance(t *testing.T) {
	f := newFixture(t, true)
	priced(f) // $0.0005 a call
	if c := putQuotas(f, `"0"`, `{"default_usd":null,"principals":{"ci:group/alpha":0.0006}}`); c != 200 {
		t.Fatal(c)
	}
	f.delayMs.Store(100)
	codes := make(chan int, 5)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, _ := pipelineCall(f)
			codes <- code
		}()
	}
	wg.Wait()
	close(codes)
	ok := 0
	for c := range codes {
		if c == 200 {
			ok++
		}
	}
	// $0 then $0.0005 are under $0.0006; the third sees $0.001.
	if ok != 2 {
		t.Fatalf("%d of 5 concurrent calls admitted against a $0.0006 quota at $0.0005 each, want 2", ok)
	}
}

func TestQueuedCallSeesALoweredQuota(t *testing.T) {
	f := newFixture(t, true)
	priced(f)
	if c := putQuotas(f, `"0"`, `{"default_usd":null,"principals":{"ci:group/alpha":5}}`); c != 200 {
		t.Fatal(c)
	}
	f.delayMs.Store(300)
	first := make(chan int, 1)
	go func() { c, _ := pipelineCall(f); first <- c }()
	// The first call holds the principal's lock once it reaches the model (which answers slowly).
	for deadline := time.Now().Add(10 * time.Second); f.calls.Load() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("first call never reached the model")
		}
		time.Sleep(5 * time.Millisecond)
	}
	second := make(chan int, 1)
	go func() { c, _ := pipelineCall(f); second <- c }()
	time.Sleep(50 * time.Millisecond) // the second waits on the lock
	if c := putQuotas(f, `"1"`, `{"default_usd":null,"principals":{"ci:group/alpha":0}}`); c != 200 {
		t.Fatal(c)
	}
	if c := <-first; c != 200 {
		t.Fatalf("first call: %d", c)
	}
	if c := <-second; c != 429 {
		t.Fatalf("queued call ran against the old quota: %d", c)
	}
}
