package broker

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var day1 = time.Date(2026, 10, 19, 9, 30, 0, 0, time.UTC)

type allReport struct {
	Day        string                           `json:"day"`
	Since      string                           `json:"since"`
	Principals map[string]map[string]usageCount `json:"principals"`
}

func reportOf(t *testing.T, u *usageBook, now time.Time) allReport {
	t.Helper()
	var r allReport
	if err := json.Unmarshal(must(u.reportAll(now)), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestUsageSurvivesRestart(t *testing.T) {
	dir := testLedger(t)
	u := openUsage(dir, testCeiling, day1)
	u.add("alice@example.com", "model-a", tokens{Prompt: 10, Completion: 2}, day1.Add(time.Minute))
	u.add("alice@example.com", "model-a", tokens{Prompt: 5, Completion: 1}, day1.Add(2*time.Minute))
	u.add("ci:group/alpha", "model-b", tokens{Prompt: 7, Completion: 4}, day1.Add(3*time.Minute))

	again := openUsage(dir, testCeiling, day1.Add(time.Hour))
	r := reportOf(t, again, day1.Add(time.Hour))
	if got := r.Principals["alice@example.com"]["model-a"]; got != (usageCount{Requests: 2, PromptTokens: 15, CompletionTokens: 3}) {
		t.Fatalf("alice after restart: %+v", got)
	}
	if got := r.Principals["ci:group/alpha"]["model-b"]; got != (usageCount{Requests: 1, PromptTokens: 7, CompletionTokens: 4}) {
		t.Fatalf("pipeline after restart: %+v", got)
	}
	// Counting started when the ledger was first opened, not when this process started.
	if r.Since != day1.Format(time.RFC3339) {
		t.Fatalf("since %s", r.Since)
	}
}

func TestUsageSinceIsMidnightAfterRunningThroughIt(t *testing.T) {
	u := openUsage(testLedger(t), testCeiling, day1)
	next := day1.Add(20 * time.Hour) // 05:30 the next day, nothing used yet
	r := reportOf(t, u, next)
	if r.Day != "2026-10-20" || r.Since != "2026-10-20T00:00:00Z" || len(r.Principals) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestUsageHistoryRange(t *testing.T) {
	dir := testLedger(t)
	u := openUsage(dir, testCeiling, day1)
	u.add("alice@example.com", "model-a", tokens{Prompt: 10, Completion: 2}, day1)
	u.add("alice@example.com", "model-a", tokens{Prompt: 3, Completion: 1}, day1.Add(24*time.Hour))
	u.add("bob@example.com", "model-b", tokens{Prompt: 4, Completion: 4}, day1.Add(48*time.Hour))

	h, err := u.history("2026-10-19", "2026-10-20")
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 2 || h["2026-10-19"]["alice@example.com"]["model-a"] != (usageCount{Requests: 1, PromptTokens: 10, CompletionTokens: 2}) ||
		h["2026-10-20"]["alice@example.com"]["model-a"] != (usageCount{Requests: 1, PromptTokens: 3, CompletionTokens: 1}) {
		t.Fatalf("%+v", h)
	}
	if _, err := u.history("2026-10-21", "2026-10-19"); err == nil {
		t.Fatal("reversed range accepted")
	}
	if _, err := u.history("2026-10-19", "../../etc"); err == nil {
		t.Fatal("non-date accepted")
	}
	if _, err := u.history("2026-01-01", "2026-12-31"); err == nil {
		t.Fatal("range over the limit accepted")
	}
}

func TestUsageAccountedAcrossBrokerRestart(t *testing.T) {
	f := newFixture(t, true)
	if w := do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	f.open() // a new broker on the same store, as after a pod restart
	r := reportOf(t, f.b.up.usage, time.Now())
	if r.Principals["ci:group/alpha"]["model-a"].Requests != 1 {
		t.Fatalf("lost on restart: %+v", r)
	}
	today := time.Now().UTC().Format("2006-01-02")
	w := do(f.admin, "GET", "/admin/v1/usage?from="+today+"&to="+today, admin("u1"), "")
	var h struct {
		Days map[string]map[string]map[string]usageCount `json:"days"`
	}
	json.Unmarshal(w.Body.Bytes(), &h)
	if w.Code != 200 || h.Days[today]["ci:group/alpha"]["model-a"].Requests != 1 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := do(f.admin, "GET", "/admin/v1/usage?from=2026-13-01&to="+today, admin("u1"), ""); w.Code != 400 {
		t.Fatalf("bad date: %d", w.Code)
	}
}

func TestUsageCountsCachedPromptTokens(t *testing.T) {
	for name, body := range map[string]string{
		"response": `{"choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":20,"prompt_tokens_details":{"cached_tokens":896}}}`,
		"chunk":    `{"choices":[],"usage":{"prompt_tokens":1000,"prompt_tokens_details":{"cached_tokens":896},"completion_tokens":20}}`,
	} {
		got, _, ok := usageOf([]byte(body))
		if !ok || got != (tokens{Prompt: 1000, Cached: 896, Completion: 20}) {
			t.Fatalf("%s: %+v %v", name, got, ok)
		}
	}
	if got, _, ok := usageOf([]byte(`{"usage":{"prompt_tokens":5,"completion_tokens":1}}`)); !ok || got.Cached != 0 {
		t.Fatalf("no details: %+v", got)
	}
	dir := testLedger(t)
	u := openUsage(dir, testCeiling, day1)
	u.add("alice@example.com", "model-a", tokens{Prompt: 1000, Cached: 896, Completion: 20}, day1)
	u.add("alice@example.com", "model-a", tokens{Prompt: 500, Completion: 5}, day1)
	r := reportOf(t, openUsage(dir, testCeiling, day1.Add(time.Hour)), day1.Add(time.Hour))
	if got := r.Principals["alice@example.com"]["model-a"]; got != (usageCount{Requests: 2, PromptTokens: 1500, CachedPromptTokens: 896, CompletionTokens: 25}) {
		t.Fatalf("after restart: %+v", got)
	}
}

func TestStreamedCachedTokensAccounted(t *testing.T) {
	var tee usageTee
	tee.w = io.Discard
	tee.Write([]byte("data: {\"choices\":[]}\n\ndata: {\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2,\"prompt_tokens_details\":{\"cached_tokens\":8}}}\n\ndata: [DONE]\n\n"))
	if tee.used != (tokens{Prompt: 9, Cached: 8, Completion: 2}) {
		t.Fatalf("%+v", tee.used)
	}
}

// Azure Government rates for gpt-5.6-sol (short context), USD per 1M tokens, from the meters billed.
var solPrice = Price{Input: 4.40, CachedInput: 0.44, Output: 22.00}

func TestUsageCostFromRoutePrice(t *testing.T) {
	u := openUsage(testLedger(t), testCeiling, day1)
	u.prices = map[string]Price{"model-a": solPrice}
	u.add("alice@example.com", "model-a", tokens{Prompt: 1000, Cached: 896, Completion: 20}, day1)
	u.add("alice@example.com", "model-b", tokens{Prompt: 1000, Completion: 20}, day1)
	r := reportOf(t, u, day1)
	// 104 uncached x 4.40 + 896 cached x 0.44 + 20 out x 22.00, per million
	if c := r.Principals["alice@example.com"]["model-a"].CostUSD; c == nil || *c != 0.001292 {
		t.Fatalf("priced cost %v", c)
	}
	if c := r.Principals["alice@example.com"]["model-b"].CostUSD; c != nil {
		t.Fatalf("unpriced model got a cost %v; it must be absent, not zero", *c)
	}
	h, _ := u.history("2026-10-19", "2026-10-19")
	if c := h["2026-10-19"]["alice@example.com"]["model-a"].CostUSD; c == nil || *c != 0.001292 {
		t.Fatalf("history cost %v", c)
	}
	var mine struct {
		Models map[string]usageCount `json:"models"`
	}
	json.Unmarshal(must(u.report(testCeiling, "alice@example.com", day1)), &mine)
	if c := mine.Models["model-a"].CostUSD; c == nil || *c != 0.001292 {
		t.Fatalf("own report cost %v", c)
	}
}

func TestRoutePriceValidated(t *testing.T) {
	ok := RouteConfig{Model: "m", UpstreamURL: "https://x.example.com/v1", AuthHeader: "api-key", KeyFile: "/k",
		Price: &Price{Input: 1, CachedInput: 0.1, Output: 2}}
	if err := ok.check(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []Price{{Input: -1}, {Output: math.Inf(1)}, {CachedInput: math.NaN()}} {
		r := ok
		r.Price = &p
		if err := r.check(); err == nil {
			t.Errorf("price %+v accepted", p)
		}
	}
}

func TestTinyCallsStillCountTowardMonthSpend(t *testing.T) {
	u := openUsage(testLedger(t), testCeiling, day1)
	u.prices = map[string]Price{"m": {Input: 0.1}} // $0.0000001 per prompt token
	for i := 0; i < 1000; i++ {
		u.add("p", "m", tokens{Prompt: 1}, day1)
	}
	if got := u.monthSpent("p", day1); got != 0.0001 {
		t.Fatalf("1000 calls of $0.0000001 spent %v, want 0.0001", got)
	}
}

// brokenClient accepts the first write and fails every later one, as a client that disconnects
// mid-stream does.
type brokenClient struct {
	*httptest.ResponseRecorder
	writes int
}

func (b *brokenClient) Write(p []byte) (int, error) {
	b.writes++
	if b.writes > 1 {
		return 0, io.ErrClosedPipe
	}
	return b.ResponseRecorder.Write(p)
}
func (b *brokenClient) Flush() {}

func streamUpstream(t *testing.T, withUsage bool) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 5; i++ {
			io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n")
			w.(http.Flusher).Flush()
		}
		if withUsage {
			io.WriteString(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":40,\"completion_tokens\":9}}\n\n")
		}
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/v1/chat/completions"
}

func streamCall(t *testing.T, up *upstream, w http.ResponseWriter) {
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	ctx, cancel := context.WithCancel(r.Context())
	cancel() // the client is gone before the answer finishes
	up.forward(w, r.WithContext(ctx), "alice@example.com", testCeiling, usageAttr{}, up.routes["m"], &chatRequest{payload: map[string]json.RawMessage{
		"model": json.RawMessage(`"m"`), "messages": json.RawMessage(`[]`), "stream": json.RawMessage(`true`)}}, admission{})
}

func streamingUpstream(t *testing.T, url string) *upstream {
	up := newUpstream([]RouteConfig{{Model: "m", UpstreamURL: url, AuthHeader: "api-key", KeyFile: writeKey(t)}}, 2, nil, defaultUpstream)
	if err := up.routes["m"].check(); err != nil {
		t.Fatal(err)
	}
	up.usage = openUsage(testLedger(t), testCeiling, day1)
	return up
}

func TestDisconnectedStreamIsStillCharged(t *testing.T) {
	up := streamingUpstream(t, streamUpstream(t, true))
	streamCall(t, up, &brokenClient{ResponseRecorder: httptest.NewRecorder()})
	r := reportOf(t, up.usage, time.Now())
	if got := r.Principals["alice@example.com"]["m"]; got.Requests != 1 || got.PromptTokens != 40 || got.CompletionTokens != 9 {
		t.Fatalf("a call the client abandoned was not charged: %+v", got)
	}
}

func TestReplyWithoutUsageMakesSpendUnknown(t *testing.T) {
	up := streamingUpstream(t, streamUpstream(t, false))
	streamCall(t, up, httptest.NewRecorder())
	if _, err := up.usage.monthSpentErr("alice@example.com", time.Now()); err == nil {
		t.Fatal("a reply with no usage left spend known")
	}
	again := openUsage(up.usage.db, testCeiling, time.Now())
	if _, err := again.monthSpentErr("alice@example.com", time.Now()); err == nil {
		t.Fatal("unknown usage forgotten across restart")
	}
	if _, err := again.monthSpentErr("bob@example.com", time.Now()); err != nil {
		t.Fatalf("another principal's spend became unknown: %v", err)
	}
}

func TestInvalidUsageIsUnknown(t *testing.T) {
	for name, body := range map[string]string{
		"empty":           `{"usage":{}}`,
		"no completion":   `{"usage":{"prompt_tokens":5}}`,
		"negative":        `{"usage":{"prompt_tokens":-5,"completion_tokens":1}}`,
		"cached over":     `{"usage":{"prompt_tokens":5,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":6}}}`,
		"negative cached": `{"usage":{"prompt_tokens":5,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":-1}}}`,
		"string":          `{"usage":{"prompt_tokens":"5","completion_tokens":1}}`,
	} {
		if _, present, valid := usageOf([]byte(body)); !present || valid {
			t.Errorf("%s: present %v valid %v", name, present, valid)
		}
	}
	if u, present, valid := usageOf([]byte(`{"usage":{"prompt_tokens":5,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":5}}}`)); !present || !valid || u.Cached != 5 {
		t.Fatalf("valid usage refused: %+v %v %v", u, present, valid)
	}
	if _, present, _ := usageOf([]byte(`{"choices":[]}`)); present {
		t.Fatal("a chunk with no usage counted as present")
	}
}

func jsonUpstream(t *testing.T, h http.HandlerFunc) *upstream {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return streamingUpstream(t, srv.URL+"/v1/chat/completions")
}

func plainCall(up *upstream) int {
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	up.forward(w, r, "alice@example.com", testCeiling, usageAttr{}, up.routes["m"], &chatRequest{payload: map[string]json.RawMessage{
		"model": json.RawMessage(`"m"`), "messages": json.RawMessage(`[]`)}}, admission{})
	return w.Code
}

func TestFailedOrOversizedReplyMakesSpendUnknown(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"cut short": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "1000")
			io.WriteString(w, `{"choices":[`)
		},
		"oversized": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"pad":"`+strings.Repeat("x", 9<<20)+`"}`)
		},
		"invalid usage": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"choices":[],"usage":{}}`)
		},
	} {
		up := jsonUpstream(t, h)
		plainCall(up)
		if _, err := up.usage.monthSpentErr("alice@example.com", time.Now()); err == nil {
			t.Errorf("%s: spend still known", name)
		}
	}
}

func TestPriceChangesDoNotRewritePastSpend(t *testing.T) {
	dir := testLedger(t)
	u := openUsage(dir, testCeiling, day1)
	u.prices = map[string]Price{"m": {Input: 1e6}} // $1 per prompt token
	u.add("p", "m", tokens{Prompt: 3}, day1.AddDate(0, 0, -1))
	u.add("p", "m", tokens{Prompt: 2}, day1)
	for name, prices := range map[string]map[string]Price{"cheaper": {"m": {Input: 1}}, "removed": {}} {
		again := openUsage(dir, testCeiling, day1.Add(time.Hour))
		again.prices = prices
		if got, err := again.monthSpentErr("p", day1.Add(time.Hour)); err != nil || got != 5 {
			t.Errorf("%s price: month spend %v %v, want the 5 charged", name, got, err)
		}
	}
}

func TestPendingCallWithoutItsRecordIsUnknownAfterRestart(t *testing.T) {
	dir := testLedger(t)
	u := openUsage(dir, testCeiling, day1)
	if _, err := u.begin(testCeiling, "p", "m", day1); err != nil {
		t.Fatal(err)
	}
	// The process dies before the call's record is written.
	again := openUsage(dir, testCeiling, day1.Add(time.Hour))
	if _, err := again.monthSpentErr("p", day1.Add(time.Hour)); err == nil {
		t.Fatal("a call that started and never recorded its usage left spend known")
	}
	if _, err := again.monthSpentErr("q", day1.Add(time.Hour)); err != nil {
		t.Fatalf("another principal affected: %v", err)
	}
}

func TestInFlightCallIsNotUnknown(t *testing.T) {
	u := openUsage(testLedger(t), testCeiling, day1)
	call, err := u.begin(testCeiling, "p", "m", day1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.monthSpentErr("p", day1); err != nil {
		t.Fatalf("a call still running made spend unknown: %v", err)
	}
	u.finish(call, "p", "m", usageAttr{}, tokens{Prompt: 1}, day1)
	if r := reportOf(t, openUsage(u.db, testCeiling, day1.Add(time.Hour)), day1.Add(time.Hour)); r.Principals["p"]["m"].Requests != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestUnpricedCallsStayFreeWhenAPriceIsAdded(t *testing.T) {
	dir := testLedger(t)
	u := openUsage(dir, testCeiling, day1)
	u.add("p", "m", tokens{Prompt: 5}, day1) // no price for m yet
	again := openUsage(dir, testCeiling, day1.Add(time.Hour))
	again.setPrices(map[string]Price{"m": {Input: 1e6}})
	if got, err := again.monthSpentErr("p", day1.Add(time.Hour)); err != nil || got != 0 {
		t.Fatalf("a call made while unpriced was charged later: %v %v", got, err)
	}
}

func TestReportsKeepChargesAfterPriceChange(t *testing.T) {
	dir := testLedger(t)
	u := openUsage(dir, testCeiling, day1)
	u.setPrices(map[string]Price{"m": {Input: 1e6}}) // $1 per prompt token
	u.add("p", "m", tokens{Prompt: 2}, day1.AddDate(0, 0, -1))
	u.add("p", "m", tokens{Prompt: 3}, day1)
	u.setPrices(map[string]Price{"m": {Input: 10e6}}) // repriced: $10 per token
	h, err := u.history(day1.AddDate(0, 0, -1).Format("2006-01-02"), day1.Format("2006-01-02"))
	if err != nil {
		t.Fatal(err)
	}
	for day, want := range map[string]float64{"2026-10-18": 2, "2026-10-19": 3} {
		if c := h[day]["p"]["m"].CostUSD; c == nil || *c != want {
			t.Errorf("%s: cost %v, want %v (what was charged)", day, c, want)
		}
	}
	var rep struct {
		Principals map[string]map[string]usageCount `json:"principals"`
	}
	json.Unmarshal(must(u.reportAll(day1)), &rep)
	if c := rep.Principals["p"]["m"].CostUSD; c == nil || *c != 3 {
		t.Errorf("today's report cost %v, want 3", c)
	}
	// A price removed later still shows what was charged.
	u.setPrices(map[string]Price{})
	json.Unmarshal(must(u.reportAll(day1)), &rep)
	if c := rep.Principals["p"]["m"].CostUSD; c == nil || *c != 3 {
		t.Errorf("unpriced report cost %v, want 3", c)
	}
}

func TestStreamCutAfterUsageChunkMakesSpendUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// Some providers send running totals; this one reports usage, then the connection drops.
		io.WriteString(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":40,\"completion_tokens\":1}}\n\n")
		w.(http.Flusher).Flush()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	t.Cleanup(srv.Close)
	up := streamingUpstream(t, srv.URL+"/v1/chat/completions")
	streamCall(t, up, httptest.NewRecorder())
	if _, err := up.usage.monthSpentErr("alice@example.com", time.Now()); err == nil {
		t.Fatal("a stream that failed mid-read was recorded as fully counted")
	}
}

func sseUpstream(t *testing.T, body string) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/v1/chat/completions"
}

func TestStreamUsageCountsOnlyAsTheFinalChunk(t *testing.T) {
	const content = "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n"
	const usage = "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":40,\"completion_tokens\":9}}\n\n"
	for name, c := range map[string]struct {
		body  string
		known bool
	}{
		"final usage then done":         {content + usage + "data: [DONE]\n\n", true},
		"running total then more, done": {usage + content + "data: [DONE]\n\n", false},
		"usage then clean EOF":          {content + usage, false},
		"usage then error event":        {usage + "event: error\ndata: {\"error\":{\"message\":\"x\"}}\n\n", false},
	} {
		up := streamingUpstream(t, sseUpstream(t, c.body))
		streamCall(t, up, httptest.NewRecorder())
		if _, err := up.usage.monthSpentErr("alice@example.com", time.Now()); (err == nil) != c.known {
			t.Errorf("%s: spend known=%v, want %v", name, err == nil, c.known)
		}
	}
}
