package broker

import (
	"database/sql"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb/pgtest"
)

// A spend check running while other calls begin and finish never takes one of them for a call
// whose result was lost: a limited principal is not refused because the ledger was busy.
func TestSpendCheckNeverMistakesAConcurrentCallForALostOne(t *testing.T) {
	u := openUsage(testLedger(t), testCeiling, day1)
	u.setPrices(map[string]Price{"m": {Input: 1e6}})
	var wg sync.WaitGroup
	var stop atomic.Bool
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				c, err := u.begin(testCeiling, "p", "m", day1)
				if err != nil {
					t.Error(err)
					return
				}
				u.finish(c, "p", "m", usageAttr{}, tokens{Prompt: 1}, day1)
			}
		}()
	}
	refused := 0
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := u.monthSpentErr("p", day1); err != nil {
			refused++
		}
	}
	stop.Store(true)
	wg.Wait()
	if refused > 0 {
		t.Fatalf("%d spend checks called the spend unknown while calls were only in flight", refused)
	}
}

// A call's charge is never lost: if its pending row is gone when the result arrives, the result
// is written as a row of its own.
func TestFinishKeepsTheChargeWhenThePendingRowIsGone(t *testing.T) {
	d, db := pgtestMigrated(t)
	u := openUsage(db, testCeiling, day1)
	u.setPrices(map[string]Price{"m": {Input: 1e6}})
	c, err := u.begin(testCeiling, "p", "m", day1)
	if err != nil {
		t.Fatal(err)
	}
	d.Super(t, `DELETE FROM broker.usage_calls`)
	u.finish(c, "p", "m", usageAttr{}, tokens{Prompt: 4}, day1)
	if got, err := u.monthSpentErr("p", day1); err != nil || got != 4 {
		t.Fatalf("spend %v %v, want the 4 charged", got, err)
	}
}

func pgtestMigrated(t *testing.T) (*pgtest.DB, *sql.DB) {
	t.Helper()
	return pgtest.Migrated(t, pgdb.Core, Schema)
}

// add records one finished call, begun and finished as the proxy does.
func (u *usageBook) add(principal, model string, t tokens, now time.Time) {
	u.addFor(principal, model, usageAttr{}, t, now)
}

func (u *usageBook) addFor(principal, model string, attr usageAttr, t tokens, now time.Time) {
	c, err := u.begin(u.label, principal, model, now)
	if err != nil {
		panic(err)
	}
	u.finish(c, principal, model, attr, t, now)
}

// A call still pending once the longest a call can run has passed lost its result: its spend is
// unknown, on this replica or any other, without a restart.
func TestPendingCallPastItsWindowIsUnknown(t *testing.T) {
	u := openUsage(testLedger(t), testCeiling, day1)
	if _, err := u.begin(testCeiling, "p", "m", day1); err != nil {
		t.Fatal(err)
	}
	if _, err := u.monthSpentErr("p", day1.Add(u.window-time.Second)); err != nil {
		t.Fatalf("a call still within its window made spend unknown: %v", err)
	}
	if _, err := u.monthSpentErr("p", day1.Add(u.window+time.Second)); err == nil {
		t.Fatal("a call pending past the longest a call can run left spend known")
	}
	other := openUsageOn(t, u.db, "another-pod")
	if _, err := other.monthSpentErr("p", day1.Add(time.Second)); err != nil {
		t.Fatalf("another replica took a call in flight for a lost one: %v", err)
	}
}

// A result that could not be written leaves that principal's spend unknown at once, not only
// after the call's window: if the database comes straight back, the next limited call is still
// refused, so an unrecorded charge cannot be spent again.
func TestFailedFinishMakesSpendUnknownAtOnce(t *testing.T) {
	d, db := pgtestMigrated(t)
	u := openUsage(db, testCeiling, day1)
	u.setPrices(map[string]Price{"m": {Input: 1e6}})
	c, err := u.begin(testCeiling, "p", "m", day1)
	if err != nil {
		t.Fatal(err)
	}
	d.Super(t, `REVOKE UPDATE, INSERT ON broker.usage_calls FROM `+pgtest.Service)
	u.finish(c, "p", "m", usageAttr{}, tokens{Prompt: 4}, day1)
	if _, err := u.monthSpentErr("p", day1.Add(time.Second)); err == nil {
		t.Fatal("spend still known right after a call's result could not be written")
	}
	if _, err := u.monthSpentErr("q", day1.Add(time.Second)); err != nil {
		t.Fatalf("another principal affected: %v", err)
	}
	d.Super(t, `GRANT UPDATE, INSERT ON broker.usage_calls TO `+pgtest.Service)
	// Once the database answers again the result is written, so another replica (or this broker
	// after a restart) counts the charge rather than taking the call for one in flight.
	u.retry()
	other := openUsage(db, testCeiling, day1)
	other.setPrices(map[string]Price{"m": {Input: 1e6}})
	if got, err := other.monthSpentErr("p", day1.Add(time.Second)); err != nil || got != 4 {
		t.Fatalf("another replica after recovery: spend %v %v, want the 4 charged", got, err)
	}
	if got, err := u.monthSpentErr("p", day1.Add(time.Second)); err != nil || got != 4 {
		t.Fatalf("this replica after recovery: spend %v %v, want 4", got, err)
	}
}

// Failed results are remembered per month: one from the month before, failing after one from
// this month, does not clear this month's.
func TestFailedFinishesAcrossAMonthBoundary(t *testing.T) {
	d, db := pgtestMigrated(t)
	u := openUsage(db, testCeiling, day1)
	oct := time.Date(2026, 10, 31, 23, 59, 0, 0, time.UTC)
	nov := oct.Add(2 * time.Minute)
	old, err := u.begin(testCeiling, "p", "m", oct)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := u.begin(testCeiling, "p", "m", nov)
	if err != nil {
		t.Fatal(err)
	}
	d.Super(t, `REVOKE UPDATE, INSERT ON broker.usage_calls FROM `+pgtest.Service)
	u.finish(cur, "p", "m", usageAttr{}, tokens{Prompt: 1}, nov)
	u.finish(old, "p", "m", usageAttr{}, tokens{Prompt: 1}, nov)
	if _, err := u.monthSpentErr("p", nov.Add(time.Second)); err == nil {
		t.Fatal("this month's failed result was forgotten when last month's failed after it")
	}
	d.Super(t, `GRANT UPDATE, INSERT ON broker.usage_calls TO `+pgtest.Service)
}

// A retry that runs while another is still writing does not clear the marker: until a result's
// write has committed, its principal's spend stays unknown.
func TestConcurrentRetriesKeepSpendUnknownUntilWritten(t *testing.T) {
	d, db := pgtestMigrated(t)
	u := openUsage(db, testCeiling, day1)
	c, err := u.begin(testCeiling, "p", "m", day1)
	if err != nil {
		t.Fatal(err)
	}
	d.Super(t, `REVOKE UPDATE, INSERT ON broker.usage_calls FROM `+pgtest.Service)
	u.finish(c, "p", "m", usageAttr{}, tokens{Prompt: 1}, day1)
	d.Super(t, `GRANT UPDATE, INSERT ON broker.usage_calls TO `+pgtest.Service)
	stillLost := false
	beforeRetryWrite = func() {
		beforeRetryWrite = nil
		go u.retry()
		time.Sleep(200 * time.Millisecond)
		u.mu.Lock()
		stillLost = u.lost["p"][day1.Format("2006-01")]
		u.mu.Unlock()
	}
	t.Cleanup(func() { beforeRetryWrite = nil })
	u.retry()
	if !stillLost {
		t.Fatal("a concurrent retry cleared the marker while the first was still writing")
	}
}

// openUsageOn opens a usage book as a process of pod would.
func openUsageOn(t *testing.T, db *sql.DB, pod string) *usageBook {
	t.Helper()
	old := podName
	podName = func() string { return pod }
	defer func() { podName = old }()
	return openUsage(db, testCeiling, day1)
}

// A broker that restarts (same pod, new process) releases at once the calls its previous run left
// pending: their results are lost, so their principals' spend is unknown straight away, not only
// after the call window. Another live replica's calls are never touched.
func TestRestartReleasesThisPodsStrandedCalls(t *testing.T) {
	d, db := pgtestMigrated(t)
	first := openUsageOn(t, db, "pod-a")
	if _, err := first.begin(testCeiling, "p", "m", day1); err != nil { // the process dies mid-call
		t.Fatal(err)
	}
	other := openUsageOn(t, db, "pod-b")
	if _, err := other.begin(testCeiling, "q", "m", day1); err != nil { // a live replica's call in flight
		t.Fatal(err)
	}
	restarted := openUsageOn(t, db, "pod-a")
	if _, err := restarted.monthSpentErr("p", day1.Add(time.Second)); err == nil {
		t.Fatal("a call stranded by this pod's previous run left spend known after the restart")
	}
	if got := d.SuperQuery(t, `SELECT pending::text FROM broker.usage_calls WHERE principal = 'q'`); got != "true" {
		t.Fatalf("a live replica's call was touched: pending=%s", got)
	}
	if _, err := restarted.monthSpentErr("q", day1.Add(time.Second)); err != nil {
		t.Fatalf("a live replica's call in flight made spend unknown: %v", err)
	}
}

// Without a pod name (POD_NAME unset: a laptop, two processes on one host) no process releases
// another's calls: there is no way to tell its own previous run from a live neighbour.
func TestNoReclaimWithoutAPodName(t *testing.T) {
	d, db := pgtestMigrated(t)
	first := openUsageOn(t, db, "")
	if _, err := first.begin(testCeiling, "p", "m", day1); err != nil {
		t.Fatal(err)
	}
	openUsageOn(t, db, "")
	if got := d.SuperQuery(t, `SELECT pending::text FROM broker.usage_calls WHERE principal = 'p'`); got != "true" {
		t.Fatalf("a nameless process released another's call: pending=%s", got)
	}
}

// A result that arrives after its call was released (the process was thought dead) is
// reconciled onto the same row: counted once, with its real usage, not lost and not doubled.
func TestLateResultOnAReleasedCallIsReconciled(t *testing.T) {
	d, db := pgtestMigrated(t)
	first := openUsageOn(t, db, "pod-a")
	first.setPrices(map[string]Price{"m": {Input: 1e6}})
	c, err := first.begin(testCeiling, "p", "m", day1)
	if err != nil {
		t.Fatal(err)
	}
	openUsageOn(t, db, "pod-a") // a new start of pod-a releases the call
	first.finish(c, "p", "m", usageAttr{}, tokens{Prompt: 3}, day1)
	if got := d.SuperQuery(t, `SELECT count(*)::text || ' ' || bool_or(unknown)::text || ' ' || sum(charged_usd)::text FROM broker.usage_calls`); got != "1 false 3" {
		t.Fatalf("rows/unknown/charged after a late result: %s, want one row, known, charged 3", got)
	}
}
