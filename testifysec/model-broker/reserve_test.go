package broker

import (
	"errors"
	"testing"
	"time"
)

// plantPending writes a call another pod began and has not finished, with its reservation
// (reserved < 0: none recorded).
func plantPending(t *testing.T, f *fixture, principal string, reserved float64) {
	t.Helper()
	res := any(reserved)
	if reserved < 0 {
		res = nil
	}
	f.pg.Super(t, `INSERT INTO broker.usage_calls (id, day, t, principal, model, pending, label, pod, boot, reserved_usd)
		VALUES ('other-'||md5(random()::text), current_date, now(), $1, 'model-a', true, badger.label_of($2::jsonb), 'pod-other', 'b', $3)`,
		principal, f.cfg.Ceiling().Lattice(), res)
}

// A call in flight elsewhere counts at its reservation, its worst case: near the limit it refuses
// the next call, because both together could pass the limit; far from it the calls run side by
// side.
func TestCallsInFlightElsewhereCountAtTheirReservation(t *testing.T) {
	for name, c := range map[string]struct {
		limit    string
		reserved float64
		want     int
	}{
		"near the limit":     {`0.0010`, 0.0008, 429}, // $0.0005 spent + $0.0008 reserved > $0.0010
		"far from the limit": {`1`, 0.0008, 200},      // well under
		"no reservation":     {`1`, -1, 429},          // unbounded worst case: fail closed
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, true)
			priced(f)
			if code := putQuotas(f, `"0"`, `{"default_usd":null,"principals":{"ci:group/alpha":`+c.limit+`}}`); code != 200 {
				t.Fatal(code)
			}
			if code, _ := pipelineCall(f); code != 200 { // $0.0005 committed
				t.Fatal(code)
			}
			plantPending(t, f, "ci:group/alpha", c.reserved)
			if code, _ := pipelineCall(f); code != c.want {
				t.Fatalf("with a call in flight on another pod: %d, want %d", code, c.want)
			}
		})
	}
}

// After a database blip, a replica whose result write failed has a pending row it has not yet
// retried; another replica checking spend meanwhile counts that row at its reservation, so it
// cannot admit a call past the limit.
func TestBlipCannotAdmitACallPastTheLimit(t *testing.T) {
	f := newFixture(t, true)
	priced(f)
	f.b.up.usage.setReserve(map[string]float64{"model-a": 0.0005})
	if code := putQuotas(f, `"0"`, `{"default_usd":null,"principals":{"ci:group/alpha":0.0010}}`); code != 200 {
		t.Fatal(code)
	}
	if code, _ := pipelineCall(f); code != 200 { // $0.0005 committed
		t.Fatal(code)
	}
	// Pod A begins a call and its result write fails: the row stays pending, reserved $0.0005.
	a := openUsageOn(t, f.db, "pod-a")
	a.setReserve(map[string]float64{"model-a": 0.0005})
	call, err := a.begin(f.cfg.Ceiling(), "ci:group/alpha", "model-a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_ = call // never finished here: the write failed and the retry has not run yet
	// $0.0005 committed + $0.0005 reserved reaches $0.0010: without the reservation the unrecorded
	// charge would let this call through as well, two calls past the limit instead of at most one.
	if code, _ := pipelineCall(f); code != 429 {
		t.Fatalf("another replica admitted a call during the retry gap: %d", code)
	}
}

// Two replicas admitting the same principal's calls at once cannot both pass on the same balance:
// the spend check and the reservation it admits are one step per principal across replicas. Pod
// A stops between its check and its reservation; pod B's admission, started then, must wait for
// A and then see A's reservation. Without the lock B checks the old balance and both run.
func TestSimultaneousAdmissionAdmitsOne(t *testing.T) {
	_, db := pgtestMigrated(t)
	a, b := openUsageOn(t, db, "pod-a"), openUsageOn(t, db, "pod-b")
	for _, u := range []*usageBook{a, b} {
		u.setReserve(map[string]float64{"m": 0.0010})
	}
	limit := 0.0010
	var bErr error
	bDone := make(chan struct{})
	waiting := func() bool {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted
			AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&n); err != nil {
			t.Error(err)
			return true
		}
		return n > 0
	}
	beforeAdmitInsert = func() {
		beforeAdmitInsert = nil // B's own admission runs straight through
		go func() {
			defer close(bDone)
			_, bErr = b.admit(testCeiling, "p", "m", day1, &admission{monthly: &limit})
		}()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case <-bDone:
				return // B did not wait: it checked the balance A is about to reserve against
			case <-deadline:
				t.Error("B neither finished nor waited for A")
				return
			case <-time.After(10 * time.Millisecond):
				if waiting() {
					return
				}
			}
		}
	}
	t.Cleanup(func() { beforeAdmitInsert = nil })
	if _, err := a.admit(testCeiling, "p", "m", day1, &admission{monthly: &limit}); err != nil {
		t.Fatalf("first admission: %v", err)
	}
	<-bDone
	if !errors.Is(bErr, errOverQuota) {
		t.Fatalf("second admission on the same balance: %v, want errOverQuota", bErr)
	}
}
