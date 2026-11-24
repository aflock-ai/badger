package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
)

// usageCount is what one principal used of one model on one day.
type usageCount struct {
	Requests           int64 `json:"requests"`
	PromptTokens       int64 `json:"prompt_tokens"`
	CachedPromptTokens int64 `json:"cached_prompt_tokens"` // part of PromptTokens served from the prompt cache
	CompletionTokens   int64 `json:"completion_tokens"`
	// CostUSD is set in reports when the model's route has a price; absent means unpriced, not free.
	CostUSD *float64 `json:"cost_usd,omitempty"`
	charged float64  // sum of what each call was charged when it ran
}

// tokens is the usage one model reply reports. Cached is the part of Prompt the provider served
// from its prompt cache, billed at a lower rate.
type tokens struct {
	Prompt, Cached, Completion int64
	// Unknown is a successful reply that reported no usage: the call cost something nobody counted.
	Unknown bool
}

// usageRecord is one counted call in the JSON ledger files the import reads.
type usageRecord struct {
	Time       time.Time `json:"t"`
	Principal  string    `json:"principal"`
	Model      string    `json:"model"`
	Prompt     int64     `json:"prompt_tokens"`
	Cached     int64     `json:"cached_prompt_tokens,omitempty"`
	Completion int64     `json:"completion_tokens"`
	// For a pipeline: the person who owns its policy entry, and the GitLab user who started the run.
	Owner       string `json:"owner,omitempty"`
	TriggeredBy string `json:"triggered_by,omitempty"`
	// UsageUnknown marks a successful call whose reply carried no usage.
	UsageUnknown bool `json:"usage_unknown,omitempty"`
	// ChargedUSD is what the call cost at the price in force when it ran; replay sums these, so a
	// later price change never rewrites past spend.
	ChargedUSD *float64 `json:"charged_usd,omitempty"`
	// ID links a call's result to the Pending record written before it went to the model. A pending
	// record with no result means the call's usage is unknown.
	ID      string `json:"id,omitempty"`
	Pending bool   `json:"pending,omitempty"`
}

// pendingCall is a call written to the ledger before it went to the model, and the session label
// its caller runs at, which finishing it uses too.
type pendingCall struct {
	id, day string
	label   pgdb.Label
}

// usageAttr is who a pipeline call answers to; empty for people.
type usageAttr struct {
	Owner, TriggeredBy string
}

// maxHistoryDays bounds one history read.
const maxHistoryDays = 92

// usageBook is the usage ledger in broker.usage_calls: one row per model call, written pending
// before the call goes to the model and finished after it. Spend is summed from the rows, so
// concurrent calls never lose an increment, and a call whose result was never written counts as
// unknown spend. Every read and write goes to the database: if it cannot be reached, a limited
// principal's call is refused rather than let through uncounted.
type usageBook struct {
	db     *sql.DB
	label  pgdb.Label
	opened time.Time // when counting first began, kept in broker.meta
	mu     sync.Mutex
	prices map[string]Price // model -> price, from the routes
	// reserve is the most one call of a model can cost (route max_call_usd); a call in flight is
	// counted at it against a quota, and at no bound when the model has none.
	reserve map[string]float64
	// window is the longest a call can run (the listeners' write deadline, plus a margin). A row
	// still pending after it lost its result, on whichever replica began it; a younger one is a
	// call in flight. Deciding by age, not by a list of this process's calls, means a spend check
	// racing a concurrent begin or finish cannot take a live call for a lost one.
	window time.Duration
	// failed holds results that could not be written yet; lost names, per principal and month,
	// those still unwritten: that principal's spend is unknown at once, without waiting for the
	// window.
	failed  []result
	lost    map[string]map[string]bool
	retryMu sync.Mutex // one retry at a time
	// pod and boot name the process: its pod and a random id per start (see openUsage).
	pod, boot string
	// err is set when the ledger could not be opened: every limited call is refused.
	err error
}

// openUsage opens the ledger, recording now as when counting began if it never did.
func openUsage(db *sql.DB, label pgdb.Label, now time.Time) *usageBook {
	boot := make([]byte, 16)
	rand.Read(boot)
	u := &usageBook{db: db, label: label, opened: now.UTC().Truncate(time.Second), prices: map[string]Price{},
		window: callWindow(defaultUpstream), pod: podName(), boot: hex.EncodeToString(boot)}
	err := u.tx(func(tx *sql.Tx) error {
		// Calls this pod's previous run began and never finished lost their results with it:
		// they are released now, as unknown spend, rather than taken for calls in flight until
		// their window passes. Other pods' calls are not touched; a pod deleted mid-call is
		// bounded by the window.
		// Only with a pod name: without one, this process cannot tell its own previous run from
		// another live process on the same host.
		rows, err := tx.Query(`UPDATE broker.usage_calls SET pending = false, unknown = true, released = true
			WHERE pending AND $1 <> '' AND pod = $1 AND boot <> $2 RETURNING id, principal`, u.pod, u.boot)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, p string
			if err := rows.Scan(&id, &p); err != nil {
				rows.Close()
				return err
			}
			log.Printf("usage ledger: call %s of %s was left pending by this pod's previous run; released, its spend unknown", id, auditSafe(p))
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if _, err := tx.Exec(`INSERT INTO broker.meta (key, value) VALUES ('usage_opened', $1) ON CONFLICT (key) DO NOTHING`,
			u.opened.Format(time.RFC3339)); err != nil {
			return err
		}
		var v string
		if err := tx.QueryRow(`SELECT value FROM broker.meta WHERE key = 'usage_opened'`).Scan(&v); err != nil {
			return err
		}
		t, err := time.Parse(time.RFC3339, v)
		u.opened = t.UTC()
		return err
	})
	if err != nil {
		log.Printf("usage ledger unavailable (%v); limited calls are refused", err)
		u.err = fmt.Errorf("usage ledger unavailable: %w", err)
	}
	return u
}

// podName is the pod this process runs in (POD_NAME, set from the downward API); empty outside one,
// and then no call is ever released at start.
var podName = func() string { return os.Getenv("POD_NAME") }

// callWindow is the longest a call can be pending: the listeners cut every response at the write
// deadline, and a minute covers writing its result.
func callWindow(c UpstreamConfig) time.Duration {
	return time.Duration(c.ServerWriteSeconds)*time.Second + time.Minute
}

func (u *usageBook) tx(fn func(*sql.Tx) error) error { return u.txAt(u.label, fn) }

// txAt runs fn in one transaction at session label l: a caller's own label for its calls.
func (u *usageBook) txAt(l pgdb.Label, fn func(*sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	return pgdb.Tx(ctx, u.db, l, func(tx *sql.Tx) error {
		if err := sharedWriteLock(ctx, tx); err != nil {
			return err
		}
		return fn(tx)
	})
}

// setReserve installs the routes' per-call maximums.
func (u *usageBook) setReserve(r map[string]float64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reserve = r
}

// setPrices installs the routes' prices.
func (u *usageBook) setPrices(p map[string]Price) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.prices = p
}

// rawCost is what a count cost at its model's price, unrounded so that many tiny calls still add
// up; an unpriced model costs nothing here.
func (u *usageBook) rawCost(model string, c usageCount) float64 {
	p, ok := u.prices[model]
	if !ok {
		return 0
	}
	uncached := c.PromptTokens - c.CachedPromptTokens
	return (float64(uncached)*p.Input + float64(c.CachedPromptTokens)*p.CachedInput + float64(c.CompletionTokens)*p.Output) / 1e6
}

func monthRange(now time.Time) (string, string) {
	t := now.UTC()
	first := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	return first.Format("2006-01-02"), first.AddDate(0, 1, 0).Format("2006-01-02")
}

// spend sums charged spend per principal over [from, to), pricing calls recorded without a
// charge (imported from before charges were kept) at today's prices. With principal set, only
// that principal; unknown names principals with a call of unknown usage, or one pending longer
// than a call can run at now.
func (u *usageBook) spend(l pgdb.Label, from, to, principal string, now time.Time) (map[string]float64, map[string]bool, error) {
	out, _, unknown, err := u.spendAndInFlight(l, from, to, principal, now)
	return out, unknown, err
}

// spendAndInFlight is spend, and per principal the worst case of the calls still in flight (each
// at its reservation; +Inf for one with none).
func (u *usageBook) spendAndInFlight(l pgdb.Label, from, to, principal string, now time.Time) (map[string]float64, map[string]float64, map[string]bool, error) {
	var out, inflight map[string]float64
	var unknown map[string]bool
	err := u.txAt(l, func(tx *sql.Tx) error {
		var err error
		out, inflight, unknown, err = u.spendIn(tx, from, to, principal, now)
		return err
	})
	return out, inflight, unknown, err
}

// spendIn is spendAndInFlight read inside tx.
func (u *usageBook) spendIn(tx *sql.Tx, from, to, principal string, now time.Time) (map[string]float64, map[string]float64, map[string]bool, error) {
	out, inflight, unknown := map[string]float64{}, map[string]float64{}, map[string]bool{}
	lost := now.UTC().Add(-u.window)
	rows, err := tx.Query(`SELECT principal, model, pending, t, unknown, prompt, cached, completion, charged_usd, reserved_usd
		FROM broker.usage_calls WHERE day >= $1 AND day < $2 AND ($3 = '' OR principal = $3)`, from, to, principal)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p, model string
		var pending, unk bool
		var began time.Time
		var c usageCount
		var charged, reserved sql.NullFloat64
		if err := rows.Scan(&p, &model, &pending, &began, &unk, &c.PromptTokens, &c.CachedPromptTokens, &c.CompletionTokens, &charged, &reserved); err != nil {
			return nil, nil, nil, err
		}
		switch {
		case pending:
			if !began.After(lost) {
				unknown[p] = true
			} else if reserved.Valid {
				inflight[p] += reserved.Float64
			} else {
				inflight[p] = math.Inf(1)
			}
		case charged.Valid:
			out[p] += charged.Float64
		default:
			out[p] += u.rawCost(model, c)
		}
		if unk {
			unknown[p] = true
		}
	}
	return out, inflight, unknown, rows.Err()
}

// monthSpent is the principal's spend this UTC month, at the routes' prices.
func (u *usageBook) monthSpent(principal string, now time.Time) float64 {
	v, _ := u.monthSpentErr(principal, now)
	return v
}

// monthSpentErr is monthSpent, or an error when the ledger cannot be read or a call this month
// has unknown usage, so the spend is not known.
func (u *usageBook) monthSpentErr(principal string, now time.Time) (float64, error) {
	return u.monthSpentAt(u.label, principal, now)
}

// monthSpentAt is monthSpentErr read at session label l, the caller's own.
func (u *usageBook) monthSpentAt(l pgdb.Label, principal string, now time.Time) (float64, error) {
	spent, _, err := u.monthSpendAndInFlight(l, principal, now)
	return spent, err
}

// monthSpendAndInFlight is monthSpentAt, and the worst case of the principal's calls in flight
// (their reservations; +Inf if one has none). A quota check counts both.
func (u *usageBook) monthSpendAndInFlight(l pgdb.Label, principal string, now time.Time) (float64, float64, error) {
	from, to := monthRange(now)
	return u.periodSpendAndInFlight(l, principal, from, to, now)
}

// periodSpendAndInFlight is monthSpendAndInFlight over the days [from, to) of now's month.
func (u *usageBook) periodSpendAndInFlight(l pgdb.Label, principal, from, to string, now time.Time) (float64, float64, error) {
	if u.err != nil {
		return 0, 0, u.err
	}
	u.mu.Lock()
	pendingWrites := len(u.failed) > 0
	u.mu.Unlock()
	if pendingWrites {
		u.retry()
	}
	u.mu.Lock()
	lost := u.lost[principal][now.UTC().Format("2006-01")]
	u.mu.Unlock()
	if lost {
		return 0, 0, errors.New("a call's result could not be written this month, so this principal's spend is unknown")
	}
	spent, inflight, unknown, err := u.spendAndInFlight(l, from, to, principal, now)
	if err != nil {
		return 0, 0, fmt.Errorf("usage ledger unreadable: %w", err)
	}
	if unknown[principal] {
		return 0, 0, errors.New("a call this month returned no usage, so this principal's spend is unknown")
	}
	return math.Round(spent[principal]*1e6) / 1e6, inflight[principal], nil
}

// monthSpentAll is every principal's spend this UTC month.
func (u *usageBook) monthSpentAll(now time.Time) (map[string]float64, error) {
	from, to := monthRange(now)
	return u.spentAll(from, to, now)
}

// spentAll is every principal's spend over the days [from, to).
func (u *usageBook) spentAll(from, to string, now time.Time) (map[string]float64, error) {
	spent, _, err := u.spend(u.label, from, to, "", now)
	if err != nil {
		return nil, err
	}
	for p, v := range spent {
		spent[p] = math.Round(v*1e6) / 1e6
	}
	return spent, nil
}

// priced is a copy of c with its cost: what its calls were charged when they ran, so a later price
// change never rewrites a past report. Set when the model has a price or its calls were charged.
func (u *usageBook) priced(model string, c usageCount) usageCount {
	if _, ok := u.prices[model]; ok || c.charged != 0 {
		usd := math.Round(c.charged*1e6) / 1e6
		c.CostUSD = &usd
	}
	return c
}

// begin writes a pending record before a call goes to the model, so a result that is never written
// shows up as unknown usage rather than as nothing. If it cannot be written the call must not go
// ahead. The call is accounted at l, its caller's session label.
func (u *usageBook) begin(l pgdb.Label, principal, model string, now time.Time) (pendingCall, error) {
	return u.admit(l, principal, model, now, nil)
}

var (
	// errOverQuota: the principal's spend, with its calls in flight, reaches its limit.
	errOverQuota = errors.New("quota reached")
	// errSpendUnknown: a call this month has unknown usage, so the spend cannot be checked.
	errSpendUnknown = errors.New("this principal's spend is unknown")
)

// admitLockClass keys the per-principal advisory lock admit takes (two-key form, so it never
// meets the single-key locks the stores take).
const admitLockClass = int32(0x62726b72) // "brkr"

// admit is begin for a principal with a quota (limit set): the spend check and the pending record
// it admits are one transaction, under a lock per principal that every replica takes, so two calls
// admitted at once on different replicas are never checked against the same balance. Refused
// (errOverQuota) when committed spend and every call in flight, each at its reservation, reach
// the limit; errSpendUnknown when a call this month has unknown usage.
func (u *usageBook) admit(l pgdb.Label, principal, model string, now time.Time, a *admission) (pendingCall, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return pendingCall{}, err
	}
	c := pendingCall{id: hex.EncodeToString(raw), day: now.UTC().Format("2006-01-02"), label: l}
	if err := u.txAt(l, func(tx *sql.Tx) error {
		if a != nil && (a.monthly != nil || a.daily != nil) {
			if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1, hashtext($2))`, admitLockClass, principal); err != nil {
				return err
			}
			monthFrom, monthTo := monthRange(now)
			for _, p := range []struct {
				from, to string
				limit    *float64
			}{{monthFrom, monthTo, a.monthly}, {c.day, now.UTC().AddDate(0, 0, 1).Format("2006-01-02"), a.daily}} {
				if p.limit == nil {
					continue
				}
				spent, inflight, unknown, err := u.spendIn(tx, p.from, p.to, principal, now)
				if err != nil {
					return err
				}
				if unknown[principal] {
					return errSpendUnknown
				}
				if math.Round(spent[principal]*1e6)/1e6+inflight[principal] >= *p.limit {
					return errOverQuota
				}
			}
			if beforeAdmitInsert != nil {
				beforeAdmitInsert()
			}
		}
		// The principal's per-call cap, else the route's max_call_usd, is what the call counts at while it runs.
		var reserved any
		if r, ok := u.reserve[model]; ok {
			reserved = r
		}
		if a != nil && a.call != nil {
			reserved = *a.call
		}
		_, err := tx.Exec(`INSERT INTO broker.usage_calls (id, day, t, principal, model, pending, pod, boot, reserved_usd)
			VALUES ($1, $2, $3, $4, $5, true, $6, $7, $8)`, c.id, c.day, now.UTC(), principal, model, u.pod, u.boot, reserved)
		return err
	}); err != nil {
		if !errors.Is(err, errOverQuota) && !errors.Is(err, errSpendUnknown) {
			log.Printf("usage ledger write failed: %v; call refused", err)
		}
		return pendingCall{}, err
	}
	return c, nil
}

// beforeAdmitInsert, when set (tests only), runs in admit between the spend check and the insert.
var beforeAdmitInsert func()

// result is a call's outcome waiting to be written.
type result struct {
	c                pendingCall
	principal, model string
	attr             usageAttr
	t                tokens
	now              time.Time
	usd              float64
}

// finish records a call's usage and what it was charged on the pending record begin wrote; a call
// that was never begun has no record to finish. If the pending record is gone (removed outside
// the service), the result is written as a finished record of its own, so the charge still
// counts. If the write fails, that principal's spend is unknown at once in this process and the
// result is kept and written again (retry) as soon as the database answers, so the charge
// reaches every replica; until then the record stays pending, which any process counts as
// unknown once the call's window passes. A cap is never lifted by a lost write.
func (u *usageBook) finish(c pendingCall, principal, model string, attr usageAttr, t tokens, now time.Time) {
	u.mu.Lock()
	usd := u.rawCost(model, usageCount{PromptTokens: t.Prompt, CachedPromptTokens: t.Cached, CompletionTokens: t.Completion})
	u.mu.Unlock()
	if c.id == "" {
		log.Printf("usage ledger: a result arrived for a call that was never begun; not recorded")
		return
	}
	r := result{c: c, principal: principal, model: model, attr: attr, t: t, now: now, usd: usd}
	if err := u.write(r); err != nil {
		u.mu.Lock()
		u.failed = append(u.failed, r)
		u.markLost()
		u.mu.Unlock()
		log.Printf("usage ledger write failed: %v; the call's spend is unknown until it is written", err)
	}
}

// write puts one result on its pending record (or a record of its own if that is gone).
func (u *usageBook) write(r result) error {
	c, t, attr := r.c, r.t, r.attr
	return u.txAt(c.label, func(tx *sql.Tx) error {
		// A call released by a restart that thought this process dead still takes its result.
		res, err := tx.Exec(`UPDATE broker.usage_calls SET pending = false, released = false, prompt = $2, cached = $3, completion = $4,
			owner = $5, triggered_by = $6, unknown = $7, charged_usd = $8 WHERE id = $1 AND (pending OR released)`,
			c.id, t.Prompt, t.Cached, t.Completion, attr.Owner, attr.TriggeredBy, t.Unknown, r.usd)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 1 {
			return err
		}
		_, err = tx.Exec(`INSERT INTO broker.usage_calls (id, day, t, principal, model, pending, prompt, cached, completion,
			owner, triggered_by, unknown, charged_usd) VALUES ($1, $2, $3, $4, $5, false, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (id) DO NOTHING`,
			c.id, c.day, r.now.UTC(), r.principal, r.model, t.Prompt, t.Cached, t.Completion, attr.Owner, attr.TriggeredBy, t.Unknown, r.usd)
		return err
	})
}

// markLost rebuilds the per-principal, per-month markers from the results still unwritten.
// Caller holds u.mu.
func (u *usageBook) markLost() {
	u.lost = map[string]map[string]bool{}
	for _, r := range u.failed {
		if u.lost[r.principal] == nil {
			u.lost[r.principal] = map[string]bool{}
		}
		u.lost[r.principal][r.c.day[:7]] = true
	}
}

// retry writes the results that failed, in order. One retry runs at a time, and a result leaves
// the queue (and its principal's marker) only once its write has committed. It runs before every
// spend check and from a ticker (retryEvery), so a recovered database gets the charges at once
// and other replicas see them.
func (u *usageBook) retry() {
	u.retryMu.Lock()
	defer u.retryMu.Unlock()
	u.mu.Lock()
	queued := append([]result(nil), u.failed...)
	u.mu.Unlock()
	written := map[string]bool{}
	for _, r := range queued {
		if beforeRetryWrite != nil {
			beforeRetryWrite()
		}
		if u.write(r) == nil {
			written[r.c.id] = true
		}
	}
	u.mu.Lock()
	var still []result
	for _, r := range u.failed {
		if !written[r.c.id] {
			still = append(still, r)
		}
	}
	u.failed = still
	u.markLost()
	u.mu.Unlock()
}

// beforeRetryWrite, when set (tests only), runs before each write retry makes.
var beforeRetryWrite func()

// retryEvery runs retry on a ticker, for the life of the process.
func (u *usageBook) retryEvery(d time.Duration) {
	go func() {
		for range time.Tick(d) {
			u.mu.Lock()
			n := len(u.failed)
			u.mu.Unlock()
			if n > 0 {
				u.retry()
			}
		}
	}()
}

// counts is each principal's finished calls per model on day (with principal set, only theirs).
func (u *usageBook) counts(tx *sql.Tx, from, to, principal string) (map[string]map[string]map[string]usageCount, error) {
	rows, err := tx.Query(`SELECT day::text, principal, model, count(*), sum(prompt), sum(cached), sum(completion),
			coalesce(sum(charged_usd), 0), coalesce(sum(prompt) FILTER (WHERE charged_usd IS NULL), 0),
			coalesce(sum(cached) FILTER (WHERE charged_usd IS NULL), 0), coalesce(sum(completion) FILTER (WHERE charged_usd IS NULL), 0)
		FROM broker.usage_calls WHERE day >= $1 AND day <= $2 AND NOT pending AND ($3 = '' OR principal = $3)
		GROUP BY day, principal, model`, from, to, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]map[string]usageCount{}
	for rows.Next() {
		var day, p, model string
		var c, legacy usageCount
		if err := rows.Scan(&day, &p, &model, &c.Requests, &c.PromptTokens, &c.CachedPromptTokens, &c.CompletionTokens,
			&c.charged, &legacy.PromptTokens, &legacy.CachedPromptTokens, &legacy.CompletionTokens); err != nil {
			return nil, err
		}
		c.charged += u.rawCost(model, legacy)
		if out[day] == nil {
			out[day] = map[string]map[string]usageCount{}
		}
		if out[day][p] == nil {
			out[day][p] = map[string]usageCount{}
		}
		out[day][p][model] = u.priced(model, c)
	}
	return out, rows.Err()
}

func (u *usageBook) today(now time.Time) (string, time.Time) {
	day := now.UTC().Format("2006-01-02")
	since, _ := time.Parse("2006-01-02", day)
	if u.opened.After(since) {
		since = u.opened
	}
	return day, since
}

// report is the principal's counts today, read at the caller's session label.
func (u *usageBook) report(label pgdb.Label, principal string, now time.Time) ([]byte, error) {
	day, since := u.today(now)
	models := map[string]usageCount{}
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	if err := pgdb.Tx(ctx, u.db, label, func(tx *sql.Tx) error {
		c, err := u.counts(tx, day, day, principal)
		if err == nil && c[day] != nil && c[day][principal] != nil {
			models = c[day][principal]
		}
		return err
	}); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"principal": principal, "day": day, "since": since.Format(time.RFC3339), "models": models})
}

// usageOf reads the usage object from a chat completion response or one SSE data payload. present
// is false when there is no usage (or it is null, as on a stream's other chunks). valid is false
// when usage is there but is not two non-negative counts with cached tokens within the prompt.
func usageOf(data []byte) (used tokens, present, valid bool) {
	var f struct {
		Usage json.RawMessage `json:"usage"`
	}
	if json.Unmarshal(data, &f) != nil || len(f.Usage) == 0 || string(f.Usage) == "null" {
		return tokens{}, false, false
	}
	var u struct {
		Prompt     *int64 `json:"prompt_tokens"`
		Completion *int64 `json:"completion_tokens"`
		Details    *struct {
			Cached *int64 `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	}
	if json.Unmarshal(f.Usage, &u) != nil || u.Prompt == nil || u.Completion == nil || *u.Prompt < 0 || *u.Completion < 0 {
		return tokens{}, true, false
	}
	used = tokens{Prompt: *u.Prompt, Completion: *u.Completion}
	if u.Details != nil && u.Details.Cached != nil {
		if *u.Details.Cached < 0 || *u.Details.Cached > *u.Prompt {
			return tokens{}, true, false
		}
		used.Cached = *u.Details.Cached
	}
	return used, true, true
}

// usageTee passes an SSE stream through unchanged and remembers the last usage it saw. Once the
// client stops accepting writes it keeps reading, so the usage at the end of the stream is still
// counted for a call the client abandoned.
type usageTee struct {
	w       io.Writer
	line    []byte
	used    tokens
	found   bool
	invalid bool
	werr    error
	// done is the stream's [DONE]; stale is output after the last usage chunk; errored is an error
	// event. Usage is known only from a final usage chunk of a stream that finished cleanly.
	done, stale, errored bool
}

// complete is whether the stream's usage is the call's whole usage.
func (t *usageTee) complete() bool {
	return t.found && t.done && !t.invalid && !t.stale && !t.errored
}

func (t *usageTee) Write(p []byte) (int, error) {
	for _, b := range p {
		if b != '\n' {
			if len(t.line) < 1<<20 {
				t.line = append(t.line, b)
			}
			continue
		}
		line := bytes.TrimSpace(t.line)
		if bytes.Equal(line, []byte("event: error")) || bytes.Equal(line, []byte("event:error")) {
			t.errored = true
		}
		if data, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			data = bytes.TrimSpace(data)
			switch used, present, valid := usageOf(data); {
			case bytes.Equal(data, []byte("[DONE]")):
				t.done = true
			case valid:
				t.used, t.found, t.stale = used, true, false
			case present:
				t.invalid = true
			default:
				// Output after a usage chunk means that usage was a running total, not the last word.
				t.stale = t.found
				var e struct {
					Error json.RawMessage `json:"error"`
				}
				if json.Unmarshal(data, &e) == nil && len(e.Error) > 0 && string(e.Error) != "null" {
					t.errored = true
				}
			}
		}
		t.line = t.line[:0]
	}
	if t.werr == nil {
		_, t.werr = t.w.Write(p)
	}
	return len(p), nil
}

// reportAll is every principal's counts today, for the admin usage page.
func (u *usageBook) reportAll(now time.Time) ([]byte, error) {
	day, since := u.today(now)
	all := map[string]map[string]usageCount{}
	if err := u.tx(func(tx *sql.Tx) error {
		c, err := u.counts(tx, day, day, "")
		if err == nil && c[day] != nil {
			all = c[day]
		}
		return err
	}); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"day": day, "since": since.Format(time.RFC3339), "principals": all})
}

// history is every principal's counts for each day from..to (inclusive, UTC dates), leaving out
// days with no use.
func (u *usageBook) history(from, to string) (map[string]map[string]map[string]usageCount, error) {
	if err := checkRange(from, to); err != nil {
		return nil, err
	}
	var out map[string]map[string]map[string]usageCount
	err := u.tx(func(tx *sql.Tx) error {
		var err error
		out, err = u.counts(tx, from, to, "")
		return err
	})
	return out, err
}

// checkRange refuses a history range that is not two dates, in order, at most maxHistoryDays apart.
func checkRange(from, to string) error {
	first, err1 := time.Parse("2006-01-02", from)
	last, err2 := time.Parse("2006-01-02", to)
	if err1 != nil || err2 != nil {
		return errors.New("from and to must be dates (YYYY-MM-DD)")
	}
	if last.Before(first) || last.Sub(first) >= maxHistoryDays*24*time.Hour {
		return errors.New("to must be on or after from, at most 92 days")
	}
	return nil
}

// usageFilter narrows a usage read to one kind of principal ("person" or "pipeline") and one model;
// empty fields keep everything.
type usageFilter struct{ kind, model string }

func parseUsageFilter(kind, model string) (usageFilter, error) {
	if kind != "" && kind != "person" && kind != "pipeline" {
		return usageFilter{}, errors.New(`kind must be "person" or "pipeline"`)
	}
	return usageFilter{kind: kind, model: model}, nil
}

func principalKind(principal string) string {
	if strings.HasPrefix(principal, "ci:") {
		return "pipeline"
	}
	return "person"
}

func (f usageFilter) keep(principal, model string) bool {
	return (f.kind == "" || principalKind(principal) == f.kind) && (f.model == "" || model == f.model)
}

// apply drops from a history day map what the filter does not keep, and days left empty.
func (f usageFilter) apply(days map[string]map[string]map[string]usageCount) {
	for day, ps := range days {
		for p, ms := range ps {
			for m := range ms {
				if !f.keep(p, m) {
					delete(ms, m)
				}
			}
			if len(ms) == 0 {
				delete(ps, p)
			}
		}
		if len(ps) == 0 {
			delete(days, day)
		}
	}
}

// principalUsage is one row of the console's Usage tab: one principal's finished calls of one
// model in a range, split by the pipeline's owner and the user who started it (both empty for a
// person), with the last call's time.
type principalUsage struct {
	Principal   string    `json:"principal"`
	Kind        string    `json:"kind"`
	Model       string    `json:"model"`
	Owner       string    `json:"owner"`
	TriggeredBy string    `json:"triggered_by"`
	LastUsed    time.Time `json:"last_used"`
	usageCount
}

// byPrincipal is every principal's finished calls from..to (inclusive UTC dates; checkRange first)
// grouped by model, owner and triggered_by, that the filter keeps.
func (u *usageBook) byPrincipal(from, to string, f usageFilter) ([]principalUsage, error) {
	out := []principalUsage{}
	err := u.tx(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT principal, model, owner, triggered_by, max(t), count(*), sum(prompt), sum(cached), sum(completion),
				coalesce(sum(charged_usd), 0), coalesce(sum(prompt) FILTER (WHERE charged_usd IS NULL), 0),
				coalesce(sum(cached) FILTER (WHERE charged_usd IS NULL), 0), coalesce(sum(completion) FILTER (WHERE charged_usd IS NULL), 0)
			FROM broker.usage_calls WHERE day >= $1 AND day <= $2 AND NOT pending
			GROUP BY principal, model, owner, triggered_by ORDER BY principal, model, owner, triggered_by`, from, to)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r principalUsage
			var c, legacy usageCount
			if err := rows.Scan(&r.Principal, &r.Model, &r.Owner, &r.TriggeredBy, &r.LastUsed, &c.Requests, &c.PromptTokens, &c.CachedPromptTokens,
				&c.CompletionTokens, &c.charged, &legacy.PromptTokens, &legacy.CachedPromptTokens, &legacy.CompletionTokens); err != nil {
				return err
			}
			if !f.keep(r.Principal, r.Model) {
				continue
			}
			c.charged += u.rawCost(r.Model, legacy)
			r.Kind, r.LastUsed, r.usageCount = principalKind(r.Principal), r.LastUsed.UTC(), u.priced(r.Model, c)
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
