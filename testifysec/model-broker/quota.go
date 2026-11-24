package broker

import (
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
)

// QuotaSet is every limit an admin sets in the portal, as a deployment default and per principal:
// the monthly spend in USD at the routes' prices (DefaultUSD, Principals) and the Limits beside it
// (Defaults, People). A principal's own value wins, then the default; with neither, money is
// unlimited and the managed agent uses its compiled value. Zero blocks every call.
type QuotaSet struct {
	Version    int64              `json:"version"`
	DefaultUSD *float64           `json:"default_usd"`
	Principals map[string]float64 `json:"principals"`
	Defaults   Limits             `json:"defaults"`
	People     map[string]Limits  `json:"people"`
	// Seeded names the fields the operator's seed_limits has filled once; it never fills them again.
	Seeded []string `json:"seeded,omitempty"`
}

// Limits are the numbers beside the monthly quota. The per-call cap is the most one call may cost:
// it bounds the output tokens asked for (at the model's output price) and is the call's
// reservation against the daily and monthly limits while it runs. Steps, context and timeout are
// the managed agent's; the broker serves them and enforces only output and money.
type Limits struct {
	DailyUSD       *float64 `json:"daily_usd,omitempty"`
	CallUSD        *float64 `json:"call_usd,omitempty"`
	Steps          *int     `json:"steps,omitempty"`
	Context        *int     `json:"context,omitempty"`
	Output         *int     `json:"output,omitempty"`
	TimeoutSeconds *int     `json:"timeout_seconds,omitempty"`
}

// SeedLimits is the operator's first value for each default (config seed_limits). Each field is
// applied once, when the broker first sees it; after that the portal is the only source.
type SeedLimits struct {
	DefaultUSD *float64 `json:"default_usd"`
	Defaults   Limits   `json:"defaults"`
}

// maxContextTokens is a technical limit, not policy: the gateway and the broker accept a request
// body of at most 1 MiB, which holds about 262144 tokens at 4 bytes each.
const maxContextTokens = 262144

// builtInAgentLimits are the managed agent's compiled limits (packages/server/src/managed.ts,
// `limits`): what it uses for a field the broker serves no value for. Display only, for the
// console; a test holds them to managed.ts.
var builtInAgentLimits = map[string]int{"steps": 40, "context": 131072, "output": 16384, "timeout_seconds": 230}

// LimitChange is one field of one target (a principal, or "default") in a write's audit record.
type LimitChange struct {
	Target string   `json:"target"`
	Field  string   `json:"field"`
	Old    *float64 `json:"old"`
	New    *float64 `json:"new"`
}

const maxQuotaPrincipals = 1000

// errQuotaVersion is a write based on a version that is no longer current.
var errQuotaVersion = errors.New("quota version changed")

// quotaBook holds the QuotaSet in the "quotas" document. If it cannot be read, every model call
// is refused until it is repaired: a cost cap that silently disappears is worse than an outage
// someone notices.
type quotaBook struct {
	docs documents
	// maxTimeout is the longest agent timeout the broker can serve: under its whole-call limit.
	maxTimeout int
}

func (s QuotaSet) check(maxTimeout int) error {
	ok := func(v float64) bool { return v >= 0 && !math.IsInf(v, 0) && !math.IsNaN(v) }
	if s.DefaultUSD != nil && !ok(*s.DefaultUSD) {
		return errors.New("default_usd must be a finite amount, not negative")
	}
	if len(s.Principals) > maxQuotaPrincipals {
		return errors.New("over 1000 principals")
	}
	for p, v := range s.Principals {
		if p == "" || len(p) > 200 || auditSafe(p) != p || !ok(v) {
			return errors.New("each principal needs a plain name and a finite amount, not negative")
		}
	}
	if len(s.People) > maxQuotaPrincipals {
		return errors.New("over 1000 principals")
	}
	if err := s.Defaults.check(maxTimeout); err != nil {
		return fmt.Errorf("default: %w", err)
	}
	for p, l := range s.People {
		if p == "" || len(p) > 200 || auditSafe(p) != p {
			return errors.New("each principal needs a plain name")
		}
		if err := l.check(maxTimeout); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	return nil
}

// check refuses what the system cannot do, saying which technical limit it meets.
func (l Limits) check(maxTimeout int) error {
	for _, v := range []*float64{l.DailyUSD, l.CallUSD} {
		if v != nil && (*v < 0 || math.IsInf(*v, 0) || math.IsNaN(*v)) {
			return errors.New("amounts must be finite, not negative")
		}
	}
	switch {
	case l.Steps != nil && *l.Steps < 1:
		return errors.New("steps must be at least 1")
	case l.Context != nil && (*l.Context < 1 || *l.Context > maxContextTokens):
		return fmt.Errorf("context must be 1 to %d tokens: a longer history does not fit the 1 MiB request the gateway and the broker accept (technical limit, not policy)", maxContextTokens)
	case l.Output != nil && (*l.Output < 1 || *l.Output > maxContextTokens):
		return fmt.Errorf("output must be 1 to %d tokens (technical limit, not policy)", maxContextTokens)
	case l.Context != nil && l.Output != nil && *l.Output >= *l.Context:
		return errors.New("output must be smaller than context: the answer shares the model's window with the history (technical limit, not policy)")
	case l.TimeoutSeconds != nil && (*l.TimeoutSeconds < 1 || *l.TimeoutSeconds >= maxTimeout):
		return fmt.Errorf("timeout_seconds must be 1 to %d: the broker ends every call at %d s, upstream.request_seconds (technical limit, not policy)", maxTimeout-1, maxTimeout)
	}
	return nil
}

// admission is what one call of a principal is held to.
type admission struct {
	monthly, daily, call *float64
	output               *int
}

func pick[T any](own, def *T) *T {
	if own != nil {
		return own
	}
	return def
}

// effective is the principal's own value for each field, else the default's.
func (s QuotaSet) effective(principal string) (monthly *float64, l Limits) {
	monthly = s.DefaultUSD
	if v, ok := s.Principals[principal]; ok {
		monthly = &v
	}
	o, d := s.People[principal], s.Defaults
	return monthly, Limits{DailyUSD: pick(o.DailyUSD, d.DailyUSD), CallUSD: pick(o.CallUSD, d.CallUSD), Steps: pick(o.Steps, d.Steps),
		Context: pick(o.Context, d.Context), Output: pick(o.Output, d.Output), TimeoutSeconds: pick(o.TimeoutSeconds, d.TimeoutSeconds)}
}

func (s QuotaSet) admission(principal string) admission {
	monthly, l := s.effective(principal)
	return admission{monthly: monthly, daily: l.DailyUSD, call: l.CallUSD, output: l.Output}
}

// outputCap is the most output tokens a call may ask for: the output limit, and what the per-call
// cap buys at the model's output price. Zero is no cap.
func (a admission) outputCap(price *Price) int {
	limit := 0
	if a.output != nil {
		limit = *a.output
	}
	if a.call != nil && price != nil && price.Output > 0 {
		if n := max(int(*a.call*1e6/price.Output), 1); limit == 0 || n < limit {
			limit = n
		}
	}
	return limit
}

// fields is every target's values by field name, for the audit diff.
func (s QuotaSet) fields() map[string]map[string]*float64 {
	f := func(v *int) *float64 {
		if v == nil {
			return nil
		}
		x := float64(*v)
		return &x
	}
	row := func(monthly *float64, l Limits) map[string]*float64 {
		return map[string]*float64{"monthly_usd": monthly, "daily_usd": l.DailyUSD, "call_usd": l.CallUSD, "steps": f(l.Steps),
			"context": f(l.Context), "output": f(l.Output), "timeout_seconds": f(l.TimeoutSeconds)}
	}
	out := map[string]map[string]*float64{"default": row(s.DefaultUSD, s.Defaults)}
	for p, v := range s.Principals {
		out[p] = row(&v, s.People[p])
	}
	for p, l := range s.People {
		if _, ok := s.Principals[p]; !ok {
			out[p] = row(nil, l)
		}
	}
	return out
}

// changes is every field whose value differs between old and next, in a stable order.
func changes(old, next QuotaSet) []LimitChange {
	a, b := old.fields(), next.fields()
	targets := []string{}
	for t := range a {
		targets = append(targets, t)
	}
	for t := range b {
		if _, ok := a[t]; !ok {
			targets = append(targets, t)
		}
	}
	slices.Sort(targets)
	names := []string{"monthly_usd", "daily_usd", "call_usd", "steps", "context", "output", "timeout_seconds"}
	var out []LimitChange
	for _, t := range targets {
		for _, n := range names {
			x, y := a[t][n], b[t][n]
			if (x == nil) != (y == nil) || (x != nil && *x != *y) {
				out = append(out, LimitChange{Target: t, Field: n, Old: x, New: y})
			}
		}
	}
	return out
}

// seed fills each field of the operator's seed the broker has not seen before, unless an admin
// already set it, and records the field as seeded either way. It reports whether it wrote.
func (q *quotaBook) seed(seed *SeedLimits) (QuotaSet, QuotaSet, bool, error) {
	s, err := q.current()
	if err != nil || seed == nil {
		return s, s, false, err
	}
	old := s
	changed := false
	fill := func(key string, apply func() bool) {
		if !slices.Contains(s.Seeded, key) && apply() {
			s.Seeded = append(slices.Clone(s.Seeded), key)
			changed = true
		}
	}
	fill("default_usd", once(seed.DefaultUSD, &s.DefaultUSD))
	fill("defaults.daily_usd", once(seed.Defaults.DailyUSD, &s.Defaults.DailyUSD))
	fill("defaults.call_usd", once(seed.Defaults.CallUSD, &s.Defaults.CallUSD))
	fill("defaults.steps", once(seed.Defaults.Steps, &s.Defaults.Steps))
	fill("defaults.context", once(seed.Defaults.Context, &s.Defaults.Context))
	fill("defaults.output", once(seed.Defaults.Output, &s.Defaults.Output))
	fill("defaults.timeout_seconds", once(seed.Defaults.TimeoutSeconds, &s.Defaults.TimeoutSeconds))
	if !changed {
		return old, s, false, nil
	}
	saved, err := q.put(s.Version, s)
	return old, saved, err == nil, err
}

// once applies a seed value to an unset field. It reports whether the seed names the field at all.
func once[T any](seed *T, field **T) func() bool {
	return func() bool {
		if seed == nil {
			return false
		}
		if *field == nil {
			v := *seed
			*field = &v
		}
		return true
	}
}

func (q *quotaBook) current() (QuotaSet, error) {
	s := QuotaSet{Principals: map[string]float64{}}
	v, err := q.docs.load("quotas", &s)
	if err == nil {
		err = s.check(q.maxTimeout)
	}
	if err != nil {
		return QuotaSet{}, fmt.Errorf("quotas unreadable: %w", err)
	}
	if s.Principals == nil {
		s.Principals = map[string]float64{}
	}
	if s.People == nil {
		s.People = map[string]Limits{}
	}
	s.Version = v
	return s, nil
}

// put replaces the set if base is the current version.
func (q *quotaBook) put(base int64, next QuotaSet) (QuotaSet, error) {
	if next.Principals == nil {
		next.Principals = map[string]float64{}
	}
	if next.People == nil {
		next.People = map[string]Limits{}
	}
	next.Version = base + 1
	if err := q.docs.put("quotas", base, next); err != nil {
		if errors.Is(err, errDocVersion) {
			return QuotaSet{}, errQuotaVersion
		}
		return QuotaSet{}, err
	}
	return next, nil
}

// summary is the audit line for a quota write: every limit, in a stable order.
func (s QuotaSet) summary() string {
	parts := []string{"default_usd=none"}
	if s.DefaultUSD != nil {
		parts[0] = "default_usd=" + strconv.FormatFloat(*s.DefaultUSD, 'f', -1, 64)
	}
	names := make([]string, 0, len(s.Principals))
	for p := range s.Principals {
		names = append(names, p)
	}
	slices.Sort(names)
	for _, p := range names {
		parts = append(parts, p+"="+strconv.FormatFloat(s.Principals[p], 'f', -1, 64))
	}
	return strings.Join(parts, " ")
}

// withinQuota checks the principal's month-to-date and today's spend before a model call. A
// principal with a monthly or daily limit makes one call at a time: the check and the call it
// admits run under that principal's lock, so a second call is checked against the first one's
// charge, not against the same balance. Over a limit it answers 429 and returns false; from 80% it
// adds a warning header. The caller must call release once the call has been recorded. The
// admission goes to forward, which clamps the output and whose ledger admission checks the limits
// again atomically across replicas (usageBook.admit).
func (b *Broker) withinQuota(w http.ResponseWriter, r *http.Request, principal string, label pgdb.Label) (release func(), a admission, ok bool) {
	unavailable := func() (func(), admission, bool) {
		writeErr(w, http.StatusServiceUnavailable, apiError{Code: "quota_unavailable", Message: "quotas cannot be read; an admin must repair them"})
		return nil, admission{}, false
	}
	s, err := b.quotas.current()
	if err != nil {
		return unavailable()
	}
	if a = s.admission(principal); a.monthly == nil && a.daily == nil {
		return func() {}, a, true
	}
	lock, _ := b.quotaLocks.LoadOrStore(principal, make(chan struct{}, 1))
	select {
	case lock.(chan struct{}) <- struct{}{}:
	case <-r.Context().Done():
		failure(w, http.StatusServiceUnavailable)
		return nil, admission{}, false
	}
	release = func() { <-lock.(chan struct{}) }
	// Read the limits again now the lock is held: an admin may have changed them while this call queued.
	if s, err = b.quotas.current(); err != nil {
		release()
		return unavailable()
	}
	if a = s.admission(principal); a.monthly == nil && a.daily == nil {
		return release, a, true
	}
	now := time.Now().UTC()
	monthFrom, monthTo := monthRange(now)
	today := now.Format("2006-01-02")
	next := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	for _, p := range []struct {
		name, from, to, resets string
		limit                  *float64
	}{{"monthly", monthFrom, monthTo, next.Format("2 Jan 2006"), a.monthly}, {"daily", today, now.AddDate(0, 0, 1).Format("2006-01-02"), "00:00 UTC", a.daily}} {
		if p.limit == nil {
			continue
		}
		limit := *p.limit
		used, inflight, err := b.up.usage.periodSpendAndInFlight(label, principal, p.from, p.to, now)
		if err != nil {
			release()
			writeErr(w, http.StatusServiceUnavailable, apiError{Code: "quota_unavailable",
				Message: "this " + map[string]string{"monthly": "month", "daily": "day"}[p.name] + "'s spend cannot be rebuilt from the usage ledger; an admin must repair it"})
			return nil, admission{}, false
		}
		if p.name == "monthly" {
			w.Header().Set("X-Broker-Quota-USD", strconv.FormatFloat(limit, 'f', -1, 64))
			w.Header().Set("X-Broker-Quota-Used-USD", strconv.FormatFloat(used, 'f', 6, 64))
		}
		// Calls still in flight (on another replica, or one whose result is being retried) count at
		// their reservation: refused only where they and this call could pass the limit together.
		if used < limit && used+inflight >= limit {
			release()
			writeErr(w, http.StatusTooManyRequests, apiError{Code: "quota_exceeded",
				Message: fmt.Sprintf("calls still running could take the %s quota of $%.2f past its limit ($%.2f used); try again when they finish",
					p.name, limit, used)})
			return nil, admission{}, false
		}
		if used >= limit {
			release()
			writeErr(w, http.StatusTooManyRequests, apiError{Code: "quota_exceeded",
				Message: fmt.Sprintf("%s model quota of $%.2f is used ($%.2f); it resets %s, or an admin can raise it", p.name, limit, used, p.resets)})
			return nil, admission{}, false
		}
		if used >= 0.8*limit {
			w.Header().Set("X-Broker-Quota-Warning", fmt.Sprintf("%.0f%% of the %s quota used", 100*used/limit, p.name))
		}
	}
	return release, a, true
}

func (b *Broker) quotaRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/v1/quotas", func(w http.ResponseWriter, r *http.Request) {
		s, err := b.quotas.current()
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, apiError{Code: "quota_unavailable", Message: err.Error()})
			return
		}
		now := time.Now().UTC()
		from, to := monthRange(now)
		used, err := b.up.usage.spentAll(from, to, now)
		today, terr := b.up.usage.spentAll(now.Format("2006-01-02"), now.AddDate(0, 0, 1).Format("2006-01-02"), now)
		if err != nil || terr != nil {
			writeErr(w, http.StatusServiceUnavailable, apiError{Code: "usage_unavailable", Message: "the usage ledger cannot be read; usage is unknown, not zero"})
			return
		}
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(s.Version, 10)))
		writeJSON(w, http.StatusOK, map[string]any{"version": s.Version, "default_usd": s.DefaultUSD,
			"principals": s.Principals, "defaults": s.Defaults, "people": s.People, "seeded": s.Seeded,
			"month": now.Format("2006-01"), "used_usd": used, "today_usd": today,
			// What the system cannot physically do, shown beside the fields so an admin sees why a value is refused.
			"technical": map[string]int{"max_context": maxContextTokens, "max_output": maxContextTokens - 1, "max_timeout_seconds": b.quotas.maxTimeout - 1},
			"built_in":  builtInAgentLimits})
	})
	mux.HandleFunc("PUT /admin/v1/quotas", func(w http.ResponseWriter, r *http.Request) {
		c, ok := b.caller(w, r)
		if !ok {
			return
		}
		base, ok := b.ifMatch(w, r)
		if !ok {
			return
		}
		var body struct {
			DefaultUSD *float64           `json:"default_usd"`
			Principals map[string]float64 `json:"principals"`
			Defaults   Limits             `json:"defaults"`
			People     map[string]Limits  `json:"people"`
			Comment    string             `json:"comment"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		old, err := b.quotas.current()
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, apiError{Code: "quota_unavailable", Message: err.Error()})
			return
		}
		// The seed markers are the broker's own record, never the caller's.
		next := QuotaSet{DefaultUSD: body.DefaultUSD, Principals: body.Principals, Defaults: body.Defaults, People: body.People, Seeded: old.Seeded}
		if err := next.check(b.quotas.maxTimeout); err != nil || len(body.Comment) > 1000 {
			msg := "comment over 1000 bytes"
			if err != nil {
				msg = err.Error()
			}
			writeErr(w, http.StatusUnprocessableEntity, apiError{Code: "invalid_quota", Message: msg})
			return
		}
		// A change to the caller's own limits, or to a pipeline whose entry they own, is flagged in
		// the audit record and must say why.
		diff := changes(old, next)
		owners := b.principalOwners()
		self := slices.ContainsFunc(diff, func(ch LimitChange) bool {
			return ch.Target == c.id || (c.name != "" && (strings.EqualFold(ch.Target, c.name) || strings.EqualFold(owners[ch.Target], c.name)))
		})
		if self && strings.TrimSpace(body.Comment) == "" {
			writeErr(w, http.StatusUnprocessableEntity, apiError{Code: "reason_required",
				Message: "this changes your own limits, or a pipeline you own; say why in comment (it is kept in the audit log)"})
			return
		}
		saved, err := b.quotas.put(base, next)
		switch {
		case errors.Is(err, errQuotaVersion):
			writeErr(w, http.StatusPreconditionFailed, apiError{Code: "version_changed", Message: "quotas changed since you loaded them; reload"})
			return
		case err != nil:
			writeErr(w, http.StatusInternalServerError, apiError{Code: "store_unavailable", Message: "quotas not saved"})
			return
		}
		b.store.Audit(AuditRecord{Kind: "quota", Actor: c.id, Name: c.name, Version: b.currentVersion(), Changes: diff, Self: self,
			Comment: strings.TrimSpace(fmt.Sprintf("quota v%d: %s. %s", saved.Version, saved.summary(), body.Comment))})
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(saved.Version, 10)))
		writeJSON(w, http.StatusOK, saved)
	})
}

// seedLimits applies the operator's seed_limits at start and audits what it filled.
func (b *Broker) seedLimits() {
	old, saved, wrote, err := b.quotas.seed(b.cfg.SeedLimits)
	if err != nil {
		log.Printf("seed limits not applied: %v", err)
		return
	}
	if wrote {
		b.store.Audit(AuditRecord{Kind: "quota", Actor: "operator:seed", Version: b.currentVersion(), Changes: changes(old, saved),
			Comment: fmt.Sprintf("quota v%d seeded: %s", saved.Version, strings.Join(saved.Seeded, " "))})
	}
}
