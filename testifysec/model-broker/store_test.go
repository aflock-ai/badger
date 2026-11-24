package broker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb/pgtest"
)

var testCeiling = func() pgdb.Label {
	l, err := pgdb.ParseLabel("SECRET")
	if err != nil {
		panic(err)
	}
	return l
}()

// testLedger is a fresh migrated database for a usage book of its own.
func testLedger(t *testing.T) *sql.DB {
	t.Helper()
	_, db := pgtest.Migrated(t, pgdb.Core, Schema)
	return db
}

// superText reads a value as the superuser (row-level security not applying).
func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (f *fixture) superText(q string) string { return f.pg.SuperQuery(f.t, q) }

// denyAudit makes every audit write fail, as a full or broken log would.
func (f *fixture) denyAudit() {
	f.pg.Super(f.t, `REVOKE INSERT ON broker.audit FROM `+pgtest.Service)
}

func (f *fixture) allowAudit() {
	f.pg.Super(f.t, `GRANT INSERT ON broker.audit TO `+pgtest.Service)
}

// setDoc stores a settings document as someone editing the database directly would.
func (f *fixture) setDoc(name, body string) {
	f.pg.Super(f.t, `INSERT INTO broker.documents (name, version, body) VALUES ($1, 1, $2::jsonb)
		ON CONFLICT (name) DO UPDATE SET body = excluded.body`, name, body)
}

func TestStoreDetectsTampering(t *testing.T) {
	for name, tamper := range map[string]string{
		"audit record edited":  `UPDATE broker.audit SET record = replace(record, 'operator:seed', 'operator:sneak') WHERE seq = 1`,
		"audit record removed": `DELETE FROM broker.audit WHERE seq = 1`,
		"audit head moved":     `UPDATE broker.audit_head SET seq = seq + 1`,
		"version edited":       `UPDATE broker.policy_versions SET entries = replace(entries::text, 'model-b', 'model-a')::jsonb WHERE n = 1`,
		"version planted": `INSERT INTO broker.policy_versions (n, entries, author, author_name, approver, comment, created, sha256)
			SELECT 2, entries, author, author_name, approver, comment, created, sha256 FROM broker.policy_versions WHERE n = 1`,
		"version deleted":    `DELETE FROM broker.policy_versions WHERE n = 1`,
		"version renumbered": `UPDATE broker.policy_versions SET n = 2 WHERE n = 1`,
		"version time":       `UPDATE broker.policy_versions SET created = created + interval '1 day' WHERE n = 1`,
		"version time, 1us":  `UPDATE broker.policy_versions SET created = created + interval '1 microsecond' WHERE n = 1`,
		"version author":     `UPDATE broker.policy_versions SET author = 'operator:sneak' WHERE n = 1`,
		"version approver":   `UPDATE broker.policy_versions SET approver = 'u9' WHERE n = 1`,
		"version comment":    `UPDATE broker.policy_versions SET comment = 'x' WHERE n = 1`,
		"version sha256":     `UPDATE broker.policy_versions SET sha256 = repeat('0', 64) WHERE n = 1`,
		"audit chain break":  `UPDATE broker.audit SET prev = 'x' WHERE seq = 1`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, true)
			do(f.edge, "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA)
			f.pg.Super(t, tamper)
			s := OpenStore(f.db, f.cfg.Ceiling(), f.cfg.Operator())
			if s.broken == nil || s.Active() != nil {
				t.Fatal("tampering not detected")
			}
			b := newBroker(f.cfg, f.db, s, f.upstream.Client())
			b.now = f.b.now
			if w := do(b.Edge(), "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA); w.Code != 503 {
				t.Fatalf("pipeline on broken store: %d", w.Code)
			}
			if w := do(b.Edge(), "POST", "/v1/chat/completions", map[string]string{"x-broker-principal": "alice@example.com"}, chatA); w.Code != 200 {
				t.Fatalf("people on broken store: %d", w.Code)
			}
			if w := do(b.Admin(), "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), `{"entries":[]}`); w.Code != 503 {
				t.Fatalf("write on broken store: %d", w.Code)
			}
		})
	}
}

// A version the current operator config no longer allows (here: a model the operator removed)
// loads, but is not made active: pipelines are denied until an admin writes a valid policy.
func TestOperatorNarrowingFailsClosed(t *testing.T) {
	f := newFixture(t, true)
	cfg := *f.cfg
	cfg.Routes = cfg.Routes[:1]
	s := OpenStore(f.db, cfg.Ceiling(), cfg.Operator())
	if s.broken != nil || s.Active() != nil {
		t.Fatalf("broken=%v active=%v", s.broken, s.Active())
	}
}

func TestSeedOnlyIntoEmptyStore(t *testing.T) {
	f := newFixture(t, true)
	os.WriteFile(f.cfg.SeedPolicyFile, []byte(`{"entries":[]}`), 0o600)
	f.open()
	if v := f.b.store.Active(); v.N != 1 || len(v.Entries) != 4 {
		t.Fatalf("seed overwrote a non-empty store: %+v", v)
	}
	s := OpenStore(testLedger(t), f.cfg.Ceiling(), f.cfg.Operator())
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte(`{"entries":[],"issuer":"x"}`), 0o600)
	if err := s.Seed(f.cfg.Operator(), bad, testNow); err == nil || s.Active() != nil {
		t.Fatal("seed with an operator field accepted")
	}
}

// Policy versions and audit records are written once: the service role cannot change them.
func TestServiceCannotRewriteHistory(t *testing.T) {
	f := newFixture(t, true)
	for _, q := range []string{`UPDATE broker.policy_versions SET comment = 'x'`, `UPDATE broker.audit SET record = '{}'`,
		`DELETE FROM broker.policy_versions`, `DELETE FROM broker.audit`, `UPDATE broker.proposals SET entries = '[]'`} {
		err := pgdb.Tx(context.Background(), f.db, f.cfg.Ceiling(), func(tx *sql.Tx) error { _, err := tx.Exec(q); return err })
		if err == nil {
			t.Errorf("service role ran %q", q)
		}
	}
}

// An unreachable database fails closed: no pipeline decision, no workspace token, no limited
// call, no admin write, no token issue.
func TestDatabaseUnreachableFailsClosed(t *testing.T) {
	f := newFixture(t, true)
	tok := f.issue("ws-1", "alice@example.com")
	if c := putQuotas(f, `"0"`, `{"default_usd":5,"principals":{}}`); c != 200 {
		t.Fatal(c)
	}
	dead, err := sql.Open("postgres", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{db: dead, label: f.cfg.Ceiling(), op: f.cfg.Operator()}
	b := newBroker(f.cfg, dead, s, f.upstream.Client())
	b.now = f.b.now
	calls := f.calls.Load()
	for name, c := range map[string]struct {
		h            http.Handler
		method, path string
		hdr          map[string]string
		body         string
	}{
		"pipeline":  {b.Edge(), "POST", "/v1/chat/completions", map[string]string{"x-broker-ci-claims": payload(nil)}, chatA},
		"person":    {b.Edge(), "POST", "/v1/chat/completions", map[string]string{"x-broker-principal": "alice@example.com"}, chatA},
		"workspace": {b.Internal(), "POST", "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + tok}, chatA},
		"admin":     {b.Admin(), "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), `{"entries":[]}`},
		"issue": {b.Provision(), "POST", "/provision/v1/tokens", map[string]string{"Authorization": "Bearer prov-key"},
			`{"workspace":"ws-2","principal":"alice@example.com"}`},
	} {
		if w := do(c.h, c.method, c.path, c.hdr, c.body); w.Code/100 == 2 {
			t.Errorf("%s served with no database: %d", name, w.Code)
		}
	}
	if f.calls.Load() != calls {
		t.Fatal("a call reached the model with no database")
	}
}

// Concurrent calls each add their own ledger row: none is lost, whatever the interleaving.
func TestLedgerKeepsEveryConcurrentCall(t *testing.T) {
	u := openUsage(testLedger(t), testCeiling, day1)
	u.prices = map[string]Price{"m": {Input: 1e6}} // $1 per prompt token
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := u.begin(testCeiling, "p", "m", day1)
			if err != nil {
				t.Error(err)
				return
			}
			u.finish(c, "p", "m", usageAttr{}, tokens{Prompt: int64(i%3 + 1)}, day1)
		}()
	}
	wg.Wait()
	want := 0.0
	for i := range 40 {
		want += float64(i%3 + 1)
	}
	if got, err := u.monthSpentErr("p", day1); err != nil || got != want {
		t.Fatalf("spend %v %v, want %v", got, err, want)
	}
	if r := reportOf(t, u, day1); r.Principals["p"]["m"].Requests != 40 {
		t.Fatalf("requests %d", r.Principals["p"]["m"].Requests)
	}
}
