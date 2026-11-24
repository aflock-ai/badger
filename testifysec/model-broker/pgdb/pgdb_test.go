package pgdb_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb/pgtest"
)

var ctx = context.Background()

func TestMigrateOnceForwardOnly(t *testing.T) {
	d := pgtest.New(t)
	owner, err := pgdb.Open(ctx, d.OwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	two := pgdb.Component{Name: "demo", Migrations: []pgdb.Migration{
		{Version: 1, Name: "one", SQL: `CREATE TABLE demo_one (n int)`},
		{Version: 2, Name: "two", SQL: `CREATE TABLE demo_two (n int); GRANT SELECT ON demo_two TO {{service}}`}}}
	// Several replicas starting at once apply each step once.
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- pgdb.Migrate(ctx, owner, pgtest.Service, pgdb.Core, two) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var n int
	d.Admin.QueryRow(`SELECT 1`).Scan(&n)
	o2, _ := pgdb.Open(ctx, d.OwnerDSN)
	defer o2.Close()
	if err := o2.QueryRow(`SELECT count(*) FROM badger_meta.migrations`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("migrations recorded: %d %v", n, err)
	}
	renamed := two
	renamed.Migrations = []pgdb.Migration{two.Migrations[0], {Version: 2, Name: "renamed", SQL: two.Migrations[1].SQL}}
	if err := pgdb.Migrate(ctx, owner, pgtest.Service, renamed); err == nil {
		t.Fatal("an applied step under a new name was accepted")
	}
	older := pgdb.Component{Name: "demo", Migrations: two.Migrations[:1]}
	if err := pgdb.Migrate(ctx, owner, pgtest.Service, older); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("a binary older than the database was accepted: %v", err)
	}
	if err := pgdb.Migrate(ctx, owner, "Bad Role", two); err == nil {
		t.Fatal("a role name that is not plain was accepted")
	}
}

// vectors are the contract's markings and its dominance answers.
func vectors(t *testing.T) ([]marking.Marking, []struct {
	A, B      int
	Dominates bool
}) {
	t.Helper()
	raw, err := os.ReadFile("../../formal/contract/vectors/contract-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Markings []struct {
			Marking struct {
				Level                       int
				SCI, SAP, AEA, FGI          []string
				HasFGI                      bool
				Categories, Controls, NonIC []string
				RelTo, DisplayOnly          []string
			}
		}
		Dominates []struct {
			A, B      int
			Dominates bool
		}
	}
	if err := json.Unmarshal(raw, &d); err != nil || len(d.Markings) == 0 || len(d.Dominates) != len(d.Markings)*len(d.Markings) {
		t.Fatalf("contract vectors: %v", err)
	}
	none := func(l []string) []string {
		if len(l) == 0 {
			return nil
		}
		return l
	}
	ms := make([]marking.Marking, len(d.Markings))
	for i, x := range d.Markings {
		c := x.Marking
		var controls []string
		for _, p := range c.Controls {
			w, ok := marking.ControlForPortion(p)
			if !ok {
				t.Fatalf("control portion %q", p)
			}
			controls = append(controls, w)
		}
		ms[i] = marking.Marking{Level: c.Level, SCI: none(c.SCI), SAP: none(c.SAP), AEA: none(c.AEA), FGI: none(c.FGI),
			HasFGI: c.HasFGI, Categories: none(c.Categories), Controls: none(controls), NonIC: none(c.NonIC),
			RelTo: none(c.RelTo), DisplayOnly: none(c.DisplayOnly)}
	}
	return ms, d.Dominates
}

// badger.dominates agrees with the marking package and the contract on every pair of contract
// markings, so the database's rule cannot drift from the connectors' without this failing.
func TestDominanceVectors(t *testing.T) {
	_, svc := pgtest.Migrated(t, pgdb.Core)
	ms, pairs := vectors(t)
	labels := make([]json.RawMessage, len(ms))
	for i, m := range ms {
		labels[i] = json.RawMessage(pgdb.LabelOf(m).Lattice())
	}
	arg, _ := json.Marshal(labels)
	rows, err := svc.Query(`WITH l AS (SELECT ord - 1 AS i, badger.label_of(x) AS lab
		FROM jsonb_array_elements($1::jsonb) WITH ORDINALITY AS t(x, ord))
		SELECT a.i, b.i, badger.dominates(a.lab, b.lab) FROM l a CROSS JOIN l b`, string(arg))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[[2]int]bool{}
	for rows.Next() {
		var a, b int
		var dom bool
		if err := rows.Scan(&a, &b, &dom); err != nil {
			t.Fatal(err)
		}
		got[[2]int{a, b}] = dom
	}
	if len(got) != len(pairs) {
		t.Fatalf("%d answers for %d pairs", len(got), len(pairs))
	}
	agree := 0
	for _, p := range pairs {
		sql := got[[2]int{p.A, p.B}]
		if sql != p.Dominates || sql != marking.Dominates(ms[p.A], ms[p.B]) {
			t.Errorf("%d over %d: SQL %v, contract %v, marking %v", p.A, p.B, sql, p.Dominates, marking.Dominates(ms[p.A], ms[p.B]))
			continue
		}
		agree++
	}
	t.Logf("SQL dominance agrees with the contract and the marking package on %d/%d pairs", agree, len(pairs))
}

func TestLabelOfRefusesMalformed(t *testing.T) {
	_, svc := pgtest.Migrated(t, pgdb.Core)
	good := pgdb.LabelOf(marking.Marking{}).Lattice()
	var ok bool
	if err := svc.QueryRow(`SELECT badger.dominates(badger.label_of($1::jsonb), badger.label_of($1::jsonb))`, good).Scan(&ok); err != nil || !ok {
		t.Fatalf("bottom: %v %v", ok, err)
	}
	for _, bad := range []string{`{}`, `[]`, strings.Replace(good, `"controls":[]`, `"controls":null`, 1),
		strings.Replace(good, `,"sci":[]`, ``, 1), strings.Replace(good, `"level":0`, `"level":"0"`, 1)} {
		if bad == good {
			t.Fatalf("edit did not apply")
		}
		if _, err := svc.Exec(`SELECT badger.label_of($1::jsonb)`, bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

var marked = pgdb.Component{Name: "rlsdemo", Migrations: []pgdb.Migration{{Version: 1, Name: "notes", SQL: `
CREATE TABLE notes (id bigserial PRIMARY KEY, body text NOT NULL, marking text NOT NULL, label badger.label NOT NULL);
GRANT SELECT, INSERT ON notes TO {{service}};
GRANT USAGE ON SEQUENCE notes_id_seq TO {{service}};` + pgdb.Marked("notes")}}}

func label(t *testing.T, banner string) pgdb.Label {
	t.Helper()
	l, err := pgdb.ParseLabel(banner)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func insert(tx *sql.Tx, l pgdb.Label, body string) error {
	_, err := tx.Exec(`INSERT INTO notes (body, marking, label) VALUES ($1, $2, badger.label_of($3::jsonb))`, body, l.Banner, l.Lattice())
	return err
}

func bodies(t *testing.T, q interface {
	Query(string, ...any) (*sql.Rows, error)
}) []string {
	t.Helper()
	rows, err := q.Query(`SELECT body FROM notes ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var b string
		rows.Scan(&b)
		out = append(out, b)
	}
	return out
}

func TestRowLevelSecurity(t *testing.T) {
	d, svc := pgtest.Migrated(t, pgdb.Core, marked)
	u, c, s := label(t, "UNCLASSIFIED"), label(t, "CONFIDENTIAL"), label(t, "SECRET")
	for _, l := range []pgdb.Label{u, c, s} {
		if err := pgdb.Tx(ctx, svc, l, func(tx *sql.Tx) error { return insert(tx, l, l.Banner) }); err != nil {
			t.Fatalf("write at %s: %v", l.Banner, err)
		}
	}
	// Read down only: each session sees the rows its label dominates, never one above it.
	for _, c := range []struct {
		l    pgdb.Label
		want string
	}{{u, "UNCLASSIFIED"}, {c, "UNCLASSIFIED,CONFIDENTIAL"}, {s, "UNCLASSIFIED,CONFIDENTIAL,SECRET"}} {
		l, want := c.l, c.want
		var got []string
		pgdb.Tx(ctx, svc, l, func(tx *sql.Tx) error { got = bodies(t, tx); return nil })
		if strings.Join(got, ",") != want {
			t.Errorf("session %s sees %v, want %s", l.Banner, got, want)
		}
	}
	// No write down, and no write up: a row is written at exactly the session label.
	for _, c := range [][2]pgdb.Label{{s, u}, {c, u}, {u, s}, {u, c}} {
		if err := pgdb.Tx(ctx, svc, c[0], func(tx *sql.Tx) error { return insert(tx, c[1], "x") }); err == nil {
			t.Errorf("session %s wrote a row at %s", c[0].Banner, c[1].Banner)
		}
	}
	// No session label: nothing visible, nothing written, for the service and for the owner.
	owner, _ := pgdb.Open(ctx, d.OwnerDSN)
	defer owner.Close()
	for name, db := range map[string]*sql.DB{"service": svc, "owner": owner} {
		if got := bodies(t, db); len(got) != 0 {
			t.Errorf("%s with no label sees %v", name, got)
		}
		tx, _ := db.Begin()
		if err := insert(tx, u, "x"); err == nil {
			t.Errorf("%s with no label wrote a row", name)
		}
		tx.Rollback()
	}
	if err := pgdb.Tx(ctx, svc, pgdb.Label{}, func(*sql.Tx) error { return nil }); !errors.Is(err, pgdb.ErrNoLabel) {
		t.Fatalf("a transaction ran with no label: %v", err)
	}
	// Marked rows are append-only.
	if err := pgdb.Tx(ctx, svc, s, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE notes SET body = 'y'`)
		return err
	}); err == nil {
		t.Error("the service updated a marked row")
	}
	// Neither deployed role is a superuser or may bypass row-level security.
	var bad int
	if err := d.Admin.QueryRow(`SELECT count(*) FROM pg_roles WHERE rolname IN ($1, $2) AND (rolsuper OR rolbypassrls)`,
		pgtest.Owner, pgtest.Service).Scan(&bad); err != nil || bad != 0 {
		t.Fatalf("a deployed role bypasses RLS: %d %v", bad, err)
	}
	var n int
	if err := svc.QueryRow(`SELECT count(*) FROM pg_roles WHERE rolname = current_user AND NOT rolsuper AND NOT rolbypassrls`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("service role: %d %v", n, err)
	}
}

// An empty release or display list (release to nobody) is the most restrictive, never
// unrestricted: the database and the marking package agree on every pair of markings with and
// without one, beyond the contract vectors.
func TestDominanceEmptyRestrictions(t *testing.T) {
	_, svc := pgtest.Migrated(t, pgdb.Core)
	ms := []marking.Marking{{}, {Level: 3}, {Level: 3, RelTo: []string{}}, {Level: 3, RelTo: []string{"USA", "GBR"}},
		{Level: 3, RelTo: []string{"USA"}, DisplayOnly: []string{}}, {Level: 3, DisplayOnly: []string{"GBR"}}}
	for i, a := range ms {
		for j, b := range ms {
			var got bool
			if err := svc.QueryRow(`SELECT badger.dominates(badger.label_of($1::jsonb), badger.label_of($2::jsonb))`,
				pgdb.LabelOf(a).Lattice(), pgdb.LabelOf(b).Lattice()).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != marking.Dominates(a, b) {
				t.Errorf("%d over %d: SQL %v, marking %v", i, j, got, marking.Dominates(a, b))
			}
		}
	}
	if marking.Dominates(ms[1], ms[2]) {
		t.Fatal("released to the USA dominates released to nobody")
	}
}

// Check, run as the service role at start, passes only a database holding exactly this binary's
// migrations: an unmigrated database, a missing step, or one this binary does not know is refused.
func TestCheckMigrations(t *testing.T) {
	two := pgdb.Component{Name: "demo", Migrations: []pgdb.Migration{
		{Version: 1, Name: "one", SQL: `CREATE TABLE demo_one (n int)`},
		{Version: 2, Name: "two", SQL: `CREATE TABLE demo_two (n int)`}}}
	_, svc := pgtest.Migrated(t, pgdb.Core, two)
	if err := pgdb.Check(ctx, svc, pgdb.Core, two); err != nil {
		t.Fatalf("a migrated database: %v", err)
	}
	three := two
	three.Migrations = append(append([]pgdb.Migration{}, two.Migrations...), pgdb.Migration{Version: 3, Name: "three", SQL: `SELECT 1`})
	if err := pgdb.Check(ctx, svc, pgdb.Core, three); err == nil {
		t.Fatal("a database missing a step passed")
	}
	if err := pgdb.Check(ctx, svc, pgdb.Core, pgdb.Component{Name: "demo", Migrations: two.Migrations[:1]}); err == nil {
		t.Fatal("a database newer than the binary passed")
	}
	d := pgtest.New(t)
	bare, err := pgdb.Open(ctx, d.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer bare.Close()
	if err := pgdb.Check(ctx, bare, pgdb.Core); err == nil {
		t.Fatal("an unmigrated database passed")
	}
}

// The service role is never PUBLIC or a predefined pg_ role: the migrations' grants would go to
// every role that can connect. Refused before any step runs, so no grant is made.
func TestMigrateRefusesPublicAsTheServiceRole(t *testing.T) {
	d := pgtest.New(t)
	owner, err := pgdb.Open(ctx, d.OwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	comp := pgdb.Component{Name: "demo", Migrations: []pgdb.Migration{
		{Version: 1, Name: "one", SQL: `CREATE TABLE demo_secret (n int); GRANT SELECT ON demo_secret TO {{service}}`}}}
	for _, role := range []string{"public", "pg_read_all_data"} {
		if err := pgdb.Migrate(ctx, owner, role, comp); err == nil {
			t.Fatalf("migrated with service role %q", role)
		}
	}
	if got := d.SuperQuery(t, `SELECT count(*)::text FROM pg_tables WHERE tablename = 'demo_secret'`); got != "0" {
		t.Fatalf("a step ran before the refusal: %s table(s)", got)
	}
}
