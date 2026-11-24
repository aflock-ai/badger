// Package pgtest gives a test its own Postgres database, migrated by an owner role and used by a
// service role, as the service runs. BADGER_TEST_PG is a superuser connection string to a
// scratch server. Without it every database test is skipped, loudly and by name (go test -v
// lists each skip with the reason): a run without Postgres has not tested the database, and
// says so. See "Building and testing" in testifysec/model-broker/README.md.
package pgtest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
)

// Roles the tests create once per server: neither is a superuser and neither may bypass RLS.
const (
	Owner   = "badger_test_owner"
	Service = "badger_test_service"
)

var rolesOnce sync.Once

// DB is one test database.
type DB struct {
	Name     string
	Admin    *sql.DB // superuser, for setup and for checks no role in the service has
	OwnerDSN string
	DSN      string // the service role
	superDSN string
}

// Super runs q in the test database as the superuser: a stand-in for someone editing the
// database outside the service (tampering) or an operator changing grants.
func (d *DB) Super(t testing.TB, q string, args ...any) {
	t.Helper()
	db, err := pgdb.Open(context.Background(), d.superDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// SuperErr is Super that returns the error, for statements the database must refuse.
func (d *DB) SuperErr(q string, args ...any) error {
	db, err := pgdb.Open(context.Background(), d.superDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(q, args...)
	return err
}

// SuperQuery reads one text value from the test database as the superuser, row-level security
// not applying.
func (d *DB) SuperQuery(t testing.TB, q string, args ...any) string {
	t.Helper()
	db, err := pgdb.Open(context.Background(), d.superDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var s string
	if err := db.QueryRow(q, args...).Scan(&s); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return s
}

// SkipMessage is what every database test says when BADGER_TEST_PG is not set.
const SkipMessage = "BADGER_TEST_PG not set: Postgres-backed tests skipped; run them against a scratch Postgres, see testifysec/model-broker/README.md (Building and testing)"

// server is the superuser connection string, or skips the test.
func server(t testing.TB) string {
	t.Helper()
	base := os.Getenv("BADGER_TEST_PG")
	if base == "" {
		t.Skip(SkipMessage)
	}
	return base
}

func dsn(base, user, db string) string {
	u, _ := url.Parse(base)
	u.User = url.User(user)
	u.Path = "/" + db
	return u.String()
}

// New creates a fresh empty database owned by Owner and removed when the test ends.
func New(t testing.TB) *DB { return create(t, "") }

func create(t testing.TB, template string) *DB {
	t.Helper()
	base := server(t)
	ctx := context.Background()
	admin, err := pgdb.Open(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	rolesOnce.Do(func() {
		for _, r := range []string{Owner, Service} {
			admin.ExecContext(ctx, `CREATE ROLE `+r+` LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE`)
		}
	})
	raw := make([]byte, 6)
	rand.Read(raw)
	name := "bt_" + hex.EncodeToString(raw)
	q := `CREATE DATABASE ` + name + ` OWNER ` + Owner
	if template != "" {
		q += ` TEMPLATE ` + template
	}
	if _, err := admin.ExecContext(ctx, q); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(base)
	u.Path = "/" + name
	d := &DB{Name: name, Admin: admin, OwnerDSN: dsn(base, Owner, name), DSN: dsn(base, Service, name), superDSN: u.String()}
	t.Cleanup(func() { admin.ExecContext(context.Background(), `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`) })
	if _, err := admin.ExecContext(ctx, `REVOKE ALL ON DATABASE `+name+` FROM PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `GRANT CONNECT ON DATABASE `+name+` TO `+Service); err != nil {
		t.Fatal(err)
	}
	return d
}

type tpl struct {
	once sync.Once
	name string
	err  error
}

var templates sync.Map // migration hash -> *tpl

// Migrated is a fresh database migrated with comps by the owner, and the service role's
// connection. The migrations run once per set into a template database that each test copies;
// the template's name is a hash of the migrations, so a changed migration gets a new one.
func Migrated(t testing.TB, comps ...pgdb.Component) (*DB, *sql.DB) {
	t.Helper()
	server(t)
	h := sha256.New()
	// The bookkeeping Migrate keeps (badger_meta and its grants) is part of a template too.
	h.Write([]byte("pgdb-meta-2"))
	for _, c := range comps {
		h.Write([]byte(c.Name))
		for _, m := range c.Migrations {
			fmt.Fprintf(h, "%d %s %s", m.Version, m.Name, m.SQL)
		}
	}
	key := "bt_tpl_" + hex.EncodeToString(h.Sum(nil))[:16]
	v, _ := templates.LoadOrStore(key, &tpl{})
	tp := v.(*tpl)
	tp.once.Do(func() {
		ctx := context.Background()
		admin, err := pgdb.Open(ctx, os.Getenv("BADGER_TEST_PG"))
		if err != nil {
			tp.err = err
			return
		}
		defer admin.Close()
		var exists bool
		admin.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, key).Scan(&exists)
		if !exists {
			d := New(t)
			owner, err := pgdb.Open(ctx, d.OwnerDSN)
			if err != nil {
				tp.err = err
				return
			}
			err = pgdb.Migrate(ctx, owner, Service, comps...)
			owner.Close()
			if err != nil {
				tp.err = err
				return
			}
			// Another test binary may have made the same template meanwhile: CREATE DATABASE is
			// atomic, so an existing one is complete. Two binaries racing on the same name can
			// also lose on the catalog's unique index (23505) instead of 42P04.
			if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+key+` OWNER `+Owner+` TEMPLATE `+d.Name); err != nil &&
				!strings.Contains(err.Error(), "42P04") && !strings.Contains(err.Error(), "already exists") &&
				!strings.Contains(err.Error(), "pg_database_datname_index") {
				tp.err = err
				return
			}
		}
		tp.name = key
	})
	if tp.err != nil {
		t.Fatal(tp.err)
	}
	d := create(t, tp.name)
	svc, err := pgdb.Open(context.Background(), d.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	return d, svc
}
