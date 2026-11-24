package pgdb_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
)

// faultDriver is a database that accepts every statement and answers every query with one row
// and then a read error: the connection dropping halfway through a result. It needs no server.
type faultDriver struct{}

type faultConn struct{}

type faultTx struct{}

type faultRows struct{ sent bool }

var errMidRead = errors.New("connection lost while reading rows")

func (faultDriver) Open(string) (driver.Conn, error) { return faultConn{}, nil }

func (faultConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }
func (faultConn) Close() error                        { return nil }
func (faultConn) Begin() (driver.Tx, error)           { return faultTx{}, nil }
func (faultConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(0), nil
}
func (faultConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &faultRows{}, nil
}

func (faultTx) Commit() error   { return nil }
func (faultTx) Rollback() error { return nil }

func (*faultRows) Columns() []string { return []string{"version", "name"} }
func (*faultRows) Close() error      { return nil }
func (r *faultRows) Next(dest []driver.Value) error {
	if r.sent {
		return errMidRead
	}
	r.sent = true
	dest[0], dest[1] = int64(1), "one"
	return nil
}

var _ io.Closer = (*faultRows)(nil)

func init() { sql.Register("pgdb-fault", faultDriver{}) }

func faultDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgdb-fault", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// A migration history that fails partway through reading is refused: a partial history would
// otherwise skip the check that the database holds no step newer than this binary.
func TestMigrateRefusesAPartiallyReadHistory(t *testing.T) {
	comp := pgdb.Component{Name: "demo", Migrations: []pgdb.Migration{{Version: 1, Name: "one", SQL: `SELECT 1`}}}
	err := pgdb.Migrate(context.Background(), faultDB(t), "svc", comp)
	if !errors.Is(err, errMidRead) {
		t.Fatalf("Migrate after a failed read of the history: %v, want the read error", err)
	}
}

// A panic inside a transaction still rolls it back, so the connection (and any locks it holds)
// goes back to the pool instead of staying held for the life of the context.
func TestTxRollsBackWhenFnPanics(t *testing.T) {
	db := faultDB(t)
	l, err := pgdb.ParseLabel("UNCLASSIFIED")
	if err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() { recover() }()
		pgdb.Tx(context.Background(), db, l, func(*sql.Tx) error { panic("fn failed") })
	}()
	if n := db.Stats().InUse; n != 0 {
		t.Fatalf("%d connection(s) still held by a transaction whose fn panicked", n)
	}
}

// Dominates trusts a label only when its banner and its lattice form (what transactions and
// row-level security use) agree: a banner edited after parsing, or a banner with no lattice form,
// dominates nothing and is dominated by nothing.
func TestDominatesRefusesInconsistentLabels(t *testing.T) {
	secret, err := pgdb.ParseLabel("SECRET")
	if err != nil {
		t.Fatal(err)
	}
	unclass, err := pgdb.ParseLabel("UNCLASSIFIED")
	if err != nil {
		t.Fatal(err)
	}
	if !pgdb.Dominates(secret, unclass) || pgdb.Dominates(unclass, secret) {
		t.Fatal("the rule itself is wrong")
	}
	relabelled := secret
	relabelled.Banner = "UNCLASSIFIED" // still SECRET in its lattice form
	if pgdb.Dominates(unclass, relabelled) {
		t.Fatal("an UNCLASSIFIED clearance may hold a label whose lattice form is SECRET")
	}
	raised := unclass
	raised.Banner = "SECRET"
	if pgdb.Dominates(raised, secret) {
		t.Fatal("a banner raised by hand dominates SECRET")
	}
	bare := pgdb.Label{Banner: "SECRET"}
	if pgdb.Dominates(bare, unclass) || pgdb.Dominates(secret, bare) {
		t.Fatal("a banner-only label takes part in dominance")
	}
}

// Open refuses connection settings under which the driver would log credentials, take its
// settings from a service file (which overrides the connection string, sslmode included), or
// fall back between hosts by session attributes. None of these is used by the service.
func TestOpenRefusesUnsafeDriverSettings(t *testing.T) {
	ctx := context.Background()
	const ok = "postgres://u@127.0.0.1:1/db?sslmode=verify-full&connect_timeout=1"
	for name, c := range map[string]struct{ dsn, env, val string }{
		"debug logging":       {ok, "PQGO_DEBUG", "1"},
		"service in the dsn":  {"postgres://u@127.0.0.1:1/db?service=other&sslmode=verify-full", "", ""},
		"service from env":    {ok, "PGSERVICE", "other"},
		"session attrs":       {ok + "&target_session_attrs=prefer-standby", "", ""},
		"session attrs env":   {ok, "PGTARGETSESSIONATTRS", "prefer-standby"},
		"keyword form":        {"host=127.0.0.1 port=1 dbname=db sslmode=verify-full", "", ""},
		"keyword, spaced":     {"host=127.0.0.1 service = other sslmode=verify-full", "", ""},
		"padded url key":      {"postgres://u@127.0.0.1:1/db?sslmode=verify-full&%20service=other", "", ""},
		"opaque url":          {"postgres:x=y service=other", "", ""},
		"key smuggling a key": {"postgres://u@127.0.0.1:1/db?dbname%3Dx%20service=other&sslmode=verify-full", "", ""},
		// Server settings at connect: a privileged login could take on the service role
		// (role, session_authorization) and take its privileges back later.
		"options in the dsn":  {ok + "&options=-c%20session_authorization%3Dsvc", "", ""},
		"options from env":    {ok, "PGOPTIONS", "-c role=svc"},
		"a runtime parameter": {ok + "&session_authorization=svc", "", ""},
		"role":                {ok + "&role=svc", "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if c.env != "" {
				t.Setenv(c.env, c.val)
			}
			if _, err := pgdb.Open(ctx, c.dsn); !errors.Is(err, pgdb.ErrUnsafeSettings) {
				t.Fatalf("Open: %v, want ErrUnsafeSettings", err)
			}
		})
	}
}

// A transaction never runs at a label whose banner and lattice form disagree: the callback is not
// called, so nothing reads rows under a label that claims less than it holds.
func TestTxRefusesAnInconsistentLabel(t *testing.T) {
	l, err := pgdb.ParseLabel("SECRET")
	if err != nil {
		t.Fatal(err)
	}
	l.Banner = "UNCLASSIFIED"
	ran := false
	if err := pgdb.Tx(context.Background(), faultDB(t), l, func(*sql.Tx) error { ran = true; return nil }); err == nil || ran {
		t.Fatalf("Tx ran at an inconsistent label: err=%v ran=%v", err, ran)
	}
}

// A connection to another host must be authenticated TLS (sslmode=verify-full or verify-ca):
// marked audit records and signed profiles never cross the network in the clear. Loopback stays
// open for a database on the same host.
func TestRequireTLSForRemoteHosts(t *testing.T) {
	for dsn, ok := range map[string]bool{
		"postgres://svc@db.example.internal:5432/b?sslmode=disable":                                false,
		"postgres://svc@db.example.internal:5432/b?sslmode=prefer":                                 false,
		"postgres://svc@db.example.internal:5432/b?sslmode=require":                                false,
		"postgres://svc@db.example.internal:5432/b":                                                false,
		"postgres://svc@192.0.2.5:5432/b?sslmode=require":                                          false,
		"postgres://svc@db.example.internal:5432/b?sslmode=verify-full&sslrootcert=/etc/db/ca.crt": true,
		"postgres://svc@db.example.internal:5432/b?sslmode=verify-ca&sslrootcert=/etc/db/ca.crt":   true,
		"postgres://svc@localhost:5432/b?sslmode=disable":                                          true,
		"postgres://svc@127.0.0.1:5432/b?sslmode=disable":                                          true,
		"postgres://svc@[::1]:5432/b?sslmode=disable":                                              true,
		// No host in the URL: the driver would take one from PGHOST, unchecked.
		"postgres:///b?sslmode=disable":     false,
		"postgres://svc@/b?sslmode=disable": false,
	} {
		err := pgdb.RequireTLS(dsn, nil)
		if (err == nil) != ok {
			t.Errorf("%s: %v, want ok=%v", dsn, err, ok)
		}
		if err != nil && !strings.Contains(err.Error(), "sslmode=verify-full") {
			t.Errorf("%s: the refusal does not name the fix: %v", dsn, err)
		}
	}
}
