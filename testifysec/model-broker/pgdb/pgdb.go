// Package pgdb is the service's one database: Postgres, reached as two roles. The owner role runs
// the migrations and owns every object; the service role the listeners use holds grants only, is
// not a superuser and has no BYPASSRLS. Tables that can hold marked data carry the label they were
// written at, and row-level security lets a transaction read only rows its session label
// dominates and write only at exactly that label (see core.sql).
package pgdb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/lib/pq" // the driver, configured through its Config; queries use database/sql only

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// ErrUnsafeSettings is a connection setting the service refuses: one under which the driver
// logs credentials (PQGO_DEBUG=1), takes settings from a service file, which then override the
// connection string's own (sslmode included), falls back between hosts by session attributes, or
// sends server settings at connect (any parameter but TLS, connect_timeout and application_name,
// and PGOPTIONS: a privileged login could take on the service role with role or
// session_authorization and take its privileges back later); and any connection string not in
// the postgres:// URL form.
var ErrUnsafeSettings = errors.New("database: connection settings the service does not allow")

// allowedParams are the connection string parameters the service accepts: TLS and the connect
// timeout. Every other one is refused.
var allowedParams = []string{"sslmode", "sslrootcert", "sslcert", "sslkey", "sslsni", "connect_timeout", "application_name"}

// unsafeSettings reports the first setting in dsn or the environment the service refuses.
func unsafeSettings(dsn string) string {
	if os.Getenv("PQGO_DEBUG") == "1" {
		return "PQGO_DEBUG=1"
	}
	for _, k := range []string{"PGSERVICE", "PGSERVICEFILE", "PGTARGETSESSIONATTRS", "PGOPTIONS"} {
		if os.Getenv(k) != "" {
			return k
		}
	}
	// Only the URL form is accepted: its parameters are unambiguous to check here, unlike the
	// keyword form's grammar (spaces around =, quoting).
	u, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") || u.Opaque != "" {
		return "a connection string that is not a postgres:// URL"
	}
	for k := range u.Query() {
		// A name outside the keyword grammar could carry a second setting into the keyword string
		// the driver builds from the URL (dbname=x service=y).
		if !reParam.MatchString(k) {
			return "a connection parameter name that is not a plain keyword"
		}
		// Only these: the driver sends any other parameter to the server as a setting at connect,
		// and a privileged login could take on the service role that way (role,
		// session_authorization, options) and take its privileges back later.
		if !slices.Contains(allowedParams, k) {
			return k
		}
	}
	return ""
}

// Open connects with dsn and checks the database answers. Nothing is retried: a service that
// cannot reach its database refuses work instead of running without it.
func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	if what := unsafeSettings(dsn); what != "" {
		return nil, fmt.Errorf("%w: %s", ErrUnsafeSettings, what)
	}
	cfg, err := pq.NewConfig(dsn)
	if err != nil {
		return nil, errors.New("database: bad connection string")
	}
	conn, err := pq.NewConnectorConfig(cfg)
	if err != nil {
		return nil, errors.New("database: bad connection string")
	}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(32)
	db.SetMaxIdleConns(8)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("database unreachable: %w", err)
	}
	return db, nil
}

// Label is a marking as a transaction's session label or a row's label: its canonical banner
// and its comparable lattice form, both from the marking package, never from free text.
type Label struct {
	Banner  string
	lattice []byte
}

// ParseLabel reads a configured banner with the connectors' parser.
func ParseLabel(banner string) (Label, error) {
	m, err := marking.Parse(banner)
	if err != nil {
		return Label{}, err
	}
	return LabelOf(m), nil
}

// LabelOf is m as a label.
func LabelOf(m marking.Marking) Label {
	raw, _ := json.Marshal(marking.LatticeOf(m))
	return Label{Banner: marking.Banner(m), lattice: raw}
}

// Valid reports whether l was made by ParseLabel or LabelOf.
func (l Label) Valid() bool { return l.Banner != "" && len(l.lattice) > 0 }

// Lattice is the JSON the database turns into a badger.label with badger.label_of.
func (l Label) Lattice() string { return string(l.lattice) }

// ErrNoLabel is refused work: a transaction must run at a label.
var ErrNoLabel = errors.New("database: no session label")

// Tx runs fn in one transaction at session label l (SET LOCAL badger.label), committing if fn
// returns nil. Row-level security reads the label from there; nothing a client sends sets it.
func Tx(ctx context.Context, db *sql.DB, l Label, fn func(*sql.Tx) error) error {
	// The session label is the lattice form; a banner that no longer matches it (edited after
	// parsing) would claim less than the transaction can read, so it runs nothing.
	if _, ok := l.marking(); !ok {
		return ErrNoLabel
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// Rollback after Commit is a no-op; deferred, it also releases the connection and its locks
	// when fn panics.
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('badger.label', $1, true)`, l.Lattice()); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Migration is one forward-only schema step. {{service}} in SQL is replaced by the service role.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// Component is one part of the service's schema, versioned on its own.
type Component struct {
	Name       string
	Migrations []Migration
}

var (
	reRole  = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	reParam = regexp.MustCompile(`^[a-z_]+$`)
)

// lockKey is the advisory lock every migrating process takes, so two replicas starting at once
// apply each step once.
var lockKey = func() int64 {
	h := sha256.Sum256([]byte("badger-broker migrations"))
	return int64(binary.BigEndian.Uint64(h[:8]))
}()

// Migrate applies every pending step of every component, in order, each in its own transaction
// with its bookkeeping row, under one advisory lock. It runs as the owner role. A database that
// holds a step this binary does not know, or a step under another name, is refused: migrations
// only go forward and are never edited once applied.
func Migrate(ctx context.Context, owner *sql.DB, service string, comps ...Component) error {
	if !reRole.MatchString(service) {
		return errors.New("database: service role must be a plain lowercase name")
	}
	// GRANT ... TO public reaches every role that can connect; pg_ roles are predefined.
	if service == "public" || strings.HasPrefix(service, "pg_") {
		return fmt.Errorf("database: service role %q is not a role of its own", service)
	}
	conn, err := owner.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, lockKey)
	if _, err := conn.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS badger_meta;
		CREATE TABLE IF NOT EXISTS badger_meta.migrations (component text NOT NULL, version int NOT NULL,
			name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (component, version));
		GRANT USAGE ON SCHEMA badger_meta TO `+service+`;
		GRANT SELECT ON badger_meta.migrations TO `+service); err != nil {
		return err
	}
	for _, c := range comps {
		applied := map[int]string{}
		rows, err := conn.QueryContext(ctx, `SELECT version, name FROM badger_meta.migrations WHERE component = $1`, c.Name)
		if err != nil {
			return err
		}
		for rows.Next() {
			var v int
			var n string
			if err := rows.Scan(&v, &n); err != nil {
				rows.Close()
				return err
			}
			applied[v] = n
		}
		// A history cut short by a read error would skip the newer-than-this-binary check.
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		known := map[int]bool{}
		for i, m := range c.Migrations {
			if m.Version != i+1 {
				return fmt.Errorf("database: %s migrations must be numbered 1, 2, ...", c.Name)
			}
			known[m.Version] = true
			if n, ok := applied[m.Version]; ok && n != m.Name {
				return fmt.Errorf("database: %s step %d is %q in the database and %q here", c.Name, m.Version, n, m.Name)
			}
		}
		for v := range applied {
			if !known[v] {
				return fmt.Errorf("database: %s step %d is newer than this binary", c.Name, v)
			}
		}
		for _, m := range c.Migrations {
			if _, ok := applied[m.Version]; ok {
				continue
			}
			if err := step(ctx, conn, service, c.Name, m); err != nil {
				return err
			}
		}
	}
	return nil
}

// Check reports whether db holds exactly the migrations of comps, every step applied under its
// name and none this binary does not know. The service runs it at start as the service role,
// so a database nobody migrated (or migrated by another version) is refused before any work.
func Check(ctx context.Context, db *sql.DB, comps ...Component) error {
	for _, c := range comps {
		applied := map[int]string{}
		rows, err := db.QueryContext(ctx, `SELECT version, name FROM badger_meta.migrations WHERE component = $1`, c.Name)
		if err != nil {
			return fmt.Errorf("database: migrations cannot be read (was the schema migrated?): %w", err)
		}
		for rows.Next() {
			var v int
			var n string
			if err := rows.Scan(&v, &n); err != nil {
				rows.Close()
				return err
			}
			applied[v] = n
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, m := range c.Migrations {
			if n, ok := applied[m.Version]; !ok || n != m.Name {
				return fmt.Errorf("database: %s step %d (%s) is not applied", c.Name, m.Version, m.Name)
			}
		}
		if len(applied) != len(c.Migrations) {
			return fmt.Errorf("database: %s has steps this binary does not know", c.Name)
		}
	}
	return nil
}

// step applies one migration and its bookkeeping row in one transaction.
func step(ctx context.Context, conn *sql.Conn, service, component string, m Migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, strings.ReplaceAll(m.SQL, "{{service}}", service)); err != nil {
		return fmt.Errorf("database: %s step %d (%s): %w", component, m.Version, m.Name, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO badger_meta.migrations (component, version, name) VALUES ($1, $2, $3)`,
		component, m.Version, m.Name); err != nil {
		return err
	}
	return tx.Commit()
}

// Marked is the row-level security for a table with a label column: forced on its owner too,
// reads only of rows the session label dominates, inserts only at exactly the session label, and
// no update or delete at all (marked rows are append-only). Use it in the migration that creates
// the table.
func Marked(table string) string {
	return fmt.Sprintf(`
ALTER TABLE %[1]s ENABLE ROW LEVEL SECURITY;
ALTER TABLE %[1]s FORCE ROW LEVEL SECURITY;
CREATE POLICY read_down ON %[1]s FOR SELECT USING (badger.visible(label));
CREATE POLICY write_at_label ON %[1]s FOR INSERT WITH CHECK (badger.writable(label));
`, table)
}

// Dominates reports whether a system at a may hold content marked b: the marking package's rule,
// the one badger.dominates applies in the database.
func Dominates(a, b Label) bool {
	ma, oka := a.marking()
	mb, okb := b.marking()
	return oka && okb && marking.Dominates(ma, mb)
}

// marking is l's marking, if l is whole: its banner parses and gives exactly the lattice form
// transactions and row-level security use. A banner edited after parsing, or one with no lattice
// form, is not a label.
func (l Label) marking() (marking.Marking, bool) {
	m, err := marking.Parse(l.Banner)
	return m, err == nil && l.Valid() && string(LabelOf(m).lattice) == string(l.lattice)
}

// CheckService refuses a service connection that is more than the service role: connected as
// another role, as a superuser, as a role that bypasses row-level security, as the owner of the
// schema, or as a member of any other role (SET ROLE would hand it that role's privileges). Any of these would defeat the grants and the row-level security the
// stores rely on. The session's own role is checked, not only the current one: a privileged
// session that set the service role at connect (options=-c role=...) gets its privileges back
// with RESET ROLE.
func CheckService(ctx context.Context, db *sql.DB, role string) error {
	var user, session, owner string
	var super, bypass, owns, createrole, replication bool
	var memberships, owned int
	err := db.QueryRowContext(ctx, `SELECT current_user, session_user, r.rolsuper, r.rolbypassrls,
		coalesce((SELECT tableowner FROM pg_tables WHERE schemaname = 'badger_meta' AND tablename = 'migrations'), ''),
		coalesce(pg_has_role(session_user, (SELECT tableowner FROM pg_tables WHERE schemaname = 'badger_meta' AND tablename = 'migrations'), 'MEMBER'), false),
		(SELECT count(*) FROM pg_auth_members m WHERE m.member = r.oid),
		(SELECT count(*) FROM pg_class c WHERE c.relowner = r.oid) + (SELECT count(*) FROM pg_namespace n WHERE n.nspowner = r.oid) +
			(SELECT count(*) FROM pg_proc p WHERE p.proowner = r.oid) + (SELECT count(*) FROM pg_type ty WHERE ty.typowner = r.oid) +
			(SELECT count(*) FROM pg_database db WHERE db.datname = current_database() AND db.datdba = r.oid),
		r.rolcreaterole, r.rolreplication
		FROM pg_roles r WHERE r.rolname = session_user`).Scan(&user, &session, &super, &bypass, &owner, &owns, &memberships, &owned, &createrole, &replication)
	if err != nil {
		return fmt.Errorf("database: the service connection's role cannot be read: %w", err)
	}
	switch {
	case user != role || session != role:
		return fmt.Errorf("database: the service connection is role %q (session %q), not the configured service role %q", user, session, role)
	case super:
		return fmt.Errorf("database: the service role %q is a superuser", user)
	case bypass:
		return fmt.Errorf("database: the service role %q bypasses row-level security", user)
	case owns:
		return fmt.Errorf("database: the service role %q owns the schema (or is a member of its owner %q)", user, owner)
	case replication:
		// Replication (logical decoding) reads changes past row-level security.
		return fmt.Errorf("database: the service role %q has the replication attribute", user)
	case createrole:
		return fmt.Errorf("database: the service role %q can create roles", user)
	case owned > 0:
		// An owner can turn row-level security off and rewrite what it protects.
		return fmt.Errorf("database: the service role %q owns %d object(s) in this database (or the database itself); it must own none", user, owned)
	case memberships > 0:
		// SET ROLE would give it whatever another role holds, past every check above.
		return fmt.Errorf("database: the service role %q is a member of %d other role(s); it must hold its grants directly", user, memberships)
	}
	return nil
}

// RequireTLS refuses a connection string to another host that is not authenticated TLS
// (sslmode=verify-full, or verify-ca): marked records and signed profiles never cross the network
// in the clear, and a server is never trusted unverified. A loopback host is accepted as it is.
// plaintextOK, when set, names further hosts accepted without TLS (tests only).
func RequireTLS(dsn string, plaintextOK func(host string) bool) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return ErrUnsafeSettings
	}
	host := u.Hostname()
	if host == "" {
		// The driver would take the host from PGHOST, where this check cannot see it.
		return errors.New("database: the connection string names no host; name it, with sslmode=verify-full and sslrootcert=<the CA file that signed the server's certificate> unless it is loopback")
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	if plaintextOK != nil && plaintextOK(host) {
		return nil
	}
	switch u.Query().Get("sslmode") {
	case "verify-full", "verify-ca":
		return nil
	}
	return fmt.Errorf("database: the connection to %s is not authenticated TLS; set sslmode=verify-full and sslrootcert=<the CA file that signed the server's certificate> in the connection string", host)
}
