package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	broker "github.com/aflock-ai/badger/testifysec/model-broker"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb/pgtest"
)

// The service migrates its schema with the owner role at start and then works as the service
// role, which holds grants only; a connection string it cannot read, or a database it cannot
// reach, stops it.
func TestOpenDatabaseMigratesAndConnects(t *testing.T) {
	d := pgtest.New(t)
	dir := t.TempDir()
	cfg, err := broker.LoadConfig(writeConfig(t, dir, "https://model.example.com/a", ""))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "dsn"), []byte(d.DSN+"\n"), 0o600)
	cfg.Database.OwnerDSNFile = filepath.Join(dir, "owner-dsn")
	if _, err := openDatabase(context.Background(), cfg); err == nil {
		t.Fatal("started without its owner connection string file")
	}
	os.WriteFile(cfg.Database.OwnerDSNFile, []byte(d.OwnerDSN+"\n"), 0o600)
	db, err := openDatabase(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM broker.audit_head`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the service role cannot read the migrated schema: %d %v", n, err)
	}
	if _, err := db.Exec(`ALTER TABLE broker.audit_head ADD COLUMN x int`); err == nil {
		t.Fatal("the service role can change the schema")
	}
	os.WriteFile(filepath.Join(dir, "dsn"), []byte("postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1\n"), 0o600)
	cfg.Database.OwnerDSNFile = ""
	if db, err := openDatabase(context.Background(), cfg); err == nil {
		db.Close()
		t.Fatal("started on a database it cannot reach")
	}
}

// import_state_dir is acted on at start, never ignored: a directory that holds no broker state
// stops the service instead of starting it on an empty database.
func TestOpenDatabaseRunsTheImport(t *testing.T) {
	d := pgtest.New(t)
	dir := t.TempDir()
	cfg, err := broker.LoadConfig(writeConfig(t, dir, "https://model.example.com/a", ""))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "dsn"), []byte(d.DSN+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "owner-dsn"), []byte(d.OwnerDSN+"\n"), 0o600)
	cfg.Database.OwnerDSNFile = filepath.Join(dir, "owner-dsn")
	cfg.ImportStateDir = t.TempDir()
	if db, err := openDatabase(context.Background(), cfg); err == nil {
		db.Close()
		t.Fatal("started with an import_state_dir that holds no broker state")
	}
}

// Without owner_dsn_file the service migrates nothing itself, so it checks the schema is there:
// a reachable database nobody migrated stops it.
func TestOpenDatabaseRefusesAnUnmigratedDatabase(t *testing.T) {
	d := pgtest.New(t)
	dir := t.TempDir()
	cfg, err := broker.LoadConfig(writeConfig(t, dir, "https://model.example.com/a", ""))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "dsn"), []byte(d.DSN+"\n"), 0o600)
	if db, err := openDatabase(context.Background(), cfg); err == nil {
		db.Close()
		t.Fatal("started on a database with no schema")
	}
}

// The service connection must be the configured service role and nothing more: an owner of the
// schema, a superuser or a role that bypasses row-level security would defeat the grants and the
// row-level security the store relies on, so each stops the service at start.
func TestOpenDatabaseRefusesAPrivilegedServiceConnection(t *testing.T) {
	d := pgtest.New(t)
	su, err := url.Parse(os.Getenv("BADGER_TEST_PG"))
	if err != nil {
		t.Fatal(err)
	}
	su.Path = "/" + d.Name
	raw := make([]byte, 4)
	rand.Read(raw)
	bypass := "bt_bypass_" + hex.EncodeToString(raw)
	d.Super(t, `CREATE ROLE `+bypass+` LOGIN BYPASSRLS NOSUPERUSER`)
	d.Super(t, `GRANT CONNECT ON DATABASE `+d.Name+` TO `+bypass)
	t.Cleanup(func() { d.SuperErr("DR" + "OP OWNED BY " + bypass); d.SuperErr("DR" + "OP ROLE IF EXISTS " + bypass) })
	replicator := "bt_repl_" + hex.EncodeToString(raw)
	d.Super(t, `CREATE ROLE `+replicator+` LOGIN REPLICATION NOSUPERUSER NOBYPASSRLS`)
	d.Super(t, `GRANT CONNECT ON DATABASE `+d.Name+` TO `+replicator)
	t.Cleanup(func() {
		d.SuperErr("DR" + "OP OWNED BY " + replicator)
		d.SuperErr("DR" + "OP ROLE IF EXISTS " + replicator)
	})
	creator := "bt_creator_" + hex.EncodeToString(raw)
	d.Super(t, `CREATE ROLE `+creator+` LOGIN CREATEROLE NOSUPERUSER NOBYPASSRLS`)
	d.Super(t, `GRANT CONNECT ON DATABASE `+d.Name+` TO `+creator)
	t.Cleanup(func() { d.SuperErr("DR" + "OP OWNED BY " + creator); d.SuperErr("DR" + "OP ROLE IF EXISTS " + creator) })
	asUser := func(user string) string {
		u, _ := url.Parse(d.DSN)
		u.User = url.User(user)
		return u.String()
	}
	for name, c := range map[string]struct{ dsn, role string }{
		"the owner":        {d.OwnerDSN, pgtest.Service},
		"a superuser":      {su.String(), pgtest.Service},
		"bypasses RLS":     {asUser(bypass), bypass},
		"can create roles": {asUser(creator), creator},
		"replication":      {asUser(replicator), replicator},
		"another role":     {asUser(pgtest.Owner), pgtest.Service},
		// A superuser session that sets the service role at connect: current_user looks right,
		// but RESET ROLE gives the superuser back.
		"a superuser as the service role":                           {withOptions(su, "-c role="+pgtest.Service), pgtest.Service},
		"a superuser with the service role's session authorization": {withOptions(su, "-c session_authorization="+pgtest.Service), pgtest.Service},
		"a superuser with session_authorization as a parameter":     {withParam(su, "session_authorization", pgtest.Service), pgtest.Service},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg, err := broker.LoadConfig(writeConfig(t, dir, "https://model.example.com/a", ""))
			if err != nil {
				t.Fatal(err)
			}
			cfg.Database.ServiceRole = c.role
			os.WriteFile(filepath.Join(dir, "dsn"), []byte(c.dsn+"\n"), 0o600)
			os.WriteFile(filepath.Join(dir, "owner-dsn"), []byte(d.OwnerDSN+"\n"), 0o600)
			cfg.Database.OwnerDSNFile = filepath.Join(dir, "owner-dsn")
			if db, err := openDatabase(context.Background(), cfg); err == nil {
				db.Close()
				t.Fatal("started on a privileged service connection")
			}
		})
	}
	// The service role itself still starts.
	dir := t.TempDir()
	cfg, err := broker.LoadConfig(writeConfig(t, dir, "https://model.example.com/a", ""))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "dsn"), []byte(d.DSN+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "owner-dsn"), []byte(d.OwnerDSN+"\n"), 0o600)
	cfg.Database.OwnerDSNFile = filepath.Join(dir, "owner-dsn")
	db, err := openDatabase(context.Background(), cfg)
	if err != nil {
		t.Fatalf("the service role: %v", err)
	}
	db.Close()
}

// withOptions is u with the libpq options parameter set.
func withOptions(u *url.URL, options string) string { return withParam(u, "options", options) }

// withParam is u with one more connection parameter.
func withParam(u *url.URL, k, v string) string {
	c := *u
	q := c.Query()
	q.Set(k, v)
	c.RawQuery = q.Encode()
	return c.String()
}

// A service role that is a member of another role is refused: SET ROLE would give it whatever
// that role holds (here BYPASSRLS), past every check made on the service role itself.
func TestOpenDatabaseRefusesAServiceRoleWithMemberships(t *testing.T) {
	d := pgtest.New(t)
	raw := make([]byte, 4)
	rand.Read(raw)
	priv, member := "bt_priv_"+hex.EncodeToString(raw), "bt_member_"+hex.EncodeToString(raw)
	d.Super(t, `CREATE ROLE `+priv+` NOLOGIN BYPASSRLS`)
	d.Super(t, `CREATE ROLE `+member+` LOGIN NOSUPERUSER NOBYPASSRLS`)
	d.Super(t, `GRANT `+priv+` TO `+member)
	d.Super(t, `GRANT CONNECT ON DATABASE `+d.Name+` TO `+member)
	t.Cleanup(func() {
		d.SuperErr("DR" + "OP OWNED BY " + member)
		d.SuperErr("DR" + "OP ROLE IF EXISTS " + member)
		d.SuperErr("DR" + "OP ROLE IF EXISTS " + priv)
	})
	u, _ := url.Parse(d.DSN)
	u.User = url.User(member)
	dir := t.TempDir()
	cfg, err := broker.LoadConfig(writeConfig(t, dir, "https://model.example.com/a", ""))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database.ServiceRole = member
	os.WriteFile(filepath.Join(dir, "dsn"), []byte(u.String()+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "owner-dsn"), []byte(d.OwnerDSN+"\n"), 0o600)
	cfg.Database.OwnerDSNFile = filepath.Join(dir, "owner-dsn")
	if db, err := openDatabase(context.Background(), cfg); err == nil {
		db.Close()
		t.Fatal("started with a service role that can SET ROLE to a role bypassing row-level security")
	}
}

// A service role that owns any of the service's objects is refused, whoever owns the migration
// table: an owner can turn row-level security off and rewrite the records it protects.
func TestOpenDatabaseRefusesAServiceRoleOwningAnObject(t *testing.T) {
	for _, table := range []string{"broker.audit", "portal.profile_versions"} {
		t.Run(table, func(t *testing.T) {
			d := pgtest.New(t)
			dir := t.TempDir()
			cfg, err := broker.LoadConfig(writeConfig(t, dir, "https://model.example.com/a", ""))
			if err != nil {
				t.Fatal(err)
			}
			os.WriteFile(filepath.Join(dir, "dsn"), []byte(d.DSN+"\n"), 0o600)
			os.WriteFile(filepath.Join(dir, "owner-dsn"), []byte(d.OwnerDSN+"\n"), 0o600)
			cfg.Database.OwnerDSNFile = filepath.Join(dir, "owner-dsn")
			db, err := openDatabase(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			db.Close()
			d.Super(t, `ALTER TABLE `+table+` OWNER TO `+pgtest.Service)
			cfg.Database.OwnerDSNFile = ""
			if db, err := openDatabase(context.Background(), cfg); err == nil {
				db.Close()
				t.Fatalf("started with the service role owning %s", table)
			}
		})
	}
}
