package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	broker "github.com/aflock-ai/badger/testifysec/model-broker"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb/pgtest"
)

// oldDataDir is a file-backed portal's data directory in which a real admin took the admin role
// over from the bootstrap subject, so the admin bootstrap is retired for good.
func oldDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "users"), 0o700)
	sum := sha256.Sum256([]byte("oidc\nidp-sub-real"))
	id := hex.EncodeToString(sum[:])
	os.WriteFile(filepath.Join(dir, "users", id+".json"), []byte(`{"id":"`+id+`","kind":"oidc","subject":"idp-sub-real",
		"role":"admin","status":"active","createdAt":"2026-10-01T12:00:00Z","createdBy":"idp-sub-admin","granted":["admin"],"deployments":[]}`), 0o600)
	os.WriteFile(filepath.Join(dir, "users", "bootstrap-ended-admin"), []byte("final "+id+"\n"), 0o600)
	return dir
}

func withImport(section, dir string) string {
	return strings.Replace(section, `"tenant_id"`, `"import_data_dir": "`+dir+`", "tenant_id"`, 1)
}

// Moving to the database keeps a retired bootstrap retired: the portal's data directory is
// imported at start, so the bootstrap subject named in the config gets no role, and the admin who
// replaced it keeps theirs.
func TestPortalImportKeepsRetiredBootstrapRetired(t *testing.T) {
	dir := t.TempDir()
	signingKey(t, filepath.Join(dir, "signing-key"))
	cfg, err := broker.LoadConfig(writeConfig(t, dir, "https://model.example.com/a", withImport(portalSection(dir), oldDataDir(t))))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := build(cfg, testDB(t))
	if err != nil {
		t.Fatal(err)
	}
	if w := do(svc.admin, "GET", "/admin/portal/api/v1/users", admin("idp-sub-admin"), ""); w.Code != 401 {
		t.Fatalf("the retired bootstrap subject is an admin again after the move: %d", w.Code)
	}
	if w := do(svc.admin, "GET", "/admin/portal/api/v1/users", admin("idp-sub-real"), ""); w.Code != 200 {
		t.Fatalf("the imported admin: %d %s", w.Code, w.Body)
	}
}

// A deployment moving its broker state must move the portal's with it, and an old portal
// data_dir is refused with what to do instead, never dropped silently.
func TestPortalImportRequiredWhenMigrating(t *testing.T) {
	dir := t.TempDir()
	signingKey(t, filepath.Join(dir, "signing-key"))
	for name, c := range map[string]struct{ section, extra string }{
		"broker imported, portal not": {portalSection(dir), `, "import_state_dir": "` + t.TempDir() + `"`},
		"old data_dir":                {strings.Replace(portalSection(dir), `"tenant_id"`, `"data_dir": "/var/lib/portal", "tenant_id"`, 1), ""},
	} {
		path := writeConfig(t, t.TempDir(), "https://model.example.com/a", c.section)
		raw, _ := os.ReadFile(path)
		os.WriteFile(path, []byte(strings.Replace(string(raw), `"ceiling_marking": "SECRET"`, `"ceiling_marking": "SECRET"`+c.extra, 1)), 0o600)
		cfg, err := broker.LoadConfig(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_, err = build(cfg, testDB(t))
		if err == nil || !strings.Contains(err.Error(), "import_data_dir") {
			t.Errorf("%s: %v, want a refusal naming portal.import_data_dir", name, err)
		}
		if name == "broker imported, portal not" && !strings.Contains(err.Error(), `portal.import "none"`) {
			t.Errorf("%s: %v, want the refusal to name portal.import \"none\" too", name, err)
		}
	}
}

func withNoImport(section string) string {
	return strings.Replace(section, `"tenant_id"`, `"import": "none", "tenant_id"`, 1)
}

// A deployment whose portal never ran file-backed has no portal data to import: it says so with
// portal.import "none". The broker's state is imported, the declaration is recorded as the
// portal's import, and an empty directory is never passed off as one.
func TestPortalImportNoneDeclared(t *testing.T) {
	d := pgtest.New(t)
	dir := t.TempDir()
	signingKey(t, filepath.Join(dir, "signing-key"))
	cfg, err := broker.LoadConfig(writeConfig(t, dir, "https://model.example.com/a", withNoImport(portalSection(dir))))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "dsn"), []byte(d.DSN+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "owner-dsn"), []byte(d.OwnerDSN+"\n"), 0o600)
	cfg.Database.OwnerDSNFile = filepath.Join(dir, "owner-dsn")
	state := t.TempDir() // a broker that never served a call: its ledger's start only
	os.MkdirAll(filepath.Join(state, "usage"), 0o700)
	os.WriteFile(filepath.Join(state, "usage", "opened"), []byte("2026-10-01T12:00:00Z\n"), 0o600)
	cfg.ImportStateDir = state
	db, err := openDatabase(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := build(cfg, db); err != nil {
		t.Fatalf("start with portal.import none: %v", err)
	}
	var brokerFrom, portalFrom string
	if err := db.QueryRow(`SELECT value FROM broker.meta WHERE key = 'imported_from'`).Scan(&brokerFrom); err != nil || brokerFrom != state {
		t.Fatalf("broker import record: %q %v", brokerFrom, err)
	}
	if err := db.QueryRow(`SELECT value FROM portal.meta WHERE key = 'imported_from'`).Scan(&portalFrom); err != nil ||
		portalFrom != "none (declared by config)" {
		t.Fatalf("portal import record: %q %v", portalFrom, err)
	}
	// Restarting with the same config changes nothing.
	if _, err := build(cfg, db); err != nil {
		t.Fatalf("restart with portal.import none: %v", err)
	}
	// Portal data offered later is refused, not imported a second time on top of the declaration.
	later, err := broker.LoadConfig(writeConfig(t, dir, "https://model.example.com/a", withImport(portalSection(dir), oldDataDir(t))))
	if err != nil {
		t.Fatal(err)
	}
	later.ImportStateDir = state
	if _, err := build(later, db); err == nil || !strings.Contains(err.Error(), `"none"`) {
		t.Fatalf("portal data imported after a none declaration: %v", err)
	}
}

// portal.import takes "none" only, and never together with import_data_dir.
func TestPortalImportNoneConfig(t *testing.T) {
	dir := t.TempDir()
	for name, section := range map[string]string{
		"other value": strings.Replace(portalSection(dir), `"tenant_id"`, `"import": "skip", "tenant_id"`, 1),
		"both":        withNoImport(withImport(portalSection(dir), t.TempDir())),
	} {
		if _, err := parsePortal([]byte(section)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
