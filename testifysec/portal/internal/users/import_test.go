package users

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb/pgtest"
	"github.com/aflock-ai/badger/testifysec/portal/internal/auth"
	"github.com/aflock-ai/badger/testifysec/portal/internal/store"
)

var importLabel = func() pgdb.Label {
	l, err := pgdb.ParseLabel("SECRET")
	if err != nil {
		panic(err)
	}
	return l
}()

func hexOf(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// writeDataDir writes a portal data directory as the file-backed portal left it: one signed
// profile version, an assignment, a two-record audit chain, an admin who took over from the
// bootstrap subject (so the admin bootstrap is retired for good), and a decided role request.
func writeDataDir(t *testing.T, dir string) (adminID string) {
	t.Helper()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, d := range []string{"profiles/profile-a", "deployments", "users", "role-requests"} {
		os.MkdirAll(filepath.Join(dir, d), 0o700)
	}
	v, _ := json.Marshal(store.Version{ProfileID: "profile-a", TenantID: "tenant-example", DeploymentID: "deploy-a", Sequence: 1,
		PayloadSHA256: strings.Repeat("a", 64), EnvelopeSHA256: strings.Repeat("b", 64), CreatedAt: now, CreatedBy: "admin",
		Envelope: json.RawMessage(`{"payload":"e30","signatures":[]}`)})
	os.WriteFile(filepath.Join(dir, "profiles", "profile-a", "00000000000000000001.json"), v, 0o600)
	a, _ := json.Marshal(store.Assignment{DeploymentID: "deploy-a", ProfileID: "profile-a", Sequence: 1,
		PayloadSHA256: strings.Repeat("a", 64), AssignedAt: now, AssignedBy: "admin"})
	os.WriteFile(filepath.Join(dir, "deployments", "deploy-a.json"), a, 0o600)
	prev, lines := strings.Repeat("0", 64), ""
	for _, r := range []store.Record{
		{Time: now, Actor: "boot", Role: "admin", Action: "user.provision", Object: "user"},
		{Time: now, Actor: "boot", Role: "admin", Action: "profile.publish", Object: "profile-a"},
	} {
		r.Prev = prev
		line, _ := json.Marshal(r)
		lines += string(line) + "\n"
		prev = hexOf(string(line))
	}
	os.WriteFile(filepath.Join(dir, "audit.jsonl"), []byte(lines), 0o600)
	adminID = hexOf("idp|subject-admin")
	u, _ := json.Marshal(User{ID: adminID, Kind: KindIdP, Subject: "subject-admin", Role: auth.Admin, Status: Active,
		Granted: []auth.Role{auth.Admin}})
	os.WriteFile(filepath.Join(dir, "users", adminID+".json"), u, 0o600)
	os.WriteFile(filepath.Join(dir, "users", "bootstrap-ended-admin"), []byte("final "+adminID+"\n"), 0o600)
	reqID := strings.Repeat("c", 32)
	rq, _ := json.Marshal(Request{ID: reqID, Kind: "grant", UserID: adminID, RequesterID: adminID, RequestedBy: "boot",
		Role: auth.Admin, Status: Approved, DecidedBy: "approver"})
	os.WriteFile(filepath.Join(dir, "role-requests", reqID+".json"), rq, 0o600)
	return adminID
}

// The import carries the file-backed portal's state over: profiles byte for byte, assignments,
// the audit chain (it verifies and continues), the directory, and the bootstrap markers, so a
// bootstrap subject retired before the move stays retired after it. It runs once.
func TestImportDataDir(t *testing.T) {
	_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	dir := t.TempDir()
	adminID := writeDataDir(t, dir)
	rep, err := ImportFiles(context.Background(), db, importLabel, dir)
	if err != nil || !rep.Imported {
		t.Fatalf("import: %+v %v", rep, err)
	}
	want := ImportReport{Imported: true, ProfileVersions: 1, Assignments: 1, Audit: 2, Users: 1, RoleRequests: 1, BootstrapMarkers: 1}
	if rep != want {
		t.Fatalf("report %+v, want %+v", rep, want)
	}
	pg := NewPG(db, importLabel)
	if ended, err := pg.BootstrapEnded(auth.Admin); err != nil || !ended {
		t.Fatalf("the retired admin bootstrap is live again after the import: %v %v", ended, err)
	}
	if u, ok, err := pg.User(adminID); err != nil || !ok || u.Role != auth.Admin {
		t.Fatalf("imported admin: %+v %v %v", u, ok, err)
	}
	profiles := store.NewPG(db, importLabel)
	if err := profiles.Verify(); err != nil {
		t.Fatalf("imported audit chain: %v", err)
	}
	if err := profiles.Append(store.Record{Actor: "u", Action: "after.import"}); err != nil || profiles.Verify() != nil {
		t.Fatalf("the chain does not continue past the import: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "profiles", "profile-a", "00000000000000000001.json"))
	if v, ok, err := profiles.Get("profile-a", 1); err != nil || !ok || string(v.Envelope) != `{"payload":"e30","signatures":[]}` {
		t.Fatalf("imported profile: %+v %v %v (file %s)", v, ok, err, raw)
	}
	if rep, err := ImportFiles(context.Background(), db, importLabel, dir); err != nil || rep.Imported {
		t.Fatalf("second import: %+v %v", rep, err)
	}
}

// The portal import refuses, as the broker's does, anything that would lose or merge state, and
// leaves the database untouched so the corrected import still runs.
func TestImportDataDirRefuses(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string) string{
		"missing directory": func(t *testing.T, dir string) string { return filepath.Join(dir, "absent") },
		"empty directory":   func(t *testing.T, dir string) string { return t.TempDir() },
		"broken chain": func(t *testing.T, dir string) string {
			raw, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
			os.WriteFile(filepath.Join(dir, "audit.jsonl"), []byte(strings.Replace(string(raw), "user.provision", "user.sneak", 1)), 0o600)
			return dir
		},
		"damaged marker": func(t *testing.T, dir string) string {
			os.WriteFile(filepath.Join(dir, "users", "bootstrap-ended-admin"), []byte("final nobody\n"), 0o600)
			return dir
		},
		"damaged user": func(t *testing.T, dir string) string {
			os.WriteFile(filepath.Join(dir, "users", hexOf("x")+".json"), []byte(`{}`), 0o600)
			return dir
		},
		"stray file": func(t *testing.T, dir string) string {
			os.WriteFile(filepath.Join(dir, "users", ".put-123"), []byte(`{}`), 0o600)
			return dir
		},
		"profile under another name": func(t *testing.T, dir string) string {
			os.Rename(filepath.Join(dir, "profiles", "profile-a"), filepath.Join(dir, "profiles", "profile-z"))
			return dir
		},
		"users under another name": func(t *testing.T, dir string) string {
			os.Rename(filepath.Join(dir, "users"), filepath.Join(dir, "users.bak"))
			return dir
		},
		"users a dangling link": func(t *testing.T, dir string) string {
			os.RemoveAll(filepath.Join(dir, "users"))
			os.Symlink(filepath.Join(dir, "gone"), filepath.Join(dir, "users"))
			return dir
		},
		"the directory a link": func(t *testing.T, dir string) string {
			link := filepath.Join(t.TempDir(), "data")
			os.Symlink(dir, link)
			return link
		},
		"the directory a link, named with a slash": func(t *testing.T, dir string) string {
			link := filepath.Join(t.TempDir(), "data")
			os.Symlink(dir, link)
			return link + "/"
		},
		"the directory a link, named with /.": func(t *testing.T, dir string) string {
			link := filepath.Join(t.TempDir(), "data")
			os.Symlink(dir, link)
			return link + "/."
		},
		"users unlistable": func(t *testing.T, dir string) string {
			os.Chmod(filepath.Join(dir, "users"), 0o300)
			t.Cleanup(func() { os.Chmod(filepath.Join(dir, "users"), 0o700) })
			return dir
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
			dir := t.TempDir()
			writeDataDir(t, dir)
			if rep, err := ImportFiles(context.Background(), db, importLabel, breakIt(t, dir)); err == nil {
				t.Fatalf("import succeeded: %+v", rep)
			}
			good := t.TempDir()
			writeDataDir(t, good)
			if rep, err := ImportFiles(context.Background(), db, importLabel, good); err != nil || !rep.Imported {
				t.Fatalf("the corrected import: %+v %v", rep, err)
			}
		})
	}
	t.Run("database holds state", func(t *testing.T) {
		_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
		if err := NewPG(db, importLabel).PutUser(User{ID: hexOf("idp|someone"), Kind: KindIdP, Subject: "someone", Status: Pending}); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		writeDataDir(t, dir)
		if rep, err := ImportFiles(context.Background(), db, importLabel, dir); err == nil {
			t.Fatalf("import merged into a directory with users of its own: %+v", rep)
		}
	})
}

// A data directory that changes while it is copied (the file-backed portal still running and
// retiring a bootstrap subject meanwhile) is refused, not imported half old and half new.
func TestImportRefusesADirectoryThatChangesDuringTheCopy(t *testing.T) {
	_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	dir := t.TempDir()
	writeDataDir(t, dir)
	afterImportStep = func(step string) {
		if step == "users" {
			os.WriteFile(filepath.Join(dir, "users", "bootstrap-ended-approver"), []byte("final "+hexOf("idp|late")+"\n"), 0o600)
		}
	}
	t.Cleanup(func() { afterImportStep = nil })
	if rep, err := ImportFiles(context.Background(), db, importLabel, dir); err == nil {
		t.Fatalf("imported a directory that changed during the copy: %+v", rep)
	}
}

// A directory moved away after the top-level check (users/ taken out of the data directory) is
// seen at the end, because the baseline was taken before the check: the import refuses rather
// than import no users and no bootstrap markers.
func TestImportSeesAMoveAfterTheTopLevelCheck(t *testing.T) {
	_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	dir := t.TempDir()
	writeDataDir(t, dir)
	away := filepath.Join(t.TempDir(), "users")
	afterImportStep = func(step string) {
		if step == "validated" {
			os.Rename(filepath.Join(dir, "users"), away)
		}
	}
	t.Cleanup(func() { afterImportStep = nil })
	if rep, err := ImportFiles(context.Background(), db, importLabel, dir); err == nil {
		t.Fatalf("imported after users/ was moved away mid-import: %+v", rep)
	}
}

// A volume's lost+found, which the broker cannot read, is left alone: it is not portal state.
func TestImportIgnoresAnUnreadableLostAndFound(t *testing.T) {
	_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	dir := t.TempDir()
	writeDataDir(t, dir)
	lf := filepath.Join(dir, "lost+found")
	os.Mkdir(lf, 0o700)
	os.WriteFile(filepath.Join(lf, "#123"), []byte("x"), 0o600)
	os.Chmod(lf, 0)
	t.Cleanup(func() { os.Chmod(lf, 0o700) })
	if rep, err := ImportFiles(context.Background(), db, importLabel, dir); err != nil || !rep.Imported {
		t.Fatalf("import beside an unreadable lost+found: %+v %v", rep, err)
	}
}

// A record with anything after its one JSON value is refused, closing brackets included.
func TestStrictJSONRefusesTrailingData(t *testing.T) {
	for _, raw := range []string{`{"a":1}}`, `{"a":1}]`, `{"a":1} {}`, `{"a":1} x`} {
		var v map[string]any
		if strictJSON([]byte(raw), &v) == nil {
			t.Errorf("%s accepted", raw)
		}
	}
	var v map[string]any
	if err := strictJSON([]byte("{\"a\":1}\n"), &v); err != nil {
		t.Errorf("a record with a final newline: %v", err)
	}
}

// A file or directory replaced by a FIFO after the check is refused, not opened for reading: that
// would block the import and its transaction forever.
func TestImportRefusesAFIFOSwappedInAfterTheCheck(t *testing.T) {
	for _, name := range []string{"audit.jsonl", "users", "profiles"} {
		t.Run(name, func(t *testing.T) {
			_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
			dir := t.TempDir()
			writeDataDir(t, dir)
			afterImportStep = func(step string) {
				if step == "validated" {
					os.RemoveAll(filepath.Join(dir, name))
					if err := syscall.Mkfifo(filepath.Join(dir, name), 0o600); err != nil {
						t.Error(err)
					}
				}
			}
			t.Cleanup(func() { afterImportStep = nil })
			done := make(chan error, 1)
			go func() {
				_, err := ImportFiles(context.Background(), db, importLabel, dir)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("imported with a FIFO in place of " + name)
				}
			case <-time.After(20 * time.Second):
				if w, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY, 0); err == nil {
					w.Close()
				}
				t.Fatal("the import blocked opening a FIFO")
			}
		})
	}
}

// An entry the check saw must still be there when it is read: users/ moved out after the check
// and back after the copy (so every fingerprint matches) stops the import, which would otherwise
// commit with no users and no bootstrap markers.
func TestImportRefusesAnEntryAwayDuringTheCopy(t *testing.T) {
	_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	dir := t.TempDir()
	writeDataDir(t, dir)
	away := filepath.Join(t.TempDir(), "users")
	afterImportStep = func(step string) {
		switch step {
		case "validated":
			os.Rename(filepath.Join(dir, "users"), away)
		case "requests":
			os.Rename(away, filepath.Join(dir, "users"))
		}
	}
	t.Cleanup(func() { afterImportStep = nil })
	if rep, err := ImportFiles(context.Background(), db, importLabel, dir); err == nil {
		t.Fatalf("imported while users/ was away: %+v", rep)
	}
}

// A directory swapped for an empty one after the check and put back after the copy (so the final
// fingerprint matches) is refused: what is opened must be the very directory the baseline
// recorded, or the import would commit with no users and no bootstrap markers.
func TestImportRefusesADirectorySwappedAndRestored(t *testing.T) {
	_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	dir := t.TempDir()
	writeDataDir(t, dir)
	users, aside := filepath.Join(dir, "users"), filepath.Join(t.TempDir(), "users")
	afterImportStep = func(step string) {
		switch step {
		case "validated":
			os.Rename(users, aside)
			os.Mkdir(users, 0o700)
		case "requests":
			os.Remove(users)
			os.Rename(aside, users)
		}
	}
	t.Cleanup(func() { afterImportStep = nil })
	if rep, err := ImportFiles(context.Background(), db, importLabel, dir); err == nil {
		t.Fatalf("imported while users/ was swapped for an empty directory: %+v", rep)
	}
}

// A file edited in place after the baseline (same inode and size, modification time put back) and
// restored before the end is refused: what is imported must be the bytes the baseline saw.
func TestImportRefusesAnInPlaceEditRestored(t *testing.T) {
	_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	dir := t.TempDir()
	writeDataDir(t, dir)
	p := filepath.Join(dir, "role-requests", strings.Repeat("c", 32)+".json")
	orig, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	edit := func(b []byte) {
		w, err := os.OpenFile(p, os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
			return
		}
		w.WriteAt(b, 0)
		w.Close()
		os.Chtimes(p, fi.ModTime(), fi.ModTime())
	}
	changed := bytes.Replace(orig, []byte(`"approver"`), []byte(`"approvex"`), 1)
	if bytes.Equal(changed, orig) {
		t.Fatalf("fixture changed: %s", orig)
	}
	afterImportStep = func(step string) {
		switch step {
		case "validated":
			edit(changed)
		case "requests":
			edit(orig)
		}
	}
	t.Cleanup(func() { afterImportStep = nil })
	if rep, err := ImportFiles(context.Background(), db, importLabel, dir); err == nil {
		t.Fatalf("imported a request edited in place during the copy: %+v", rep)
	}
}

// Every entry moved out of users/ after the baseline (the directory's modification time put back)
// and returned after the copy is refused: a listing must hold exactly what the baseline saw, or the
// import would commit with no users and no bootstrap markers.
func TestImportRefusesAListingMissingABaselineEntry(t *testing.T) {
	_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	dir := t.TempDir()
	writeDataDir(t, dir)
	users, aside := filepath.Join(dir, "users"), t.TempDir()
	fi, _ := os.Stat(users)
	move := func(from, to string) {
		ents, _ := os.ReadDir(from)
		for _, e := range ents {
			os.Rename(filepath.Join(from, e.Name()), filepath.Join(to, e.Name()))
		}
		os.Chtimes(users, fi.ModTime(), fi.ModTime())
	}
	afterImportStep = func(step string) {
		switch step {
		case "validated":
			move(users, aside)
		case "requests":
			move(aside, users)
		}
	}
	t.Cleanup(func() { afterImportStep = nil })
	if rep, err := ImportFiles(context.Background(), db, importLabel, dir); err == nil {
		t.Fatalf("imported with users/ emptied during the copy: %+v", rep)
	}
}

// An import waiting for another replica's import lock gives up when its context ends: startup
// has a deadline, and a wait on the lock that ignored it would hold the process past it.
func TestImportWaitingOnTheLockHonoursItsContext(t *testing.T) {
	_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	dir := t.TempDir()
	writeDataDir(t, dir)
	holder, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.Exec(`SELECT pg_advisory_xact_lock($1)`, importLock); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := ImportFiles(ctx, db, importLabel, dir)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("imported while another transaction held the import lock")
		}
	case <-time.After(15 * time.Second):
		holder.Rollback() // let the blocked import finish so the test can end
		<-done
		t.Fatal("the import kept waiting on the lock after its context ended")
	}
}

// A data directory with nothing in it to import (an empty users/ and an empty audit log) is
// refused, never recorded as imported: the real directory could not be imported after it.
func TestImportRefusesADirectoryWithNoRecords(t *testing.T) {
	_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	empty := t.TempDir()
	os.Mkdir(filepath.Join(empty, "users"), 0o700)
	os.WriteFile(filepath.Join(empty, "audit.jsonl"), nil, 0o600)
	if rep, err := ImportFiles(context.Background(), db, importLabel, empty); err == nil {
		t.Fatalf("imported a directory with no records: %+v", rep)
	}
	good := t.TempDir()
	writeDataDir(t, good)
	if rep, err := ImportFiles(context.Background(), db, importLabel, good); err != nil || !rep.Imported {
		t.Fatalf("the corrected import: %+v %v", rep, err)
	}
}

// Signed profiles with no audit log are refused inside the import, as the store refuses them at
// start: committed, they would stop every start with no way to import the corrected directory.
func TestImportRefusesProfilesWithoutAnAuditLog(t *testing.T) {
	_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	dir := t.TempDir()
	writeDataDir(t, dir)
	os.Remove(filepath.Join(dir, "audit.jsonl"))
	if rep, err := ImportFiles(context.Background(), db, importLabel, dir); err == nil {
		t.Fatalf("imported signed profiles with no audit log: %+v", rep)
	}
	good := t.TempDir()
	writeDataDir(t, good)
	if rep, err := ImportFiles(context.Background(), db, importLabel, good); err != nil || !rep.Imported {
		t.Fatalf("the corrected import: %+v %v", rep, err)
	}
}

// A replica writing while another imports waits for the import: an audit record appended after
// the import checked the database was empty would otherwise be left behind a head the import
// reset, and the store would refuse to start with the import already recorded.
func TestImportExcludesConcurrentWrites(t *testing.T) {
	_, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	dir := t.TempDir()
	writeDataDir(t, dir)
	os.WriteFile(filepath.Join(dir, "audit.jsonl"), nil, 0o600) // users, no audit records
	os.RemoveAll(filepath.Join(dir, "profiles"))
	os.RemoveAll(filepath.Join(dir, "deployments"))
	other := store.NewPG(db, importLabel)
	appended := make(chan error, 1)
	waiting := func() bool {
		var n int
		db.QueryRow(`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted
			AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&n)
		return n > 0
	}
	afterImportStep = func(step string) {
		if step != "validated" {
			return
		}
		afterImportStep = nil
		go func() {
			appended <- other.Append(store.Record{Time: time.Now().UTC(), Actor: "x", Role: "admin", Action: "user.provision", Object: "user"})
		}()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case err := <-appended:
				appended <- err
				return // the append did not wait for the import
			case <-deadline:
				return
			case <-time.After(10 * time.Millisecond):
				if waiting() {
					return
				}
			}
		}
	}
	t.Cleanup(func() { afterImportStep = nil })
	_, err := ImportFiles(context.Background(), db, importLabel, dir)
	if aerr := <-appended; aerr != nil {
		t.Fatalf("append: %v", aerr)
	}
	if err == nil {
		if verr := other.Verify(); verr != nil {
			t.Fatalf("the import was recorded but the store now refuses to start: %v", verr)
		}
	}
}
