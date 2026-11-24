package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writeState writes a broker state directory as the file-backed broker left it.
func writeState(t *testing.T, dir string, entries []Entry, now time.Time) {
	t.Helper()
	os.MkdirAll(filepath.Join(dir, "versions"), 0o700)
	os.MkdirAll(filepath.Join(dir, "usage"), 0o700)
	v := Version{N: 1, Entries: entries, Author: "operator:seed", Comment: "seed policy", Created: now.UTC(), SHA256: entriesHash(entries)}
	raw, _ := json.MarshalIndent(v, "", " ")
	os.WriteFile(filepath.Join(dir, "versions", "00000001.json"), raw, 0o400)
	var lines []string
	prev := ""
	for i, r := range []AuditRecord{
		{Time: v.Created, Kind: "write", Actor: v.Author, Version: 1, Comment: v.Comment, SHA256: v.SHA256, Added: entries},
		{Time: now, Kind: "decision", Decision: "allow", Principal: entries[len(entries)-1].Principal(), Version: 1},
		{Time: now, Kind: "propose", Actor: "u1", Version: 1, Proposal: 1, Entries: entries[:1]},
	} {
		r.Seq, r.Prev = int64(i+1), prev
		line, _ := json.Marshal(r)
		lines = append(lines, string(line))
		prev = sha256hex(line)
	}
	os.WriteFile(filepath.Join(dir, "audit.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	owners := map[string]string{}
	for _, e := range entries {
		owners[e.ID] = "alice@example.com"
	}
	raw, _ = json.Marshal(OwnerSet{Version: 3, Owners: owners})
	os.WriteFile(filepath.Join(dir, "owners.json"), raw, 0o600)
	os.WriteFile(filepath.Join(dir, "quotas.json"), []byte(`{"version":2,"default_usd":null,"principals":{"alice@example.com":7}}`), 0o600)
	raw, _ = json.Marshal([]TokenRec{{Workspace: "ws-old", Hash: hashToken("bbt_imported"), Principal: "alice@example.com", Expires: now.Add(time.Hour)}})
	os.WriteFile(filepath.Join(dir, "tokens.json"), raw, 0o600)
	os.WriteFile(filepath.Join(dir, "usage", "opened"), []byte(now.Add(-48*time.Hour).UTC().Format(time.RFC3339)+"\n"), 0o600)
	day := now.UTC().Format("2006-01-02")
	usd := 1.5
	recs := []usageRecord{
		{Time: now, Principal: "alice@example.com", Model: "model-a", ID: "a1", Pending: true},
		{Time: now, Principal: "alice@example.com", Model: "model-a", Prompt: 10, Completion: 5, ID: "a1", ChargedUSD: &usd},
		{Time: now, Principal: "bob@example.com", Model: "model-a", ID: "b1", Pending: true}, // never finished
	}
	var ul []string
	for _, r := range recs {
		b, _ := json.Marshal(r)
		ul = append(ul, string(b))
	}
	os.WriteFile(filepath.Join(dir, "usage", day+".jsonl"), []byte(strings.Join(ul, "\n")+"\n"), 0o600)
}

// The one-time import carries a file-backed broker's state over intact: policy (with issuers and
// issuer-qualified principals), the unbroken audit chain, open proposals, owners, quotas, tokens
// and the usage ledger. It runs once, and never merges into a database with state of its own.
func TestImportStateDirectory(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	entries := append([]Entry{}, c.Entries...)
	other := entries[0]
	other.ID, other.Issuer = "other-issuer", "gitlab-2"
	entries = append(entries, other)
	dir := t.TempDir()
	now := testNow.UTC()
	writeState(t, dir, entries, now)

	db := testLedger(t)
	rep, err := ImportState(context.Background(), db, f.cfg, dir)
	if err != nil || !rep.Imported {
		t.Fatalf("import: %+v %v", rep, err)
	}
	s := OpenStore(db, f.cfg.Ceiling(), f.cfg.Operator())
	if s.broken != nil {
		t.Fatalf("imported store fails its checks: %v", s.broken)
	}
	v := s.Active()
	if v == nil || v.N != 1 || entriesHash(v.Entries) != entriesHash(entries) {
		t.Fatalf("active policy after import: %+v", v)
	}
	if p := v.Entries[len(v.Entries)-1].Principal(); p != "ci:gitlab-2:"+other.ProjectPath {
		t.Fatalf("issuer-qualified principal %q", p)
	}
	if ps := s.OpenProposals(); len(ps) != 1 || ps[0].ID != 1 {
		t.Fatalf("proposals %+v", ps)
	}
	recs, err := s.AuditAfter(0, 10)
	if err != nil || len(recs) != 3 || recs[2].Kind != "propose" {
		t.Fatalf("audit %+v %v", recs, err)
	}
	// The chain continues past the import.
	if err := s.Audit(AuditRecord{Kind: "refused", Reason: "x"}); err != nil {
		t.Fatal(err)
	}
	if OpenStore(db, f.cfg.Ceiling(), f.cfg.Operator()).broken != nil {
		t.Fatal("chain broken after a write past the import")
	}
	docs := documents{db: db, label: f.cfg.Ceiling()}
	if o, err := (&ownerBook{docs: docs}).current(); err != nil || o.Version != 3 || o.Owners["other-issuer"] != "alice@example.com" {
		t.Fatalf("owners %+v %v", o, err)
	}
	if q, err := (&quotaBook{docs: docs}).current(); err != nil || q.Version != 2 || q.Principals["alice@example.com"] != 7 {
		t.Fatalf("quotas %+v %v", q, err)
	}
	if p, ok := openTokens(db, f.cfg.Ceiling()).Auth("bbt_imported", f.cfg.HumanPrincipals, now); !ok || p != "alice@example.com" {
		t.Fatal("imported token does not authenticate")
	}
	u := openUsage(db, f.cfg.Ceiling(), now)
	if got, err := u.monthSpentErr("alice@example.com", now); err != nil || got != 1.5 {
		t.Fatalf("alice spend %v %v", got, err)
	}
	if _, err := u.monthSpentErr("bob@example.com", now); err == nil {
		t.Fatal("a call that never finished is not unknown spend after import")
	}
	if !u.opened.Equal(now.Add(-48 * time.Hour).Truncate(time.Second)) {
		t.Fatalf("opened %v", u.opened)
	}
	if rep, err := ImportState(context.Background(), db, f.cfg, dir); rep.Imported || err != nil {
		t.Fatalf("second import: %+v %v", rep, err)
	}
	if _, err := ImportState(context.Background(), f.db, f.cfg, dir); err == nil {
		t.Fatal("import merged into a database with its own state")
	}
	// A broken chain is refused, leaving the database empty.
	bad := t.TempDir()
	writeState(t, bad, entries, now)
	raw, _ := os.ReadFile(filepath.Join(bad, "audit.jsonl"))
	os.WriteFile(filepath.Join(bad, "audit.jsonl"), []byte(strings.Replace(string(raw), "operator:seed", "operator:sneak", 1)), 0o600)
	empty := testLedger(t)
	if _, err := ImportState(context.Background(), empty, f.cfg, bad); err == nil {
		t.Fatal("imported a broken audit chain")
	}
	if n := fmt.Sprint(len(OpenStore(empty, f.cfg.Ceiling(), f.cfg.Operator()).Versions())); n != "0" {
		t.Fatalf("a failed import left %s versions", n)
	}
}

// A file-backed broker wrote its times with nanoseconds; the database keeps microseconds and rounds.
// The imported store must still pass its checks (the version's time against its audit write record),
// or every pipeline is denied after the move.
func TestImportKeepsNanosecondTimesVerifiable(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.Add(207109993*time.Nanosecond).UTC())
	db := testLedger(t)
	if rep, err := ImportState(context.Background(), db, f.cfg, dir); err != nil || !rep.Imported {
		t.Fatalf("import: %+v %v", rep, err)
	}
	s := OpenStore(db, f.cfg.Ceiling(), f.cfg.Operator())
	if s.broken != nil {
		t.Fatalf("imported store with nanosecond times fails its checks: %v", s.broken)
	}
	if v := s.Active(); v == nil || v.N != 1 {
		t.Fatalf("no active policy after import: %+v", v)
	}
}

// The import refuses every case where it would otherwise lose or merge data, and leaves the
// database as it found it, so the corrected import can still run: a path that does not exist or
// holds no broker state, a state directory it cannot list, a file it does not know, and a
// database that already holds state of any kind.
func TestImportRefusesRatherThanLoseOrMerge(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	now := testNow.UTC()
	good := func() string {
		dir := t.TempDir()
		writeState(t, dir, c.Entries, now)
		return dir
	}
	unlistable := func(sub string) func() string {
		return func() string {
			dir := good()
			os.Chmod(filepath.Join(dir, sub), 0o300) // entries reachable by name, the listing refused
			t.Cleanup(func() { os.Chmod(filepath.Join(dir, sub), 0o700) })
			return dir
		}
	}
	for name, source := range map[string]func() string{
		"missing directory":   func() string { return filepath.Join(t.TempDir(), "no-such-state") },
		"empty directory":     func() string { return t.TempDir() },
		"a file, not a dir":   func() string { p := filepath.Join(t.TempDir(), "state"); os.WriteFile(p, nil, 0o600); return p },
		"usage unlistable":    unlistable("usage"),
		"versions unlistable": unlistable("versions"),
		"unknown usage file": func() string {
			dir := good()
			os.WriteFile(filepath.Join(dir, "usage", now.Format("2006-01-02")+".jsonl.tmp"), []byte("{}\n"), 0o600)
			return dir
		},
		"stray file at the top": func() string {
			dir := good()
			os.Rename(filepath.Join(dir, "quotas.json"), filepath.Join(dir, "quotas.json.tmp"))
			return dir
		},
		"dangling quotas.json link": func() string {
			dir := good()
			os.Remove(filepath.Join(dir, "quotas.json"))
			os.Symlink(filepath.Join(dir, "gone.json"), filepath.Join(dir, "quotas.json"))
			return dir
		},
		"usage as a link": func() string {
			dir := good()
			os.Rename(filepath.Join(dir, "usage"), filepath.Join(dir, "..", filepath.Base(dir)+"-usage"))
			os.Symlink(filepath.Join(dir, "..", filepath.Base(dir)+"-usage"), filepath.Join(dir, "usage"))
			return dir
		},
		"empty directories only": func() string {
			dir := t.TempDir()
			os.MkdirAll(filepath.Join(dir, "versions"), 0o700)
			os.MkdirAll(filepath.Join(dir, "usage"), 0o700)
			return dir
		},
		"the directory a link": func() string {
			link := filepath.Join(t.TempDir(), "state")
			os.Symlink(good(), link)
			return link
		},
		"the directory a link, named with a slash": func() string {
			link := filepath.Join(t.TempDir(), "state")
			os.Symlink(good(), link)
			return link + "/"
		},
		"the directory a link, named with /.": func() string {
			link := filepath.Join(t.TempDir(), "state")
			os.Symlink(good(), link)
			return link + "/."
		},
		"unknown version file": func() string {
			dir := good()
			os.WriteFile(filepath.Join(dir, "versions", "00000002.json.tmp"), []byte("{}"), 0o600)
			return dir
		},
	} {
		t.Run(name, func(t *testing.T) {
			db := testLedger(t)
			if rep, err := ImportState(context.Background(), db, f.cfg, source()); err == nil {
				t.Fatalf("import succeeded: %+v", rep)
			}
			// Nothing was recorded, so pointing the import at the right directory still works.
			if rep, err := ImportState(context.Background(), db, f.cfg, good()); err != nil || !rep.Imported {
				t.Fatalf("the corrected import: %+v %v", rep, err)
			}
		})
	}
	for name, plant := range map[string]string{
		"usage call": `INSERT INTO broker.usage_calls (id, day, t, principal, model, pending, label)
			VALUES ('x', current_date, now(), 'p', 'm', false, badger.label_of($1::jsonb))`,
		"proposal": `INSERT INTO broker.proposals (id, base, entries, author, created, open)
			SELECT 9, 0, '[]', 'u9', now(), true WHERE $1::text IS NOT NULL`,
		"meta": `INSERT INTO broker.meta (key, value) SELECT 'usage_opened', '2026-01-01T00:00:00Z' WHERE $1::text IS NOT NULL`,
	} {
		t.Run("database holds a "+name, func(t *testing.T) {
			d, db := pgtestMigrated(t)
			d.Super(t, plant, f.cfg.Ceiling().Lattice())
			if rep, err := ImportState(context.Background(), db, f.cfg, good()); err == nil {
				t.Fatalf("import merged into a database holding a %s: %+v", name, rep)
			}
		})
	}
}

// The import reports what it copied, so an operator can check it against the source.
func TestImportReportsCounts(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.UTC())
	rep, err := ImportState(context.Background(), testLedger(t), f.cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := ImportReport{Imported: true, Versions: 1, Audit: 3, Proposals: 1, Documents: 2, Tokens: 1, UsageCalls: 2, Opened: true}
	if rep != want {
		t.Fatalf("report %+v, want %+v", rep, want)
	}
	if s := rep.String(); !strings.Contains(s, "versions=1 audit=3 proposals=1 documents=2 tokens=1 usage_calls=2") {
		t.Fatalf("report line %q", s)
	}
}

// The import checks what it copied as the store will at open, before recording itself: a version
// that does not match its audit record is refused and nothing stays behind, so the corrected
// directory can still be imported.
func TestImportRefusesStateTheStoreWouldRefuse(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.UTC())
	p := filepath.Join(dir, "versions", "00000001.json")
	raw, _ := os.ReadFile(p)
	os.Chmod(p, 0o600)
	os.WriteFile(p, []byte(strings.Replace(string(raw), `"seed policy"`, `"edited"`, 1)), 0o600)
	db := testLedger(t)
	if rep, err := ImportState(context.Background(), db, f.cfg, dir); err == nil {
		t.Fatalf("imported a version that fails its checks: %+v", rep)
	}
	good := t.TempDir()
	writeState(t, good, c.Entries, testNow.UTC())
	if rep, err := ImportState(context.Background(), db, f.cfg, good); err != nil || !rep.Imported {
		t.Fatalf("the corrected import: %+v %v", rep, err)
	}
}

// A call pending when the old broker stopped keeps who it answers to.
func TestImportKeepsAPendingCallsAttribution(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.UTC())
	day := testNow.UTC().Format("2006-01-02")
	b, _ := json.Marshal(usageRecord{Time: testNow, Principal: "ci:group/alpha", Model: "model-a", ID: "p1", Pending: true,
		Owner: "alice@example.com", TriggeredBy: "alice"})
	fh, _ := os.OpenFile(filepath.Join(dir, "usage", day+".jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	fh.Write(append(b, '\n'))
	fh.Close()
	d, db := pgtestMigrated(t)
	if _, err := ImportState(context.Background(), db, f.cfg, dir); err != nil {
		t.Fatal(err)
	}
	if got := d.SuperQuery(t, `SELECT owner || '/' || triggered_by FROM broker.usage_calls WHERE id LIKE '%-p1'`); got != "alice@example.com/alice" {
		t.Fatalf("pending call attributed to %q", got)
	}
}

// A pending call without an id, or two pending records under one id, cannot be told apart: the
// import refuses rather than keep one and lose the other's unknown spend.
func TestImportRefusesAmbiguousPendingCalls(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	day := testNow.UTC().Format("2006-01-02")
	for name, recs := range map[string][]usageRecord{
		"no id": {{Time: testNow, Principal: "alice@example.com", Model: "model-a", Pending: true},
			{Time: testNow, Principal: "bob@example.com", Model: "model-a", Pending: true}},
		"one id twice": {{Time: testNow, Principal: "alice@example.com", Model: "model-a", ID: "x", Pending: true},
			{Time: testNow, Principal: "bob@example.com", Model: "model-a", ID: "x", Pending: true}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeState(t, dir, c.Entries, testNow.UTC())
			fh, _ := os.OpenFile(filepath.Join(dir, "usage", day+".jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
			for _, r := range recs {
				b, _ := json.Marshal(r)
				fh.Write(append(b, '\n'))
			}
			fh.Close()
			db := testLedger(t)
			if rep, err := ImportState(context.Background(), db, f.cfg, dir); err == nil {
				t.Fatalf("imported ambiguous pending calls: %+v", rep)
			}
		})
	}
}

// A result whose id is pending for someone else is not that call's result: the import refuses
// rather than clear another principal's unknown spend.
func TestImportRefusesAResultForAnotherPrincipalsCall(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	day := testNow.UTC().Format("2006-01-02")
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.UTC())
	fh, _ := os.OpenFile(filepath.Join(dir, "usage", day+".jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	for _, r := range []usageRecord{{Time: testNow, Principal: "bob@example.com", Model: "model-a", ID: "z", Pending: true},
		{Time: testNow, Principal: "alice@example.com", Model: "model-a", ID: "z", Prompt: 1}} {
		b, _ := json.Marshal(r)
		fh.Write(append(b, '\n'))
	}
	fh.Close()
	if rep, err := ImportState(context.Background(), testLedger(t), f.cfg, dir); err == nil {
		t.Fatalf("a result cleared another principal's pending call: %+v", rep)
	}
}

// A usage/opened that is not a regular file (a FIFO would block the read forever, holding the
// import's transaction) is refused before it is read.
func TestImportRefusesASpecialFileBeforeReadingIt(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.UTC())
	os.Remove(filepath.Join(dir, "usage", "opened"))
	if err := syscall.Mkfifo(filepath.Join(dir, "usage", "opened"), 0o600); err != nil {
		t.Skip("no FIFOs here:", err)
	}
	done := make(chan error, 1)
	go func() { _, err := ImportState(context.Background(), testLedger(t), f.cfg, dir); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("imported a usage/opened that is a FIFO")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the import hung reading a FIFO")
	}
}

// A result whose owner or trigger differs from its pending call's is not that call's result.
func TestImportRefusesAResultWithAnotherOwner(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	day := testNow.UTC().Format("2006-01-02")
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.UTC())
	fh, _ := os.OpenFile(filepath.Join(dir, "usage", day+".jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	for _, r := range []usageRecord{
		{Time: testNow, Principal: "ci:group/alpha", Model: "model-a", ID: "o", Pending: true, Owner: "alice@example.com"},
		{Time: testNow, Principal: "ci:group/alpha", Model: "model-a", ID: "o", Prompt: 1, Owner: "bob@example.com"}} {
		b, _ := json.Marshal(r)
		fh.Write(append(b, '\n'))
	}
	fh.Close()
	if rep, err := ImportState(context.Background(), testLedger(t), f.cfg, dir); err == nil {
		t.Fatalf("a result took over another owner's pending call: %+v", rep)
	}
}

// A ledger that was opened but never used still carries when counting began: importing only
// usage/opened is state, not an empty directory.
func TestImportOfAnUnusedLedger(t *testing.T) {
	f := newFixture(t, true)
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "usage"), 0o700)
	os.WriteFile(filepath.Join(dir, "usage", "opened"), []byte(testNow.UTC().Format(time.RFC3339)+"\n"), 0o600)
	rep, err := ImportState(context.Background(), testLedger(t), f.cfg, dir)
	if err != nil || !rep.Imported || !rep.Opened {
		t.Fatalf("import of an unused ledger: %+v %v", rep, err)
	}
}

// The directory checked is the directory read: one moved aside after the check, with another put
// in its place, is still read whole from the one that was checked (or the import refused), never
// half from each, which would drop the owners and quotas without a word.
func TestImportReadsTheDirectoryItChecked(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	parent := t.TempDir()
	dir := filepath.Join(parent, "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeState(t, dir, c.Entries, testNow.UTC())
	afterStateDirCheck = func() {
		afterStateDirCheck = nil
		if err := os.Rename(dir, filepath.Join(parent, "moved")); err != nil {
			t.Error(err)
		}
		os.Mkdir(dir, 0o700)
		writeState(t, dir, c.Entries, testNow.UTC())
		os.Remove(filepath.Join(dir, "owners.json"))
		os.Remove(filepath.Join(dir, "quotas.json"))
	}
	t.Cleanup(func() { afterStateDirCheck = nil })
	rep, err := ImportState(context.Background(), testLedger(t), f.cfg, dir)
	if err == nil && rep.Documents != 2 {
		t.Fatalf("import read a directory swapped in after its check: %+v", rep)
	}
}

// An entry changed inside the directory after its check (a state file replaced by a link that
// reads as absent, or usage/ taken away) stops the import: it is never recorded as done with part
// of the state missing, so the corrected directory can still be imported.
func TestImportRefusesAnEntryChangedAfterTheCheck(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	for name, change := range map[string]func(dir string){
		"quotas.json a dangling link": func(dir string) {
			os.Remove(filepath.Join(dir, "quotas.json"))
			os.Symlink("gone.json", filepath.Join(dir, "quotas.json"))
		},
		"usage removed": func(dir string) { os.RemoveAll(filepath.Join(dir, "usage")) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeState(t, dir, c.Entries, testNow.UTC())
			afterStateDirCheck = func() { afterStateDirCheck = nil; change(dir) }
			t.Cleanup(func() { afterStateDirCheck = nil })
			db := testLedger(t)
			if rep, err := ImportState(context.Background(), db, f.cfg, dir); err == nil {
				t.Fatalf("imported a directory changed after its check: %+v", rep)
			}
			good := t.TempDir()
			writeState(t, good, c.Entries, testNow.UTC())
			if rep, err := ImportState(context.Background(), db, f.cfg, good); err != nil || !rep.Imported {
				t.Fatalf("the corrected import: %+v %v", rep, err)
			}
		})
	}
}

// A volume's lost+found, which the broker cannot read, is left alone: it is not state.
func TestImportIgnoresAnUnreadableLostAndFound(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.UTC())
	lf := filepath.Join(dir, "lost+found")
	os.Mkdir(lf, 0o700)
	os.WriteFile(filepath.Join(lf, "#123"), []byte("x"), 0o600)
	os.Chmod(lf, 0)
	t.Cleanup(func() { os.Chmod(lf, 0o700) })
	if rep, err := ImportState(context.Background(), testLedger(t), f.cfg, dir); err != nil || !rep.Imported {
		t.Fatalf("import beside an unreadable lost+found: %+v %v", rep, err)
	}
}

// A state file or directory replaced by a FIFO after the check is refused, not opened for reading:
// that would block the import, its transaction and the policy lock, forever.
func TestImportRefusesAFIFOSwappedInAfterTheCheck(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	for _, name := range []string{"quotas.json", filepath.Join("usage", "opened"), "versions", "usage"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeState(t, dir, c.Entries, testNow.UTC())
			afterStateDirCheck = func() {
				afterStateDirCheck = nil
				os.RemoveAll(filepath.Join(dir, name))
				if err := syscall.Mkfifo(filepath.Join(dir, name), 0o600); err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(func() { afterStateDirCheck = nil })
			done := make(chan error, 1)
			go func() {
				_, err := ImportState(context.Background(), testLedger(t), f.cfg, dir)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("imported with a FIFO in place of a state file")
				}
			case <-time.After(20 * time.Second):
				// Unblock the reader so the test process can finish.
				if w, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY, 0); err == nil {
					w.Close()
				}
				t.Fatal("the import blocked reading a FIFO")
			}
		})
	}
}

// An entry the check saw must still be there when it is read: usage/ moved out after the check
// and back before the end (so every fingerprint matches) stops the import, which would otherwise
// commit with no usage ledger.
func TestImportRefusesAnEntryAwayDuringTheCopy(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.UTC())
	away := filepath.Join(t.TempDir(), "usage")
	afterStateDirCheck = func() {
		afterStateDirCheck = nil
		os.Rename(filepath.Join(dir, "usage"), away)
	}
	beforeImportVerify = func() {
		beforeImportVerify = nil
		os.Rename(away, filepath.Join(dir, "usage"))
	}
	t.Cleanup(func() { afterStateDirCheck, beforeImportVerify = nil, nil })
	if rep, err := ImportState(context.Background(), testLedger(t), f.cfg, dir); err == nil {
		t.Fatalf("imported while usage/ was away: %+v", rep)
	}
}

// A state file swapped for another after the check and put back before the end (so the final
// fingerprint matches) is refused: what is opened must be the very file the baseline recorded, or
// a permissive quotas.json read in between would be imported in place of the real one.
func TestImportRefusesAFileSwappedAndRestored(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.UTC())
	q, orig := filepath.Join(dir, "quotas.json"), filepath.Join(t.TempDir(), "quotas.json")
	afterStateDirCheck = func() {
		afterStateDirCheck = nil
		os.Rename(q, orig)
		os.WriteFile(q, []byte(`{"version":2,"default_usd":null,"principals":{}}`), 0o600)
	}
	beforeImportVerify = func() {
		beforeImportVerify = nil
		os.Remove(q)
		os.Rename(orig, q)
	}
	t.Cleanup(func() { afterStateDirCheck, beforeImportVerify = nil, nil })
	if rep, err := ImportState(context.Background(), testLedger(t), f.cfg, dir); err == nil {
		t.Fatalf("imported a quotas.json swapped in and out during the copy: %+v", rep)
	}
}

// A state file edited in place after the baseline (same inode and size, modification time put
// back) and restored before the end is refused: what is imported must be the bytes the baseline
// saw, or a raised quota read in between would be imported while the source still says 7.
func TestImportRefusesAnInPlaceEditRestored(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.UTC())
	q := filepath.Join(dir, "quotas.json")
	orig, _ := os.ReadFile(q)
	fi, _ := os.Stat(q)
	edit := func(b []byte) {
		w, err := os.OpenFile(q, os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
			return
		}
		w.WriteAt(b, 0)
		w.Close()
		os.Chtimes(q, fi.ModTime(), fi.ModTime())
	}
	raised := bytes.Replace(orig, []byte(":7}"), []byte(":9}"), 1)
	if bytes.Equal(raised, orig) {
		t.Fatalf("fixture changed: %s", orig)
	}
	afterStateDirCheck = func() { afterStateDirCheck = nil; edit(raised) }
	beforeImportVerify = func() { beforeImportVerify = nil; edit(orig) }
	t.Cleanup(func() { afterStateDirCheck, beforeImportVerify = nil, nil })
	if rep, err := ImportState(context.Background(), testLedger(t), f.cfg, dir); err == nil {
		t.Fatalf("imported a quotas.json edited in place during the copy: %+v", rep)
	}
}

// A day's ledger moved out of usage/ after the baseline (the directory's modification time put
// back) and returned before the end is refused: a listing must hold exactly what the baseline saw,
// or the import would commit without that day's spend.
func TestImportRefusesAListingMissingABaselineEntry(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.UTC())
	usage := filepath.Join(dir, "usage")
	ents, _ := os.ReadDir(usage)
	var day string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			day = e.Name()
		}
	}
	if day == "" {
		t.Fatal("fixture has no day ledger")
	}
	fi, _ := os.Stat(usage)
	away := filepath.Join(t.TempDir(), day)
	afterStateDirCheck = func() {
		afterStateDirCheck = nil
		os.Rename(filepath.Join(usage, day), away)
		os.Chtimes(usage, fi.ModTime(), fi.ModTime())
	}
	beforeImportVerify = func() {
		beforeImportVerify = nil
		os.Rename(away, filepath.Join(usage, day))
		os.Chtimes(usage, fi.ModTime(), fi.ModTime())
	}
	t.Cleanup(func() { afterStateDirCheck, beforeImportVerify = nil, nil })
	if rep, err := ImportState(context.Background(), testLedger(t), f.cfg, dir); err == nil {
		t.Fatalf("imported with a day's ledger away during the copy: %+v", rep)
	}
}

// An import waiting for the policy lock gives up when its context ends: startup has a deadline,
// and a wait on the lock that ignored it would hold the process past it.
func TestImportWaitingOnTheLockHonoursItsContext(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.UTC())
	db := testLedger(t)
	holder, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.Exec(`SELECT pg_advisory_xact_lock($1)`, policyLock); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := ImportState(ctx, db, f.cfg, dir)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("imported while another transaction held the policy lock")
		}
	case <-time.After(15 * time.Second):
		holder.Rollback() // let the blocked import finish so the test can end
		<-done
		t.Fatal("the import kept waiting on the lock after its context ended")
	}
}

// A file-backed broker that stopped between writing an approved version and appending its approve
// record left a log whose last record is the write carrying the proposal: the old replay took that
// write as closing the proposal. The import keeps it closed and the store accepts it.
func TestImportOfAnApprovalInterruptedBeforeItsApproveRecord(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	now := testNow.UTC()
	dir := t.TempDir()
	writeState(t, dir, c.Entries, now)
	audit := filepath.Join(dir, "audit.jsonl")
	raw, _ := os.ReadFile(audit)
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	entries := c.Entries[:1] // what proposal 1 proposed
	v := Version{N: 2, Entries: entries, Author: "u1", Approver: "u2", Comment: "approved", Created: now, SHA256: entriesHash(entries)}
	vraw, _ := json.MarshalIndent(v, "", " ")
	os.WriteFile(filepath.Join(dir, "versions", "00000002.json"), vraw, 0o400)
	w := AuditRecord{Seq: int64(len(lines) + 1), Prev: sha256hex([]byte(lines[len(lines)-1])), Time: now, Kind: "write", Actor: "u1",
		Approver: "u2", Version: 2, Comment: "approved", SHA256: v.SHA256, Proposal: 1, Added: entries}
	line, _ := json.Marshal(w)
	os.WriteFile(audit, []byte(strings.Join(append(lines, string(line)), "\n")+"\n"), 0o600)
	db := testLedger(t)
	rep, err := ImportState(context.Background(), db, f.cfg, dir)
	if err != nil {
		t.Fatalf("an interrupted approval's log: %v", err)
	}
	if rep.Versions != 2 || rep.Proposals != 1 {
		t.Fatalf("report %+v", rep)
	}
	var open bool
	if err := db.QueryRow(`SELECT open FROM broker.proposals WHERE id = 1`).Scan(&open); err != nil || open {
		t.Fatalf("proposal 1 open=%v %v, want closed by its write", open, err)
	}
}

// Times exactly halfway between two microseconds import verifiable: Go and Postgres round that
// case differently, so the import stores each time already rounded as the verifier rounds it.
func TestImportKeepsHalfwayTimesVerifiable(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	for _, ns := range []int{500, 1500, 2500} {
		dir := t.TempDir()
		writeState(t, dir, c.Entries, testNow.Truncate(time.Microsecond).Add(time.Duration(ns)).UTC())
		db := testLedger(t)
		if rep, err := ImportState(context.Background(), db, f.cfg, dir); err != nil || !rep.Imported {
			t.Fatalf("+%dns: import: %+v %v", ns, rep, err)
		}
		if s := OpenStore(db, f.cfg.Ceiling(), f.cfg.Operator()); s.broken != nil {
			t.Fatalf("+%dns: imported store fails its checks: %v", ns, s.broken)
		}
	}
}

// A replica beginning a model call while another imports waits for the import: a ledger row
// written after the import checked the database was empty would otherwise be merged into it.
func TestImportExcludesConcurrentWrites(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.UTC())
	db := testLedger(t)
	began := make(chan error, 1)
	hookRan := false
	duringImport := false
	waiting := func() bool {
		var n int
		db.QueryRow(`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted
			AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&n)
		return n > 0
	}
	afterStateDirCheck = func() {
		afterStateDirCheck = nil
		hookRan = true
		// Another replica: its book opens and begins a call while the import runs.
		go func() {
			_, err := openUsageOn(t, db, "pod-other").begin(testCeiling, "p", "m", time.Now())
			began <- err
		}()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case err := <-began:
				began <- err
				duringImport = true // the call did not wait for the import
				return
			case <-deadline:
				return
			case <-time.After(10 * time.Millisecond):
				if waiting() {
					return
				}
			}
		}
	}
	t.Cleanup(func() { afterStateDirCheck = nil })
	_, err := ImportState(context.Background(), db, f.cfg, dir)
	if !hookRan {
		t.Fatalf("the import stopped before its check: %v", err)
	}
	if berr := <-began; berr != nil {
		t.Fatalf("begin: %v", berr)
	}
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if duringImport {
		t.Fatal("a call was written to the ledger while the import ran, and the import was recorded")
	}
}

// The import takes its locks in the order every writer does (the write lock, then the policy
// lock): a token issued while an import starts waits for it instead of deadlocking with it.
func TestImportLockOrderMatchesWriters(t *testing.T) {
	f := newFixture(t, true)
	c, _ := loadCorpus(t)
	dir := t.TempDir()
	writeState(t, dir, c.Entries, testNow.UTC())
	db := testLedger(t)
	writer, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if err := sharedWriteLock(context.Background(), writer); err != nil { // a writer, as tokens.tx starts
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ImportState(context.Background(), db, f.cfg, dir); done <- err }()
	for deadline := time.Now().Add(10 * time.Second); ; {
		var n int
		db.QueryRow(`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted
			AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&n)
		if n > 0 {
			break // the import is waiting on a lock
		}
		if time.Now().After(deadline) {
			t.Fatal("the import never waited for the writer")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The writer now takes the policy lock, as AuditTx does inside token issuance.
	if _, err := writer.Exec(`SELECT pg_advisory_xact_lock($1)`, policyLock); err != nil {
		t.Fatalf("the writer deadlocked with the import: %v", err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("import: %v", err)
	}
}
