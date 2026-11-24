package broker

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// proposeNamed has u1 propose adding a named-branch entry, which needs a second admin.
func proposeNamed(t *testing.T, f *fixture) {
	t.Helper()
	exp := testNow.Add(48 * time.Hour)
	body := policyBody(t, f, func(es []Entry) []Entry {
		return append(es, Entry{ID: "alpha-feature", Kind: KindNamed, ProjectPath: "group/alpha", Ref: "feat/y",
			Sources: []string{"web"}, Models: []string{"model-a"}, TriggerUsers: []string{"alice"}, ExpiresAt: &exp, Enabled: true})
	})
	if w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), body); w.Code != 202 {
		t.Fatalf("propose: %d %s", w.Code, w.Body)
	}
}

// A proposal is what its chained propose record says, not what its row says: a row edited
// outside the service (other entries, another author, another base, reopened after approval, or
// planted with no record) is refused at approval and fails the store's checks at open. The
// author swap is the two-person rule's bypass: u1 approving their own change.
func TestProposalTamperingRefused(t *testing.T) {
	for name, c := range map[string]struct {
		tamper   string
		approver string
		before   func(*fixture) // runs before the tamper
	}{
		"entries edited": {tamper: `UPDATE broker.proposals SET entries = jsonb_set(entries, '{0,models}', '["model-a","model-b"]')`, approver: "u2"},
		"author swapped": {tamper: `UPDATE broker.proposals SET author = 'u9'`, approver: "u1"},
		"base edited":    {tamper: `UPDATE broker.proposals SET base = 0`, approver: "u2"},
		"comment edited": {tamper: `UPDATE broker.proposals SET comment = 'reviewed by security'`, approver: "u2"},
		"created edited": {tamper: `UPDATE broker.proposals SET created = created - interval '1 day'`, approver: "u2"},
		"reopened": {tamper: `UPDATE broker.proposals SET open = true`, approver: "u3", before: func(f *fixture) {
			if w := do(f.admin, "POST", "/admin/v1/proposals/1/approve", admin("u2"), ""); w.Code != 201 {
				f.t.Fatalf("approval: %d %s", w.Code, w.Body)
			}
		}},
		"planted": {tamper: `INSERT INTO broker.proposals (id, base, entries, author, author_name, comment, created, open)
			SELECT 2, base, entries, 'u9', author_name, comment, created, true FROM broker.proposals WHERE id = 1`, approver: "u2"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, true)
			proposeNamed(t, f)
			if c.before != nil {
				c.before(f)
			}
			versions := len(f.b.store.Versions())
			f.pg.Super(t, c.tamper)
			id := "1"
			if name == "planted" {
				id = "2"
			}
			if w := do(f.admin, "POST", "/admin/v1/proposals/"+id+"/approve", admin(c.approver), ""); w.Code == 201 {
				t.Fatalf("a tampered proposal was approved: %s", w.Body)
			}
			if n := len(f.b.store.Versions()); n != versions {
				t.Fatalf("versions %d -> %d after approving a tampered proposal", versions, n)
			}
			if s := OpenStore(f.db, f.cfg.Ceiling(), f.cfg.Operator()); s.broken == nil {
				t.Fatal("a tampered proposal passed the store's checks at open")
			}
		})
	}
}

// A propose record whose proposal row is gone fails the checks at open.
func TestProposalRowDeletedDetected(t *testing.T) {
	f := newFixture(t, true)
	proposeNamed(t, f)
	f.pg.Super(t, `DELETE FROM broker.proposals`)
	if s := OpenStore(f.db, f.cfg.Ceiling(), f.cfg.Operator()); s.broken == nil {
		t.Fatal("a missing proposal row passed the store's checks")
	}
}

// An untouched proposal still survives a restart and is approved by a second admin.
func TestProposalSurvivesRestartUntouched(t *testing.T) {
	f := newFixture(t, true)
	proposeNamed(t, f)
	f.open()
	if f.b.store.broken != nil {
		t.Fatal(f.b.store.broken)
	}
	if w := do(f.admin, "POST", "/admin/v1/proposals/1/approve", admin("u2"), ""); w.Code != 201 {
		t.Fatalf("approval after restart: %d %s", w.Code, w.Body)
	}
	f.open()
	if f.b.store.broken != nil {
		t.Fatalf("an approved proposal fails the checks at open: %v", f.b.store.broken)
	}
}

// Every policy write logs the audit chain's head next to the version, so a log collector holds an
// anchor off the database: rewriting the audit history and its head together contradicts it.
func TestPolicyWriteLogsAuditAnchor(t *testing.T) {
	f := newFixture(t, true)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	body := policyBody(t, f, func(es []Entry) []Entry { return es[:3] })
	if w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), body); w.Code != 201 {
		t.Fatalf("write: %d %s", w.Code, w.Body)
	}
	head := f.superText(`SELECT 'audit_seq=' || seq || ' audit_head=' || hash FROM broker.audit_head`)
	var line string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, "policy write version=2 ") {
			line = l
		}
	}
	if !strings.HasSuffix(line, head) {
		t.Fatalf("policy write log line %q does not end with the audit head %q", line, head)
	}
}

// A store that already has versions ignores the seed without reading it: an obsolete or
// unreadable seed file does not fail a deployment whose current policy is valid.
func TestSeedIgnoredOnceVersionsExist(t *testing.T) {
	f := newFixture(t, true)
	bad := filepath.Join(t.TempDir(), "obsolete.json")
	os.WriteFile(bad, []byte(`{"entries":[{"id":"x","kind":"no-such-kind"}],"issuer":"retired"}`), 0o600)
	for _, path := range []string{bad, filepath.Join(t.TempDir(), "missing.json")} {
		if err := f.b.store.Seed(f.cfg.Operator(), path, testNow); err != nil {
			t.Fatalf("seed %s on a store with versions: %v", filepath.Base(path), err)
		}
	}
	if v := f.b.store.Active(); v == nil || v.N != 1 {
		t.Fatalf("active after ignored seeds: %+v", v)
	}
}

// A version planted while the store is open (an operator-valid policy, the next number, no audit
// record) is never made active: the store checks a version it has not seen before using it.
func TestVersionPlantedWhileOpenNotActivated(t *testing.T) {
	f := newFixture(t, true)
	if v := f.b.store.Active(); v == nil || v.N != 1 {
		t.Fatalf("active %+v", v)
	}
	f.pg.Super(t, `INSERT INTO broker.policy_versions (n, entries, author, author_name, approver, comment, created, sha256)
		SELECT 2, entries, 'mallory', '', '', '', created, sha256 FROM broker.policy_versions WHERE n = 1`)
	if v := f.b.store.Active(); v != nil && v.N == 2 {
		t.Fatal("a planted version became active without an audited write")
	}
}

// Rewriting a proposal's author together with its propose record, that record's hash and the
// next record's prev still contradicts the chain past it: approval checks every link up to the
// head, so the author cannot approve their own proposal this way.
func TestProposalRewriteThroughTheChainRefused(t *testing.T) {
	f := newFixture(t, true)
	proposeNamed(t, f)
	f.b.store.Audit(AuditRecord{Kind: "refused", Reason: "after the proposal"})
	f.b.store.Audit(AuditRecord{Kind: "refused", Reason: "and another"})
	seq := f.superText(`SELECT seq::text FROM broker.audit WHERE record::jsonb->>'kind' = 'propose'`)
	f.pg.Super(t, `UPDATE broker.proposals SET author = 'u9'`)
	f.pg.Super(t, `UPDATE broker.audit SET record = replace(record, '"actor":"u1"', '"actor":"u9"') WHERE seq = `+seq)
	f.pg.Super(t, `UPDATE broker.audit SET hash = encode(sha256(convert_to(record, 'UTF8')), 'hex') WHERE seq = `+seq)
	f.pg.Super(t, `UPDATE broker.audit a SET prev = b.hash FROM broker.audit b WHERE b.seq = `+seq+` AND a.seq = b.seq + 1`)
	if w := do(f.admin, "POST", "/admin/v1/proposals/1/approve", admin("u1"), ""); w.Code == 201 {
		t.Fatal("the author approved their own proposal after rewriting one link of the chain")
	}
}

// The two-person rule decides against the verified current policy, not the row as it reads now:
// a grant planted into the current version's row for one write cannot make adding it look like
// no change.
func TestTwoPersonDecidesAgainstTheVerifiedPolicy(t *testing.T) {
	f := newFixture(t, true)
	exp := testNow.Add(48 * time.Hour)
	grant := Entry{ID: "alpha-feature", Kind: KindNamed, ProjectPath: "group/alpha", Ref: "feat/y",
		Sources: []string{"web"}, Models: []string{"model-a"}, TriggerUsers: []string{"alice"}, ExpiresAt: &exp, Enabled: true}
	body := policyBody(t, f, func(es []Entry) []Entry { return append(es, grant) })
	raw, _ := json.Marshal(grant)
	f.pg.Super(t, `UPDATE broker.policy_versions SET entries = entries || $1::jsonb WHERE n = 1`, "["+string(raw)+"]")
	w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"1"`), body)
	if w.Code == 201 {
		t.Fatal("a single admin added a named-branch grant by planting it in the current version first")
	}
}

// Checking the store after open reads only the audit records written since the last check, so a
// policy write's check does not grow with the log (every pipeline decision is a record, and the
// check holds the lock audit writes need). The whole log, here thousands of records, is checked
// at open.
func TestChecksAfterOpenReadOnlyNewRecords(t *testing.T) {
	f := newFixture(t, true)
	if err := f.b.store.txFor(time.Minute, func(tx *sql.Tx) error {
		for i := 0; i < 5000; i++ {
			if err := f.b.store.appendAudit(tx, AuditRecord{Kind: "decision", Decision: "allow", Principal: "ci:group/alpha"}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.open()
	if c := f.b.store.checked.Load(); c == nil || c.scanned < 5000 {
		t.Fatalf("open did not check the whole log: %+v", c)
	}
	write := func(n string, mutate func([]Entry) []Entry) {
		if w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u1"), "If-Match", `"`+n+`"`), policyBody(t, f, mutate)); w.Code != 201 {
			t.Fatalf("write: %d %s", w.Code, w.Body)
		}
	}
	write("1", func(es []Entry) []Entry { return es[:3] })
	for i := 0; i < 3; i++ {
		f.b.store.Audit(AuditRecord{Kind: "refused", Reason: "x"})
	}
	write("2", func(es []Entry) []Entry { return es[:2] })
	if c := f.b.store.checked.Load(); c.scanned > 5 {
		t.Fatalf("a policy write's check read %d records, want only the few written since the last check", c.scanned)
	}
}

// When the operator has narrowed what a policy may say, the current version is not in force, so
// the two-person rule takes nothing as already granted: a single admin repairing it cannot carry
// a named-branch grant through as unchanged.
func TestTwoPersonAfterOperatorNarrowing(t *testing.T) {
	f := newFixture(t, true)
	proposeNamed(t, f)
	if w := do(f.admin, "POST", "/admin/v1/proposals/1/approve", admin("u2"), ""); w.Code != 201 {
		t.Fatalf("approval: %d %s", w.Code, w.Body)
	}
	f.cfg.Routes = f.cfg.Routes[:1] // model-b withdrawn: version 2 no longer validates
	f.open()
	if f.b.store.Active() != nil {
		t.Fatal("a version the operator narrowed is still active")
	}
	v2, err := f.b.store.Version(2)
	if err != nil {
		t.Fatal(err)
	}
	var kept []Entry
	for _, e := range v2.Entries {
		if !slices.Contains(e.Models, "model-b") {
			kept = append(kept, e)
		}
	}
	raw, _ := json.Marshal(map[string]any{"entries": kept, "comment": "repair"})
	keep := string(raw)
	if w := do(f.admin, "PUT", "/admin/v1/policy", with(admin("u3"), "If-Match", `"2"`), keep); w.Code == 201 {
		t.Fatal("one admin re-enabled a named-branch grant by repairing a narrowed policy")
	}
}

// Approving a proposal made long ago reads only the records written since the store's last check,
// not everything since the proposal: approval holds the propose record to the hash that check saw.
func TestApprovingAnOldProposalReadsOnlyNewRecords(t *testing.T) {
	f := newFixture(t, true)
	proposeNamed(t, f)
	if err := f.b.store.txFor(time.Minute, func(tx *sql.Tx) error {
		for i := 0; i < 5000; i++ {
			if err := f.b.store.appendAudit(tx, AuditRecord{Kind: "decision", Decision: "allow", Principal: "ci:group/alpha"}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.open() // the whole log is checked here
	for i := 0; i < 3; i++ {
		f.b.store.Audit(AuditRecord{Kind: "refused", Reason: "x"})
	}
	if w := do(f.admin, "POST", "/admin/v1/proposals/1/approve", admin("u2"), ""); w.Code != 201 {
		t.Fatalf("approval: %d %s", w.Code, w.Body)
	}
	if c := f.b.store.checked.Load(); c.scanned > 5 {
		t.Fatalf("approval read %d records, want only the few written since the last check", c.scanned)
	}
}
