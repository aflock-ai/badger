package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb/pgtest"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	_, db := pgtest.Migrated(t, pgdb.Core, Schema)
	return db
}

var testLabel = func() pgdb.Label {
	l, err := pgdb.ParseLabel("SECRET")
	if err != nil {
		panic(err)
	}
	return l
}()

func TestVersionsAreWriteOnce(t *testing.T) {
	f := NewPG(testDB(t), testLabel)
	for _, seq := range []uint64{9, 10, 2} {
		if err := f.Put(Version{ProfileID: "engineering", Sequence: seq, CreatedBy: "first"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Put(Version{ProfileID: "engineering", Sequence: 10, CreatedBy: "second"}); !errors.Is(err, ErrExists) {
		t.Fatalf("overwrite: %v", err)
	}
	v, ok, err := f.Latest("engineering")
	if err != nil || !ok || v.Sequence != 10 || v.CreatedBy != "first" {
		t.Fatalf("latest: %+v %v %v", v, ok, err)
	}
	if vs, err := f.List(); err != nil || len(vs) != 1 {
		t.Fatalf("list: %v %v", vs, err)
	}
}

func TestVersionHistoryAndGet(t *testing.T) {
	f := NewPG(testDB(t), testLabel)
	for _, seq := range []uint64{10, 12, 11} {
		if err := f.Put(Version{ProfileID: "engineering", Sequence: seq}); err != nil {
			t.Fatal(err)
		}
	}
	vs, err := f.Versions("engineering")
	if err != nil || len(vs) != 3 || vs[0].Sequence != 12 || vs[2].Sequence != 10 {
		t.Fatalf("history, newest first: %+v %v", vs, err)
	}
	if v, ok, err := f.Get("engineering", 11); err != nil || !ok || v.Sequence != 11 {
		t.Fatalf("get 11: %+v %v %v", v, ok, err)
	}
	if _, ok, err := f.Get("engineering", 13); err != nil || ok {
		t.Fatalf("get missing: %v %v", ok, err)
	}
	if _, _, err := f.Get("../x", 1); !errors.Is(err, ErrProfileID) {
		t.Fatalf("get traversal: %v", err)
	}
}

func TestAssignmentReplacedAtomically(t *testing.T) {
	f := NewPG(testDB(t), testLabel)
	if _, ok, err := f.Assignment("deploy-a"); err != nil || ok {
		t.Fatalf("empty: %v %v", ok, err)
	}
	for _, seq := range []uint64{10, 11} {
		if err := f.PutAssignment(Assignment{DeploymentID: "deploy-a", ProfileID: "engineering", Sequence: seq}); err != nil {
			t.Fatal(err)
		}
	}
	if a, ok, err := f.Assignment("deploy-a"); err != nil || !ok || a.Sequence != 11 {
		t.Fatalf("assignment: %+v %v %v", a, ok, err)
	}
	if err := f.PutAssignment(Assignment{DeploymentID: "../x"}); !errors.Is(err, ErrProfileID) {
		t.Fatalf("traversal: %v", err)
	}
}

// The audit chain verifies, and an edit or a removal made outside the service breaks it.
func TestAuditChainDetectsEdits(t *testing.T) {
	d, db := pgtest.Migrated(t, pgdb.Core, Schema)
	p := NewPG(db, testLabel)
	for _, a := range []string{"one", "two", "three"} {
		if err := p.Append(Record{Actor: "admin", Action: a}); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Verify(); err != nil {
		t.Fatal(err)
	}
	if n, err := p.Records(); err != nil || n != 3 {
		t.Fatalf("records %d %v", n, err)
	}
	d.Super(t, `UPDATE portal.audit SET record = replace(record, '"two"', '"twice"') WHERE seq = 2`)
	if err := p.Verify(); err == nil {
		t.Fatal("an edited record verified")
	}
}

// Signed profiles beside an empty audit log mean the log was lost: the portal must not start.
func TestProfilesWithoutAuditRefused(t *testing.T) {
	p := NewPG(testDB(t), testLabel)
	if err := p.Put(Version{ProfileID: "engineering", Sequence: 1}); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(); err == nil {
		t.Fatal("profiles without an audit log verified")
	}
}

// Profile versions are marked at the label they were written at: a lower session sees none.
func TestProfilesReadDownOnly(t *testing.T) {
	db := testDB(t)
	if err := NewPG(db, testLabel).Put(Version{ProfileID: "engineering", Sequence: 1}); err != nil {
		t.Fatal(err)
	}
	low, _ := pgdb.ParseLabel("UNCLASSIFIED")
	if vs, err := NewPG(db, low).List(); err != nil || len(vs) != 0 {
		t.Fatalf("a lower session read %d versions: %v", len(vs), err)
	}
	var n int
	if err := pgdb.Tx(context.Background(), db, low, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE portal.profile_versions SET body = '{}'`)
		return err
	}); err == nil {
		t.Fatal("the service role updated a signed profile")
	}
	_ = n
}

// Verify runs while another replica appends (a rolling restart): it sees a consistent log and
// head, never a valid chain that only looks broken.
func TestVerifyWhileAppending(t *testing.T) {
	_, db := pgtest.Migrated(t, pgdb.Core, Schema)
	p := NewPG(db, testLabel)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			p.Append(Record{Actor: "u", Action: "a"})
		}
	}()
	for {
		select {
		case <-done:
			if err := p.Verify(); err != nil {
				t.Fatal(err)
			}
			return
		default:
			if err := p.Verify(); err != nil {
				t.Fatalf("Verify during appends: %v", err)
			}
		}
	}
}

// A deployment's assignment never moves back across replicas: a replica that checked before
// another assigned a newer version cannot then write its older one over it, nor a version of
// another profile.
func TestAssignmentNeverMovesBackAcrossReplicas(t *testing.T) {
	db := testDB(t)
	a, b := NewPG(db, testLabel), NewPG(db, testLabel)
	if err := b.PutAssignment(Assignment{DeploymentID: "deploy-a", ProfileID: "engineering", Sequence: 11}); err != nil {
		t.Fatal(err)
	}
	for name, stale := range map[string]Assignment{
		"older sequence": {DeploymentID: "deploy-a", ProfileID: "engineering", Sequence: 10},
		"other profile":  {DeploymentID: "deploy-a", ProfileID: "research", Sequence: 12},
	} {
		if err := a.PutAssignment(stale); !errors.Is(err, ErrRollback) {
			t.Errorf("%s: %v, want ErrRollback", name, err)
		}
	}
	if got, _, _ := a.Assignment("deploy-a"); got.ProfileID != "engineering" || got.Sequence != 11 {
		t.Fatalf("assignment after the stale writes: %+v", got)
	}
	if err := a.PutAssignment(Assignment{DeploymentID: "deploy-a", ProfileID: "engineering", Sequence: 11}); err != nil {
		t.Fatalf("the same assignment again: %v", err)
	}
}
