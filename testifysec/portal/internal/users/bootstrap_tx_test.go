package users

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/portal/internal/auth"
)

// Granting a role and retiring that role's bootstrap commit together: no reader, on this replica
// or another, ever sees the user holding the role while the bootstrap marker is still tentative
// (a replica that stopped in between would leave the bootstrap subject its role).
func TestRoleAndBootstrapRetirementCommitTogether(t *testing.T) {
	db := testDB(t)
	p := NewPG(db, testLabel)
	stop := make(chan struct{})
	seen := make(chan bool, 1)
	go func() {
		bad := false
		for {
			select {
			case <-stop:
				seen <- bad
				return
			default:
			}
			var torn bool
			pgdb.Tx(context.Background(), db, testLabel, func(tx *sql.Tx) error {
				return tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM portal.users WHERE body->>'role' = 'admin')
					AND NOT EXISTS (SELECT 1 FROM portal.bootstrap_ended WHERE role = 'admin' AND final)`).Scan(&torn)
			})
			bad = bad || torn
		}
	}()
	for i := 0; i < 50; i++ {
		id := Identity{Kind: KindIdP, Subject: fmt.Sprintf("admin-%d", i)}
		if err := p.PutUser(User{ID: id.ID(), Kind: KindIdP, Subject: id.Subject, Role: auth.Admin, Status: Active}); err != nil {
			t.Fatal(err)
		}
		pgtestReset(t, p)
	}
	close(stop)
	if <-seen {
		t.Fatal("a reader saw an admin while the admin bootstrap was not yet retired")
	}
}

// pgtestReset removes the users and markers so each grant starts from a live bootstrap.
func pgtestReset(t *testing.T, p *PG) {
	t.Helper()
	superOf(t, p).Super(t, `DELETE FROM portal.users; DELETE FROM portal.bootstrap_ended`)
}

// Offboarding is final across replicas: a replica that read the user before another offboarded
// them cannot write its stale copy back (a role approval restoring Active and access).
func TestOffboardBeatsAStaleGrant(t *testing.T) {
	db := testDB(t)
	a, b := NewPG(db, testLabel), NewPG(db, testLabel)
	id := Identity{Kind: KindIdP, Subject: "someone"}
	u := User{ID: id.ID(), Kind: KindIdP, Subject: id.Subject, Status: Active}
	if err := a.PutUser(u); err != nil {
		t.Fatal(err)
	}
	stale, _, err := a.User(u.ID) // replica A reads, to grant a role
	if err != nil {
		t.Fatal(err)
	}
	off := stale
	off.Status = Offboarded
	if err := b.PutUser(off); err != nil { // replica B offboards meanwhile
		t.Fatal(err)
	}
	stale.Role = auth.Approver
	if err := a.PutUser(stale); err == nil {
		t.Fatal("a stale grant brought an offboarded user back")
	}
	if got, _, _ := b.User(u.ID); got.Status != Offboarded {
		t.Fatalf("status after the stale write: %s", got.Status)
	}
}

// One decision per request across replicas: once a rejection is stored, an approval read before it
// cannot grant the role, and once an approval is applied, a rejection read before it cannot be
// stored over it.
func TestApproveAndRejectCannotBothLand(t *testing.T) {
	db := testDB(t)
	a, b := NewPG(db, testLabel), NewPG(db, testLabel)
	who := Identity{Kind: KindIdP, Subject: "candidate"}
	u := User{ID: who.ID(), Kind: KindIdP, Subject: who.Subject, Status: Active}
	if err := a.PutUser(u); err != nil {
		t.Fatal(err)
	}
	approver := Identity{Kind: KindIdP, Subject: "approver"}.ID()
	req := func(id string) Request {
		return Request{ID: id, Kind: "grant", UserID: u.ID, Role: auth.Approver, RequestedBy: "admin", RequesterID: approver, Status: Undecided}
	}
	// Rejected first: the approval, read before it, must not grant.
	r1 := req(strings.Repeat("1", 32))
	if err := a.PutRequest(r1); err != nil {
		t.Fatal(err)
	}
	rej := r1
	rej.Status, rej.DecidedBy = Rejected, "approver-b"
	if err := b.PutRequest(rej); err != nil {
		t.Fatal(err)
	}
	granted := u
	granted.Role = auth.Approver
	granted.Applied = []Applied{{Request: r1.ID, By: "approver-a"}}
	if err := a.PutUser(granted); err == nil {
		t.Fatal("an approval read before a rejection granted the role")
	}
	// Approved first: the rejection, read before it, must not be stored.
	r2 := req(strings.Repeat("2", 32))
	if err := a.PutRequest(r2); err != nil {
		t.Fatal(err)
	}
	granted.Applied = []Applied{{Request: r2.ID, By: "approver-a"}}
	if err := a.PutUser(granted); err != nil {
		t.Fatal(err)
	}
	rej2 := r2
	rej2.Status, rej2.DecidedBy = Rejected, "approver-b"
	if err := b.PutRequest(rej2); err == nil {
		t.Fatal("a rejection was stored over an approval already applied")
	}
}

// A copy read before another replica changed the user is never written back: a delayed replay of
// an approval cannot restore a role dropped since, nor erase the approvals recorded since.
func TestAStaleCopyCannotUndoANewerChange(t *testing.T) {
	db := testDB(t)
	a, b := NewPG(db, testLabel), NewPG(db, testLabel)
	who := Identity{Kind: KindIdP, Subject: "holder"}
	r1 := Request{ID: strings.Repeat("3", 32), Kind: "grant", UserID: who.ID(), Role: auth.Approver, RequestedBy: "admin",
		RequesterID: Identity{Kind: KindIdP, Subject: "admin"}.ID(), Status: Undecided}
	if err := a.PutRequest(r1); err != nil {
		t.Fatal(err)
	}
	if err := a.PutUser(User{ID: who.ID(), Kind: KindIdP, Subject: who.Subject, Status: Active, Role: auth.Approver,
		Applied: []Applied{{Request: r1.ID, By: "approver"}}}); err != nil {
		t.Fatal(err)
	}
	stale, _, err := a.User(who.ID()) // replica A reads, to replay the approval
	if err != nil {
		t.Fatal(err)
	}
	dropped, _, err := b.User(who.ID()) // replica B drops the role meanwhile
	if err != nil {
		t.Fatal(err)
	}
	dropped.Role = auth.None
	if err := b.PutUser(dropped); err != nil {
		t.Fatal(err)
	}
	if err := a.PutUser(stale); err == nil {
		t.Fatal("a stale copy was written over a newer change")
	}
	if got, _, _ := b.User(who.ID()); got.Role != auth.None {
		t.Fatalf("role after the stale write: %q", got.Role)
	}
}

// An approval applied to a user needs its request, pending or approved, in the same transaction: a
// request that is missing, or whose status is gone, grants nothing.
func TestAGrantNeedsItsRequest(t *testing.T) {
	for name, plant := range map[string]string{
		"missing":              "",
		"no status":            `UPDATE portal.role_requests SET body = body - 'status'`,
		"empty status":         `UPDATE portal.role_requests SET body = jsonb_set(body, '{status}', '""')`,
		"damaged, status kept": `UPDATE portal.role_requests SET body = '{"status":"pending"}'`,
		"another user's":       `UPDATE portal.role_requests SET body = jsonb_set(body, '{userId}', to_jsonb(repeat('e', 64)))`,
	} {
		t.Run(name, func(t *testing.T) {
			db := testDB(t)
			p := NewPG(db, testLabel)
			who := Identity{Kind: KindIdP, Subject: "candidate"}
			u := User{ID: who.ID(), Kind: KindIdP, Subject: who.Subject, Status: Active}
			if err := p.PutUser(u); err != nil {
				t.Fatal(err)
			}
			id := strings.Repeat("4", 32)
			if plant != "" {
				if err := p.PutRequest(Request{ID: id, Kind: "grant", UserID: u.ID, Role: auth.Approver, RequestedBy: "admin",
					RequesterID: Identity{Kind: KindIdP, Subject: "admin"}.ID(), Status: Undecided}); err != nil {
					t.Fatal(err)
				}
				superOf(t, p).Super(t, plant)
			}
			u, _, _ = p.User(u.ID)
			u.Role = auth.Approver
			u.Applied = []Applied{{Request: id, By: "approver"}}
			if err := p.PutUser(u); err == nil {
				t.Fatal("a grant was stored without a pending or approved request")
			}
		})
	}
}

// A copy taken from the user list is stale like one read on its own: written back after another
// replica dropped the role, it is refused, and the role stays dropped.
func TestAListedCopyIsStaleToo(t *testing.T) {
	db := testDB(t)
	a, b := NewPG(db, testLabel), NewPG(db, testLabel)
	who := Identity{Kind: KindIdP, Subject: "listed"}
	if err := a.PutUser(User{ID: who.ID(), Kind: KindIdP, Subject: who.Subject, Status: Active, Role: auth.Admin}); err != nil {
		t.Fatal(err)
	}
	all, err := a.Users() // replica A lists
	if err != nil || len(all) != 1 {
		t.Fatal(all, err)
	}
	dropped, _, err := b.User(who.ID()) // replica B drops the role meanwhile
	if err != nil {
		t.Fatal(err)
	}
	dropped.Role = auth.None
	if err := b.PutUser(dropped); err != nil {
		t.Fatal(err)
	}
	if err := a.PutUser(all[0]); err == nil {
		t.Fatal("a listed copy was written over a newer change")
	}
	if got, _, _ := b.User(who.ID()); got.Role != auth.None {
		t.Fatalf("role after the stale write: %q", got.Role)
	}
}
