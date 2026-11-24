package users

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb/pgtest"
	"github.com/aflock-ai/badger/testifysec/portal/internal/auth"
	"github.com/aflock-ai/badger/testifysec/portal/internal/store"
)

type memAudit struct{ records []store.Record }

func (m *memAudit) Append(r store.Record) error { m.records = append(m.records, r); return nil }

// as identifies a request by an X-Test-Subject header; production reads the verified certificate.
func as(subject string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Test-Subject", subject)
	return r
}

func service(t *testing.T) (*Service, *memAudit) {
	t.Helper()
	files := NewPG(testDB(t), testLabel)
	a := &memAudit{}
	return &Service{Store: files, Audit: a, Now: time.Now,
		Bootstrap: map[string]auth.Role{"CN=First Admin": auth.Admin, "CN=First Approver": auth.Approver},
		Identify: func(r *http.Request) (Identity, error) {
			if s := r.Header.Get("X-Test-Subject"); s != "" {
				return Identity{Kind: "oidc", Subject: s}, nil
			}
			return Identity{}, errors.New("no identity")
		}}, a
}

func principal(t *testing.T, s *Service, subject string) auth.Principal {
	t.Helper()
	p, err := s.Authenticate(as(subject))
	if err != nil {
		t.Fatalf("%s: %v", subject, err)
	}
	return p
}

func TestBootstrapAndProvisioning(t *testing.T) {
	s, audit := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	if admin.Role != auth.Admin || approver.Role != auth.Approver || admin.UserID != (Identity{"oidc", "CN=First Admin"}).ID() {
		t.Fatalf("bootstrap roles: %+v %+v", admin, approver)
	}
	if p, _ := s.Authenticate(as("CN=Stranger")); p.Role != auth.None {
		t.Fatalf("an unprovisioned certificate has a role: %+v", p)
	}
	u, _, err := s.Provision(admin, Identity{Kind: "oidc", Subject: "CN=Dana"})
	if err != nil || u.Role != auth.None || u.Status != Pending {
		t.Fatalf("provision: %+v %v", u, err)
	}
	if p := principal(t, s, "CN=Dana"); p.Role != auth.None {
		t.Fatal("provisioning granted a role")
	}
	if _, _, err := s.Provision(admin, Identity{Kind: "oidc", Subject: "CN=Dana"}); !errors.Is(err, ErrExists) {
		t.Fatalf("provisioned twice: %v", err)
	}
	if _, _, err := s.Provision(approver, Identity{Kind: "oidc", Subject: "CN=Eve"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("an approver provisioned a user: %v", err)
	}
	for _, bad := range []Identity{{Kind: "x509", Subject: "x"}, {Kind: "oidc"}} {
		if _, _, err := s.Provision(admin, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if len(audit.records) != 1 || audit.records[0].Action != "user.invite" {
		t.Fatalf("provisioning must be audited once: %+v", audit.records)
	}
}

func TestBootstrapEndsWhenTheRoleIsHeld(t *testing.T) {
	s, _ := service(t)
	held := Identity{Kind: "oidc", Subject: "CN=Real Admin"}
	if err := s.Store.PutUser(User{ID: held.ID(), Kind: "oidc", Subject: held.Subject, Role: auth.Admin, Status: Active}); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Authenticate(as("CN=First Admin")); p.Role != auth.None {
		t.Fatalf("bootstrap admin kept its role after a real admin exists: %+v", p)
	}
	if p := principal(t, s, "CN=First Approver"); p.Role != auth.Approver {
		t.Fatal("bootstrap approver lost its role before a real approver exists")
	}
	if p := principal(t, s, "CN=Real Admin"); p.Role != auth.Admin {
		t.Fatalf("stored role: %+v", p)
	}
	disabled := Identity{Kind: "oidc", Subject: "CN=First Approver"}
	if err := s.Store.PutUser(User{ID: disabled.ID(), Kind: "oidc", Subject: disabled.Subject, Status: Offboarded}); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Authenticate(as("CN=First Approver")); p.Role != auth.None {
		t.Fatal("an offboarded record still received its bootstrap role")
	}
	// The admin bootstrap ended when a real admin was seen; offboarding that admin must not
	// bring it back (one admin could otherwise offboard the rest and regain the role).
	if err := s.Store.PutUser(User{ID: held.ID(), Kind: "oidc", Subject: held.Subject, Status: Offboarded}); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Authenticate(as("CN=First Admin")); p.Role != auth.None {
		t.Fatalf("bootstrap admin revived after every admin was offboarded: %+v", p)
	}
}

// onboard invites subject, activates it, and grants role (none skips the grant).
func onboard(t *testing.T, s *Service, admin, approver auth.Principal, subject string, role auth.Role) auth.Principal {
	t.Helper()
	_, act, err := s.Provision(admin, Identity{Kind: "oidc", Subject: subject})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Decide(approver, act.ID, true); err != nil {
		t.Fatal(err)
	}
	p := principal(t, s, subject)
	if role != auth.None {
		req, err := s.RequestRole(admin, p.UserID, role)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Decide(approver, req.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	return principal(t, s, subject)
}

func TestInviteActivateGrantDrop(t *testing.T) {
	s, audit := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	u, act, err := s.Provision(admin, Identity{Kind: "oidc", Subject: "CN=Dana"})
	if err != nil || act.Kind != "activate" || act.UserID != u.ID {
		t.Fatalf("invite: %+v %v", act, err)
	}
	if _, err := s.RequestRole(admin, u.ID, auth.Auditor); !errors.Is(err, ErrState) {
		t.Fatalf("granted a role to a pending user: %v", err)
	}
	if _, err := s.Decide(admin, act.ID, true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("an admin activated: %v", err)
	}
	if _, err := s.Decide(approver, act.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(approver, act.ID, false); !errors.Is(err, ErrDecided) {
		t.Fatalf("decided twice: %v", err)
	}
	if _, err := s.RequestRole(admin, u.ID, auth.None); !errors.Is(err, ErrInvalid) {
		t.Fatalf("requested no role: %v", err)
	}
	req, err := s.RequestRole(admin, u.ID, auth.Auditor)
	if err != nil {
		t.Fatal(err)
	}
	if p := principal(t, s, "CN=Dana"); p.Role != auth.None {
		t.Fatal("a role took effect before approval")
	}
	if _, err := s.Decide(approver, req.ID, true); err != nil {
		t.Fatal(err)
	}
	if p := principal(t, s, "CN=Dana"); p.Role != auth.Auditor {
		t.Fatalf("approved role: %+v", p)
	}
	if _, err := s.DropRole(approver, u.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("an approver dropped a role: %v", err)
	}
	if _, err := s.DropRole(admin, u.ID); err != nil {
		t.Fatal(err)
	}
	if p := principal(t, s, "CN=Dana"); p.Role != auth.None {
		t.Fatal("drop-role did not take effect at once")
	}
	if _, err := s.DropRole(admin, u.ID); !errors.Is(err, ErrState) {
		t.Fatalf("dropped a role twice: %v", err)
	}
	// invite, activate, request, approve, drop: one record each.
	if len(audit.records) != 5 {
		t.Fatalf("audit records: %d", len(audit.records))
	}
}

func TestRejectedActivationLeavesUserPending(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	_, act, _ := s.Provision(admin, Identity{Kind: "oidc", Subject: "CN=Mallory"})
	if req, err := s.Decide(approver, act.ID, false); err != nil || req.Status != Rejected {
		t.Fatalf("reject: %+v %v", req, err)
	}
	if u, _, _ := s.Store.User(act.UserID); u.Status != Pending {
		t.Fatalf("rejected user: %+v", u)
	}
}

func TestNoSelfApproval(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	second := onboard(t, s, admin, approver, "CN=Second Approver", auth.Approver)
	third := onboard(t, s, admin, second, "CN=Third", auth.None)
	// An approver may not approve a grant about itself, nor one it requested.
	req, _ := s.RequestRole(admin, second.UserID, auth.Admin)
	if _, err := s.Decide(second, req.ID, true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("approver approved its own elevation: %v", err)
	}
	if third.Role != auth.None || second.Role != auth.Approver {
		t.Fatalf("roles: %+v %+v", second, third)
	}
	if _, err := s.Decide(auth.Principal{UserID: admin.UserID, Role: auth.Approver}, req.ID, true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("the requester approved: %v", err)
	}
}

func TestStoringARoleHolderEndsBootstrapWithoutALogin(t *testing.T) {
	s, _ := service(t)
	held := Identity{Kind: "oidc", Subject: "CN=Real Admin"}
	u := User{ID: held.ID(), Kind: "oidc", Subject: held.Subject, Role: auth.Admin, Status: Active}
	if err := s.Store.PutUser(u); err != nil {
		t.Fatal(err)
	}
	u.Status, u.Role = Offboarded, auth.None // offboarded before the bootstrap subject signs in again
	if err := s.Store.PutUser(u); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Authenticate(as("CN=First Admin")); p.Role != auth.None {
		t.Fatalf("bootstrap admin revived after grant then offboard: %+v", p)
	}
}

func TestProvisioningALiveBootstrapSubjectIsRefused(t *testing.T) {
	s, _ := service(t)
	admin := principal(t, s, "CN=First Admin")
	// Found while recording the videos: this made the bootstrap approver act as nobody before
	// any real approver existed, so nothing could ever be approved.
	if _, _, err := s.Provision(admin, Identity{Kind: "oidc", Subject: "CN=First Approver"}); !errors.Is(err, ErrBootstrapLive) {
		t.Fatalf("provisioned a live bootstrap subject: %v", err)
	}
	if p := principal(t, s, "CN=First Approver"); p.Role != auth.Approver {
		t.Fatalf("bootstrap approver lost its role: %+v", p)
	}
	// After a real approver holds the role, the subject may be provisioned like anyone.
	real := Identity{Kind: "oidc", Subject: "CN=Real Approver"}
	if err := s.Store.PutUser(User{ID: real.ID(), Kind: "oidc", Subject: real.Subject, Role: auth.Approver, Status: Active}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Provision(admin, Identity{Kind: "oidc", Subject: "CN=First Approver"}); err != nil {
		t.Fatalf("provisioning a retired bootstrap subject: %v", err)
	}
}

func TestInterruptedGrantThenOffboardKeepsBootstrapRetired(t *testing.T) {
	s, _ := service(t)
	files := s.Store.(*PG)
	held := Identity{Kind: "oidc", Subject: "CN=Real Admin"}
	// A grant interrupted after the marker but before the user: the marker names nobody, so
	// the bootstrap admin can still act and retry.
	if err := files.EndBootstrap(auth.Admin, held.ID()); err != nil {
		t.Fatal(err)
	}
	if p := principal(t, s, "CN=First Admin"); p.Role != auth.Admin {
		t.Fatalf("a marker naming no user retired the bootstrap: %+v", p)
	}
	// The retry stores the holder; then the holder is offboarded with no bootstrap sign-in.
	u := User{ID: held.ID(), Kind: "oidc", Subject: held.Subject, Role: auth.Admin, Status: Active}
	if err := files.PutUser(u); err != nil {
		t.Fatal(err)
	}
	u.Status, u.Role = Offboarded, auth.None
	if err := files.PutUser(u); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Authenticate(as("CN=First Admin")); p.Role != auth.None {
		t.Fatalf("bootstrap revived: %+v", p)
	}
}

func TestInterruptedGrantOfAPendingUserLeavesBootstrapLive(t *testing.T) {
	s, _ := service(t)
	files := s.Store.(*PG)
	admin := principal(t, s, "CN=First Admin")
	u, _, err := s.Provision(admin, Identity{Kind: "oidc", Subject: "CN=Dana"})
	if err != nil {
		t.Fatal(err)
	}
	// The grant writes its marker naming Dana, then the user write fails.
	if err := files.EndBootstrap(auth.Admin, u.ID); err != nil {
		t.Fatal(err)
	}
	if p := principal(t, s, "CN=First Admin"); p.Role != auth.Admin {
		t.Fatalf("a marker naming a user who never held the role retired the bootstrap: %+v", p)
	}
}

func TestDamagedMarkerFailsClosed(t *testing.T) {
	s, _ := service(t)
	files := s.Store.(*PG)
	held := Identity{Kind: "oidc", Subject: "CN=Real Admin"}
	u := User{ID: held.ID(), Kind: "oidc", Subject: held.Subject, Role: auth.Admin, Status: Active}
	files.PutUser(u)
	u.Status, u.Role = Offboarded, auth.None
	files.PutUser(u)
	// The database refuses a damaged marker outright, so the final one stays in effect.
	if err := superOf(t, files).SuperErr(`UPDATE portal.bootstrap_ended SET holder = 'garbage' WHERE role = 'admin'`); err == nil {
		t.Fatal("the database stored a damaged marker")
	}
	if p, err := s.Authenticate(as("CN=First Admin")); err == nil && p.Role != auth.None {
		t.Fatalf("a damaged marker revived the bootstrap: %+v", p)
	}
}

func TestDamagedHolderRecordFailsClosed(t *testing.T) {
	for _, body := range []string{"null", "{}", `{"id":"x"}`} {
		s, _ := service(t)
		files := s.Store.(*PG)
		held := Identity{Kind: "oidc", Subject: "CN=Real Admin"}
		u := User{ID: held.ID(), Kind: "oidc", Subject: held.Subject, Role: auth.Admin, Status: Active}
		if err := files.PutUser(u); err != nil {
			t.Fatal(err)
		}
		// The marker names this holder; its record is then damaged.
		superOf(t, files).Super(t, `UPDATE portal.users SET body = $1::jsonb WHERE id = $2`, body, u.ID)
		if p, err := s.Authenticate(as("CN=First Admin")); err == nil && p.Role != auth.None {
			t.Fatalf("holder record %s revived the bootstrap: %+v", body, p)
		}
		if _, _, err := files.User(u.ID); err == nil {
			t.Fatalf("read a damaged record %s without error", body)
		}
		if err := files.PutUser(u); err == nil {
			t.Fatalf("overwrote a damaged record %s, losing its history", body)
		}
	}
}

func TestErasedRoleHistoryKeepsBootstrapRetired(t *testing.T) {
	s, _ := service(t)
	files := s.Store.(*PG)
	held := Identity{Kind: "oidc", Subject: "CN=Real Admin"}
	u := User{ID: held.ID(), Kind: "oidc", Subject: held.Subject, Role: auth.Admin, Status: Active}
	if err := files.PutUser(u); err != nil {
		t.Fatal(err)
	}
	u.Status, u.Role = Offboarded, auth.None
	if err := files.PutUser(u); err != nil {
		t.Fatal(err)
	}
	// The offboarded holder's record loses its role history: still a valid record.
	u.Granted = nil
	raw, _ := json.Marshal(u)
	superOf(t, files).Super(t, `UPDATE portal.users SET body = $1::jsonb WHERE id = $2`, string(raw), u.ID)
	if p, err := s.Authenticate(as("CN=First Admin")); err == nil && p.Role != auth.None {
		t.Fatalf("erasing the holder's history revived the bootstrap: %+v", p)
	}
}

func TestStoreRefusesBadIDs(t *testing.T) {
	f := NewPG(testDB(t), testLabel)
	if _, _, err := f.User("../x"); err == nil {
		t.Fatal("read a user by path")
	}
	if err := f.PutUser(User{ID: "../x"}); err == nil {
		t.Fatal("wrote a user by path")
	}
}

func TestGrantEndsBootstrapBeforeOffboarding(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	real := onboard(t, s, admin, approver, "CN=Real Admin", auth.Admin)
	u, _, _ := s.Store.User(real.UserID)
	u.Status = Offboarded
	if err := s.Store.PutUser(u); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Authenticate(as("CN=First Admin")); p.Role != auth.None {
		t.Fatalf("bootstrap admin revived: %+v", p)
	}
}

// flaky fails the next user or request writes it is told to.
type flaky struct {
	Store
	users, requests int
}

func (f *flaky) PutUser(u User) error {
	if f.users > 0 {
		f.users--
		return errors.New("disk said no")
	}
	return f.Store.PutUser(u)
}

func (f *flaky) PutRequest(r Request) error {
	if f.requests > 0 {
		f.requests--
		return errors.New("disk said no")
	}
	return f.Store.PutRequest(r)
}

func TestApprovalRecoversFromFailedWrites(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	_, act, _ := s.Provision(admin, Identity{Kind: "oidc", Subject: "CN=Dana"})
	base := s.Store
	// The user write fails: nothing changed, the request is still pending, retry works.
	s.Store = &flaky{Store: base, users: 1}
	if _, err := s.Decide(approver, act.ID, true); err == nil {
		t.Fatal("approval reported success after a failed write")
	}
	if r, _, _ := base.Request(act.ID); r.Status != Undecided {
		t.Fatalf("request decided though the user was not changed: %+v", r)
	}
	// The request write fails after the user changed: the retry finishes the decision.
	s.Store = &flaky{Store: base, requests: 1}
	if _, err := s.Decide(approver, act.ID, true); err == nil {
		t.Fatal("approval reported success after a failed request write")
	}
	s.Store = base
	if r, err := s.Decide(approver, act.ID, true); err != nil || r.Status != Approved {
		t.Fatalf("retry: %+v %v", r, err)
	}
	if u, _, _ := base.User(act.UserID); u.Status != Active {
		t.Fatalf("user after retry: %+v", u)
	}
	// A failed grant leaves bootstrap working: the role is not held yet.
	req, _ := s.RequestRole(admin, act.UserID, auth.Approver)
	s.Store = &flaky{Store: base, users: 1}
	s.Decide(approver, req.ID, true)
	s.Store = base
	if p := principal(t, s, "CN=First Approver"); p.Role != auth.Approver {
		t.Fatal("a failed grant retired the bootstrap approver")
	}
	if _, err := s.Decide(approver, req.ID, true); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Authenticate(as("CN=First Approver")); p.Role != auth.None {
		t.Fatal("the bootstrap approver survived a granted approver")
	}
}

func TestInviteRecoversFromAFailedUserWrite(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	base := s.Store
	s.Store = &flaky{Store: base, users: 1}
	_, _, err := s.Provision(admin, Identity{Kind: "oidc", Subject: "CN=Eve"})
	if err == nil {
		t.Fatal("invite reported success after a failed user write")
	}
	s.Store = base
	u, act, err := s.Provision(admin, Identity{Kind: "oidc", Subject: "CN=Eve"})
	if err != nil || u.Status != Pending {
		t.Fatalf("inviting again: %+v %v", u, err)
	}
	if _, err := s.Decide(approver, act.ID, true); err != nil {
		t.Fatal(err)
	}
}

func TestPartlyAppliedApprovalCannotBeRejected(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	dana := onboard(t, s, admin, approver, "CN=Dana", auth.None)
	req, err := s.RequestRole(admin, dana.UserID, auth.Auditor)
	if err != nil {
		t.Fatal(err)
	}
	base := s.Store
	s.Store = &flaky{Store: base, requests: 1} // the role is granted, the decision is not recorded
	if _, err := s.Decide(approver, req.ID, true); err == nil {
		t.Fatal("approval reported success after a failed request write")
	}
	s.Store = base
	if _, err := s.Decide(approver, req.ID, false); !errors.Is(err, ErrDecided) {
		t.Fatalf("rejected a request whose access was already granted: %v", err)
	}
	// The refused rejection wrote the stored approval down.
	if r, _, _ := base.Request(req.ID); r.Status != Approved || r.DecidedBy != approver.Name {
		t.Fatalf("the stored approval was not finished: %+v", r)
	}
	if _, err := s.RequestRole(admin, dana.UserID, auth.Auditor); !errors.Is(err, ErrState) {
		t.Fatalf("requested the role already held: %v", err)
	}
}

func TestDuplicateGrantCanStillBeRejected(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	dana := onboard(t, s, admin, approver, "CN=Dana", auth.None)
	first, _ := s.RequestRole(admin, dana.UserID, auth.Auditor)
	second, err := s.RequestRole(admin, dana.UserID, auth.Auditor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(approver, first.ID, true); err != nil {
		t.Fatal(err)
	}
	// The second request was never applied, so rejecting it must work.
	if r, err := s.Decide(approver, second.ID, false); err != nil || r.Status != Rejected {
		t.Fatalf("rejecting an unapplied duplicate: %+v %v", r, err)
	}
}

func TestInterruptedFirstApproverGrantStillFinishes(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	real := onboard(t, s, admin, approver, "CN=Real Approver", auth.None)
	req, err := s.RequestRole(admin, real.UserID, auth.Approver)
	if err != nil {
		t.Fatal(err)
	}
	base := s.Store
	// The grant is stored, so the bootstrap approver retires; the decision write fails.
	s.Store = &flaky{Store: base, requests: 1}
	if _, err := s.Decide(approver, req.ID, true); err == nil {
		t.Fatal("approval reported success after a failed request write")
	}
	s.Store = base
	if p, _ := s.Authenticate(as("CN=First Approver")); p.Role != auth.None {
		t.Fatalf("bootstrap approver still acts after the grant was stored: %+v", p)
	}
	// The only approver left is the subject. The decision is on its record, so it finishes
	// as the bootstrap approver's, not as a self-approval.
	now := principal(t, s, "CN=Real Approver")
	if now.Role != auth.Approver {
		t.Fatalf("grant not in effect: %+v", now)
	}
	r, err := s.Decide(now, req.ID, true)
	if err != nil || r.Status != Approved || r.DecidedBy != approver.Name {
		t.Fatalf("finishing the stored approval: %+v %v", r, err)
	}
	if stored, _, _ := base.Request(req.ID); stored.Status != Approved || stored.DecidedBy != approver.Name {
		t.Fatalf("stored decision: %+v", stored)
	}
}

func TestInvitingAPendingUserAgainGivesItAnActivationRequest(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	// A pending user stored with no activation request, as earlier versions did.
	id := Identity{Kind: "oidc", Subject: "CN=Legacy"}
	if err := s.Store.PutUser(User{ID: id.ID(), Kind: id.Kind, Subject: id.Subject, Status: Pending}); err != nil {
		t.Fatal(err)
	}
	u, act, err := s.Provision(admin, id)
	if err != nil || u.Status != Pending || act.Kind != "activate" {
		t.Fatalf("inviting a pending user again: %+v %+v %v", u, act, err)
	}
	if _, err := s.Decide(approver, act.ID, true); err != nil {
		t.Fatal(err)
	}
	if p := principal(t, s, "CN=Legacy"); p.UserID != id.ID() {
		t.Fatalf("legacy user: %+v", p)
	}
	if u, _, _ := s.Store.User(id.ID()); u.Status != Active {
		t.Fatalf("not activated: %+v", u)
	}
	if _, _, err := s.Provision(admin, id); !errors.Is(err, ErrExists) {
		t.Fatalf("invited an active user again: %v", err)
	}
}

func TestDamagedRequestsFailClosed(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	dana := onboard(t, s, admin, approver, "CN=Dana", auth.None)
	files := s.Store.(*PG)
	good, err := s.RequestRole(admin, dana.UserID, auth.Auditor)
	if err != nil {
		t.Fatal(err)
	}
	for name, damage := range map[string]func(*Request){
		"no requester":   func(r *Request) { r.RequesterID = "" },
		"unknown kind":   func(r *Request) { r.Kind = "promote" },
		"no role":        func(r *Request) { r.Role = auth.None },
		"activate+role":  func(r *Request) { r.Kind = "activate" },
		"unknown status": func(r *Request) { r.Status = "maybe" },
		"wrong id":       func(r *Request) { r.ID = "00000000000000000000000000000000" },
	} {
		r := good
		damage(&r)
		raw, _ := json.Marshal(r)
		superOf(t, files).Super(t, `UPDATE portal.role_requests SET body = $1::jsonb WHERE id = $2`, string(raw), good.ID)
		if _, err := s.Decide(approver, good.ID, true); !errors.Is(err, ErrDamaged) {
			t.Fatalf("%s: decided a damaged request: %v", name, err)
		}
		if _, err := files.Requests(); !errors.Is(err, ErrDamaged) {
			t.Fatalf("%s: listed a damaged request: %v", name, err)
		}
	}
	if u, _, _ := files.User(dana.UserID); u.Role != auth.None {
		t.Fatalf("a damaged request granted a role: %+v", u)
	}
}

func TestReinviteDoesNotRewriteThePendingUser(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	id := Identity{Kind: "oidc", Subject: "CN=Legacy"}
	if err := s.Store.PutUser(User{ID: id.ID(), Kind: id.Kind, Subject: id.Subject, Status: Pending}); err != nil {
		t.Fatal(err)
	}
	base := s.Store
	// Only the request is written: a failing user write cannot strand it.
	s.Store = &flaky{Store: base, users: 1}
	_, act, err := s.Provision(admin, id)
	if err != nil {
		t.Fatalf("re-invite: %v", err)
	}
	s.Store = base
	if _, err := s.Decide(approver, act.ID, true); err != nil {
		t.Fatal(err)
	}
}

// testDB is a fresh migrated database; testLabel the ceiling the tests run at.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	d, db := pgtest.Migrated(t, pgdb.Core, store.Schema)
	supers.Store(db, d)
	return db
}

var supers sync.Map // *sql.DB -> *pgtest.DB

// superOf is the superuser handle on the directory's database, to damage records as someone
// editing the database outside the service would.
func superOf(t *testing.T, p *PG) *pgtest.DB {
	t.Helper()
	d, ok := supers.Load(p.db)
	if !ok {
		t.Fatal("no test database")
	}
	return d.(*pgtest.DB)
}

var testLabel = func() pgdb.Label {
	l, err := pgdb.ParseLabel("SECRET")
	if err != nil {
		panic(err)
	}
	return l
}()
