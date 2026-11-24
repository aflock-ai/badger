package users

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aflock-ai/badger/testifysec/portal/internal/auth"
)

func TestMembershipAddAndRemove(t *testing.T) {
	s, audit := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	dana := onboard(t, s, admin, approver, "CN=Dana", auth.None)
	before := len(audit.records)
	u, err := s.Assign(admin, dana.UserID, "deploy-a")
	if err != nil || len(u.Deployments) != 1 || u.Deployments[0] != "deploy-a" {
		t.Fatalf("assign: %+v %v", u, err)
	}
	if u, err = s.Assign(admin, dana.UserID, "deploy-a"); err != nil || len(u.Deployments) != 1 {
		t.Fatalf("assigning twice must be a no-op: %+v %v", u, err)
	}
	if _, err := s.Assign(approver, dana.UserID, "deploy-b"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("approver assigned: %v", err)
	}
	if _, err := s.Assign(admin, dana.UserID, "../x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad deployment id: %v", err)
	}
	if u, err = s.Unassign(admin, dana.UserID, "deploy-a"); err != nil || len(u.Deployments) != 0 {
		t.Fatalf("unassign: %+v %v", u, err)
	}
	if got := len(audit.records) - before; got != 2 {
		t.Fatalf("one record per change, none for no-ops or refusals: %d", got)
	}
	_, act, _ := s.Provision(admin, Identity{Kind: "oidc", Subject: "CN=Pending"})
	if _, err := s.Assign(admin, act.UserID, "deploy-a"); !errors.Is(err, ErrState) {
		t.Fatalf("assigned a pending user: %v", err)
	}
}

func TestOffboardIsFinalAndClearsEverything(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	frank := onboard(t, s, admin, approver, "CN=Frank", auth.Auditor)
	s.Assign(admin, frank.UserID, "deploy-a")
	pending, _ := s.RequestRole(admin, frank.UserID, auth.Approver)
	if _, err := s.Offboard(admin, admin.UserID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("an admin offboarded itself: %v", err)
	}
	u, err := s.Offboard(admin, frank.UserID)
	if err != nil || u.Status != Offboarded || u.Role != auth.None || len(u.Deployments) != 0 {
		t.Fatalf("offboard: %+v %v", u, err)
	}
	if r, _, _ := s.Store.Request(pending.ID); r.Status != Dropped {
		t.Fatalf("pending request about the user survived: %+v", r)
	}
	if p, _ := s.Authenticate(as("CN=Frank")); p.Role != auth.None {
		t.Fatal("an offboarded user still acts")
	}
	if _, _, err := s.Provision(admin, Identity{Kind: "oidc", Subject: "CN=Frank"}); !errors.Is(err, ErrExists) {
		t.Fatalf("re-invited an offboarded identity: %v", err)
	}
	if _, err := s.Offboard(admin, frank.UserID); !errors.Is(err, ErrState) {
		t.Fatalf("offboarded twice: %v", err)
	}
	if open, _ := s.Pending(); len(open) != 0 {
		t.Fatalf("pending queue: %+v", open)
	}
}

// failingRequests fails the next n request writes.
type failingRequests struct {
	Store
	n int
}

func (f *failingRequests) PutRequest(r Request) error {
	if f.n > 0 {
		f.n--
		return errors.New("disk said no")
	}
	return f.Store.PutRequest(r)
}

func TestOffboardRecoversFromAFailedRequestWrite(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	gus := onboard(t, s, admin, approver, "CN=Gus", auth.Auditor)
	pending, _ := s.RequestRole(admin, gus.UserID, auth.Approver)
	s.Store = &failingRequests{Store: s.Store, n: 1}
	if _, err := s.Offboard(admin, gus.UserID); err == nil {
		t.Fatal("offboard reported success after a failed write")
	}
	if u, _, _ := s.Store.User(gus.UserID); u.Status != Active {
		t.Fatalf("user marked offboarded before its requests were dropped: %+v", u)
	}
	if u, err := s.Offboard(admin, gus.UserID); err != nil || u.Status != Offboarded {
		t.Fatalf("retry: %+v %v", u, err)
	}
	if r, _, _ := s.Store.Request(pending.ID); r.Status != Dropped {
		t.Fatalf("request after retry: %+v", r)
	}
}

func TestNoMembershipsEncodeAsEmptyArray(t *testing.T) {
	raw, err := json.Marshal(User{ID: "x"})
	if err != nil || !strings.Contains(string(raw), `"deployments":[]`) {
		t.Fatalf("%s %v", raw, err)
	}
}

func TestOffboardDropsRequestsTheUserMade(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	second := onboard(t, s, admin, approver, "CN=Second Admin", auth.Admin)
	// The second admin invites someone; that activation request is theirs.
	_, act, err := s.Provision(second, Identity{Kind: "oidc", Subject: "CN=Invitee"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Offboard(admin, second.UserID); err != nil {
		t.Fatal(err)
	}
	if r, _, _ := s.Store.Request(act.ID); r.Status != Dropped {
		t.Fatalf("a request the offboarded admin made survived: %+v", r)
	}
	if _, err := s.Decide(approver, act.ID, true); !errors.Is(err, ErrDecided) {
		t.Fatalf("a dropped request was approved: %v", err)
	}
}

func TestOffboardRetiresTheBootstrapItsRoleHeld(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	real := onboard(t, s, admin, approver, "CN=Real Admin", auth.Admin)
	other := onboard(t, s, admin, approver, "CN=Other Admin", auth.Admin)
	// Lose the marker the grants wrote, as a failed marker write would.
	files := s.Store.(*PG)
	superOf(t, files).Super(t, `DELETE FROM portal.bootstrap_ended WHERE role = 'admin'`)
	if _, err := s.Offboard(other, real.UserID); err != nil {
		t.Fatal(err)
	}
	// The last holder leaves by a plain store write (no grant, no offboard path).
	u, _, _ := files.User(other.UserID)
	u.Status, u.Role = Offboarded, auth.None
	if err := files.PutUser(u); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Authenticate(as("CN=First Admin")); p.Role != auth.None {
		t.Fatalf("bootstrap admin revived after its role's holders went: %+v", p)
	}
}

func TestOffboardingABootstrapPrincipal(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	// While its role is live, removing the bootstrap approver would block every approval.
	if _, err := s.Offboard(admin, approver.UserID); !errors.Is(err, ErrBootstrapLive) {
		t.Fatalf("offboarded a live bootstrap approver: %v", err)
	}
	onboard(t, s, admin, approver, "CN=Real Approver", auth.Approver)
	// After hand-over it is offboarded like anyone, not reported missing, and stays out.
	u, err := s.Offboard(admin, approver.UserID)
	if err != nil || u.Status != Offboarded {
		t.Fatalf("offboard handed-over bootstrap approver: %+v %v", u, err)
	}
	if p, _ := s.Authenticate(as("CN=First Approver")); p.Role != auth.None {
		t.Fatalf("offboarded bootstrap principal still acts: %+v", p)
	}
	if _, err := s.Offboard(admin, (Identity{Kind: "oidc", Subject: "CN=Nobody"}).ID()); !errors.Is(err, ErrMissing) {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestOffboardingABootstrapPrincipalDropsItsRequests(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	// The bootstrap admin invites someone, then hands its role over.
	_, act, err := s.Provision(admin, Identity{Kind: "oidc", Subject: "CN=Invitee"})
	if err != nil {
		t.Fatal(err)
	}
	real := onboard(t, s, admin, approver, "CN=Real Admin", auth.Admin)
	if _, err := s.Offboard(real, admin.UserID); err != nil {
		t.Fatal(err)
	}
	if r, _, _ := s.Store.Request(act.ID); r.Status != Dropped {
		t.Fatalf("a request the offboarded bootstrap admin made survived: %+v", r)
	}
	if _, err := s.Decide(approver, act.ID, true); !errors.Is(err, ErrDecided) {
		t.Fatalf("a dropped request was approved: %v", err)
	}
}

func TestStoredApprovalIsFinishedNotQueuedOrDropped(t *testing.T) {
	s, _ := service(t)
	admin, approver := principal(t, s, "CN=First Admin"), principal(t, s, "CN=First Approver")
	second := onboard(t, s, admin, approver, "CN=Second Admin", auth.Admin)
	dana := onboard(t, s, admin, approver, "CN=Dana", auth.None)
	req, err := s.RequestRole(second, dana.UserID, auth.Auditor)
	if err != nil {
		t.Fatal(err)
	}
	base := s.Store
	s.Store = &failingRequests{Store: base, n: 1} // the grant is stored, the decision is not
	if _, err := s.Decide(approver, req.ID, true); err == nil {
		t.Fatal("approval reported success after a failed request write")
	}
	s.Store = base
	if queue, err := s.Pending(); err != nil || len(queue) != 0 {
		t.Fatalf("a stored approval is still queued: %+v %v", queue, err)
	}
	// Offboarding the requester must not record as dropped a grant that is in effect.
	if _, err := s.Offboard(admin, second.UserID); err != nil {
		t.Fatal(err)
	}
	if r, _, _ := base.Request(req.ID); r.Status != Approved || r.DecidedBy != approver.Name {
		t.Fatalf("stored approval: %+v", r)
	}
}
