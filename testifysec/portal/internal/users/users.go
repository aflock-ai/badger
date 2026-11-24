// Package users is the portal's user directory. People come from the IdP:
// the portal stores who they are and what role they hold, never a password. A role changes
// only when an approver who is neither the requester nor the person approves it.
package users

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/aflock-ai/badger/testifysec/portal/internal/auth"
	"github.com/aflock-ai/badger/testifysec/portal/internal/store"
)

// Identity is what the IdP vouches for, through the service's admin check: the stable subject
// of a person signed in with an admin group (Kind KindIdP).
// KindIdP is the only identity kind: an IdP subject.
const KindIdP = "oidc"

type Identity struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
}

// ID is stable and safe as a file name.
func (i Identity) ID() string {
	sum := sha256.Sum256([]byte(i.Kind + "\n" + i.Subject))
	return hex.EncodeToString(sum[:])
}

type Status string

const (
	// Pending: invited, not yet approved; acts as nobody. Offboarded is final.
	Pending    Status = "pending"
	Active     Status = "active"
	Offboarded Status = "offboarded"
)

type User struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Subject   string    `json:"subject"`
	Role      auth.Role `json:"role"`
	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	CreatedBy string    `json:"createdBy"`
	// Granted lists every role the user has ever held; it only grows. A bootstrap marker
	// takes effect only for a holder whose record shows the role.
	Granted []auth.Role `json:"granted,omitempty"`
	// Applied lists the approvals whose change has been stored on this user, with who made
	// them: the decision is durable in the same write as the change it grants.
	Applied []Applied `json:"applied,omitempty"`
	// Deployments are memberships.
	Deployments []string `json:"deployments"`
	// read is the stored record this copy was read from (Store.User), so the store can refuse to
	// write it back once another writer has changed the record: absent for a record built in
	// code, notStored for one built to be stored for the first time.
	read string
}

func (u *User) setRead(raw string) { u.read = raw }

// notStored marks a User built to be written where no record exists yet.
const notStored = "\x00none"

// MarshalJSON writes no memberships as [], never null, as the API schema requires.
func (u User) MarshalJSON() ([]byte, error) {
	type plain User
	if u.Deployments == nil {
		u.Deployments = []string{}
	}
	return json.Marshal(plain(u))
}

// Applied is one approval stored on the user it changed.
type Applied struct {
	Request string    `json:"request"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
}

func (u User) applied(requestID string) (Applied, bool) {
	for _, a := range u.Applied {
		if a.Request == requestID {
			return a, true
		}
	}
	return Applied{}, false
}

type Decision string

const (
	Undecided Decision = "pending"
	Approved  Decision = "approved"
	Rejected  Decision = "rejected"
	Dropped   Decision = "dropped" // by offboarding
)

// Request asks an approver to activate an invited user (Kind activate) or to give an active
// user Role (Kind grant).
type Request struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	UserID      string    `json:"userId"`
	Role        auth.Role `json:"role"`
	RequestedBy string    `json:"requestedBy"`
	RequesterID string    `json:"requesterId"`
	RequestedAt time.Time `json:"requestedAt"`
	Status      Decision  `json:"status"`
	DecidedBy   string    `json:"decidedBy,omitempty"`
	DecidedAt   time.Time `json:"decidedAt,omitzero"`
}

var (
	ErrExists    = errors.New("user already provisioned")
	ErrMissing   = errors.New("no such user or request")
	ErrForbidden = errors.New("not allowed for this principal")
	ErrDecided   = errors.New("request already decided")
	ErrState     = errors.New("user is not in a state that allows this")
	ErrInvalid   = errors.New("invalid user or role")
	// ErrDamaged: a stored record does not parse as one. Authorization fails closed on it.
	ErrDamaged = errors.New("stored record is damaged; restore it offline")
	// ErrStale: the record changed after the copy being written was read.
	ErrStale  = errors.New("record changed since it was read")
	hexID     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	requestID = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

type Store interface {
	User(id string) (User, bool, error)
	Users() ([]User, error)
	PutUser(User) error
	Request(id string) (Request, bool, error)
	PutRequest(Request) error
	Requests() ([]Request, error)
	// BootstrapEnded and EndBootstrap record, durably and for good, that a role's bootstrap
	// entry no longer works. Nothing in the portal clears it.
	// The marker names the holder whose arrival ended it. It is written before the holder,
	// takes effect once that holder's record shows the role, and is then made final, so it
	// no longer depends on that record at all.
	BootstrapEnded(role auth.Role) (bool, error)
	EndBootstrap(role auth.Role, holderID string) error
}

type Service struct {
	Store    Store
	Audit    store.AuditSink
	Identify func(*http.Request) (Identity, error)
	// Bootstrap (IdP subject -> role) gives a configured subject a role until a user
	// first holds that role; then it ends for good (bootstrapLive).
	Bootstrap map[string]auth.Role
	Now       func() time.Time
	mu        sync.Mutex
}

// Authenticate returns a principal for any IdP-verified identity; one with no role or a
// disabled record has role None and is refused by every guarded route.
func (s *Service) Authenticate(r *http.Request) (auth.Principal, error) {
	id, err := s.Identify(r)
	if err != nil {
		return auth.Principal{}, err
	}
	p := auth.Principal{UserID: id.ID(), Name: id.Subject}
	u, ok, err := s.Store.User(p.UserID)
	if err != nil {
		return auth.Principal{}, err
	}
	if ok && u.Status == Active && u.Role.Valid() {
		p.Role = u.Role
		return p, nil
	}
	if ok {
		return p, nil // a pending or offboarded record, or one with no role, acts as nobody
	}
	if role, boot := s.Bootstrap[id.Subject]; boot && id.Kind == KindIdP && role.Valid() {
		if live, err := s.bootstrapLive(role); err != nil {
			return auth.Principal{}, err
		} else if live {
			p.Role = role
		}
	}
	return p, nil
}

// bootstrapLive: a bootstrap role works only until an active user first holds the role, and
// then never again, even if every holder is later offboarded. Reviving it would let one admin
// offboard the others and regain the role through config with no second person.
func (s *Service) bootstrapLive(role auth.Role) (bool, error) {
	if ended, err := s.Store.BootstrapEnded(role); err != nil || ended {
		return false, err
	}
	all, err := s.Store.Users()
	if err != nil {
		return false, err
	}
	for _, u := range all {
		if u.Status == Active && u.Role == role {
			return false, s.Store.EndBootstrap(role, u.ID) // repair a marker a crash lost
		}
	}
	return true, nil
}

var ErrBootstrapLive = errors.New("that subject holds a bootstrap role that has not been handed over; grant the role to a real user first")

// Provision invites an identity the enclave already vouches for: the user is pending, acts as
// nobody, and an activation request waits for an approver. It grants no role.
func (s *Service) Provision(actor auth.Principal, id Identity) (User, Request, error) {
	if actor.Role != auth.Admin {
		return User{}, Request{}, ErrForbidden
	}
	if id.Kind != KindIdP || id.Subject == "" || len(id.Subject) > 1024 {
		return User{}, Request{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A record for a live bootstrap subject would make it act as nobody before a real user holds
	// its role: one admin could provision the bootstrap approver and block every approval.
	if role, boot := s.Bootstrap[id.Subject]; boot {
		if live, err := s.bootstrapLive(role); err != nil {
			return User{}, Request{}, err
		} else if live {
			return User{}, Request{}, ErrBootstrapLive
		}
	}
	u := User{ID: id.ID(), Kind: id.Kind, Subject: id.Subject, Status: Pending, CreatedAt: s.Now().UTC(), CreatedBy: actor.Name}
	existing := false
	if old, ok, err := s.Store.User(u.ID); err != nil {
		return User{}, Request{}, err
	} else if ok && old.Status != Pending {
		return User{}, Request{}, ErrExists
	} else if ok {
		// Inviting a pending user again issues an activation request only if none is open:
		// the way to activate one stored with none, or whose request was rejected.
		all, err := s.Store.Requests()
		if err != nil {
			return User{}, Request{}, err
		}
		for _, r := range all {
			if r.Kind == "activate" && r.UserID == u.ID && r.Status == Undecided {
				return User{}, Request{}, ErrExists
			}
		}
		u, existing = old, true
	}
	req := s.newRequest(actor, "activate", u.ID, auth.None)
	// One record for the one action, as the onboarding model counts it.
	if err := s.audit(actor, "user.invite", "user/"+u.ID, "", "subject:"+u.Subject+" request:"+req.ID); err != nil {
		return User{}, Request{}, err
	}
	// The request first, the user last: if the user write fails there is no pending user
	// without an activation request, and inviting again works. An orphaned request names a
	// user who does not exist, so deciding it is not-found. A user already stored is not
	// written again, so a re-invite has one write and cannot strand its request.
	if err := s.Store.PutRequest(req); err != nil {
		return User{}, Request{}, err
	} else if existing {
		return u, req, nil
	}
	u.read = notStored // another replica storing the same user meanwhile wins; this one refuses
	if err := s.Store.PutUser(u); err != nil {
		return User{}, Request{}, err
	}
	return u, req, nil
}

func (s *Service) newRequest(actor auth.Principal, kind, userID string, role auth.Role) Request {
	raw := make([]byte, 16)
	rand.Read(raw)
	return Request{ID: hex.EncodeToString(raw), Kind: kind, UserID: userID, Role: role, RequestedBy: actor.Name,
		RequesterID: actor.UserID, RequestedAt: s.Now().UTC(), Status: Undecided}
}

// DropRole removes an active user's role at once: taking access away needs no second person.
func (s *Service) DropRole(actor auth.Principal, userID string) (User, error) {
	if actor.Role != auth.Admin {
		return User{}, ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok, err := s.Store.User(userID)
	if err != nil {
		return User{}, err
	} else if !ok {
		return User{}, ErrMissing
	} else if u.Status != Active || u.Role == auth.None {
		return User{}, ErrState
	}
	if err = s.audit(actor, "role.drop", "user/"+u.ID, "role:"+string(u.Role), "role:"); err != nil {
		return User{}, err
	}
	u.Role = auth.None
	return u, s.Store.PutUser(u)
}

// RequestRole asks for an active user to be granted role; nothing changes until an approver
// decides. Removing a role is DropRole.
func (s *Service) RequestRole(actor auth.Principal, userID string, role auth.Role) (Request, error) {
	if actor.Role != auth.Admin {
		return Request{}, ErrForbidden
	}
	if !role.Valid() {
		return Request{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok, err := s.Store.User(userID); err != nil {
		return Request{}, err
	} else if !ok {
		return Request{}, ErrMissing
	} else if u.Status != Active || u.Role == role {
		return Request{}, ErrState // a grant of the role already held could never be told from a partial approval
	}
	req := s.newRequest(actor, "grant", userID, role)
	if err := s.audit(actor, "role.request", "user/"+userID, "", "role:"+string(role)); err != nil {
		return Request{}, err
	}
	return req, s.Store.PutRequest(req)
}

// Decide approves or rejects a pending request. The approver may be neither the requester
// nor the person whose role it is.
func (s *Service) Decide(actor auth.Principal, id string, approve bool) (Request, error) {
	if actor.Role != auth.Approver {
		return Request{}, ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok, err := s.Store.Request(id)
	if err != nil {
		return Request{}, err
	} else if !ok {
		return Request{}, ErrMissing
	} else if req.Status != Undecided {
		return Request{}, ErrDecided
	}
	u, ok, err := s.Store.User(req.UserID)
	if err != nil {
		return Request{}, err
	} else if !ok {
		return Request{}, ErrMissing
	}
	// The approval was stored on the user but the request write failed. It is already
	// decided, by whoever approved it, so any approver's call writes it down; nobody can
	// reject it. Without this, granting the first real approver would retire the bootstrap
	// one and leave only the subject, who may not decide about itself.
	if a, done := u.applied(req.ID); done {
		req.Status, req.DecidedBy, req.DecidedAt = Approved, a.By, a.At
		if err = s.Store.PutRequest(req); err != nil {
			return Request{}, err
		} else if !approve {
			return Request{}, ErrDecided
		}
		return req, nil
	}
	if actor.UserID == req.RequesterID || actor.UserID == req.UserID {
		return Request{}, ErrForbidden
	}
	if approve && (req.Kind == "activate" && u.Status != Pending || req.Kind == "grant" && u.Status != Active) {
		return Request{}, ErrState
	}
	before, after := "status:"+string(u.Status), "status:"+string(Active)
	if req.Kind == "grant" {
		before, after = "role:"+string(u.Role), "role:"+string(req.Role)
	}
	req.Status, req.DecidedBy, req.DecidedAt = Rejected, actor.Name, s.Now().UTC()
	action := req.Kind + ".reject"
	if approve {
		req.Status, action = Approved, req.Kind+".approve"
	}
	if !approve {
		after = before
	}
	if err = s.audit(actor, action, "user/"+u.ID, before, after); err != nil {
		return Request{}, err
	}
	// Change the user first, recording the approval on it in the same write, and mark the
	// request decided last: a failure leaves the request pending, and the next call finds
	// the approval on the user. Storing a role holder ends that role's bootstrap.
	if approve {
		if req.Kind == "activate" {
			u.Status = Active
		} else {
			u.Role = req.Role
		}
		u.Applied = append(slices.Clone(u.Applied), Applied{Request: req.ID, By: req.DecidedBy, At: req.DecidedAt})
		if err = s.Store.PutUser(u); err != nil {
			return Request{}, err
		}
	}
	return req, s.Store.PutRequest(req)
}

func (s *Service) audit(actor auth.Principal, action, object, before, after string) error {
	return s.Audit.Append(store.Record{Time: s.Now().UTC(), Actor: actor.Name, Role: string(actor.Role),
		Action: action, Object: object, Before: before, After: after})
}
