package users

import (
	"fmt"
	"slices"

	"github.com/aflock-ai/badger/testifysec/portal/internal/auth"
	"github.com/aflock-ai/badger/testifysec/portal/internal/profile"
)

// Assign makes an active user a member of a deployment. The data classification level a person is
// authorized for is delegated to an external service (PORTAL.md); the portal neither stores nor
// checks it.
func (s *Service) Assign(actor auth.Principal, userID, deploymentID string) (User, error) {
	return s.membership(actor, userID, deploymentID, true)
}

func (s *Service) Unassign(actor auth.Principal, userID, deploymentID string) (User, error) {
	return s.membership(actor, userID, deploymentID, false)
}

func (s *Service) membership(actor auth.Principal, userID, deploymentID string, add bool) (User, error) {
	if actor.Role != auth.Admin {
		return User{}, ErrForbidden
	}
	if !profile.ValidIdentifier(deploymentID) {
		return User{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok, err := s.Store.User(userID)
	if err != nil {
		return User{}, err
	} else if !ok {
		return User{}, ErrMissing
	} else if u.Status != Active {
		return User{}, ErrState
	}
	has := slices.Contains(u.Deployments, deploymentID)
	if has == add {
		return u, nil
	}
	next := slices.DeleteFunc(slices.Clone(u.Deployments), func(d string) bool { return d == deploymentID })
	action := "deployment.unassign"
	if add {
		next, action = append(next, deploymentID), "deployment.assign"
	}
	if err = s.audit(actor, action, "user/"+u.ID, fmt.Sprint(u.Deployments), fmt.Sprint(next)); err != nil {
		return User{}, err
	}
	u.Deployments = next
	return u, s.Store.PutUser(u)
}

// Offboard is final: role and memberships cleared, every pending request by or about the
// user dropped, in one audited step. An identity once offboarded cannot be invited again.
// Device revocation joins this step when devices land (PR 8).
func (s *Service) Offboard(actor auth.Principal, userID string) (User, error) {
	if actor.Role != auth.Admin || actor.UserID == userID {
		return User{}, ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok, err := s.Store.User(userID)
	if err != nil {
		return User{}, err
	} else if !ok {
		return s.offboardBootstrap(actor, userID)
	} else if u.Status == Offboarded {
		return User{}, ErrState
	}
	dropped, err := s.toDrop(actor, u.ID)
	if err != nil {
		return User{}, err
	}
	// Retire the role's bootstrap before its holder goes, in case storing the holder could
	// not write the marker; otherwise offboarding the last holder would bring it back.
	if u.Role.Valid() {
		if err = s.Store.EndBootstrap(u.Role, u.ID); err != nil {
			return User{}, err
		}
	}
	if err = s.audit(actor, "user.offboard", "user/"+u.ID,
		fmt.Sprintf("status:%s role:%s deployments:%v", u.Status, u.Role, u.Deployments),
		fmt.Sprintf("status:offboarded role: deployments:[] dropped:%d", len(dropped))); err != nil {
		return User{}, err
	}
	if err = s.drop(dropped); err != nil {
		return User{}, err
	}
	u.Status, u.Role, u.Deployments = Offboarded, auth.None, nil
	return u, s.Store.PutUser(u)
}

// toDrop lists the pending requests by or about a user being offboarded, marked dropped.
func (s *Service) toDrop(actor auth.Principal, userID string) ([]Request, error) {
	open, err := s.pending()
	if err != nil {
		return nil, err
	}
	var dropped []Request
	for _, r := range open {
		if r.UserID == userID || r.RequesterID == userID {
			r.Status, r.DecidedBy, r.DecidedAt = Dropped, actor.Name, s.Now().UTC()
			dropped = append(dropped, r)
		}
	}
	return dropped, nil
}

// drop stores dropped requests. Callers drop first and mark the user last: if a write
// fails, the user is not yet offboarded, so a retry runs again and finishes what is left.
func (s *Service) drop(dropped []Request) error {
	for _, r := range dropped {
		if err := s.Store.PutRequest(r); err != nil {
			return err
		}
	}
	return nil
}

// Pending is the approver queue.
func (s *Service) Pending() ([]Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending()
}

// pending lists undecided requests. One whose approval is already stored on its user (the
// request write failed) is written down as that approval and left out: it is decided.
func (s *Service) pending() ([]Request, error) {
	all, err := s.Store.Requests()
	if err != nil {
		return nil, err
	}
	var open []Request
	for _, r := range all {
		if r.Status != Undecided {
			continue
		}
		u, ok, err := s.Store.User(r.UserID)
		if err != nil {
			return nil, err
		}
		if a, done := u.applied(r.ID); ok && done {
			r.Status, r.DecidedBy, r.DecidedAt = Approved, a.By, a.At
			if err = s.Store.PutRequest(r); err != nil {
				return nil, err
			}
			continue
		}
		open = append(open, r)
	}
	return open, nil
}

// offboardBootstrap handles a bootstrap principal, which has no record. While its role is
// live, an admin may not remove it: removing the bootstrap approver before a real approver
// exists would block every approval. Once handed over, offboarding records it as offboarded,
// final, like anyone else. Any other unknown ID is not-found.
func (s *Service) offboardBootstrap(actor auth.Principal, userID string) (User, error) {
	for subject, role := range s.Bootstrap {
		id := Identity{Kind: KindIdP, Subject: subject}
		if id.ID() != userID {
			continue
		}
		if live, err := s.bootstrapLive(role); err != nil {
			return User{}, err
		} else if live {
			return User{}, ErrBootstrapLive
		}
		// Requests it made while it held the role are dropped too, as for anyone offboarded.
		dropped, err := s.toDrop(actor, userID)
		if err != nil {
			return User{}, err
		}
		u := User{ID: userID, Kind: id.Kind, Subject: subject, Status: Offboarded, CreatedAt: s.Now().UTC(), CreatedBy: actor.Name, read: notStored}
		if err := s.audit(actor, "user.offboard", "user/"+userID, "bootstrap:"+string(role),
			fmt.Sprintf("status:offboarded dropped:%d", len(dropped))); err != nil {
			return User{}, err
		}
		if err := s.drop(dropped); err != nil {
			return User{}, err
		}
		return u, s.Store.PutUser(u)
	}
	return User{}, ErrMissing
}
