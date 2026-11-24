package users

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/portal/internal/auth"
	"github.com/aflock-ai/badger/testifysec/portal/internal/store"
)

// PG is the directory in the service's database (portal.users, portal.role_requests and
// portal.bootstrap_ended, created by the store package's schema). Each record is replaced in
// one statement. A record that does not parse is ErrDamaged: authorization fails closed on it.
type PG struct {
	db    *sql.DB
	label pgdb.Label
}

func NewPG(db *sql.DB, label pgdb.Label) *PG { return &PG{db: db, label: label} }

func (p *PG) tx(fn func(*sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pgdb.Tx(ctx, p.db, p.label, func(tx *sql.Tx) error {
		// Shared with every portal transaction, exclusive to the import (store.WriteLock).
		if err := store.SharedWriteLock(ctx, tx); err != nil {
			return err
		}
		return fn(tx)
	})
}

func (p *PG) get(table, id string, valid *regexp.Regexp, v any) (bool, error) {
	if !valid.MatchString(id) {
		return false, fmt.Errorf("%w: id", ErrInvalid)
	}
	found := false
	err := p.tx(func(tx *sql.Tx) error {
		var raw []byte
		err := tx.QueryRow(`SELECT body FROM portal.`+table+` WHERE id = $1`, id).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		if json.Unmarshal(raw, v) != nil {
			return ErrDamaged
		}
		return nil
	})
	return found, err
}

func (p *PG) put(table, id string, valid *regexp.Regexp, v any) error {
	if !valid.MatchString(id) {
		return fmt.Errorf("%w: id", ErrInvalid)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return p.tx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO portal.`+table+` (id, body) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET body = excluded.body`, id, raw)
		return err
	})
}

func (p *PG) User(id string) (User, bool, error) {
	var u User
	var raw json.RawMessage
	ok, err := p.get("users", id, hexID, &raw)
	if err == nil && ok {
		if json.Unmarshal(raw, &u) != nil {
			return User{}, true, ErrDamaged
		}
		u.setRead(string(raw))
		err = u.check(id)
	}
	return u, ok, err
}

// check refuses a record that is not a whole user stored under its own ID, so a damaged
// file (null, {}, a stray field) can never read as a user without its role history.
func (u User) check(id string) error {
	ok := u.ID == id && u.Kind != "" && u.Subject != "" && (u.Role == auth.None || u.Role.Valid()) &&
		(u.Status == Pending || u.Status == Active || u.Status == Offboarded)
	for _, r := range u.Granted {
		ok = ok && r.Valid()
	}
	for _, a := range u.Applied {
		ok = ok && requestID.MatchString(a.Request) && a.By != ""
	}
	if !ok {
		return fmt.Errorf("%w: %s", ErrDamaged, id)
	}
	return nil
}

// PutUser stores u. Storing an active user with a role ends that role's bootstrap for good: the
// record and a final marker naming u commit in one transaction, so the role is never usable
// through config again once the record exists, whatever happens to u later.
func (p *PG) PutUser(u User) error {
	if !hexID.MatchString(u.ID) {
		return fmt.Errorf("%w: id", ErrInvalid)
	}
	// One transaction: the user record and, when it holds a role, that role's bootstrap marker
	// (final) commit together, so no reader on any replica sees the role held while the
	// bootstrap can still act, and no replica stopping in between can leave it so.
	return p.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, directoryLock); err != nil {
			return err
		}
		// Granted never shrinks, whatever the caller passes: keep the stored history.
		granted := slices.Clone(u.Granted)
		var prior []Applied
		var raw []byte
		switch err := tx.QueryRow(`SELECT body FROM portal.users WHERE id = $1`, u.ID).Scan(&raw); {
		case errors.Is(err, sql.ErrNoRows):
			if u.read != "" && u.read != notStored {
				return fmt.Errorf("%w: %s was removed since it was read", ErrStale, u.ID)
			}
		case err != nil:
			return err
		default:
			// A damaged record is never overwritten: its role history would be lost.
			var old User
			if json.Unmarshal(raw, &old) != nil || old.check(u.ID) != nil {
				return fmt.Errorf("%w: %s", ErrDamaged, u.ID)
			}
			// A copy read from the store is written back only over the record it was read from:
			// one read before another replica's change would undo that change.
			if u.read != "" && u.read != string(raw) {
				return fmt.Errorf("%w: %s changed since it was read; read it again", ErrStale, u.ID)
			}
			// Offboarding is final: a copy read before it (on this replica or another) is never
			// written back over it.
			if old.Status == Offboarded && u.Status != Offboarded {
				return fmt.Errorf("%w: %s is offboarded", ErrForbidden, u.ID)
			}
			granted = append(granted, old.Granted...)
			prior = old.Applied
		}
		// An approval newly applied here needs its request, stored, whole, about this user, and
		// pending or approved: a request missing, damaged or decided otherwise grants nothing.
		for _, a := range u.Applied {
			if slices.ContainsFunc(prior, func(x Applied) bool { return x.Request == a.Request }) {
				continue
			}
			var body []byte
			err := tx.QueryRow(`SELECT body FROM portal.role_requests WHERE id = $1`, a.Request).Scan(&body)
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: request %s", ErrMissing, a.Request)
			}
			if err != nil {
				return err
			}
			// The whole request, as Request() would check it, and about this user.
			var r Request
			if json.Unmarshal(body, &r) != nil || r.check(a.Request) != nil || r.UserID != u.ID {
				return fmt.Errorf("%w: request %s", ErrDamaged, a.Request)
			}
			if r.Status != Undecided && r.Status != Approved {
				return ErrDecided
			}
		}
		holds := u.Status == Active && u.Role.Valid()
		if holds {
			granted = append(granted, u.Role)
		}
		slices.Sort(granted)
		u.Granted = slices.Compact(granted)
		body, err := json.Marshal(u)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO portal.users (id, body) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET body = excluded.body`, u.ID, body); err != nil {
			return err
		}
		if !holds {
			return nil
		}
		_, err = tx.Exec(`INSERT INTO portal.bootstrap_ended (role, holder, final) VALUES ($1, $2, true)
			ON CONFLICT (role) DO UPDATE SET holder = excluded.holder, final = true
			WHERE NOT portal.bootstrap_ended.final`, string(u.Role), u.ID)
		return err
	})
}

// directoryLock serialises the directory's writes that touch a bootstrap marker.
const directoryLock = int64(0x706f7274616c02) // "portal\x02"

func (p *PG) Request(id string) (Request, bool, error) {
	var r Request
	ok, err := p.get("role_requests", id, requestID, &r)
	if err == nil && ok {
		err = r.check(id)
	}
	return r, ok, err
}

// check refuses a request that is not whole: authorization reads its requester, subject,
// kind and role, so a damaged one must never be decided or listed.
func (r Request) check(id string) error {
	ok := r.ID == id && hexID.MatchString(r.UserID) && hexID.MatchString(r.RequesterID) && r.RequestedBy != "" &&
		(r.Kind == "activate" && r.Role == auth.None || r.Kind == "grant" && r.Role.Valid())
	switch r.Status {
	case Undecided:
	case Approved, Rejected, Dropped:
		ok = ok && r.DecidedBy != ""
	default:
		ok = false
	}
	if !ok {
		return fmt.Errorf("%w: request %s", ErrDamaged, id)
	}
	return nil
}

// PutRequest stores r. A request is decided once, across replicas: a decision is never written
// over a different one, and a rejection is refused once a user record carries the request's
// approval. Both checks run under the lock PutUser takes. (Offboarding drops undecided requests
// whatever was applied: it is final anyway.)
func (p *PG) PutRequest(r Request) error {
	if !requestID.MatchString(r.ID) {
		return fmt.Errorf("%w: id", ErrInvalid)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return p.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, directoryLock); err != nil {
			return err
		}
		var stored []byte
		switch err := tx.QueryRow(`SELECT body FROM portal.role_requests WHERE id = $1`, r.ID).Scan(&stored); {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return err
		default:
			var old Request
			if json.Unmarshal(stored, &old) != nil {
				return fmt.Errorf("%w: request %s", ErrDamaged, r.ID)
			}
			if old.Status != Undecided && old.Status != r.Status {
				return ErrDecided
			}
		}
		if r.Status == Rejected {
			var applied bool
			if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM portal.users WHERE body->'applied' @> jsonb_build_array(jsonb_build_object('request', $1::text)))`,
				r.ID).Scan(&applied); err != nil {
				return err
			}
			if applied {
				return ErrDecided
			}
		}
		_, err := tx.Exec(`INSERT INTO portal.role_requests (id, body) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET body = excluded.body`, r.ID, raw)
		return err
	})
}

func list[T interface{ check(string) error }](p *PG, table string) ([]T, error) {
	var out []T
	err := p.tx(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT id, body FROM portal.` + table + ` ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var key string
			var v T
			if err := rows.Scan(&key, &raw); err != nil {
				return err
			}
			if json.Unmarshal(raw, &v) != nil {
				return ErrDamaged
			}
			// A listed user carries the record it was read from, as one read alone does.
			if r, ok := any(&v).(interface{ setRead(string) }); ok {
				r.setRead(string(raw))
			}
			if err := v.check(key); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}

func (p *PG) Users() ([]User, error)       { return list[User](p, "users") }
func (p *PG) Requests() ([]Request, error) { return list[Request](p, "role_requests") }

func (p *PG) marker(role auth.Role) (holder string, final, ok bool, err error) {
	err = p.tx(func(tx *sql.Tx) error {
		e := tx.QueryRow(`SELECT holder, final FROM portal.bootstrap_ended WHERE role = $1`, string(role)).Scan(&holder, &final)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		ok = e == nil
		return e
	})
	return
}

func (p *PG) holds(id string, role auth.Role) (bool, error) {
	u, ok, err := p.User(id)
	return ok && slices.Contains(u.Granted, role), err
}

// BootstrapEnded: a final marker ends the role's bootstrap for good; a tentative one only once
// its holder's record shows the role.
func (p *PG) BootstrapEnded(role auth.Role) (bool, error) {
	holder, final, ok, err := p.marker(role)
	if err != nil || !ok || final {
		return final, err
	}
	return p.holds(holder, role)
}

// EndBootstrap records holderID as the user whose arrival ends role's bootstrap: final if its
// record already shows the role, tentative otherwise. A final marker is never replaced, and a
// tentative one already in effect is made final rather than replaced.
func (p *PG) EndBootstrap(role auth.Role, holderID string) error {
	if !role.Valid() || !hexID.MatchString(holderID) {
		return ErrInvalid
	}
	cur, final, ok, err := p.marker(role)
	if err != nil || final {
		return err
	}
	holder, makeFinal := holderID, false
	if held, err := p.holds(holderID, role); err != nil {
		return err
	} else if held {
		makeFinal = true
	} else if ok {
		if held, err := p.holds(cur, role); err != nil {
			return err
		} else if held {
			holder, makeFinal = cur, true
		}
	}
	return p.tx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO portal.bootstrap_ended (role, holder, final) VALUES ($1, $2, $3)
			ON CONFLICT (role) DO UPDATE SET holder = excluded.holder, final = excluded.final
			WHERE NOT portal.bootstrap_ended.final`, string(role), holder, makeFinal)
		return err
	})
}
