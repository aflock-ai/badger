package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/portal/internal/profile"
)

//go:embed schema.sql
var schemaSQL string

// Schema is the portal's profiles, assignments and audit log (component "portal"), with
// row-level security on the marked tables. Migrate pgdb.Core first.
var Schema = pgdb.Component{Name: "portal", Migrations: []pgdb.Migration{
	{Version: 1, Name: "initial", SQL: schemaSQL + pgdb.Marked("portal.profile_versions") + pgdb.Marked("portal.audit")},
}}

// PG keeps profiles, assignments and the audit log in the service's database. Profile versions
// and audit records are written once, at the session label, and read only by sessions that
// dominate it. It is a ProfileStore, an AssignmentStore and an AuditSink.
type PG struct {
	db    *sql.DB
	label pgdb.Label
}

// NewPG uses db at label: the deployment's ceiling, the label admin sessions run at.
func NewPG(db *sql.DB, label pgdb.Label) *PG { return &PG{db: db, label: label} }

func (p *PG) tx(fn func(*sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pgdb.Tx(ctx, p.db, p.label, func(tx *sql.Tx) error {
		if err := SharedWriteLock(ctx, tx); err != nil {
			return err
		}
		return fn(tx)
	})
}

// WriteLock is held shared by every portal transaction and exclusively by the import (and its
// "none" declaration), so no replica writes between the import's emptiness check and its commit.
const WriteLock = int64(0x706f7274616c03) // "portal\x03"

// SharedWriteLock takes WriteLock shared in tx.
func SharedWriteLock(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, WriteLock)
	return err
}

func (p *PG) Put(v Version) error {
	if !profile.ValidIdentifier(v.ProfileID) {
		return ErrProfileID
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	err = p.tx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO portal.profile_versions (profile_id, sequence, body, marking, label)
			VALUES ($1, $2, $3, $4, badger.label_of($5::jsonb))`, v.ProfileID, int64(v.Sequence), string(raw), p.label.Banner, p.label.Lattice())
		return err
	})
	var pe *pq.Error
	if errors.As(err, &pe) && pe.Code == "23505" { // unique violation: a sequence is written once
		return ErrExists
	}
	return err
}

func (p *PG) versions(where string, args ...any) ([]Version, error) {
	var out []Version
	err := p.tx(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT body FROM portal.profile_versions `+where, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var v Version
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf("profile version unreadable: %w", err)
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}

func (p *PG) Latest(profileID string) (Version, bool, error) {
	if !profile.ValidIdentifier(profileID) {
		return Version{}, false, ErrProfileID
	}
	vs, err := p.versions(`WHERE profile_id = $1 ORDER BY sequence DESC LIMIT 1`, profileID)
	if err != nil || len(vs) == 0 {
		return Version{}, false, err
	}
	return vs[0], true, nil
}

func (p *PG) Versions(profileID string) ([]Version, error) {
	if !profile.ValidIdentifier(profileID) {
		return nil, ErrProfileID
	}
	return p.versions(`WHERE profile_id = $1 ORDER BY sequence DESC`, profileID) // newest first
}

func (p *PG) Get(profileID string, sequence uint64) (Version, bool, error) {
	if !profile.ValidIdentifier(profileID) {
		return Version{}, false, ErrProfileID
	}
	vs, err := p.versions(`WHERE profile_id = $1 AND sequence = $2`, profileID, int64(sequence))
	if err != nil || len(vs) == 0 {
		return Version{}, false, err
	}
	return vs[0], true, nil
}

// List is every profile's latest version.
func (p *PG) List() ([]Version, error) {
	return p.versions(`WHERE (profile_id, sequence) IN (SELECT profile_id, max(sequence) FROM portal.profile_versions GROUP BY profile_id) ORDER BY profile_id`)
}

func (p *PG) Assignment(deploymentID string) (Assignment, bool, error) {
	if !profile.ValidIdentifier(deploymentID) {
		return Assignment{}, false, ErrProfileID
	}
	var a Assignment
	found := false
	err := p.tx(func(tx *sql.Tx) error {
		var raw []byte
		err := tx.QueryRow(`SELECT body FROM portal.assignments WHERE deployment_id = $1`, deploymentID).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return json.Unmarshal(raw, &a)
	})
	return a, found, err
}

// PutAssignment replaces a deployment's assignment in one statement.
func (p *PG) PutAssignment(a Assignment) error {
	if !profile.ValidIdentifier(a.DeploymentID) {
		return ErrProfileID
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	// Forward only, checked against the stored row under lock: a replica that checked before
	// another assigned a newer version never writes its older one over it.
	return p.tx(func(tx *sql.Tx) error {
		// The lock covers a deployment with no row yet, which FOR UPDATE could not.
		if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext('portal.assignment:' || $1))`, a.DeploymentID); err != nil {
			return err
		}
		var stored []byte
		switch err := tx.QueryRow(`SELECT body FROM portal.assignments WHERE deployment_id = $1`, a.DeploymentID).Scan(&stored); {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return err
		default:
			var cur Assignment
			if json.Unmarshal(stored, &cur) != nil {
				return fmt.Errorf("assignment for %s is damaged", a.DeploymentID)
			}
			if cur.ProfileID == a.ProfileID && cur.Sequence == a.Sequence {
				return nil
			}
			if cur.ProfileID != a.ProfileID || cur.Sequence > a.Sequence {
				return ErrRollback
			}
		}
		_, err := tx.Exec(`INSERT INTO portal.assignments (deployment_id, body) VALUES ($1, $2)
			ON CONFLICT (deployment_id) DO UPDATE SET body = excluded.body`, a.DeploymentID, raw)
		return err
	})
}

var zeroPrev = strings.Repeat("0", 64)

// Append extends the audit chain by one record: its prev is the digest of the record before it,
// read from the head row under lock, so concurrent appends never fork the chain.
func (p *PG) Append(r Record) error {
	return p.tx(func(tx *sql.Tx) error {
		var seq int64
		var prev string
		if err := tx.QueryRow(`SELECT seq, hash FROM portal.audit_head FOR UPDATE`).Scan(&seq, &prev); err != nil {
			return errors.Join(ErrAuditBroken, err)
		}
		r.Prev = prev
		line, err := json.Marshal(r)
		if err != nil {
			return err
		}
		h := digest(line)
		if _, err := tx.Exec(`INSERT INTO portal.audit (seq, prev, hash, record, marking, label)
			VALUES ($1, $2, $3, $4, $5, badger.label_of($6::jsonb))`, seq+1, prev, h, string(line), p.label.Banner, p.label.Lattice()); err != nil {
			return errors.Join(ErrAuditBroken, err)
		}
		_, err = tx.Exec(`UPDATE portal.audit_head SET seq = $1, hash = $2`, seq+1, h)
		return err
	})
}

// Records is the number of audit records the session label can read.
func (p *PG) Records() (int, error) {
	var n int
	err := p.tx(func(tx *sql.Tx) error { return tx.QueryRow(`SELECT count(*) FROM portal.audit`).Scan(&n) })
	return n, err
}

// Verify checks the audit chain and that signed profiles are not present without records: an
// emptied log beside signed profiles means the log was lost, and the portal must not start.
func (p *PG) Verify() error {
	return p.tx(func(tx *sql.Tx) error {
		// Hold the head, as Append does, so a concurrent append cannot land between reading the
		// log and reading the head: a valid chain never looks broken.
		if _, err := tx.Exec(`SELECT 1 FROM portal.audit_head FOR UPDATE`); err != nil {
			return err
		}
		rows, err := tx.Query(`SELECT seq, prev, hash, record FROM portal.audit ORDER BY seq`)
		if err != nil {
			return err
		}
		defer rows.Close()
		var seq int64
		prev := zeroPrev
		for rows.Next() {
			var n int64
			var pv, h, line string
			if err := rows.Scan(&n, &pv, &h, &line); err != nil {
				return err
			}
			var r Record
			if json.Unmarshal([]byte(line), &r) != nil || n != seq+1 || pv != prev || r.Prev != prev || h != digest([]byte(line)) {
				return fmt.Errorf("portal audit chain broken at record %d", seq+1)
			}
			seq, prev = n, h
		}
		if err := rows.Err(); err != nil {
			return err
		}
		var hs int64
		var hh string
		var versions int
		if err := tx.QueryRow(`SELECT seq, hash FROM portal.audit_head`).Scan(&hs, &hh); err != nil || hs != seq || hh != prev {
			return errors.New("portal audit head does not match the log")
		}
		if err := tx.QueryRow(`SELECT count(*) FROM portal.profile_versions`).Scan(&versions); err != nil {
			return err
		}
		if versions > 0 && seq == 0 {
			return errors.New("signed profiles exist but the audit log is empty; restore it before starting")
		}
		return nil
	})
}
