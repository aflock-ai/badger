package broker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
)

// documents are the versioned settings in broker.documents ("quotas", "owners"): each write names
// the version it was based on and replaces the document only if that is still current, in one
// statement, so two admins never overwrite each other. Every read goes to the database, so a
// limit or an owner never outlives a database that cannot be read: the caller refuses instead.
type documents struct {
	db    *sql.DB
	label pgdb.Label
}

var errDocVersion = errors.New("document version changed")

// strictObject decodes a stored document that must be a JSON object: null, an array or a bare
// value would otherwise decode to an empty set and quietly lift every limit.
func strictObject(raw []byte, v any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("not a JSON object")
	}
	return json.Unmarshal(trimmed, v)
}

func (d documents) tx(fn func(*sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	return pgdb.Tx(ctx, d.db, d.label, func(tx *sql.Tx) error {
		if err := sharedWriteLock(ctx, tx); err != nil {
			return err
		}
		return fn(tx)
	})
}

// load decodes the document into v and returns its version; an absent document is version 0
// and leaves v as it is.
func (d documents) load(name string, v any) (int64, error) {
	var version int64
	err := d.tx(func(tx *sql.Tx) error {
		var raw []byte
		err := tx.QueryRow(`SELECT version, body FROM broker.documents WHERE name = $1`, name).Scan(&version, &raw)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := strictObject(raw, v); err != nil {
			return fmt.Errorf("%s unreadable: %w", name, err)
		}
		return nil
	})
	return version, err
}

// put stores v as version base+1 if base is still current.
func (d documents) put(name string, base int64, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return d.tx(func(tx *sql.Tx) error {
		var res sql.Result
		if base == 0 {
			res, err = tx.Exec(`INSERT INTO broker.documents (name, version, body) VALUES ($1, 1, $2) ON CONFLICT (name) DO NOTHING`, name, raw)
		} else {
			res, err = tx.Exec(`UPDATE broker.documents SET version = version + 1, body = $3 WHERE name = $1 AND version = $2`, name, base, raw)
		}
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return errDocVersion
		}
		return nil
	})
}
