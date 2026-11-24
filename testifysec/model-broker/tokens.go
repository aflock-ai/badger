package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
)

// Workspace tokens: formal/BadgerBroker/WorkspaceTokens.lean. A provisioner asks for a token for
// (workspace, owner); the broker keeps only its SHA-256, bound to that owner, and the internal
// listener serves a request as the owner of the token it presents. Issuing again for a workspace
// replaces its token; revoking removes it. The registry is the broker.tokens table.

const tokenPrefix = "bbt_"

var reWorkspace = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// TokenRec is Lean `TokenRec`, with the token replaced by its hash.
type TokenRec struct {
	Workspace string    `json:"workspace"`
	Hash      string    `json:"sha256"`
	Principal string    `json:"principal"`
	Expires   time.Time `json:"expires"`
	// Device marks a record issued by device sign-in (Lean `TokenRec.device`). Ownership is this
	// flag, not the name: a provisioned workspace named like a device stays the provisioner's.
	Device bool `json:"device,omitempty"`
	// Marking is the label the workspace's own requests run at: its high-water label, as the
	// provisioner set it (default the lowest).
	Marking string `json:"marking,omitempty"`
}

type tokenRegistry struct {
	db    *sql.DB
	label pgdb.Label
}

func openTokens(db *sql.DB, label pgdb.Label) *tokenRegistry {
	return &tokenRegistry{db: db, label: label}
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func (t *tokenRegistry) tx(fn func(*sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	return pgdb.Tx(ctx, t.db, t.label, func(tx *sql.Tx) error {
		if err := sharedWriteLock(ctx, tx); err != nil {
			return err
		}
		return fn(tx)
	})
}

const tokenCols = `workspace, hash, principal, expires, device, marking`

func scanToken(row interface{ Scan(...any) error }) (TokenRec, error) {
	var r TokenRec
	err := row.Scan(&r.Workspace, &r.Hash, &r.Principal, &r.Expires, &r.Device, &r.Marking)
	r.Expires = r.Expires.UTC()
	return r, err
}

// byHash is the record holding tok's hash, if any.
func (t *tokenRegistry) byHash(tok string) (TokenRec, bool, error) {
	h := hashToken(tok)
	var r TokenRec
	var found bool
	err := t.tx(func(tx *sql.Tx) error {
		var err error
		r, err = scanToken(tx.QueryRow(`SELECT `+tokenCols+` FROM broker.tokens WHERE hash = $1`, h))
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		found = err == nil && subtle.ConstantTimeCompare([]byte(r.Hash), []byte(h)) == 1
		return err
	})
	return r, found, err
}

// Auth is Lean `authToken`: the principal the presented token speaks for, if any. An unreadable
// registry accepts nothing.
func (t *tokenRegistry) Auth(tok string, humans []string, now time.Time) (string, bool) {
	r, ok := t.AuthRec(tok, humans, now)
	return r.Principal, ok
}

// AuthRec is Auth with the whole record, for the workspace's label.
func (t *tokenRegistry) AuthRec(tok string, humans []string, now time.Time) (TokenRec, bool) {
	if !strings.HasPrefix(tok, tokenPrefix) || len(tok) > 128 {
		return TokenRec{}, false
	}
	r, found, err := t.byHash(tok)
	if err != nil || !found {
		return TokenRec{}, false
	}
	_, person := configuredPrincipal(humans, r.Principal)
	ok := now.Before(r.Expires) && person
	return r, ok
}

var errIssue = errors.New("refused")

// devicePrefix starts every device record's name, so device names stay out of the way of
// workspace names. It is a convention: who owns a record is its Device flag.
const devicePrefix = "dev-"

// Issue is Lean `provisionL` `.issue`: a fresh token for the workspace, replacing its old one,
// refused if a device record holds the name.
// Issue mints a token. record is called after the request is validated and before the token is
// stored; if it fails, nothing is stored, so no token exists without its audit record.
// label is the workspace's own label (its banner); empty is the lowest.
func (t *tokenRegistry) Issue(workspace, principal, label string, humans []string, ttl time.Duration, now time.Time, record func(*sql.Tx) error) (string, time.Time, error) {
	return t.issue(TokenRec{Workspace: workspace, Principal: principal, Marking: label}, humans, ttl, now, record,
		func(r TokenRec) bool { return !r.Device },
		func(recs []TokenRec) []TokenRec { return recs })
}

// IssueDevice is Lean `deviceIssue`: a token for a device the principal approved, replacing that
// device's old token; refused if the name is held by a workspace or by another person's device.
// At most max device tokens per principal are kept: the ones expiring soonest (the oldest
// sign-ins) are dropped, and only that principal's device records are ever dropped.
func (t *tokenRegistry) IssueDevice(workspace, principal string, humans []string, ttl time.Duration, max int, now time.Time, record func(*sql.Tx) error) (string, time.Time, error) {
	principal, person := configuredPrincipal(humans, principal)
	if !strings.HasPrefix(workspace, devicePrefix) || max < 1 || !person {
		return "", time.Time{}, errIssue
	}
	return t.issue(TokenRec{Workspace: workspace, Principal: principal, Device: true}, humans, ttl, now, record,
		func(r TokenRec) bool { return r.Device && samePrincipal(r.Principal, principal) },
		func(recs []TokenRec) []TokenRec {
			var mine []TokenRec
			out := []TokenRec{}
			for _, r := range recs {
				if r.Device && samePrincipal(r.Principal, principal) {
					if now.Before(r.Expires) {
						mine = append(mine, r)
					}
					continue
				}
				out = append(out, r)
			}
			slices.SortFunc(mine, func(a, b TokenRec) int { return b.Expires.Compare(a.Expires) })
			if len(mine) > max-1 {
				mine = mine[:max-1]
			}
			return append(out, mine...)
		})
}

// issue stores a fresh token for rec's workspace. replaceable says whether an existing record for
// that name may be replaced (otherwise the issue is refused); others selects which of the
// remaining records stay. It runs in one transaction holding the table's write lock, so two
// issues never interleave.
func (t *tokenRegistry) issue(rec TokenRec, humans []string, ttl time.Duration, now time.Time, record func(*sql.Tx) error, replaceable func(TokenRec) bool, others func([]TokenRec) []TokenRec) (string, time.Time, error) {
	workspace := rec.Workspace
	principal, person := configuredPrincipal(humans, rec.Principal)
	if !reWorkspace.MatchString(workspace) || !person {
		return "", time.Time{}, errIssue
	}
	rec.Principal = principal // stored in the configured spelling
	if rec.Marking == "" {
		rec.Marking = bottomBanner
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	tok := tokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	rec.Hash, rec.Expires = hashToken(tok), now.Add(ttl).UTC().Truncate(time.Microsecond)
	err := t.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`LOCK TABLE broker.tokens IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return err
		}
		rows, err := tx.Query(`SELECT ` + tokenCols + ` FROM broker.tokens`)
		if err != nil {
			return err
		}
		var rest []TokenRec
		for rows.Next() {
			r, err := scanToken(rows)
			if err != nil {
				rows.Close()
				return err
			}
			if r.Hash == rec.Hash {
				rows.Close()
				return errIssue // W2: never reissue a held token
			}
			if r.Workspace != workspace {
				rest = append(rest, r)
			} else if !replaceable(r) {
				rows.Close()
				return errIssue
			}
		}
		rows.Close()
		if err := record(tx); err != nil {
			return err
		}
		keep := map[string]bool{}
		for _, r := range others(rest) {
			keep[r.Workspace] = true
		}
		for _, r := range rest {
			if !keep[r.Workspace] {
				if _, err := tx.Exec(`DELETE FROM broker.tokens WHERE workspace = $1`, r.Workspace); err != nil {
					return err
				}
			}
		}
		if _, err := tx.Exec(`DELETE FROM broker.tokens WHERE workspace = $1`, workspace); err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO broker.tokens (`+tokenCols+`) VALUES ($1, $2, $3, $4, $5, $6)`,
			rec.Workspace, rec.Hash, rec.Principal, rec.Expires, rec.Device, rec.Marking)
		return err
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return tok, rec.Expires, nil
}

// Lookup returns the unexpired record holding tok, without the person checks Auth makes. An
// unreadable registry is an error, never "not found": a caller must not mistake it for a token
// that is already gone.
func (t *tokenRegistry) Lookup(tok string, now time.Time) (TokenRec, bool, error) {
	if !strings.HasPrefix(tok, tokenPrefix) || len(tok) > 128 {
		return TokenRec{}, false, nil
	}
	r, found, err := t.byHash(tok)
	if err != nil || !found || !now.Before(r.Expires) {
		return TokenRec{}, false, err
	}
	return r, true, nil
}

// RevokeToken is Lean `revokeToken`: remove the record holding the presented token, and only it.
func (t *tokenRegistry) RevokeToken(tok string) (TokenRec, bool, error) {
	if !strings.HasPrefix(tok, tokenPrefix) || len(tok) > 128 {
		return TokenRec{}, false, nil
	}
	var gone TokenRec
	found := false
	err := t.tx(func(tx *sql.Tx) error {
		var err error
		gone, err = scanToken(tx.QueryRow(`DELETE FROM broker.tokens WHERE hash = $1 RETURNING `+tokenCols, hashToken(tok)))
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	return gone, found, err
}

// Revoke is Lean `provisionL` `.revoke`: refused (errIssue) if a device record holds the name.
func (t *tokenRegistry) Revoke(workspace string) (bool, error) {
	found := false
	err := t.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`LOCK TABLE broker.tokens IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return err
		}
		var device bool
		err := tx.QueryRow(`SELECT device FROM broker.tokens WHERE workspace = $1`, workspace).Scan(&device)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil
		case err != nil:
			return err
		case device:
			return errIssue
		}
		found = true
		_, err = tx.Exec(`DELETE FROM broker.tokens WHERE workspace = $1`, workspace)
		return err
	})
	return found, err
}

// Provision is the provisioning listener (W3: network policy admits only the provisioner, and it
// must present the provisioning key). Tokens are returned once and never logged.
func (b *Broker) Provision() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /provision/v1/tokens", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Workspace string `json:"workspace"`
			Principal string `json:"principal"`
			// Marking is the workspace's high-water label; its own requests run at it. It must be
			// a banner the marking package reads, at or below the deployment's ceiling.
			Marking string `json:"marking,omitempty"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		label := bottomBanner
		if body.Marking != "" {
			l, err := pgdb.ParseLabel(body.Marking)
			if err != nil || !b.underCeiling(l) {
				writeErr(w, http.StatusUnprocessableEntity, apiError{Code: "refused", Message: "marking must be a banner at or below the deployment's ceiling"})
				return
			}
			label = l.Banner
		}
		version := b.currentVersion()
		tok, exp, err := b.tokens.Issue(body.Workspace, body.Principal, label, b.cfg.HumanPrincipals, b.tokenTTL(), b.now(),
			func(tx *sql.Tx) error {
				return b.store.AuditTx(tx, AuditRecord{Kind: "token_issue", Actor: "provisioner", Name: auditSafe(body.Workspace),
					Principal: auditSafe(body.Principal), Version: version})
			})
		if errors.Is(err, errIssue) {
			writeErr(w, http.StatusUnprocessableEntity, apiError{Code: "refused", Message: "workspace or principal not allowed"})
			return
		}
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, apiError{Code: "store_unavailable", Message: "token not issued"})
			return
		}
		log.Printf("workspace token issued workspace=%s principal=%s expires=%s", auditSafe(body.Workspace),
			auditSafe(body.Principal), exp.Format(time.RFC3339))
		writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "expires_at": exp})
	})
	mux.HandleFunc("DELETE /provision/v1/tokens/{workspace}", func(w http.ResponseWriter, r *http.Request) {
		ws := r.PathValue("workspace")
		found, err := b.tokens.Revoke(ws)
		if errors.Is(err, errIssue) {
			writeErr(w, http.StatusUnprocessableEntity, apiError{Code: "refused", Message: "workspace not allowed"})
			return
		}
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, apiError{Code: "store_unavailable", Message: "not revoked"})
			return
		}
		if found {
			// Revoking comes first: a credential must not stay usable because its record failed.
			if b.store.Audit(AuditRecord{Kind: "token_revoke", Actor: "provisioner", Name: auditSafe(ws), Version: b.currentVersion()}) != nil {
				log.Printf("workspace token revoked workspace=%s but the revocation could not be audited", auditSafe(ws))
				writeErr(w, http.StatusServiceUnavailable, apiError{Code: "audit_unavailable",
					Message: "revoked, but the revocation could not be recorded; repair the audit log"})
				return
			}
			log.Printf("workspace token revoked workspace=%s", auditSafe(ws))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path == "/healthz" {
			w.Write([]byte(`{"ok":true}`))
			return
		}
		key := secret(b.cfg.ProvisionerKeyFile)
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		gh, kh := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(key))
		if key == "" || len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare(gh[:], kh[:]) != 1 {
			writeErr(w, http.StatusUnauthorized, apiError{Code: "unauthorized", Message: "provisioning key required"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (b *Broker) tokenTTL() time.Duration {
	return time.Duration(b.cfg.WorkspaceTokenTTLHours) * time.Hour
}
