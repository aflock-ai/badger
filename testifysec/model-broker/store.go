package broker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
)

// Store keeps every policy version and the audit log in the database (formal PolicyAdmin.lean
// `State`). Versions are rows written once; the audit log is append-only, each record carrying
// the SHA-256 of the record before it, so an edit made outside the service is detectable when the
// store opens. Every write runs in one transaction under an advisory lock, so replicas never
// race; the active policy is read from the database on each use, so an unreachable database
// denies every pipeline.
type Store struct {
	db    *sql.DB
	label pgdb.Label // the service's own session label: the deployment's ceiling
	op    *Operator
	mu    sync.Mutex
	// cache is the last active version read, reused while it is still the newest.
	cache atomic.Pointer[Version]
	// checked is the audit log as far as it has been checked, so each later check reads only the
	// records written since (the whole log is checked at open).
	checked atomic.Pointer[chainState]
	// broken is set when the stored state fails its checks at open: no policy is active and every
	// write is refused until an operator repairs it.
	broken error
}

// Version is one immutable policy version.
type Version struct {
	N          int64     `json:"version"`
	Entries    []Entry   `json:"entries"`
	Author     string    `json:"author"`
	AuthorName string    `json:"author_name,omitempty"`
	Approver   string    `json:"approver,omitempty"`
	Comment    string    `json:"comment,omitempty"`
	Created    time.Time `json:"created"`
	SHA256     string    `json:"sha256"`
	// auditSeq and auditHead are the chain's head after this version's write record: the anchor
	// committed logs off the database.
	auditSeq  int64
	auditHead string
}

type VersionMeta struct {
	N        int64     `json:"version"`
	Author   string    `json:"author"`
	Approver string    `json:"approver,omitempty"`
	Created  time.Time `json:"created"`
	SHA256   string    `json:"sha256"`
	Entries  int       `json:"entries"`
}

// Proposal is a change waiting for a second admin (two-person rule).
type Proposal struct {
	ID         int64     `json:"id"`
	Base       int64     `json:"base_version"`
	Entries    []Entry   `json:"entries"`
	Author     string    `json:"author"`
	AuthorName string    `json:"author_name,omitempty"`
	Comment    string    `json:"comment,omitempty"`
	Created    time.Time `json:"created"`
	Open       bool      `json:"open"`
}

// AuditRecord is one audit line. Kinds: write, propose, approve, reject, refused, decision.
type AuditRecord struct {
	Seq      int64     `json:"seq"`
	Time     time.Time `json:"time"`
	Prev     string    `json:"prev"`
	Kind     string    `json:"kind"`
	Actor    string    `json:"actor,omitempty"`
	Name     string    `json:"actor_name,omitempty"`
	Version  int64     `json:"policy_version"`
	Proposal int64     `json:"proposal,omitempty"`
	Removed  []Entry   `json:"removed,omitempty"`
	Added    []Entry   `json:"added,omitempty"`
	Comment  string    `json:"comment,omitempty"`
	Approver string    `json:"approver,omitempty"`
	SHA256   string    `json:"sha256,omitempty"` // write records: the new version's entries hash
	// Entries is the full proposed entry list on a propose record (Removed/Added are the diff).
	Entries []Entry `json:"entries,omitempty"`
	// decision records
	Decision  string `json:"decision,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Principal string `json:"principal,omitempty"`
	EntryID   string `json:"entry,omitempty"`
	Issuer    string `json:"issuer,omitempty"` // the issuer id whose header carried the payload
	Project   string `json:"project_path,omitempty"`
	Ref       string `json:"ref,omitempty"`
	Source    string `json:"pipeline_source,omitempty"`
	UserLogin string `json:"user_login,omitempty"`
	Owner     string `json:"owner,omitempty"` // the human accountable for the pipeline
	Model     string `json:"model,omitempty"`
	// quota records: each field changed, old and new, and whether the admin changed their own.
	Changes []LimitChange `json:"changes,omitempty"`
	Self    bool          `json:"self,omitempty"`
}

func entriesHash(es []Entry) string {
	b, _ := json.Marshal(es)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// policyLock serialises policy and audit writes across replicas.
const policyLock = int64(0x62726b7201) // "brkr\x01"

const dbTimeout = 10 * time.Second

// OpenStore checks the stored state: the audit chain is unbroken and every version matches the
// write record that created it. A store that fails still opens, denying every pipeline and
// refusing every write until an operator repairs it.
func OpenStore(db *sql.DB, label pgdb.Label, o *Operator) *Store {
	s := &Store{db: db, label: label, op: o}
	if err := s.txFor(openTimeout, func(tx *sql.Tx) error { _, err := s.verified(tx); return err }); err != nil {
		log.Printf("policy store refused: %v", err)
		s.broken = err
	}
	return s
}

// openTimeout bounds the check of the whole audit log at open, which grows with the log.
const openTimeout = 10 * time.Minute

// verified checks the store from the last checkpoint (from the start the first time), moves the
// checkpoint on, and returns the newest version as checked. Callers hold the policy lock (tx).
func (s *Store) verified(tx *sql.Tx) (*Version, error) {
	var base chainState
	if c := s.checked.Load(); c != nil {
		base = *c
	}
	st, v, err := verifyFrom(tx, base)
	if err != nil {
		return nil, err
	}
	s.checked.Store(&st)
	return v, nil
}

// tx runs fn in one transaction at the service's label, holding the policy write lock.
func (s *Store) tx(fn func(*sql.Tx) error) error { return s.txFor(dbTimeout, fn) }

func (s *Store) txFor(d time.Duration, fn func(*sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return pgdb.Tx(ctx, s.db, s.label, func(tx *sql.Tx) error {
		// The write lock (shared) before the policy lock, as every writer and the import take them.
		if err := sharedWriteLock(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, policyLock); err != nil {
			return err
		}
		return fn(tx)
	})
}

// verifyState checks the stored state in tx: the audit chain is unbroken and matches its head,
// every version matches the write record that created it, and every proposal its propose record.
func verifyState(tx *sql.Tx) error {
	_, err := verifiedState(tx)
	return err
}

// chainState is what a check of the audit log has established up to record seq (hash prev): the
// write record of every version and every propose record, and which proposals are closed. The
// store keeps the last one as a checkpoint, so a later check reads only the records after it.
type chainState struct {
	seq      int64
	prev     string
	writes   map[int64]AuditRecord
	proposes map[int64]AuditRecord
	closed   map[int64]bool
	// byWrite are proposals closed by the version written from them and not yet by their approve
	// record, which follows the write (or never came: a file-backed broker stopped in between).
	byWrite map[int64]bool
	// proposeHash is each propose record's hash as checked, so approval can hold a record to it
	// without reading the log again.
	proposeHash map[int64]string
	proposeSeq  map[int64]int64
	scanned     int // records read by the check that produced this state
}

func (c chainState) clone() chainState {
	n := chainState{seq: c.seq, prev: c.prev, writes: map[int64]AuditRecord{}, proposes: map[int64]AuditRecord{}, closed: map[int64]bool{},
		byWrite: map[int64]bool{}, proposeHash: map[int64]string{}, proposeSeq: map[int64]int64{}}
	for k, v := range c.byWrite {
		n.byWrite[k] = v
	}
	for k, v := range c.proposeHash {
		n.proposeHash[k] = v
	}
	for k, v := range c.proposeSeq {
		n.proposeSeq[k] = v
	}
	for k, v := range c.writes {
		n.writes[k] = v
	}
	for k, v := range c.proposes {
		n.proposes[k] = v
	}
	for k, v := range c.closed {
		n.closed[k] = v
	}
	return n
}

// verifiedState is verifyState returning the newest version exactly as it was checked (nil for
// none), so what is decided against is what was verified, never a second read of the row.
func verifiedState(tx *sql.Tx) (*Version, error) {
	_, v, err := verifyFrom(tx, chainState{})
	return v, err
}

// verifyFrom checks the audit records after base (all of them for the zero chainState), the head,
// every version against its write record and every proposal against its propose record, and
// returns the state reached and the newest version as checked.
func verifyFrom(tx *sql.Tx, base chainState) (chainState, *Version, error) {
	st := base.clone()
	rows, err := tx.Query(`SELECT seq, prev, hash, record FROM broker.audit WHERE seq > $1 ORDER BY seq`, st.seq)
	if err != nil {
		return base, nil, err
	}
	defer rows.Close()
	seq, prev := st.seq, st.prev
	writes, proposes, closed := st.writes, st.proposes, st.closed
	for rows.Next() {
		st.scanned++
		var n int64
		var p, h, line string
		if err := rows.Scan(&n, &p, &h, &line); err != nil {
			return base, nil, err
		}
		var r AuditRecord
		sum := sha256.Sum256([]byte(line))
		if json.Unmarshal([]byte(line), &r) != nil || n != seq+1 || r.Seq != n || p != prev || r.Prev != prev ||
			h != hex.EncodeToString(sum[:]) {
			return base, nil, fmt.Errorf("store: audit log breaks its chain at record %d", seq+1)
		}
		if r.Kind == "write" {
			if _, dup := writes[r.Version]; dup {
				return base, nil, errors.New("store: the audit log writes one version twice")
			}
			writes[r.Version] = r
		}
		switch r.Kind {
		case "write":
			// A version written from a proposal closes it, as the file-backed store's replay did:
			// a broker that stopped before appending the approve record left the write last.
			if _, ok := proposes[r.Proposal]; r.Proposal != 0 && ok && !closed[r.Proposal] {
				closed[r.Proposal], st.byWrite[r.Proposal] = true, true
			}
		case "propose":
			if _, dup := proposes[r.Proposal]; dup || r.Proposal < 1 {
				return base, nil, errors.New("store: the audit log proposes one id twice")
			}
			proposes[r.Proposal] = r
			st.proposeHash[r.Proposal], st.proposeSeq[r.Proposal] = h, n
		case "approve", "reject":
			// An approve follows the write it committed; anything else closes an open proposal.
			if _, ok := proposes[r.Proposal]; !ok || closed[r.Proposal] && !(r.Kind == "approve" && st.byWrite[r.Proposal]) {
				return base, nil, fmt.Errorf("store: the audit log closes proposal %d without an open one", r.Proposal)
			}
			closed[r.Proposal] = true
			delete(st.byWrite, r.Proposal)
		}
		seq, prev = n, h
	}
	if err := rows.Err(); err != nil {
		return base, nil, err
	}
	var hs int64
	var hh string
	if err := tx.QueryRow(`SELECT seq, hash FROM broker.audit_head`).Scan(&hs, &hh); err != nil || hs != seq || hh != prev {
		return base, nil, errors.New("store: the audit head does not match the log")
	}
	vs, err := versions(tx, 0)
	if err != nil {
		return base, nil, err
	}
	for i, v := range vs {
		rec, ok := writes[v.N]
		// The write record also carries the version's time, author, approver and comment, so
		// editing any of them (created drives the named-branch TTL check) is caught here.
		// The database keeps microseconds (rounded); an imported file-backed record has nanoseconds.
		if !ok || v.N != int64(i+1) || v.SHA256 != entriesHash(v.Entries) || rec.SHA256 != v.SHA256 ||
			!v.Created.Equal(rec.Time.Round(time.Microsecond)) || v.Author != rec.Actor || v.AuthorName != rec.Name ||
			v.Approver != rec.Approver || v.Comment != rec.Comment {
			return base, nil, fmt.Errorf("store: version %d fails its checks", v.N)
		}
	}
	if len(writes) != len(vs) {
		return base, nil, errors.New("store: the audit log records a version that is missing")
	}
	if err := checkProposals(tx, proposes, closed); err != nil {
		return base, nil, err
	}
	st.seq, st.prev = seq, prev
	if len(vs) == 0 {
		return st, nil, nil
	}
	return st, vs[len(vs)-1], nil
}

// checkProposals holds every proposal row to its propose record: same id, base, entries, author,
// comment and time, and open exactly when no approve or reject record closed it. Approve commits
// a proposal's entries under its author, so a row edited outside the service would otherwise
// change what is approved or let its author approve it.
func checkProposals(tx *sql.Tx, proposes map[int64]AuditRecord, closed map[int64]bool) error {
	rows, err := tx.Query(`SELECT id, base, entries, author, author_name, comment, created, open FROM broker.proposals ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		p := &Proposal{}
		var raw []byte
		if err := rows.Scan(&p.ID, &p.Base, &raw, &p.Author, &p.AuthorName, &p.Comment, &p.Created, &p.Open); err != nil {
			return err
		}
		rec, ok := proposes[p.ID]
		if !ok || json.Unmarshal(raw, &p.Entries) != nil || !p.matches(rec) || p.Open == closed[p.ID] {
			return fmt.Errorf("store: proposal %d does not match its audit record", p.ID)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if n != len(proposes) {
		return errors.New("store: the audit log records a proposal that is missing")
	}
	return nil
}

// matches reports whether p is the proposal its propose record describes.
func (p *Proposal) matches(r AuditRecord) bool {
	// The record drops an empty entry list (omitempty); the row keeps [].
	norm := func(es []Entry) []Entry {
		if es == nil {
			return []Entry{}
		}
		return es
	}
	return r.Kind == "propose" && r.Proposal == p.ID && r.Version == p.Base && entriesHash(norm(r.Entries)) == entriesHash(norm(p.Entries)) &&
		r.Actor == p.Author && r.Name == p.AuthorName && r.Comment == p.Comment && p.Created.Equal(r.Time.Round(time.Microsecond))
}

// errTampered is a proposal whose row and chained records disagree: refused, never approved.
var errTampered = errors.New("store: the proposal does not match the audit log")

// checkProposal holds one open proposal to the audit log at approval, against st, the store's
// check of the log up to its head: the proposal must have a propose record in st and none closing
// it, and the record as stored now must still hash to the value st checked and match the row.
// Nothing before st's checkpoint is read again.
func checkProposal(tx *sql.Tx, p *Proposal, st *chainState) error {
	want, ok := st.proposeHash[p.ID]
	if !ok || st.closed[p.ID] {
		return errTampered
	}
	var h, line string
	if err := tx.QueryRow(`SELECT hash, record FROM broker.audit WHERE seq = $1`, st.proposeSeq[p.ID]).Scan(&h, &line); err != nil {
		return errTampered
	}
	var r AuditRecord
	sum := sha256.Sum256([]byte(line))
	if json.Unmarshal([]byte(line), &r) != nil || h != want || hex.EncodeToString(sum[:]) != want || r.Kind != "propose" || !p.matches(r) {
		return errTampered
	}
	return nil
}

// versions reads every version from n on (0: all), in order.
func versions(q interface {
	Query(string, ...any) (*sql.Rows, error)
}, from int64) ([]*Version, error) {
	rows, err := q.Query(`SELECT n, entries, author, author_name, approver, comment, created, sha256
		FROM broker.policy_versions WHERE n >= $1 ORDER BY n`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Version
	for rows.Next() {
		var v Version
		var raw []byte
		if err := rows.Scan(&v.N, &raw, &v.Author, &v.AuthorName, &v.Approver, &v.Comment, &v.Created, &v.SHA256); err != nil {
			return nil, err
		}
		if json.Unmarshal(raw, &v.Entries) != nil || v.Entries == nil {
			return nil, fmt.Errorf("store: version %d unreadable", v.N)
		}
		v.Created = v.Created.UTC()
		out = append(out, &v)
	}
	return out, rows.Err()
}

func current(tx *sql.Tx) (int64, error) {
	var n int64
	err := tx.QueryRow(`SELECT coalesce(max(n), 0) FROM broker.policy_versions`).Scan(&n)
	return n, err
}

// Active returns the policy every pipeline request is decided against, or nil: no policy, a
// broken store, a policy the operator has since narrowed, or a database that cannot be read.
func (s *Store) Active() *Version {
	if s.broken != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	var n int64
	if err := s.db.QueryRowContext(ctx, `SELECT coalesce(max(n), 0) FROM broker.policy_versions`).Scan(&n); err != nil || n == 0 {
		return nil
	}
	if c := s.cache.Load(); c != nil && c.N == n {
		return c
	}
	// A version this process has not checked yet (written by another replica, or planted) is
	// checked with the whole store, as at open, before anything is decided against it.
	var v *Version
	if err := s.tx(func(tx *sql.Tx) (err error) { v, err = s.verified(tx); return err }); err != nil {
		log.Printf("policy store refused: %v; every pipeline is denied until it is repaired", err)
		return nil
	}
	if v == nil {
		return nil
	}
	// Fail closed if the operator has since narrowed what a policy may say.
	if errs := s.op.Validate(&Policy{Entries: v.Entries}, v.Created); len(errs) > 0 {
		return nil
	}
	s.cache.Store(v)
	return v
}

// appendAudit extends the chain by one record, in tx, at the service's label.
func (s *Store) appendAudit(tx *sql.Tx, r AuditRecord) error {
	_, _, err := s.appendAuditHead(tx, r)
	return err
}

// appendAuditHead is appendAudit returning the chain's new head.
func (s *Store) appendAuditHead(tx *sql.Tx, r AuditRecord) (int64, string, error) {
	var seq int64
	var prev string
	if err := tx.QueryRow(`SELECT seq, hash FROM broker.audit_head FOR UPDATE`).Scan(&seq, &prev); err != nil {
		return 0, "", err
	}
	r.Seq, r.Prev = seq+1, prev
	if r.Time.IsZero() {
		r.Time = time.Now().UTC().Truncate(time.Microsecond)
	}
	line, err := json.Marshal(r)
	if err != nil {
		return 0, "", err
	}
	sum := sha256.Sum256(line)
	h := hex.EncodeToString(sum[:])
	if _, err := tx.Exec(`INSERT INTO broker.audit (seq, prev, hash, record, marking, label)
		VALUES ($1, $2, $3, $4, $5, badger.label_of($6::jsonb))`, r.Seq, prev, h, string(line), s.label.Banner, s.label.Lattice()); err != nil {
		return 0, "", err
	}
	if _, err = tx.Exec(`UPDATE broker.audit_head SET seq = $1, hash = $2`, r.Seq, h); err != nil {
		return 0, "", err
	}
	return r.Seq, h, nil
}

// Audit appends one record that changes no policy (a decision or a refusal). An error tells the
// caller to refuse the request at hand: nothing is served without its record.
func (s *Store) Audit(r AuditRecord) error {
	if s.broken != nil {
		return s.broken
	}
	return s.tx(func(tx *sql.Tx) error { return s.appendAudit(tx, r) })
}

// AuditTx appends r in tx, a transaction of the caller's (at the service's label), so a change
// and its record commit together on one connection. It takes the policy write lock in tx.
func (s *Store) AuditTx(tx *sql.Tx, r AuditRecord) error {
	if s.broken != nil {
		return s.broken
	}
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, policyLock); err != nil {
		return err
	}
	return s.appendAudit(tx, r)
}

func diff(old, new []Entry) (removed, added []Entry) {
	has := func(es []Entry, e *Entry) bool {
		return slices.ContainsFunc(es, func(x Entry) bool { return x.equal(e) })
	}
	for i := range old {
		if !has(new, &old[i]) {
			removed = append(removed, old[i])
		}
	}
	for i := range new {
		if !has(old, &new[i]) {
			added = append(added, new[i])
		}
	}
	return
}

// commit writes version current+1 with its audit record (Lean `commit`), in tx.
// base is the current version as verifiedState returned it (nil for none).
func (s *Store) commit(tx *sql.Tx, base *Version, entries []Entry, author, name, approver, comment string, proposal int64, now time.Time) (*Version, error) {
	var cur int64
	var old []Entry
	if base != nil {
		cur, old = base.N, base.Entries
	}
	var err error
	if entries == nil {
		entries = []Entry{}
	}
	v := &Version{N: cur + 1, Entries: entries, Author: author, AuthorName: name, Approver: approver,
		Comment: comment, Created: now.UTC().Truncate(time.Microsecond), SHA256: entriesHash(entries)}
	raw, _ := json.Marshal(entries)
	if _, err := tx.Exec(`INSERT INTO broker.policy_versions (n, entries, author, author_name, approver, comment, created, sha256)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, v.N, raw, author, name, approver, comment, v.Created, v.SHA256); err != nil {
		return nil, err
	}
	removed, added := diff(old, entries)
	if v.auditSeq, v.auditHead, err = s.appendAuditHead(tx, AuditRecord{Time: v.Created, Kind: "write", Actor: author, Name: name, Version: v.N,
		Removed: removed, Added: added, Comment: comment, Proposal: proposal, Approver: approver, SHA256: v.SHA256}); err != nil {
		return nil, err
	}
	return v, nil
}

// committed logs a write once its transaction commits. The line carries the audit chain's head
// after the write record: an anchor off the database, so rewriting the audit history and its head
// together still contradicts what the log collector already holds.
func (s *Store) committed(v *Version) {
	log.Printf("policy write version=%d sha256=%s author=%s approver=%s audit_seq=%d audit_head=%s",
		v.N, v.SHA256, auditSafe(v.Author), logField(v.Approver), v.auditSeq, v.auditHead)
}

// needsSecond is Lean `needsSecond`.
func needsSecond(o *Operator, old, new []Entry) bool {
	if !o.TwoPerson {
		return false
	}
	for i := range new {
		e := &new[i]
		if e.Kind == KindNamed && e.Enabled && !slices.ContainsFunc(old, func(x Entry) bool { return x.equal(e) }) {
			return true
		}
	}
	return false
}

type WriteResult struct {
	Version  *Version
	Proposal *Proposal
	Invalid  []string
	Stale    bool
}

// Put is Lean `handle` for `.put`: the caller is already known to be an admin.
func (s *Store) Put(o *Operator, ifMatch int64, entries []Entry, actor, name, comment string, now time.Time) (WriteResult, error) {
	if s.broken != nil {
		return WriteResult{}, s.broken
	}
	var res WriteResult
	err := s.tx(func(tx *sql.Tx) error {
		res = WriteResult{}
		// The two-person rule compares against the verified current policy, never the row as it
		// reads now: a grant planted there would otherwise look like no change.
		base, err := s.verified(tx)
		if err != nil {
			return err
		}
		var cur int64
		var old []Entry
		if base != nil {
			cur = base.N
			// Only a version in force counts as already granted: one the operator has since
			// narrowed is not (Active serves none), so nothing in it passes as unchanged.
			if errs := o.Validate(&Policy{Entries: base.Entries}, base.Created); len(errs) == 0 {
				old = base.Entries
			}
		}
		if ifMatch != cur {
			res.Stale = true
			return nil
		}
		if errs := o.Validate(&Policy{Entries: entries}, now); len(errs) > 0 {
			res.Invalid = errs
			return nil
		}
		if needsSecond(o, old, entries) {
			var id int64
			if err := tx.QueryRow(`SELECT coalesce(max(id), 0) + 1 FROM broker.proposals`).Scan(&id); err != nil {
				return err
			}
			p := &Proposal{ID: id, Base: cur, Entries: entries, Author: actor, AuthorName: name, Comment: comment,
				Created: now.UTC().Truncate(time.Microsecond), Open: true}
			raw, _ := json.Marshal(entries)
			if _, err := tx.Exec(`INSERT INTO broker.proposals (id, base, entries, author, author_name, comment, created, open)
				VALUES ($1, $2, $3, $4, $5, $6, $7, true)`, p.ID, p.Base, raw, actor, name, comment, p.Created); err != nil {
				return err
			}
			removed, added := diff(old, entries)
			if err := s.appendAudit(tx, AuditRecord{Time: p.Created, Kind: "propose", Actor: actor, Name: name,
				Version: p.Base, Proposal: p.ID, Removed: removed, Added: added, Entries: entries, Comment: comment}); err != nil {
				return err
			}
			res.Proposal = p
			return nil
		}
		res.Version, err = s.commit(tx, base, entries, actor, name, "", comment, 0, now)
		return err
	})
	if err != nil {
		return WriteResult{}, err
	}
	if res.Version != nil {
		s.committed(res.Version)
	}
	return res, nil
}

var (
	errNoProposal = errors.New("no such open proposal")
	errSameAuthor = errors.New("the author cannot approve their own proposal")
)

func openProposal(tx *sql.Tx, id int64) (*Proposal, error) {
	p := &Proposal{ID: id}
	var raw []byte
	err := tx.QueryRow(`SELECT base, entries, author, author_name, comment, created, open FROM broker.proposals
		WHERE id = $1 FOR UPDATE`, id).Scan(&p.Base, &raw, &p.Author, &p.AuthorName, &p.Comment, &p.Created, &p.Open)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !p.Open {
		return nil, errNoProposal
	}
	if err != nil {
		return nil, err
	}
	p.Created = p.Created.UTC()
	return p, json.Unmarshal(raw, &p.Entries)
}

// Approve is Lean `handle` for `.approve`.
func (s *Store) Approve(o *Operator, id int64, actor, name string, now time.Time) (WriteResult, error) {
	if s.broken != nil {
		return WriteResult{}, s.broken
	}
	var res WriteResult
	err := s.tx(func(tx *sql.Tx) error {
		res = WriteResult{}
		p, err := openProposal(tx, id)
		if err != nil {
			return err
		}
		base, err := s.verified(tx)
		if err != nil {
			return err
		}
		if err := checkProposal(tx, p, s.checked.Load()); err != nil {
			log.Printf("policy approval refused: proposal %d does not match the audit log", id)
			return err
		}
		if p.Author == actor {
			return errSameAuthor
		}
		if base == nil && p.Base != 0 || base != nil && p.Base != base.N {
			res.Stale = true
			return nil
		}
		if errs := o.Validate(&Policy{Entries: p.Entries}, now); len(errs) > 0 {
			res.Invalid = errs
			return nil
		}
		if res.Version, err = s.commit(tx, base, p.Entries, p.Author, p.AuthorName, actor, p.Comment, id, now); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE broker.proposals SET open = false WHERE id = $1`, id); err != nil {
			return err
		}
		return s.appendAudit(tx, AuditRecord{Time: now.UTC().Truncate(time.Microsecond), Kind: "approve", Actor: actor,
			Name: name, Version: p.Base, Proposal: id})
	})
	if err != nil {
		return WriteResult{}, err
	}
	if res.Version != nil {
		s.committed(res.Version)
	}
	return res, nil
}

// Reject closes a proposal. Any admin may reject, including its author.
func (s *Store) Reject(id int64, actor, name string, now time.Time) error {
	if s.broken != nil {
		return s.broken
	}
	return s.tx(func(tx *sql.Tx) error {
		if _, err := openProposal(tx, id); err != nil {
			return err
		}
		cur, err := current(tx)
		if err != nil {
			return err
		}
		if err := s.appendAudit(tx, AuditRecord{Time: now.UTC().Truncate(time.Microsecond), Kind: "reject", Actor: actor,
			Name: name, Version: cur, Proposal: id}); err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE broker.proposals SET open = false WHERE id = $1`, id)
		return err
	})
}

// Seed writes version 1 from the operator's seed file when the store is empty. The seed is the
// operator's own authority (it is reviewed where the deployment config is reviewed), so the
// two-person rule does not apply to it. A non-empty store ignores the seed.
func (s *Store) Seed(o *Operator, path string, now time.Time) error {
	if path == "" || s.broken != nil {
		return s.broken
	}
	// A store with versions ignores the seed unread: an obsolete seed file must not fail a
	// deployment whose current policy is valid. The transaction below checks again.
	var cur int64
	if err := s.tx(func(tx *sql.Tx) (err error) { cur, err = current(tx); return err }); err != nil || cur != 0 {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return errors.New("seed: cannot read policy file")
	}
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	if errs := o.Validate(&p, now); len(errs) > 0 {
		return fmt.Errorf("seed: invalid policy: %s", strings.Join(errs, "; "))
	}
	var v *Version
	err = s.tx(func(tx *sql.Tx) error {
		if cur, err := current(tx); err != nil || cur != 0 {
			return err
		}
		v, err = s.commit(tx, nil, p.Entries, "operator:seed", "", "", "seed policy", 0, now)
		return err
	})
	if err == nil && v != nil {
		s.committed(v)
	}
	return err
}

func (s *Store) Versions() []VersionMeta {
	out := []VersionMeta{}
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT n, author, approver, created, sha256, jsonb_array_length(entries)
		FROM broker.policy_versions ORDER BY n`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var m VersionMeta
		if rows.Scan(&m.N, &m.Author, &m.Approver, &m.Created, &m.SHA256, &m.Entries) == nil {
			m.Created = m.Created.UTC()
			out = append(out, m)
		}
	}
	return out
}

func (s *Store) Version(n int64) (*Version, error) {
	vs, err := versions(s.db, n)
	if err != nil {
		return nil, err
	}
	if n < 1 || len(vs) == 0 || vs[0].N != n {
		return nil, fs.ErrNotExist
	}
	return vs[0], nil
}

func (s *Store) OpenProposals() []Proposal {
	out := []Proposal{}
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT id, base, entries, author, author_name, comment, created
		FROM broker.proposals WHERE open ORDER BY id`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		p := Proposal{Open: true}
		var raw []byte
		if rows.Scan(&p.ID, &p.Base, &raw, &p.Author, &p.AuthorName, &p.Comment, &p.Created) == nil && json.Unmarshal(raw, &p.Entries) == nil {
			p.Created = p.Created.UTC()
			out = append(out, p)
		}
	}
	return out
}

// AuditAfter returns up to limit records with seq > after that the service's label may read.
func (s *Store) AuditAfter(after int64, limit int) ([]AuditRecord, error) {
	out := []AuditRecord{}
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	err := pgdb.Tx(ctx, s.db, s.label, func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT record FROM broker.audit WHERE seq > $1 ORDER BY seq LIMIT $2`, after, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var line string
			var r AuditRecord
			if err := rows.Scan(&line); err != nil || json.Unmarshal([]byte(line), &r) != nil {
				return errors.New("audit log unreadable")
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

func parseVersionTag(tag string) (int64, bool) {
	tag = strings.TrimPrefix(strings.TrimSpace(tag), "W/")
	tag = strings.Trim(tag, `"`)
	n, err := strconv.ParseInt(tag, 10, 64)
	return n, err == nil && n >= 0
}
