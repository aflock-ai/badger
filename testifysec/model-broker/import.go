package broker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
)

// ImportState copies a broker state directory from before the database into db, once: policy
// versions, the audit log (its chain continues unbroken: each record keeps its exact bytes and
// hash), open proposals rebuilt from it, owners, quotas, workspace and device tokens, and the
// usage ledger. It runs in one transaction at the deployment's ceiling and records itself in
// broker.meta, so it never runs twice; a database already holding state it did not import is
// refused rather than merged. The directory is only read. OpenStore then checks the result as it
// checks any store.
func ImportState(ctx context.Context, db *sql.DB, cfg *FileConfig, dir string) (ImportReport, error) {
	var rep ImportReport
	err := pgdb.Tx(ctx, db, cfg.Ceiling(), func(tx *sql.Tx) error {
		rep = ImportReport{}
		// No ledger, token or document write runs until the import ends (writeLock), then no
		// policy write (policyLock): the order every writer takes them in, so none deadlocks.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, writeLock); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, policyLock); err != nil {
			return err
		}
		var done int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM broker.meta WHERE key = 'imported_from'`).Scan(&done); err != nil || done > 0 {
			return err
		}
		// Every table that holds state, so nothing is ever merged (meta: usage counting began).
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM broker.policy_versions) + (SELECT count(*) FROM broker.audit)
			+ (SELECT count(*) FROM broker.proposals) + (SELECT count(*) FROM broker.tokens) + (SELECT count(*) FROM broker.documents)
			+ (SELECT count(*) FROM broker.usage_calls) + (SELECT count(*) FROM broker.meta)`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return errors.New("import: the database already holds broker state; refusing to merge a state directory into it")
		}
		// "state/" and "state/." name a link at state as the link itself, so it is refused too.
		dir := filepath.Clean(dir)
		root, err := openStateDir(dir)
		if err != nil {
			return err
		}
		defer root.Close()
		// The baseline comes before the directory is checked or read: an entry changed at any
		// point after it (a state file replaced by a link that reads as absent, usage/ taken
		// away) is seen at the end and the import refused, never recorded with state missing.
		// Every open after the baseline is checked against it: the very entry it recorded, so one
		// swapped out and back during the copy, which no later fingerprint shows, is refused.
		before, snap, err := fingerprint(root)
		if err != nil {
			return fmt.Errorf("import %s: %w", dir, err)
		}
		seen, err := isStateDir(root, dir, snap)
		if err != nil {
			return err
		}
		if afterStateDirCheck != nil {
			afterStateDirCheck()
		}
		im := &importer{ctx: ctx, tx: tx, root: root, seen: seen, snap: snap, label: cfg.Ceiling(), rep: &rep}
		for _, step := range []func() error{im.versions, im.audit, im.documents, im.tokens, im.usage} {
			if err := step(); err != nil {
				return fmt.Errorf("import %s: %w", dir, err)
			}
		}
		// Directories with nothing in them are not a broker's state: recording that import would
		// stop the right directory from ever being imported.
		if rep.Versions+rep.Audit+rep.Documents+rep.Tokens+rep.UsageCalls == 0 && !rep.Opened {
			return fmt.Errorf("import %s: it holds no broker state to import", dir)
		}
		// What was copied must pass the checks the store makes at open, or the import would be
		// recorded as done and every pipeline denied with no way to import again.
		if err := verifyState(tx); err != nil {
			return fmt.Errorf("import %s: %w", dir, err)
		}
		if beforeImportVerify != nil {
			beforeImportVerify()
		}
		if after, _, err := fingerprint(root); err != nil || after != before {
			return fmt.Errorf("import %s: the state directory changed while it was copied; stop the file-backed broker and start again", dir)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO broker.meta (key, value) VALUES ('imported_from', $1), ('imported_at', $2)`,
			dir, time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
		rep.Imported = true
		return nil
	})
	if err != nil {
		return ImportReport{}, err
	}
	return rep, nil
}

// ImportReport is what an import copied, for the operator to check against the source.
type ImportReport struct {
	Imported                                                  bool
	Versions, Audit, Proposals, Documents, Tokens, UsageCalls int
	Opened                                                    bool // usage/opened: when counting began
}

func (r ImportReport) String() string {
	return fmt.Sprintf("versions=%d audit=%d proposals=%d documents=%d tokens=%d usage_calls=%d usage_opened=%t",
		r.Versions, r.Audit, r.Proposals, r.Documents, r.Tokens, r.UsageCalls, r.Opened)
}

// stateFiles are what a file-backed broker keeps in its state directory.
var stateFiles = []string{"versions", "audit.jsonl", "owners.json", "quotas.json", "tokens.json", "usage"}

// openStateDir opens the directory once; every read goes through that handle (os.Root), so what is
// checked is what is read even if the path is moved or replaced meanwhile, and nothing is read
// from outside it.
func openStateDir(dir string) (*os.Root, error) {
	// Lstat: a link would be checked as one tree and read as whatever it points at later.
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("import: %s is not a directory (a link is refused)", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("import: %s cannot be opened: %w", dir, err)
	}
	if opened, err := root.Stat("."); err != nil || !os.SameFile(fi, opened) {
		root.Close()
		return nil, fmt.Errorf("import: %s changed while it was opened", dir)
	}
	return root, nil
}

// snapshot is every entry under the directory, as the baseline walk found it, by clean path:
// its file info and, for a regular file, the SHA-256 of its bytes.
type snapshot map[string]snapEntry

type snapEntry struct {
	fi  os.FileInfo
	sum string
}

// fingerprint is every entry under root, the directory itself included, with its kind, size,
// modification time and (a regular file) content hash; a volume's lost+found is not state, and
// may not be readable, so it is left out. The snapshot it returns is what later opens and reads
// are checked against.
func fingerprint(root *os.Root) (string, snapshot, error) {
	h := sha256.New()
	snap := snapshot{}
	add := func(path string, fi os.FileInfo) error {
		e := snapEntry{fi: fi}
		if fi.Mode().IsRegular() {
			raw, err := readRegular(root, path, nil)
			if err != nil {
				return err
			}
			e.sum = contentSum(raw)
		}
		snap[path] = e
		fmt.Fprintf(h, "%s\x00%v\x00%d\x00%d\x00%s\n", path, fi.Mode(), fi.Size(), fi.ModTime().UnixNano(), e.sum)
		return nil
	}
	var walk func(dir string) error
	walk = func(dir string) error {
		ents, err := readDir(root, dir, nil)
		if err != nil {
			return err
		}
		for _, e := range ents {
			path := filepath.Join(dir, e.Name())
			if path == "lost+found" && e.IsDir() {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				return err
			}
			if err := add(path, fi); err != nil {
				return err
			}
			if e.IsDir() {
				if err := walk(path); err != nil {
					return err
				}
			}
		}
		return nil
	}
	top, err := root.Lstat(".")
	if err != nil {
		return "", nil, err
	}
	if err := add(".", top); err != nil {
		return "", nil, err
	}
	err = walk(".")
	return hex.EncodeToString(h.Sum(nil)), snap, err
}

// same refuses an opened file that is not the entry the baseline recorded at name: replaced, even
// if the original is put back before the end, or not there at the baseline at all.
func (s snapshot) same(name string, fi os.FileInfo) error {
	if s == nil {
		return nil
	}
	want, ok := s[filepath.Clean(name)]
	if !ok {
		return fmt.Errorf("%s was not there when the directory was checked", name)
	}
	if !os.SameFile(want.fi, fi) || want.fi.Size() != fi.Size() || !want.fi.ModTime().Equal(fi.ModTime()) {
		return fmt.Errorf("%s changed after the directory was checked", name)
	}
	return nil
}

// sameChildren refuses a listing of dir that is not exactly the entries the baseline found there
// (lost+found at the top aside): one moved out and back, even with the directory's modification
// time put back, is never imported as absent.
func (s snapshot) sameChildren(dir string, got []string) error {
	if s == nil {
		return nil
	}
	dir = filepath.Clean(dir)
	var want []string
	for path := range s {
		if path != "." && filepath.Dir(path) == dir {
			want = append(want, filepath.Base(path))
		}
	}
	got = slices.DeleteFunc(slices.Clone(got), func(n string) bool { return dir == "." && n == "lost+found" })
	slices.Sort(want)
	if !slices.Equal(want, got) {
		return fmt.Errorf("%s does not hold what it held when the directory was checked", dir)
	}
	return nil
}

// sameBytes refuses bytes read from name that are not the bytes the baseline read: an edit in
// place, even one that puts the modification time back, is not imported.
func (s snapshot) sameBytes(name string, raw []byte) error {
	if s == nil {
		return nil
	}
	if s[filepath.Clean(name)].sum != contentSum(raw) {
		return fmt.Errorf("%s changed after the directory was checked", name)
	}
	return nil
}

// isStateDir refuses a path that is not a directory holding at least one of the broker's state
// files: a mistyped path or an empty volume would otherwise import nothing and record the import
// as done, so the right directory could never be imported afterwards. Every entry at the top must
// be one the broker keeps (or the portal's data directory, or a volume's lost+found), as a plain
// file or directory: a state file left half-written under another name (quotas.json.tmp), or a
// link whose target is gone, would otherwise be skipped as absent.
func isStateDir(root *os.Root, dir string, snap snapshot) (map[string]bool, error) {
	ents, err := readDir(root, ".", snap)
	if err != nil {
		return nil, fmt.Errorf("import: %s cannot be listed: %w", dir, err)
	}
	dirs := []string{"versions", "usage", "portal", "lost+found"}
	seen := map[string]bool{}
	for _, e := range ents {
		name := e.Name()
		seen[name] = true
		switch {
		case !slices.Contains(stateFiles, name) && name != "portal" && name != "lost+found":
			return nil, fmt.Errorf("import: %s/%s is not a file the broker writes", dir, name)
		// A link (dangling or not) is refused: a missing target would read as state that was
		// never there. Each entry must be the kind the broker made.
		case slices.Contains(dirs, name) != e.IsDir() || !e.IsDir() && !e.Type().IsRegular():
			return nil, fmt.Errorf("import: %s/%s is not the kind of entry the broker writes", dir, name)
		}
	}
	for _, name := range stateFiles {
		if seen[name] {
			return seen, nil
		}
	}
	return nil, fmt.Errorf("import: %s holds no broker state (none of %s)", dir, strings.Join(stateFiles, ", "))
}

// list names the entries of a state subdirectory, which may be absent. A directory that cannot
// be listed is an error, never an empty one; every entry must be named as keep says, so a stray
// or half-written file stops the import for an operator to look at rather than be skipped.
func (im *importer) list(sub string, keep func(string) bool) ([]string, error) {
	ents, err := readDir(im.root, sub, im.snap)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, gone(im.seen, sub, err)
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if !keep(e.Name()) || !e.Type().IsRegular() {
			return nil, fmt.Errorf("%s/%s is not a file the broker writes", sub, e.Name())
		}
		names = append(names, filepath.Join(sub, e.Name()))
	}
	return names, nil
}

var (
	reVersionFile = regexp.MustCompile(`^[0-9]{8}\.json$`)
	reUsageFile   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}\.jsonl$`)
)

type importer struct {
	ctx   context.Context // the import's: every statement ends with it
	tx    *sql.Tx
	root  *os.Root        // the state directory
	seen  map[string]bool // its entries at the top when it was checked
	snap  snapshot        // every entry under it at the baseline
	label pgdb.Label
	rep   *ImportReport
}

// readDir lists name inside root, sorted, if it is still a directory once opened: the open does
// not wait (a FIFO swapped in after the check would otherwise block it), and the opened
// descriptor, not the path, is checked.
func readDir(root *os.Root, name string, snap snapshot) ([]os.DirEntry, error) {
	d, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	fi, err := d.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", name)
	}
	if err := snap.same(name, fi); err != nil {
		return nil, err
	}
	ents, err := d.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(ents, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	var got []string
	for _, e := range ents {
		got = append(got, e.Name())
	}
	return ents, snap.sameChildren(name, got)
}

// afterStateDirCheck, when set (tests only), runs once the state directory has been checked;
// beforeImportVerify, once everything is copied.
var afterStateDirCheck, beforeImportVerify func()

// gone is the error for name missing at read time: absent is fine only for an entry the check did
// not see at the top. One seen then and missing now (moved out and back during the copy, which no
// fingerprint shows) would import as never there.
func gone(seen map[string]bool, name string, err error) error {
	if seen[strings.SplitN(filepath.ToSlash(name), "/", 2)[0]] {
		return fmt.Errorf("%s was there when the directory was checked and is gone now: %w", name, err)
	}
	return nil
}

func (im *importer) read(name string) ([]byte, bool, error) {
	raw, err := readRegular(im.root, name, im.snap)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, gone(im.seen, name, err)
	}
	return raw, err == nil, err
}

// versions copies versions/NNNNNNNN.json; they must be 1..n with no gap.
func (im *importer) versions() error {
	names, err := im.list("versions", reVersionFile.MatchString)
	if err != nil {
		return err
	}
	slices.Sort(names)
	for i, name := range names {
		raw, err := readRegular(im.root, name, im.snap)
		if err != nil {
			return err
		}
		var v Version
		if err := json.Unmarshal(raw, &v); err != nil || v.Entries == nil || v.N != int64(i+1) ||
			filepath.Base(name) != fmt.Sprintf("%08d.json", v.N) {
			return fmt.Errorf("version file %s is not version %d", filepath.Base(name), i+1)
		}
		entries, _ := json.Marshal(v.Entries)
		if _, err := im.tx.ExecContext(im.ctx, `INSERT INTO broker.policy_versions (n, entries, author, author_name, approver, comment, created, sha256)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, v.N, entries, v.Author, v.AuthorName, v.Approver, v.Comment, dbTime(v.Created), v.SHA256); err != nil {
			return err
		}
		im.rep.Versions++
	}
	return nil
}

// audit copies audit.jsonl line by line, checking its chain, and rebuilds the proposals.
func (im *importer) audit() error {
	raw, ok, err := im.read("audit.jsonl")
	if err != nil || !ok {
		return err
	}
	var seq int64
	prev := ""
	props := map[int64]*Proposal{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		line := sc.Bytes()
		var r AuditRecord
		if json.Unmarshal(line, &r) != nil || r.Seq != seq+1 || r.Prev != prev {
			return fmt.Errorf("audit log breaks its chain at line %d", seq+1)
		}
		sum := sha256.Sum256(line)
		h := hex.EncodeToString(sum[:])
		if _, err := im.tx.ExecContext(im.ctx, `INSERT INTO broker.audit (seq, prev, hash, record, marking, label)
			VALUES ($1, $2, $3, $4, $5, badger.label_of($6::jsonb))`, r.Seq, prev, h, string(line), im.label.Banner, im.label.Lattice()); err != nil {
			return err
		}
		im.rep.Audit++
		switch r.Kind {
		case "propose":
			props[r.Proposal] = &Proposal{ID: r.Proposal, Base: r.Version, Entries: r.Entries, Author: r.Actor,
				AuthorName: r.Name, Comment: r.Comment, Created: r.Time, Open: true}
		case "write", "approve", "reject":
			if p := props[r.Proposal]; r.Proposal != 0 && p != nil {
				p.Open = false
			}
		}
		seq, prev = r.Seq, h
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if _, err := im.tx.ExecContext(im.ctx, `UPDATE broker.audit_head SET seq = $1, hash = $2`, seq, prev); err != nil {
		return err
	}
	for _, p := range props {
		entries, _ := json.Marshal(p.Entries)
		if p.Entries == nil {
			entries = []byte("[]")
		}
		if _, err := im.tx.ExecContext(im.ctx, `INSERT INTO broker.proposals (id, base, entries, author, author_name, comment, created, open)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, p.ID, p.Base, entries, p.Author, p.AuthorName, p.Comment, dbTime(p.Created), p.Open); err != nil {
			return err
		}
		im.rep.Proposals++
	}
	return nil
}

// documents copies owners.json and quotas.json with their versions.
func (im *importer) documents() error {
	for _, name := range []string{"owners", "quotas"} {
		raw, ok, err := im.read(name + ".json")
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		var head struct {
			Version int64 `json:"version"`
		}
		var check any = &OwnerSet{}
		if name == "quotas" {
			check = &QuotaSet{}
		}
		if strictObject(raw, &head) != nil || strictObject(raw, check) != nil || head.Version < 1 {
			return fmt.Errorf("%s.json is not a versioned %s document", name, name)
		}
		if q, isQuota := check.(*QuotaSet); isQuota && q.check(defaultUpstream.RequestSeconds) != nil {
			return errors.New("quotas.json fails its checks")
		}
		if _, err := im.tx.ExecContext(im.ctx, `INSERT INTO broker.documents (name, version, body) VALUES ($1, $2, $3)`, name, head.Version, raw); err != nil {
			return err
		}
		im.rep.Documents++
	}
	return nil
}

// tokens copies tokens.json; every workspace runs at the lowest label until reissued with one.
func (im *importer) tokens() error {
	raw, ok, err := im.read("tokens.json")
	if err != nil || !ok {
		return err
	}
	var recs []TokenRec
	if err := json.Unmarshal(raw, &recs); err != nil {
		return errors.New("tokens.json unreadable")
	}
	for _, r := range recs {
		if _, err := im.tx.ExecContext(im.ctx, `INSERT INTO broker.tokens (`+tokenCols+`) VALUES ($1, $2, $3, $4, $5, $6)`,
			r.Workspace, r.Hash, r.Principal, dbTime(r.Expires), r.Device, bottomBanner); err != nil {
			return err
		}
		im.rep.Tokens++
	}
	return nil
}

// usage copies the ledger: usage/opened and one row per call in usage/YYYY-MM-DD.jsonl. A call
// begun and never finished lost its result with the process that ran it: it is written finished
// with unknown usage, so its spend stays unknown, as it was.
func (im *importer) usage() error {
	// Every entry is checked to be a file the broker wrote before any is read: a FIFO would
	// block the read, and the import's transaction, forever.
	days, err := im.list("usage", func(name string) bool { return name == "opened" || reUsageFile.MatchString(name) })
	if err != nil {
		return err
	}
	if raw, ok, err := im.read(filepath.Join("usage", "opened")); err != nil {
		return err
	} else if ok {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(raw)))
		if err != nil {
			return errors.New("usage/opened unreadable")
		}
		if _, err := im.tx.ExecContext(im.ctx, `INSERT INTO broker.meta (key, value) VALUES ('usage_opened', $1)`, t.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
		im.rep.Opened = true
	}
	for _, path := range days {
		if filepath.Base(path) == "opened" {
			continue
		}
		day := strings.TrimSuffix(filepath.Base(path), ".jsonl")
		if _, err := time.Parse("2006-01-02", day); err != nil {
			return fmt.Errorf("usage/%s is not a day's ledger", filepath.Base(path))
		}
		raw, err := readRegular(im.root, path, im.snap)
		if err != nil {
			return err
		}
		pending := map[string]usageRecord{}
		var done []usageRecord
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var r usageRecord
			if json.Unmarshal(sc.Bytes(), &r) != nil || r.Principal == "" || r.Model == "" {
				// A line cut short by a crash may have been a charged call: the month's spend would be
				// unknown, so the import stops for an operator to look rather than guess.
				return fmt.Errorf("usage/%s.jsonl has a record that cannot be read", day)
			}
			if r.Pending {
				// A pending call is matched to its result by id: without one, or under an id
				// already pending, two calls cannot be told apart and one would be lost.
				if _, dup := pending[r.ID]; r.ID == "" || dup {
					return fmt.Errorf("usage/%s.jsonl has a pending call with no id or a repeated one", day)
				}
				pending[r.ID] = r
				continue
			}
			// A result belongs to its pending call: one under another principal's pending id would
			// clear that principal's unknown spend.
			if p, ok := pending[r.ID]; ok && (p.Principal != r.Principal || p.Model != r.Model ||
				p.Owner != "" && p.Owner != r.Owner || p.TriggeredBy != "" && p.TriggeredBy != r.TriggeredBy) {
				return fmt.Errorf("usage/%s.jsonl has a result that does not match its pending call", day)
			}
			delete(pending, r.ID)
			done = append(done, r)
		}
		if err := sc.Err(); err != nil {
			return err
		}
		ids := func(r usageRecord) string {
			if r.ID != "" {
				return day + "-" + r.ID
			}
			b := make([]byte, 8)
			rand.Read(b)
			return day + "-imported-" + hex.EncodeToString(b)
		}
		for _, r := range done {
			var charged any
			if r.ChargedUSD != nil {
				charged = *r.ChargedUSD
			}
			if _, err := im.tx.ExecContext(im.ctx, `INSERT INTO broker.usage_calls (id, day, t, principal, model, pending, prompt, cached, completion,
				owner, triggered_by, unknown, charged_usd) VALUES ($1, $2, $3, $4, $5, false, $6, $7, $8, $9, $10, $11, $12)`,
				ids(r), day, dbTime(r.Time), r.Principal, r.Model, r.Prompt, r.Cached, r.Completion, r.Owner, r.TriggeredBy,
				r.UsageUnknown, charged); err != nil {
				return err
			}
			im.rep.UsageCalls++
		}
		for _, r := range pending {
			if _, err := im.tx.ExecContext(im.ctx, `INSERT INTO broker.usage_calls (id, day, t, principal, model, pending, unknown, owner, triggered_by)
				VALUES ($1, $2, $3, $4, $5, false, true, $6, $7)`, ids(r), day, dbTime(r.Time), r.Principal, r.Model, r.Owner, r.TriggeredBy); err != nil {
				return err
			}
			im.rep.UsageCalls++
		}
	}
	return nil
}

// readRegular reads name inside root only if it is still a regular file once opened: the open
// does not wait (a FIFO swapped in after the check would otherwise block it), and the opened
// descriptor, not the path, is checked.
func readRegular(root *os.Root, name string, snap snapshot) ([]byte, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if err := snap.same(name, fi); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return raw, snap.sameBytes(name, raw)
}

// contentSum is the SHA-256 of raw, in hex.
func contentSum(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// dbTime is t as the database keeps it, rounded to the microsecond the way the verifier rounds
// (Go's Round, halves away from zero) rather than left to Postgres, which rounds a halfway value
// differently, so an imported time always matches its audit record.
func dbTime(t time.Time) time.Time { return t.Round(time.Microsecond).UTC() }

// writeLock is held shared by every usage, token and document transaction and exclusively by the
// import, so no replica writes between the import's emptiness check and its commit. Policy writes
// are already excluded by policyLock.
const writeLock = int64(0x62726b7202) // "brkr\x02"

// sharedWriteLock takes writeLock shared in tx.
func sharedWriteLock(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, writeLock)
	return err
}
