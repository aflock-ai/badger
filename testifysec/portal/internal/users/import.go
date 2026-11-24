package users

import (
	"bufio"
	"bytes"
	"context"
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
	"strconv"
	"strings"
	"syscall"

	"github.com/aflock-ai/badger/testifysec/model-broker/pgdb"
	"github.com/aflock-ai/badger/testifysec/portal/internal/auth"
	"github.com/aflock-ai/badger/testifysec/portal/internal/profile"
	"github.com/aflock-ai/badger/testifysec/portal/internal/store"
)

// ImportReport is what a portal import copied, for the operator to check against the source.
type ImportReport struct {
	Imported                                                                   bool
	ProfileVersions, Assignments, Audit, Users, RoleRequests, BootstrapMarkers int
}

func (r ImportReport) String() string {
	return fmt.Sprintf("profile_versions=%d assignments=%d audit=%d users=%d role_requests=%d bootstrap_markers=%d",
		r.ProfileVersions, r.Assignments, r.Audit, r.Users, r.RoleRequests, r.BootstrapMarkers)
}

// ImportFiles copies a file-backed portal's data directory into db, once: signed profile versions
// (byte for byte), assignments, the audit chain (checked, and continued by the next append), the
// directory's users and role requests, and the bootstrap markers, so a bootstrap subject whose role
// was handed over before the move stays retired after it. Everything runs in one transaction at
// label (the deployment's ceiling) and is recorded in portal.meta, so it never runs twice. It
// refuses rather than skips or merges: a path that is not a portal data directory, a directory it
// cannot list, a file it does not know, a record that fails its checks, a broken chain, or a
// database whose portal tables already hold anything. The directory is only read.
func ImportFiles(ctx context.Context, db *sql.DB, label pgdb.Label, dir string) (ImportReport, error) {
	var rep ImportReport
	err := pgdb.Tx(ctx, db, label, func(tx *sql.Tx) error {
		rep = ImportReport{}
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, importLock); err != nil {
			return err
		}
		// No other portal transaction runs until this one ends (store.WriteLock).
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, store.WriteLock); err != nil {
			return err
		}
		switch from, err := importedFrom(ctx, tx); {
		case err != nil:
			return err
		case from == NoImport:
			return fmt.Errorf(`portal import %s: this database recorded portal.import "none" (no portal data to import); `+
				"importing a data directory now needs the reset described in the model broker's README (State)", dir)
		case from != "":
			return nil
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM portal.profile_versions) + (SELECT count(*) FROM portal.assignments)
			+ (SELECT count(*) FROM portal.audit) + (SELECT seq FROM portal.audit_head) + (SELECT count(*) FROM portal.users)
			+ (SELECT count(*) FROM portal.role_requests) + (SELECT count(*) FROM portal.bootstrap_ended)
			+ (SELECT count(*) FROM portal.meta)`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return errors.New("portal import: the database already holds portal state; refusing to merge a data directory into it")
		}
		// "data/" and "data/." name a link at data as the link itself, so it is refused too.
		dir := filepath.Clean(dir)
		// Lstat: a link would be fingerprinted as the link, not the tree it points at.
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() {
			return fmt.Errorf("portal import: %s is not a directory (a link is refused)", dir)
		}
		// Opened once; every read and both fingerprints go through this handle, so the directory
		// checked is the one read, and nothing outside it is.
		root, err := os.OpenRoot(dir)
		if err != nil {
			return fmt.Errorf("portal import: %s cannot be opened: %w", dir, err)
		}
		defer root.Close()
		if opened, err := root.Stat("."); err != nil || !os.SameFile(fi, opened) {
			return fmt.Errorf("portal import: %s changed while it was opened", dir)
		}
		im := &portalImporter{ctx: ctx, tx: tx, root: root, seen: map[string]bool{}, label: label, rep: &rep}
		// The baseline is taken before anything in the directory is read, so a change at any point
		// after it, the top-level entries included, is seen at the end.
		before, snap, err := fingerprint(root)
		if err != nil {
			return fmt.Errorf("portal import %s: %w", dir, err)
		}
		// Every open after this is checked against the baseline: the very entry it recorded, so
		// one swapped out and back during the copy, which no later fingerprint shows, is refused.
		im.snap = snap

		// Every entry at the top must be one the portal keeps (or a volume's lost+found): a
		// directory under another name (users.bak) would otherwise be skipped, and with it the
		// bootstrap markers.
		ents, err := readDir(root, ".", snap)
		if err != nil {
			return fmt.Errorf("portal import: %s cannot be listed: %w", dir, err)
		}
		known := []string{"profiles", "deployments", "audit.jsonl", "users", "role-requests"}
		found := false
		for _, e := range ents {
			im.seen[e.Name()] = true
			switch {
			// Each must be the kind the portal made: a link, dangling or not, is refused, since a
			// missing target would read as a directory that was never there.
			case slices.Contains(known, e.Name()) && (e.Name() == "audit.jsonl") != e.IsDir() && (e.IsDir() || e.Type().IsRegular()):
				found = true
			case e.Name() == "lost+found":
			default:
				return fmt.Errorf("portal import: %s/%s is not a file the portal writes", dir, e.Name())
			}
		}
		if !found {
			return fmt.Errorf("portal import: %s holds no portal state", dir)
		}
		if afterImportStep != nil {
			afterImportStep("validated")
		}
		for _, step := range []struct {
			name string
			run  func() error
		}{{"profiles", im.profiles}, {"assignments", im.assignments}, {"audit", im.audit}, {"users", im.users}, {"requests", im.requests}} {
			if err := step.run(); err != nil {
				return fmt.Errorf("portal import %s: %w", dir, err)
			}
			if afterImportStep != nil {
				afterImportStep(step.name)
			}
		}
		// A directory with no records is not a portal's data: recording that import would stop
		// the real directory from ever being imported.
		if rep.ProfileVersions+rep.Assignments+rep.Audit+rep.Users+rep.RoleRequests+rep.BootstrapMarkers == 0 {
			return fmt.Errorf("portal import %s: it holds no portal records to import", dir)
		}
		// The store refuses signed profiles with no audit log at start; refused here, inside the
		// transaction, the corrected directory can still be imported.
		if rep.ProfileVersions > 0 && rep.Audit == 0 {
			return fmt.Errorf("portal import %s: it holds signed profiles but no audit log", dir)
		}
		// Nothing can lock a directory another process writes, so the copy is checked instead:
		// if anything in it changed while it was read (a running file-backed portal retiring a
		// bootstrap subject), the import is refused and can run again once that portal is stopped.
		if after, _, err := fingerprint(root); err != nil || after != before {
			return fmt.Errorf("portal import %s: the data directory changed while it was copied; stop the file-backed portal and start again", dir)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO portal.meta (key, value) VALUES ('imported_from', $1)`, dir); err != nil {
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

// afterImportStep, when set (tests only), runs after each copy step.
var afterImportStep func(step string)

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

// importLock serialises two replicas starting the import at once.
const importLock = int64(0x706f7274616c01) // "portal\x01"

type portalImporter struct {
	ctx   context.Context // the import's: every statement ends with it
	tx    *sql.Tx
	root  *os.Root        // the data directory
	seen  map[string]bool // its entries at the top when it was checked
	snap  snapshot        // every entry under it at the baseline
	label pgdb.Label
	rep   *ImportReport
}

// list names the regular files in sub (which may be absent), each matching keep; a directory
// that cannot be listed, or any other entry (a leftover temporary file), is an error.
func (im *portalImporter) list(sub string, keep func(string) bool) ([]string, error) {
	ents, err := readDir(im.root, sub, im.snap)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, gone(im.seen, sub, err)
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if !e.Type().IsRegular() || !keep(e.Name()) {
			return nil, fmt.Errorf("%s/%s is not a file the portal writes", sub, e.Name())
		}
		names = append(names, e.Name())
	}
	return names, nil
}

var reVersionFile = regexp.MustCompile(`^[0-9]{20}\.json$`)

// profiles copies profiles/<id>/<sequence>.json; each must be the version its path names.
func (im *portalImporter) profiles() error {
	ents, err := readDir(im.root, "profiles", im.snap)
	if errors.Is(err, fs.ErrNotExist) {
		return gone(im.seen, "profiles", err)
	}
	if err != nil {
		return err
	}
	for _, e := range ents {
		if !e.IsDir() || !profile.ValidIdentifier(e.Name()) {
			return fmt.Errorf("profiles/%s is not a profile directory", e.Name())
		}
		names, err := im.list(filepath.Join("profiles", e.Name()), reVersionFile.MatchString)
		if err != nil {
			return err
		}
		for _, name := range names {
			raw, err := readRegular(im.root, filepath.Join("profiles", e.Name(), name), im.snap)
			if err != nil {
				return err
			}
			var v store.Version
			seq, _ := strconv.ParseUint(strings.TrimSuffix(name, ".json"), 10, 64)
			if json.Unmarshal(raw, &v) != nil || v.ProfileID != e.Name() || v.Sequence != seq || seq < 1 || seq > profile.MaxSequence {
				return fmt.Errorf("profiles/%s/%s is not that version", e.Name(), name)
			}
			if _, err := im.tx.ExecContext(im.ctx, `INSERT INTO portal.profile_versions (profile_id, sequence, body, marking, label)
				VALUES ($1, $2, $3, $4, badger.label_of($5::jsonb))`, v.ProfileID, int64(seq), string(raw), im.label.Banner, im.label.Lattice()); err != nil {
				return err
			}
			im.rep.ProfileVersions++
		}
	}
	return nil
}

// assignments copies deployments/<id>.json.
func (im *portalImporter) assignments() error {
	names, err := im.list("deployments", func(n string) bool {
		return strings.HasSuffix(n, ".json") && profile.ValidIdentifier(strings.TrimSuffix(n, ".json"))
	})
	if err != nil {
		return err
	}
	for _, name := range names {
		raw, err := readRegular(im.root, filepath.Join("deployments", name), im.snap)
		if err != nil {
			return err
		}
		var a store.Assignment
		if json.Unmarshal(raw, &a) != nil || a.DeploymentID != strings.TrimSuffix(name, ".json") || !profile.ValidIdentifier(a.ProfileID) || a.Sequence < 1 {
			return fmt.Errorf("deployments/%s is not that deployment's assignment", name)
		}
		if _, err := im.tx.ExecContext(im.ctx, `INSERT INTO portal.assignments (deployment_id, body) VALUES ($1, $2)`, a.DeploymentID, raw); err != nil {
			return err
		}
		im.rep.Assignments++
	}
	return nil
}

// audit copies audit.jsonl line by line, keeping each record's exact bytes, and checks its chain:
// each record's prev is the SHA-256 of the line before it (zeros for the first).
func (im *portalImporter) audit() error {
	raw, err := readRegular(im.root, "audit.jsonl", im.snap)
	if errors.Is(err, fs.ErrNotExist) {
		return gone(im.seen, "audit.jsonl", err)
	}
	if err != nil {
		return err
	}
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		return errors.New("audit.jsonl ends in a partial line")
	}
	prev := strings.Repeat("0", 64)
	var seq int64
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		line := sc.Bytes()
		var r store.Record
		if json.Unmarshal(line, &r) != nil || r.Prev != prev {
			return fmt.Errorf("audit.jsonl breaks its chain at line %d", seq+1)
		}
		sum := sha256.Sum256(line)
		h := hex.EncodeToString(sum[:])
		seq++
		if _, err := im.tx.ExecContext(im.ctx, `INSERT INTO portal.audit (seq, prev, hash, record, marking, label)
			VALUES ($1, $2, $3, $4, $5, badger.label_of($6::jsonb))`, seq, prev, h, string(line), im.label.Banner, im.label.Lattice()); err != nil {
			return err
		}
		prev = h
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if _, err := im.tx.ExecContext(im.ctx, `UPDATE portal.audit_head SET seq = $1, hash = $2`, seq, prev); err != nil {
		return err
	}
	im.rep.Audit = int(seq)
	return nil
}

// users copies users/<id>.json (each a whole user under its own ID) and the bootstrap markers
// users/bootstrap-ended-<role> ("<holder>", tentative, or "final <holder>").
func (im *portalImporter) users() error {
	names, err := im.list("users", func(n string) bool {
		return strings.HasSuffix(n, ".json") && hexID.MatchString(strings.TrimSuffix(n, ".json")) ||
			strings.HasPrefix(n, "bootstrap-ended-") && auth.Role(strings.TrimPrefix(n, "bootstrap-ended-")).Valid()
	})
	if err != nil {
		return err
	}
	for _, name := range names {
		raw, err := readRegular(im.root, filepath.Join("users", name), im.snap)
		if err != nil {
			return err
		}
		if role, ok := strings.CutPrefix(name, "bootstrap-ended-"); ok {
			holder, final := strings.CutPrefix(strings.TrimSpace(string(raw)), "final ")
			if !hexID.MatchString(holder) {
				return fmt.Errorf("users/%s is damaged", name)
			}
			if _, err := im.tx.ExecContext(im.ctx, `INSERT INTO portal.bootstrap_ended (role, holder, final) VALUES ($1, $2, $3)`, role, holder, final); err != nil {
				return err
			}
			im.rep.BootstrapMarkers++
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		var u User
		if err := strictJSON(raw, &u); err != nil || u.check(id) != nil {
			return fmt.Errorf("users/%s is not a whole user", name)
		}
		if _, err := im.tx.ExecContext(im.ctx, `INSERT INTO portal.users (id, body) VALUES ($1, $2)`, id, raw); err != nil {
			return err
		}
		im.rep.Users++
	}
	return nil
}

// requests copies role-requests/<id>.json, each a whole request under its own ID.
func (im *portalImporter) requests() error {
	names, err := im.list("role-requests", func(n string) bool {
		return strings.HasSuffix(n, ".json") && requestID.MatchString(strings.TrimSuffix(n, ".json"))
	})
	if err != nil {
		return err
	}
	for _, name := range names {
		raw, err := readRegular(im.root, filepath.Join("role-requests", name), im.snap)
		if err != nil {
			return err
		}
		id := strings.TrimSuffix(name, ".json")
		var r Request
		if err := strictJSON(raw, &r); err != nil || r.check(id) != nil {
			return fmt.Errorf("role-requests/%s is not a whole request", name)
		}
		if _, err := im.tx.ExecContext(im.ctx, `INSERT INTO portal.role_requests (id, body) VALUES ($1, $2)`, id, raw); err != nil {
			return err
		}
		im.rep.RoleRequests++
	}
	return nil
}

// strictJSON decodes one JSON object into v, refusing unknown fields and trailing data.
func strictJSON(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Exactly one value: a second Decode must find the end (More misses a stray ']' or '}').
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return errors.New("trailing data")
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

// gone is the error for name missing at read time: absent is fine only for an entry the check did
// not see at the top. One seen then and missing now (moved out and back during the copy, which no
// fingerprint shows) would import as never there.
func gone(seen map[string]bool, name string, err error) error {
	if seen[strings.SplitN(filepath.ToSlash(name), "/", 2)[0]] {
		return fmt.Errorf("%s was there when the directory was checked and is gone now: %w", name, err)
	}
	return nil
}

// contentSum is the SHA-256 of raw, in hex.
func contentSum(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// NoImport is the portal's import record when the configuration declared there was no portal data
// to import (portal.import "none").
const NoImport = "none (declared by config)"

// importedFrom is the portal's import record: empty when nothing was imported or declared.
func importedFrom(ctx context.Context, tx *sql.Tx) (string, error) {
	var from string
	err := tx.QueryRowContext(ctx, `SELECT value FROM portal.meta WHERE key = 'imported_from'`).Scan(&from)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return from, err
}

// DeclareNoImport records, once, that there is no portal data to import: the portal's import is
// done, as NoImport, so a data directory offered later is refused rather than imported on top. It
// refuses a database whose portal tables already hold anything, as an import would. recorded is
// false when an import or declaration was already recorded (a restart).
func DeclareNoImport(ctx context.Context, db *sql.DB, label pgdb.Label) (recorded bool, err error) {
	err = pgdb.Tx(ctx, db, label, func(tx *sql.Tx) error {
		recorded = false
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, importLock); err != nil {
			return err
		}
		// No other portal transaction runs until this one ends (store.WriteLock).
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, store.WriteLock); err != nil {
			return err
		}
		if from, err := importedFrom(ctx, tx); err != nil || from != "" {
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM portal.profile_versions) + (SELECT count(*) FROM portal.assignments)
			+ (SELECT count(*) FROM portal.audit) + (SELECT seq FROM portal.audit_head) + (SELECT count(*) FROM portal.users)
			+ (SELECT count(*) FROM portal.role_requests) + (SELECT count(*) FROM portal.bootstrap_ended)
			+ (SELECT count(*) FROM portal.meta)`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return errors.New(`portal import "none": the database already holds portal state; refusing to record that there was none`)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO portal.meta (key, value) VALUES ('imported_from', $1)`, NoImport); err != nil {
			return err
		}
		recorded = true
		return nil
	})
	return recorded, err
}
