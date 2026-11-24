package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/aflock-ai/badger/testifysec/connectors/marking"
)

// labels keeps one no-write-down label per workspace: the join of the markings of every connector
// whose answer the workspace has received. A pod keeps them durably in a labels file: each raise is
// appended and synced before the answer that carries it is passed on, and the file is read back on
// start, so a restart never forgets what a workspace has read.
type labels struct {
	mu  sync.Mutex
	set map[string]marking.Marking
	// reg holds the workspaces a controller registered (owner and ceiling); see workspaces.go.
	reg  map[string]registration
	file *os.File // nil keeps labels in memory only (tests)
	// failed is the first error writing the file. From then on every raise fails, so no answer
	// is passed on whose label might not be on disk; only a restart, which reads the file back,
	// restores service.
	failed error
}

func newLabels() *labels {
	return &labels{set: map[string]marking.Marking{}, reg: map[string]registration{}}
}

// labelsHeader is the first line of a us-gov labels file. A file without a header is refused, so an
// empty or missing volume cannot pass for a pod with nothing read: a first install, or an
// administrator's reset, writes a header-only file with `conngw --init-labels`. A deployment on any
// other scheme writes version 2, which names the scheme's digest (header); its labels mean nothing
// under another scheme, so a file whose scheme is not the gateway's is refused.
const labelsHeader = `{"conngw-labels":1}`

// header is the labels file's first line for a scheme: version 1 for us-gov, so existing files
// stay as they are; version 2 with the digest for any other.
func header(s *marking.Scheme) string {
	if s.IsDefault() {
		return labelsHeader
	}
	b, _ := json.Marshal(struct {
		V      int    `json:"conngw-labels"`
		Scheme string `json:"scheme"`
	}{2, s.Digest()})
	return string(b)
}

// labelRecord is one line of the labels file: a workspace's whole label after a raise, its
// registration (owner and ceiling, written once), or both (a fork).
type labelRecord struct {
	Workspace string `json:"workspace"`
	Label     string `json:"label,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Ceiling   string `json:"ceiling,omitempty"`
}

// initLabels writes a header-only labels file for the scheme, refusing one that exists.
func initLabels(path string, s *marking.Scheme) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(header(s) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// openLabels rebuilds every workspace's label from the labels file and keeps it open for appends.
// A missing file, a missing header or any unreadable record refuses: the pod cannot know what a
// workspace has read. Only a torn last record (no newline, written when the pod stopped mid-append)
// is dropped, since its answer was never passed on; the file is cut back to the last whole record.
func openLabels(path string, s *marking.Scheme) (*labels, error) {
	// O_APPEND: every record goes at the end, whatever another holder did. The exclusive lock is
	// taken before the file is read and held for the life of the process, so a second conngw on the
	// same file (an overlapping rollout) refuses instead of keeping its own copy of the labels.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		return nil, fmt.Errorf("labels file: %w (a first install runs conngw --init-labels)", err)
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, errors.New("labels file: another conngw holds it; run one replica, with the Recreate strategy")
	}
	b, err := io.ReadAll(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("labels file: %w", err)
	}
	whole := bytes.LastIndexByte(b, '\n') + 1
	lines := bytes.Split(b[:whole], []byte("\n"))
	if whole == 0 || !strings.HasPrefix(string(lines[0]), `{"conngw-labels":`) {
		f.Close()
		return nil, errors.New("labels file: no header line; refusing rather than forgetting what workspaces have read")
	}
	if string(lines[0]) != header(s) {
		f.Close()
		held := "us-gov"
		if string(lines[0]) != labelsHeader {
			held = "another scheme's"
		}
		return nil, fmt.Errorf("labels file: it holds %s labels and this gateway uses the %s scheme (%s); labels are never read under another scheme: migrate the file (marking-migrate) or start from an empty one", held, s.Name, s.Digest())
	}
	l := newLabels()
	for i, line := range lines[1 : len(lines)-1] {
		if err := l.load(line); err != nil {
			f.Close()
			return nil, fmt.Errorf("labels file: record %d: %v", i+1, err)
		}
	}
	if whole < len(b) {
		if err := f.Truncate(int64(whole)); err != nil {
			f.Close()
			return nil, err
		}
	}
	l.file = f
	return l, nil
}

// record reads one line as exactly one record: known fields only, nothing after it, a workspace
// named "<namespace>/<account>", and markings the token table knows.
func record(line []byte) (labelRecord, error) {
	var r labelRecord
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, errors.New("unreadable")
	}
	if _, err := d.Token(); err != io.EOF {
		return r, errors.New("trailing data after the record")
	}
	// Records written before workspaces were DNS labels (name) still read back.
	ns, account, ok := strings.Cut(r.Workspace, "/")
	if !ok || !(dnsLabel.MatchString(ns) || name.MatchString(ns)) || !(dnsLabel.MatchString(account) || name.MatchString(account)) {
		return r, errors.New("not a workspace name")
	}
	if r.Label == "" && r.Owner == "" {
		return r, errors.New("neither a label nor a registration")
	}
	if (r.Owner == "") != (r.Ceiling == "") || (r.Owner != "" && !ownerID.MatchString(r.Owner)) {
		return r, errors.New("a registration needs a valid owner and a ceiling")
	}
	return r, nil
}

// load applies one record read back from the file. Each label record is the workspace's whole
// label after a raise, so it dominates the one before; one that does not, a second owner, another
// ceiling or a label above the ceiling means the file is not what this pod wrote.
func (l *labels) load(line []byte) error {
	r, err := record(line)
	if err != nil {
		return err
	}
	if r.Owner != "" {
		c, err := marking.Parse(r.Ceiling)
		if err != nil {
			return err
		}
		if before, ok := l.reg[r.Workspace]; ok && (before.owner != r.Owner || marking.Banner(before.ceiling) != marking.Banner(c)) {
			return errors.New("changes a workspace's registration")
		}
		l.reg[r.Workspace] = registration{owner: r.Owner, ceiling: c}
	}
	if r.Label != "" {
		m, err := marking.Parse(r.Label)
		if err != nil {
			return err
		}
		if before, ok := l.set[r.Workspace]; ok && !marking.Dominates(m, before) {
			return errors.New("lowers a workspace's label")
		}
		if _, _, err := l.join(r.Workspace, m); err != nil {
			return err
		}
	}
	if reg, ok := l.reg[r.Workspace]; ok {
		if label, ok := l.set[r.Workspace]; ok && !marking.Dominates(reg.ceiling, label) {
			return errors.New("a label above the workspace's ceiling")
		}
	}
	return nil
}

// allows reports whether a call to a connector marked m may carry what the workspace has read: m
// must dominate its label. A workspace that has read nothing may call anything. When m dominates
// the label their join is m itself, so an allowed call never leads to a label no banner prints.
func (l *labels) allows(ws string, m marking.Marking) (marking.Marking, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	label, ok := l.set[ws]
	return label, !ok || marking.Dominates(m, label)
}

// join raises the workspace's label to include m. A combination no banner prints (marking.Join's
// refusal) changes nothing and is returned as an error.
func (l *labels) join(ws string, m marking.Marking) (marking.Marking, bool, error) {
	label, ok := l.set[ws]
	if ok {
		joined, err := marking.Join(label, m)
		if err != nil {
			return label, false, err
		}
		if marking.Banner(joined) == marking.Banner(label) {
			return label, false, nil
		}
		m = joined
	}
	l.set[ws] = m
	return m, true, nil
}

// raise joins m into the workspace's label, before the answer that carries it is passed on. When
// the label changes it is recorded durably first. If that fails, the label is still raised in
// memory, the error says the answer must not be passed on, and every later raise fails too, for any
// workspace, even one that changes nothing: its label may be the one that was not written.
func (l *labels) raise(ws string, m marking.Marking) (marking.Marking, error) {
	label, _, err := l.raised(ws, m)
	return label, err
}

// raised is raise that also returns the label's banner before it ("" when the workspace had none),
// for the raise's audit event.
func (l *labels) raised(ws string, m marking.Marking) (label marking.Marking, prior string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if before, ok := l.set[ws]; ok {
		prior = marking.Banner(before)
	}
	label, err = l.raiseLocked(ws, m)
	return label, prior, err
}

func (l *labels) raiseLocked(ws string, m marking.Marking) (marking.Marking, error) {
	// A registered workspace rises only to its ceiling: anything higher is a fork's job. Checked
	// before the join, so a refused raise changes nothing.
	if reg, ok := l.reg[ws]; ok {
		next := m
		if label, ok := l.set[ws]; ok {
			var err error
			if next, err = marking.Join(label, m); err != nil {
				return label, fmt.Errorf("high-water: %w", err)
			}
		}
		if !marking.Dominates(reg.ceiling, next) {
			return l.set[ws], errAboveCeiling
		}
	}
	label, changed, err := l.join(ws, m)
	if err != nil {
		// Nothing is recorded and the answer is not passed on.
		return label, fmt.Errorf("high-water: %w", err)
	}
	if l.failed != nil {
		return label, l.failed
	}
	if !changed {
		return label, nil
	}
	return label, l.append(labelRecord{Workspace: ws, Label: marking.Banner(label)})
}

// append writes one record and syncs it. The first failure stops every later write (raise).
// Called with mu held.
func (l *labels) append(r labelRecord) error {
	if l.failed != nil {
		return l.failed
	}
	if l.file == nil {
		return nil
	}
	b, _ := json.Marshal(r)
	if _, err := l.file.Write(append(b, '\n')); err != nil {
		l.failed = fmt.Errorf("labels file: %w", err)
		return l.failed
	}
	if err := l.file.Sync(); err != nil {
		l.failed = fmt.Errorf("labels file: %w", err)
		return l.failed
	}
	return nil
}
