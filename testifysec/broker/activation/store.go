package activation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Store keeps one device's State in a broker-owned directory, durably and before a new pin takes
// effect (testifysec/PORTAL.md, "High-water state and reset"):
//
//	installed   "fresh" from the installer, then "activated <reset high-water>"
//	state.json  the counters and the pinned digest
//	lock        held (flock) for every load and commit, by every Store on the directory
//
// Each file is replaced with a fresh file, fsync, rename and a directory fsync. Whenever the
// marker changes it is written before the state, so a crash between the two leaves an activated
// marker (and the reset high-water) with the old or no state: never a fresh marker beside state.
//
// A missing state file never resets the counters. With the marker "fresh" and no state the device
// starts at the compiled floor once; with "activated" and no state it fails closed and admits only
// a reset record for this device, above the reset high-water the marker keeps, so a consumed reset
// does not replay after the state is lost again; with no marker it admits nothing. Root can still
// delete every file and rerun the installer; counters in a TPM NV index (PR 4b) close that.
type Store struct {
	root  *os.Root
	floor State
	read  func(*os.Root, string) ([]byte, error) // readPrivate; a test replaces it
}

const (
	markerFile = "installed"
	stateFile  = "state.json"
	lockFile   = "lock"
	fresh      = "fresh\n"
)

// errResetInterrupted is RefuseState for a reset that crashed between its marker and state writes.
var errResetInterrupted = fmt.Errorf("%w: reset interrupted", RefuseState)

var activatedMarker = regexp.MustCompile(`^activated (0|[1-9][0-9]{0,15})\n$`)

// marker is the first-install marker: whether the device has activated, and the highest reset it
// has consumed.
type marker struct {
	activated bool
	reset     uint64
}

func (m marker) bytes() []byte { return []byte("activated " + strconv.FormatUint(m.reset, 10) + "\n") }

// Install writes the first-install marker unless one exists. Only the installer calls it. It holds
// the directory's lock, so a delayed installer cannot replace a marker the broker has since
// activated.
func Install(dir string) error {
	root, err := openDir(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	unlock, err := lockRoot(root)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err = root.Lstat(markerFile); !errors.Is(err, fs.ErrNotExist) {
		return err // nil when a marker exists: it is never replaced
	}
	return writeDurably(root, markerFile, []byte(fresh))
}

// Open opens a device's state directory; floor is the compiled starting state for a fresh install.
func Open(dir string, floor State) (*Store, error) {
	root, err := openDir(dir)
	if err != nil {
		return nil, err
	}
	return &Store{root: root, floor: floor, read: readPrivate}, nil
}

func (s *Store) Close() error { return s.root.Close() }

// lock takes the directory's exclusive lock, which every Store and Install on it honours.
func (s *Store) lock() (func(), error) { return lockRoot(s.root) }

func lockRoot(root *os.Root) (func(), error) {
	file, err := root.OpenFile(lockFile, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, RefuseState
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, RefuseState
	}
	return func() { syscall.Flock(int(file.Fd()), syscall.LOCK_UN); file.Close() }, nil
}

// Load returns the device's state, or RefuseState when it has none it may use.
func (s *Store) Load() (State, error) {
	unlock, err := s.lock()
	if err != nil {
		return State{}, err
	}
	defer unlock()
	state, _, err := s.load()
	return state, err
}

// load reads the marker and the state. Found beside state, a fresh marker (which a crash between
// two writes of an older broker could leave) is consumed before the state is used.
func (s *Store) load() (State, marker, error) {
	var m marker
	if err := syncDirectory(s.root); err != nil {
		return State{}, m, RefuseState // nothing visible is trusted until it is durable
	}
	raw, err := s.read(s.root, markerFile)
	switch {
	case err == nil && string(raw) == fresh:
	case err == nil && activatedMarker.Match(raw):
		m.activated = true
		m.reset, _ = strconv.ParseUint(strings.Fields(string(raw))[1], 10, 64)
	default:
		return State{}, m, RefuseState
	}
	raw, err = s.read(s.root, stateFile)
	if errors.Is(err, fs.ErrNotExist) {
		if !m.activated {
			return s.floor, m, nil
		}
		return State{}, m, RefuseState
	}
	if err != nil {
		return State{}, m, RefuseState // whatever bytes came with the error are not trusted
	}
	f, err := fields(raw, "profileHighWater", "activationHighWater", "resetHighWater", "profileSha256")
	if err != nil {
		return State{}, m, RefuseState
	}
	p := parser{f: f}
	state := State{ProfileHighWater: p.number("profileHighWater", 0, maxSequence), ActivationHighWater: p.number("activationHighWater", 0, maxSequence),
		ResetHighWater: p.number("resetHighWater", 0, maxSequence), ProfileSHA256: p.match("profileSha256", nil)}
	if p.err != nil || (state.ProfileSHA256 != "" && !hexDigest.MatchString(state.ProfileSHA256)) {
		return State{}, m, RefuseState
	}
	// The marker is written before the state, so a marker ahead of the state is a reset that
	// crashed between its two writes: the state's counters are the pre-reset ones. Fail closed;
	// Apply then admits that reset again (or a later one), nothing else.
	if m.reset > state.ResetHighWater {
		return State{}, m, errResetInterrupted
	}
	if !m.activated {
		m = marker{activated: true, reset: state.ResetHighWater}
		if err = writeDurably(s.root, markerFile, m.bytes()); err != nil {
			return State{}, m, RefuseState
		}
	}
	return state, m, nil
}

// Apply verifies a record, steps the state and commits it durably before returning the new state.
// Nothing changes when any of those fails.
func (s *Store) Apply(t Trust, envelope []byte, now time.Time) (State, error) {
	unlock, err := s.lock()
	if err != nil {
		return State{}, err
	}
	defer unlock()
	state, m, err := s.load()
	interrupted := errors.Is(err, errResetInterrupted)
	lost := err != nil && m.activated
	if err != nil && !lost {
		return State{}, err
	}
	record, err := Verify(t, envelope)
	if err != nil {
		return State{}, err
	}
	if lost {
		if record.Reset == nil {
			return State{}, RefuseState // only a reset for this device re-establishes lost counters
		}
		state = State{ResetHighWater: m.reset}
		if interrupted {
			state.ResetHighWater = m.reset - 1 // the interrupted reset may be applied again
		}
	}
	next, err := Step(t, state, now, record)
	if err != nil {
		return State{}, err
	}
	if !m.activated || m.reset != next.ResetHighWater {
		if err = writeDurably(s.root, markerFile, marker{true, next.ResetHighWater}.bytes()); err != nil {
			return State{}, err
		}
	}
	raw, _ := json.Marshal(next)
	if err = writeDurably(s.root, stateFile, raw); err != nil {
		return State{}, err
	}
	return next, nil
}

// openDir opens the state directory and checks the directory it actually opened: broker-owned
// and not group- or world-writable, and the same directory a link-free lookup of the path names.
func openDir(dir string) (*os.Root, error) {
	before, err := os.Lstat(dir)
	if err != nil || !before.IsDir() {
		return nil, RefuseState
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, RefuseState
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) || !owned(opened) || opened.Mode().Perm()&0022 != 0 {
		root.Close()
		return nil, RefuseState
	}
	return root, nil
}

func owned(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Getuid())
}

// readPrivate opens name without following a link and checks and reads that one open file, so
// nothing can be swapped in between the check and the read.
func readPrivate(root *os.Root, name string) ([]byte, error) {
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return nil, RefuseState
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, RefuseState
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !owned(info) || info.Mode().Perm()&0077 != 0 || !ok || stat.Nlink != 1 || info.Size() > 4096 {
		return nil, RefuseState
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) > 4096 {
		return nil, RefuseState
	}
	return raw, nil
}

// writeDurably replaces name with data: a fresh temporary file, fsync, rename, then a directory
// fsync, so a crash leaves either the old file or the new one.
func writeDurably(root *os.Root, name string, data []byte) error {
	temporary := name + ".tmp"
	if err := root.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	err = errors.Join(err, file.Sync(), file.Close())
	if err == nil {
		err = root.Rename(temporary, name)
	}
	if err != nil {
		return err
	}
	return syncDirectory(root)
}

// syncDirectory flushes the directory's entries. load calls it before trusting anything it reads,
// so a rename whose directory sync failed is never used before it is durable. A test replaces it.
var syncDirectory = func(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
