package activation

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func refused(t *testing.T, err error, want Refusal) {
	t.Helper()
	var got Refusal
	if !errors.As(err, &got) || got != want {
		t.Fatalf("got %v, want refusal %s", err, want)
	}
}

func installed(t *testing.T) (string, *Store) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = Install(dir); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir, State{ProfileHighWater: 10, ActivationHighWater: 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return dir, store
}

func TestStoreHighWaterSurvivesAndRatchets(t *testing.T) {
	root := newRoot(t, "enclave root")
	trust := trustFor(root)
	leaf := signer{issuer: root, notBefore: -86400, last: 6 * 86400, san: portalSAN}
	dir, store := installed(t)
	// Fresh install: the compiled floor once.
	if s, err := store.Load(); err != nil || s.ActivationHighWater != 20 || s.ProfileSHA256 != "" {
		t.Fatalf("fresh state %+v %v", s, err)
	}
	refused(t, applyAt(store, trust, envelope(t, ActivationType, activationBody(20, 10, 1, -60, 3600), leaf)), RefuseRollback)
	first := envelope(t, ActivationType, activationBody(21, 10, 1, -60, 3600), leaf)
	if s, err := store.Apply(trust, first, now); err != nil || s.ProfileSHA256 != digestOf(1) || s.ActivationHighWater != 21 {
		t.Fatalf("first activation %+v %v", s, err)
	}
	onDisk, _ := os.ReadFile(filepath.Join(dir, stateFile))
	// Replay, and rollback to an older activation, change nothing on disk.
	refused(t, applyAt(store, trust, first), RefuseRollback)
	refused(t, applyAt(store, trust, envelope(t, ActivationType, activationBody(21, 11, 2, -60, 3600), leaf)), RefuseRollback)
	if again, _ := os.ReadFile(filepath.Join(dir, stateFile)); string(again) != string(onDisk) {
		t.Fatal("a refused record changed the state file")
	}
	// A reopened store reads the same counters: the high-water is not process memory.
	reopened, err := Open(dir, State{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if s, err := reopened.Load(); err != nil || s.ActivationHighWater != 21 || s.ProfileSHA256 != digestOf(1) {
		t.Fatalf("reopened %+v %v", s, err)
	}
	if s, err := reopened.Apply(trust, envelope(t, ActivationType, activationBody(22, 12, 3, -60, 3600), leaf), now); err != nil || s.ProfileHighWater != 12 {
		t.Fatalf("next activation %+v %v", s, err)
	}
}

// Deleting the state file after the first activation does not reset the counters: the device
// fails closed until a reset record for its own key, and never falls back to the compiled floor.
func TestStoreFailsClosedWithoutState(t *testing.T) {
	root := newRoot(t, "enclave root")
	trust := trustFor(root)
	leaf := signer{issuer: root, notBefore: -86400, last: 6 * 86400, san: portalSAN}
	dir, store := installed(t)
	if _, err := store.Apply(trust, envelope(t, ActivationType, activationBody(30, 10, 1, -60, 3600), leaf), now); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, stateFile)); err != nil {
		t.Fatal(err)
	}
	_, err := store.Load()
	refused(t, err, RefuseState)
	// The old floor's activation 21, valid and signed, is not admitted.
	refused(t, applyAt(store, trust, envelope(t, ActivationType, activationBody(21, 10, 9, -60, 3600), leaf)), RefuseState)
	refused(t, applyAt(store, trust, envelope(t, ResetType, resetBody(9, 1, 10, 30, -60, 3600), leaf)), RefuseAssignment)
	refused(t, applyAt(store, trust, envelope(t, ResetType, resetBody(7, 1, 10, 30, -60, 3600), signer{issuer: newRoot(t, "other"),
		notBefore: -86400, last: 6 * 86400, san: portalSAN})), RefuseChain)
	reset := envelope(t, ResetType, resetBody(7, 1, 10, 30, -60, 3600), leaf)
	if s, err := store.Apply(trust, reset, now); err != nil || s.ActivationHighWater != 30 || s.ResetHighWater != 1 || s.ProfileSHA256 != "" {
		t.Fatalf("reset %+v %v", s, err)
	}
	refused(t, applyAt(store, trust, reset), RefuseRollback) // a consumed reset does not replay
	refused(t, applyAt(store, trust, envelope(t, ActivationType, activationBody(30, 10, 9, -60, 3600), leaf)), RefuseRollback)
	if _, err := store.Apply(trust, envelope(t, ActivationType, activationBody(31, 10, 9, -60, 3600), leaf), now); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRefusesUninstalledAndUnsafeState(t *testing.T) {
	root := newRoot(t, "enclave root")
	trust := trustFor(root)
	record := envelope(t, ActivationType, activationBody(21, 10, 1, -60, 3600), signer{issuer: root, notBefore: -86400, last: 6 * 86400, san: portalSAN})
	dir, store := installed(t)
	if err := os.Remove(filepath.Join(dir, markerFile)); err != nil {
		t.Fatal(err)
	}
	refused(t, applyAt(store, trust, record), RefuseState) // no marker: not installed
	_, store = installed(t)
	if _, err := store.Apply(trust, record, now); err != nil {
		t.Fatal(err)
	}
	dir, store = installed(t)
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(`{"profileHighWater":0,"activationHighWater":0,"resetHighWater":0,"profileSha256":""}`), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := store.Load()
	refused(t, err, RefuseState) // readable by others
	wide := t.TempDir()
	if err = os.Chmod(wide, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(wide, State{}); err == nil {
		t.Fatal("a world-writable state directory opened")
	}
}

func applyAt(s *Store, t Trust, raw []byte) error {
	_, err := s.Apply(t, raw, now)
	return err
}

// Codex review of the first version: a consumed reset must not replay after the state is lost a
// second time; a fresh marker left beside state (a crash between two writes) must not let a later
// state deletion restore the floor; and two Stores on one directory must not interleave.
func TestStoreSurvivesCrashesAndSecondLoss(t *testing.T) {
	root := newRoot(t, "enclave root")
	trust := trustFor(root)
	leaf := signer{issuer: root, notBefore: -86400, last: 6 * 86400, san: portalSAN}
	dir, store := installed(t)
	if _, err := store.Apply(trust, envelope(t, ActivationType, activationBody(30, 10, 1, -60, 3600), leaf), now); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, stateFile)
	reset := envelope(t, ResetType, resetBody(7, 1, 10, 25, -60, 3600), leaf)
	for loss := 1; loss <= 2; loss++ {
		if err := os.Remove(state); err != nil {
			t.Fatal(err)
		}
		_, err := store.Apply(trust, reset, now)
		if loss == 1 && err != nil {
			t.Fatalf("first reset after a loss: %v", err)
		}
		if loss == 2 {
			refused(t, err, RefuseRollback) // the marker remembers reset 1
		}
	}
	// A fresh marker beside committed state, as a crash between the two writes could leave it.
	dir, store = installed(t)
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(`{"profileHighWater":10,"activationHighWater":30,"resetHighWater":0,"profileSha256":"`+digestOf(1)+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := store.Load(); err != nil || s.ActivationHighWater != 30 {
		t.Fatalf("state beside a fresh marker: %+v %v", s, err)
	}
	if err := os.Remove(filepath.Join(dir, stateFile)); err != nil {
		t.Fatal(err)
	}
	_, err := store.Load()
	refused(t, err, RefuseState) // the fresh marker was consumed; no fallback to the floor
}

func TestStoresOnOneDirectorySerialize(t *testing.T) {
	root := newRoot(t, "enclave root")
	trust := trustFor(root)
	leaf := signer{issuer: root, notBefore: -86400, last: 6 * 86400, san: portalSAN}
	dir, first := installed(t)
	second, err := Open(dir, State{})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	unlock, err := second.lock()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := first.Apply(trust, envelope(t, ActivationType, activationBody(21, 10, 1, -60, 3600), leaf), now)
		done <- err
	}()
	select {
	case err = <-done:
		t.Fatalf("committed while another store held the directory: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

// Codex review: an installer that observed no marker before the broker activated must not
// replace the activated marker with a fresh one; Install waits for the lock and then keeps it.
func TestLateInstallKeepsTheActivatedMarker(t *testing.T) {
	root := newRoot(t, "enclave root")
	dir, store := installed(t)
	unlock, err := store.lock()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Install(dir) }()
	select {
	case err = <-done:
		t.Fatalf("installed while the broker held the directory: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	record := envelope(t, ActivationType, activationBody(21, 10, 1, -60, 3600), signer{issuer: root, notBefore: -86400, last: 6 * 86400, san: portalSAN})
	if _, err = store.Apply(trustFor(root), record, now); err != nil {
		t.Fatal(err)
	}
	if err = Install(dir); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(dir, stateFile)); err != nil {
		t.Fatal(err)
	}
	_, err = store.Load()
	refused(t, err, RefuseState) // still activated: no floor after a second install
}

// Codex review: a read that returns bytes and an error is a failed read, even when the bytes are
// valid state.
func TestStoreRefusesStateReadWithError(t *testing.T) {
	_, store := installed(t)
	valid := []byte(`{"profileHighWater":10,"activationHighWater":30,"resetHighWater":0,"profileSha256":""}`)
	store.read = func(root *os.Root, name string) ([]byte, error) {
		if name == stateFile {
			return valid, io.ErrUnexpectedEOF
		}
		return readPrivate(root, name)
	}
	_, err := store.Load()
	refused(t, err, RefuseState)
}

// Codex review: checks and reads go through the opened handles. A link in place of the state
// file or the state directory, or a second hard link to the state, is refused rather than read.
func TestStoreReadsOnlyWhatItChecked(t *testing.T) {
	dir, store := installed(t)
	elsewhere := filepath.Join(t.TempDir(), "forged.json")
	forged := []byte(`{"profileHighWater":0,"activationHighWater":0,"resetHighWater":0,"profileSha256":""}`)
	if err := os.WriteFile(elsewhere, forged, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(dir, stateFile)); err != nil {
		t.Fatal(err)
	}
	_, err := store.Load()
	refused(t, err, RefuseState)
	if err = os.Remove(filepath.Join(dir, stateFile)); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(elsewhere, filepath.Join(dir, stateFile)); err != nil {
		t.Fatal(err)
	}
	_, err = store.Load()
	refused(t, err, RefuseState)
	link := filepath.Join(t.TempDir(), "state-link")
	if err = os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(link, State{}); err == nil {
		t.Fatal("a linked state directory opened")
	}
}

// Codex review: a reset that crashed after its marker write but before its state write leaves the
// marker ahead of the state. The old state's pin and counters must not be used, and only that
// reset (or a later one) re-establishes the device.
func TestStoreFailsClosedOnInterruptedReset(t *testing.T) {
	root := newRoot(t, "enclave root")
	trust := trustFor(root)
	leaf := signer{issuer: root, notBefore: -86400, last: 6 * 86400, san: portalSAN}
	_, store := installed(t)
	if _, err := store.Apply(trust, envelope(t, ActivationType, activationBody(30, 10, 1, -60, 3600), leaf), now); err != nil {
		t.Fatal(err)
	}
	// The crash: the reset's marker (reset 1) is written, the state still says reset 0.
	if err := writeDurably(store.root, markerFile, marker{activated: true, reset: 1}.bytes()); err != nil {
		t.Fatal(err)
	}
	_, err := store.Load()
	refused(t, err, RefuseState)
	refused(t, applyAt(store, trust, envelope(t, ActivationType, activationBody(31, 10, 2, -60, 3600), leaf)), RefuseState)
	if s, err := store.Apply(trust, envelope(t, ResetType, resetBody(7, 1, 10, 100, -60, 3600), leaf), now); err != nil || s.ActivationHighWater != 100 || s.ResetHighWater != 1 {
		t.Fatalf("retrying the interrupted reset: %+v %v", s, err)
	}
	refused(t, applyAt(store, trust, envelope(t, ActivationType, activationBody(31, 10, 2, -60, 3600), leaf)), RefuseRollback)
}

// Review: if the directory sync after the state's rename fails, the new state is visible but not
// durable. Apply fails, nothing loads it while syncs fail, and it is used only once a directory
// sync has succeeded (then it is durable).
func TestStoreTrustsNothingBeforeTheDirectoryIsDurable(t *testing.T) {
	root := newRoot(t, "enclave root")
	trust := trustFor(root)
	leaf := signer{issuer: root, notBefore: -86400, last: 6 * 86400, san: portalSAN}
	dir, store := installed(t)
	real := syncDirectory
	defer func() { syncDirectory = real }()
	calls := 0
	syncDirectory = func(r *os.Root) error {
		calls++
		if calls >= 3 { // load, then the marker's write, then the state's write fails
			return io.ErrShortWrite
		}
		return real(r)
	}
	if _, err := store.Apply(trust, envelope(t, ActivationType, activationBody(21, 10, 1, -60, 3600), leaf), now); err == nil {
		t.Fatal("applied without a durable directory")
	}
	if _, err := os.Stat(filepath.Join(dir, stateFile)); err != nil {
		t.Fatalf("the test did not reach the rename: %v", err)
	}
	_, err := store.Load()
	refused(t, err, RefuseState)
	syncDirectory = real
	if s, err := store.Load(); err != nil || s.ActivationHighWater != 21 {
		t.Fatalf("after a good sync: %+v %v", s, err)
	}
}
