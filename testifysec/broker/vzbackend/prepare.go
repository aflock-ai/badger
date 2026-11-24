package vzbackend

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Verifier struct{ assignment Assignment }

func New(a Assignment) (*Verifier, error) {
	if err := validateAssignment(a); err != nil {
		return nil, err
	}
	return &Verifier{a}, nil
}

// Prepared owns one private, fresh backend stage. Run consumes it once; paths
// remain private. Close cancels an active run and waits for its cleanup facts.
type Prepared struct {
	mu              sync.Mutex
	once            sync.Once
	parent          *custody
	root            *os.Root
	info            os.FileInfo
	name            string
	path            string
	observation     Observation
	notBefore       time.Time
	expires         time.Time
	ctx             context.Context
	cancel          context.CancelFunc
	closed          bool
	closeErr        error
	assignment      Assignment
	envelope        []byte
	runDone         chan struct{}
	runUnsafe       bool
	runStage        *Prepared
	ownedNames      []string
	runInputs       []role
	runConfigSHA256 string
}

func newStage(ctx context.Context, path string) (p *Prepared, resultErr error) {
	c, err := openCustody(path, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, c.close())
		}
	}()
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	name := "vz-" + hex.EncodeToString(random[:])
	if err = c.root().Mkdir(name, 0700); err != nil {
		return nil, err
	}
	root, err := c.root().OpenRoot(name)
	if err != nil {
		return nil, errors.Join(err, errCleanup)
	}
	info, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, errors.Join(err, errCleanup)
	}
	local, cancel := context.WithCancel(ctx)
	return &Prepared{parent: c, root: root, info: info, name: name, path: filepath.Join(path, name), ctx: local, cancel: cancel}, nil
}
func (v *Verifier) Prepare(ctx context.Context, envelope []byte) (_ *Prepared, resultErr error) {
	if ctx.Err() != nil {
		return nil, refused("cancelled")
	}
	if len(envelope) == 0 || len(envelope) > EnvelopeLimit {
		return nil, refused("profile_invalid")
	}
	envelope = append([]byte(nil), envelope...)
	p, err := newStage(ctx, v.assignment.StagingDirectory)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			if errors.Is(resultErr, errCleanup) {
				resultErr = errors.Join(resultErr, p.retain())
			} else {
				resultErr = errors.Join(resultErr, p.Close())
			}
		}
	}()
	admitted, err := v.admit(ctx, envelope, p.path)
	if err != nil {
		return nil, err
	}
	p.notBefore, p.expires = admitted.notBefore, admitted.expires
	p.assignment = v.assignment
	p.envelope = append([]byte(nil), envelope...)
	if err = v.populate(ctx, p); err != nil {
		return nil, err
	}
	if _, err = p.Inspect(ctx); err != nil {
		return nil, err
	}
	return p, nil
}
func (v *Verifier) populate(ctx context.Context, p *Prepared) (resultErr error) {
	source, err := openCustody(v.assignment.InstallationDirectory, false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, source.close()) }()
	if _, err = inventory(source.root()); err != nil {
		return err
	}
	raw, err := readBounded(ctx, source.root(), "backend.json", ManifestLimit)
	if err != nil {
		return err
	}
	if hash(raw) != v.assignment.ManifestSHA256 {
		return refused("manifest_digest")
	}
	manifest, err := parseManifest(raw)
	if err != nil {
		return err
	}
	p.observation = Observation{v.assignment.ManifestSHA256, v.assignment.ProfileSHA256, manifest.Files}
	if err = writeManifest(p.root, raw); err != nil {
		return err
	}
	for _, r := range roles(manifest.Files) {
		if err = copyRole(ctx, source.root(), p.root, r); err != nil {
			return err
		}
	}
	if _, err = inventory(source.root()); err != nil {
		return err
	}
	return source.check()
}
func writeManifest(root *os.Root, raw []byte) (resultErr error) {
	file, err := root.OpenFile("backend.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	if _, err = file.Write(raw); err != nil {
		return err
	}
	return file.Chmod(0400)
}
func (p *Prepared) check() error {
	if p.closed {
		return refused("prepared_closed")
	}
	if p.ctx.Err() != nil {
		return refused("cancelled")
	}
	now := time.Now()
	if now.Before(p.notBefore) || !now.Before(p.expires) {
		return refused("profile_expired")
	}
	return p.checkDirectory()
}
func (p *Prepared) checkDirectory() error {
	if err := p.parent.check(); err != nil {
		return err
	}
	opened, err := p.root.Stat(".")
	named, e := p.parent.root().Lstat(p.name)
	if err != nil || e != nil || !sameDirectory(p.info, opened) || !sameDirectory(opened, named) {
		return refused("custody_changed")
	}
	return nil
}

// Inspect hashes exact copied bytes again. The observation is diagnostic data,
// not a reusable execution grant; no availability or hardware claim is made.
func (p *Prepared) Inspect(ctx context.Context) (Observation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.runDone != nil {
		return Observation{}, refused("run_consumed")
	}
	return p.inspectLocked(ctx)
}
func (p *Prepared) inspectLocked(ctx context.Context) (Observation, error) {
	if err := p.check(); err != nil {
		return Observation{}, err
	}
	active, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(p.ctx, cancel)
	defer stop()
	if err := p.verifyBackend(active); err != nil {
		return Observation{}, err
	}
	if err := p.check(); err != nil {
		return Observation{}, err
	}
	return p.observation, nil
}

// verifyBackend checks custody and bytes only. Post-run cleanup uses an
// independent bounded context: expiry/cancellation must not skip integrity.
func (p *Prepared) verifyBackend(ctx context.Context) error {
	if err := p.checkDirectory(); err != nil {
		return err
	}
	if _, err := inventory(p.root); err != nil {
		return err
	}
	raw, err := readBounded(ctx, p.root, "backend.json", ManifestLimit)
	if err != nil {
		return err
	}
	if hash(raw) != p.observation.ManifestSHA256 {
		return refused("manifest_digest")
	}
	for _, r := range roles(p.observation.Files) {
		if err = verifyRole(ctx, p.root, r); err != nil {
			return err
		}
	}
	if err = p.checkDirectory(); err != nil {
		return err
	}
	_, err = inventory(p.root)
	return err
}

func (p *Prepared) Close() error { return p.finishClose(false) }

// Retain invalidates the handle and closes descriptors without deleting its
// files. The session service uses this when its gateway/scratch cleanup remains
// uncertain. It returns cleanup_failed and permanently prevents later removal.
func (p *Prepared) Retain() error { return p.finishClose(true) }
func (p *Prepared) retain() error { return p.Retain() }
func (p *Prepared) finishClose(retain bool) error {
	p.once.Do(func() {
		p.cancel()
		p.mu.Lock()
		done := p.runDone
		p.mu.Unlock()
		if done != nil {
			<-done
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		p.closed = true
		retain = retain || p.runUnsafe
		if p.runStage != nil {
			if retain {
				p.closeErr = p.runStage.Retain()
			} else {
				p.closeErr = p.runStage.Close()
			}
			if p.closeErr != nil {
				retain = true
			}
		}
		if retain {
			p.closeErr = errors.Join(p.closeErr, errCleanup)
		} else {
			p.closeErr = errors.Join(p.closeErr, p.remove())
		}
		p.closeErr = errors.Join(p.closeErr, p.root.Close(), p.parent.close())
		if p.closeErr != nil {
			p.closeErr = errors.Join(errCleanup, p.closeErr)
		}
	})
	return p.closeErr
}
func (p *Prepared) remove() error {
	if err := p.checkDirectory(); err != nil {
		return err
	}
	// Unknown content means custody is ambiguous. Retain it for the owning
	// service to inspect; never sweep unrelated paths or recover stale runs.
	names := p.ownedNames
	if names == nil {
		names = backendNames()
	}
	entries, err := inventoryKnown(p.root, false, names)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		info, e := p.root.Lstat(entry.Name())
		if e != nil || !safeFile(info, false) {
			return errCleanup
		}
	}
	for _, entry := range entries {
		if err = p.root.Remove(entry.Name()); err != nil {
			return err
		}
	}
	if err = p.checkDirectory(); err != nil {
		return err
	}
	return p.parent.root().Remove(p.name)
}

func backendNames() []string {
	return []string{"backend.json", "hc-vm", "kernel", "root.ext4", "build.json"}
}
func inventory(root *os.Root) ([]os.DirEntry, error) {
	return inventoryKnown(root, true, backendNames())
}
func inventoryKnown(root *os.Root, complete bool, names []string) ([]os.DirEntry, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := directory.ReadDir(len(names) + 1)
	if err == io.EOF {
		err = nil
	}
	err = errors.Join(err, directory.Close())
	if err != nil {
		return nil, err
	}
	if len(entries) > len(names) || (complete && len(entries) != len(names)) {
		return nil, refused("file_inventory")
	}
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return nil, refused("file_inventory")
		}
	}
	return entries, nil
}
