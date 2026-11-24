package vzsession

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

type ownedDirectory struct {
	parent *custody
	root   *os.Root
	info   os.FileInfo
	name   string
	path   string
	files  map[string]string
	socket os.FileInfo
}

func newDirectory(parent, name string) (_ *ownedDirectory, err error) {
	c, err := openCustody(parent, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, c.close())
		}
	}()
	if err = c.root().Mkdir(name, 0700); err != nil {
		return nil, err
	}
	r, err := c.root().OpenRoot(name)
	if err != nil {
		return nil, errors.Join(err, errCleanup)
	}
	info, err := r.Stat(".")
	if err != nil {
		_ = r.Close()
		return nil, errors.Join(err, errCleanup)
	}
	return &ownedDirectory{c, r, info, name, filepath.Join(parent, name), map[string]string{}, nil}, nil
}

func (d *ownedDirectory) check() error {
	if err := d.parent.check(); err != nil {
		return err
	}
	actual, err := d.root.Stat(".")
	named, e := d.parent.root().Lstat(d.name)
	if err != nil || e != nil || !sameDirectory(d.info, actual) || !sameDirectory(actual, named) {
		return refused("session_custody")
	}
	return nil
}

func (d *ownedDirectory) write(name string, raw []byte, mode os.FileMode) error {
	if err := d.check(); err != nil {
		return err
	}
	f, err := d.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(raw)
	err = errors.Join(writeErr, f.Close())
	if err != nil || n != len(raw) {
		return errors.Join(err, errCleanup)
	}
	d.files[name] = hash(raw)
	if err = d.root.Chmod(name, mode); err != nil {
		return err
	}
	return d.check()
}

func (d *ownedDirectory) verify() error {
	if err := d.check(); err != nil {
		return err
	}
	h, err := d.root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := h.ReadDir(len(d.files) + 2)
	_ = h.Close()
	if readErr != nil && readErr != io.EOF {
		return readErr
	}
	if len(entries) > len(d.files)+1 {
		return refused("session_inventory")
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if name == "gateway.sock" {
			if err = d.checkSocket(); err != nil {
				return err
			}
			continue
		}
		digest, ok := d.files[name]
		if !ok {
			return refused("session_inventory")
		}
		raw, e := readFile(d.root, name, 64<<20, name == "gateway", true)
		if e != nil || hash(raw) != digest {
			return refused("session_file_changed")
		}
		seen[name] = true
	}
	if len(seen) != len(d.files) {
		return refused("session_inventory")
	}
	return d.check()
}

func (d *ownedDirectory) checkSocket() error {
	actual, err := d.root.Lstat("gateway.sock")
	if err != nil || d.socket == nil || actual.Mode()&os.ModeSocket == 0 || !os.SameFile(actual, d.socket) {
		return refused("session_socket_changed")
	}
	return nil
}

// Remove only positively identified files after the VM and gateway have stopped.
// Any unexpected replacement or unknown entry causes retention.
func (d *ownedDirectory) remove() error {
	if err := d.verify(); err != nil {
		return errors.Join(err, errCleanup)
	}
	for name := range d.files {
		if err := d.root.Remove(name); err != nil {
			return errors.Join(err, errCleanup)
		}
	}
	if info, err := d.root.Lstat("gateway.sock"); err == nil {
		if d.socket == nil || !os.SameFile(info, d.socket) {
			return errCleanup
		}
		if err = d.root.Remove("gateway.sock"); err != nil {
			return errors.Join(err, errCleanup)
		}
	} else if !os.IsNotExist(err) {
		return errors.Join(err, errCleanup)
	}
	if err := d.check(); err != nil {
		return errors.Join(err, errCleanup)
	}
	return d.parent.root().Remove(d.name)
}

func (d *ownedDirectory) close() error { return errors.Join(d.root.Close(), d.parent.close()) }

func gatewayBytes(path string) ([]byte, error) {
	c, err := openCustody(filepath.Dir(path), false)
	if err != nil {
		return nil, err
	}
	defer c.close()
	raw, err := readFile(c.root(), filepath.Base(path), 64<<20, true, false)
	if err != nil {
		return nil, err
	}
	if err = c.check(); err != nil {
		return nil, err
	}
	return raw, nil
}
