package vzsession

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Keep each ancestor open so revalidation follows the same parent descriptors.
type custody struct {
	roots []*os.Root
	infos []os.FileInfo
	names []string
}

func (c *custody) root() *os.Root { return c.roots[len(c.roots)-1] }
func (c *custody) close() error {
	var err error
	for i := len(c.roots) - 1; i >= 0; i-- {
		err = errors.Join(err, c.roots[i].Close())
	}
	return err
}
func safeDirectory(info os.FileInfo) bool {
	uid, _, _, ok := fileIdentity(info)
	return ok && info.IsDir() && (uid == 0 || uid == int64(os.Geteuid())) && (info.Mode().Perm()&0022 == 0 || (uid == 0 && info.Mode()&os.ModeSticky != 0)) && info.Mode()&(os.ModeSetuid|os.ModeSetgid) == 0
}
func sameDirectory(a, b os.FileInfo) bool {
	au, _, _, ao := fileIdentity(a)
	bu, _, _, bo := fileIdentity(b)
	return ao && bo && os.SameFile(a, b) && a.Mode() == b.Mode() && au == bu && safeDirectory(b)
}
func (c *custody) check() error {
	for i, r := range c.roots {
		now, err := r.Stat(".")
		if err != nil || !sameDirectory(c.infos[i], now) {
			return refused("custody_changed")
		}
		if i > 0 {
			named, e := c.roots[i-1].Lstat(c.names[i])
			if e != nil || !sameDirectory(now, named) {
				return refused("custody_changed")
			}
		}
	}
	return nil
}
func openCustody(path string, private bool) (_ *custody, resultErr error) {
	if !absolute(path) {
		return nil, refused("unsafe_directory")
	}
	c := &custody{}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, c.close())
		}
	}()
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	c.roots = append(c.roots, root)
	info, err := root.Stat(".")
	if err != nil || !safeDirectory(info) {
		return nil, refused("unsafe_directory")
	}
	c.infos = append(c.infos, info)
	c.names = append(c.names, "")
	for _, part := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		if err = c.descend(part); err != nil {
			return nil, err
		}
	}
	if private {
		info = c.infos[len(c.infos)-1]
		uid, _, _, ok := fileIdentity(info)
		if !ok || uid != int64(os.Geteuid()) || info.Mode().Perm() != 0700 {
			return nil, refused("unsafe_staging_directory")
		}
	}
	if err = c.check(); err != nil {
		return nil, err
	}
	return c, nil
}
func (c *custody) descend(part string) error {
	before, err := c.root().Lstat(part)
	if err != nil || !safeDirectory(before) {
		return refused("unsafe_directory")
	}
	next, err := c.root().OpenRoot(part)
	if err != nil {
		return err
	}
	opened, err := next.Stat(".")
	after, afterErr := c.root().Lstat(part)
	if err != nil || afterErr != nil || !sameDirectory(before, opened) || !sameDirectory(opened, after) {
		return errors.Join(refused("custody_changed"), next.Close())
	}
	c.roots = append(c.roots, next)
	c.infos = append(c.infos, opened)
	c.names = append(c.names, part)
	return nil
}
func safeFile(info os.FileInfo, executable bool) bool {
	uid, links, _, ok := fileIdentity(info)
	return ok && info.Mode().IsRegular() && (uid == 0 || uid == int64(os.Geteuid())) && links == 1 && info.Mode().Perm()&0022 == 0 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && (!executable || info.Mode().Perm()&0100 != 0)
}
func stableFile(a, b os.FileInfo) bool {
	au, al, ac, ao := fileIdentity(a)
	bu, bl, bc, bo := fileIdentity(b)
	return ao && bo && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime() == b.ModTime() && au == bu && al == bl && ac == bc
}
func openChecked(root *os.Root, name string, executable bool) (*os.File, os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil || !safeFile(before, executable) {
		return nil, nil, refused("unsafe_file")
	}
	file, err := root.OpenFile(name, readFlags(), 0)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	after, e := root.Lstat(name)
	if err != nil || e != nil || !stableFile(before, opened) || !stableFile(opened, after) {
		return nil, nil, errors.Join(refused("file_changed"), file.Close())
	}
	return file, opened, nil
}
func checkFile(root *os.Root, name string, file *os.File, before os.FileInfo) error {
	after, err := file.Stat()
	named, e := root.Lstat(name)
	if err != nil || e != nil || !stableFile(before, after) || !stableFile(after, named) {
		return refused("file_changed")
	}
	return nil
}
