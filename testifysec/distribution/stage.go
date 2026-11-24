package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Staging is deliberately separate from promotion. It consumes an already
// admitted manifest and writes only its exact inventory into a new private
// directory. No active symlink, service, rollback floor or executable is changed.
func stageArchive(directory, archive string, m manifest) (result string, failure error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return "", errors.New("absolute clean staging root required")
	}
	root, err := protectedRoot(directory)
	if err != nil {
		return "", err
	}
	defer root.Close()
	info, err := root.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("private staging root required")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return "", errors.New("staging root must belong to the service user")
	}
	parents := map[string]bool{}
	for _, file := range m.Artifacts {
		parts := strings.Split(file.Path, "/")
		if len(parts) > 16 {
			return "", errors.New("staged path depth exceeded")
		}
		for i := 1; i < len(parts); i++ {
			parents[strings.Join(parts[:i], "/")] = true
		}
	}
	if len(parents) > 4096 {
		return "", errors.New("staged directory budget exceeded")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	name := ".staging-" + hex.EncodeToString(nonce[:])
	if err := root.Mkdir(name, 0700); err != nil {
		return "", err
	}
	complete := false
	defer func() {
		if !complete {
			failure = errors.Join(failure, root.RemoveAll(name))
		}
	}()
	destination, err := root.OpenRoot(name)
	if err != nil {
		return "", err
	}
	defer destination.Close()
	f, err := regularFile(archive)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := consumeArchive(f, m, destination); err != nil {
		return "", err
	}
	// Persist directory entries from the deepest directory outward. A staging
	// result is returned only after all bytes and their containing directories sync.
	if err := syncTree(destination, "."); err != nil {
		return "", err
	}
	// Rename to a random result name only after complete verification. Both names
	// stay under the held root; only the trusted service UID can mutate that root.
	final := "bundle-" + hex.EncodeToString(nonce[:])
	if _, err := root.Lstat(final); !os.IsNotExist(err) {
		return "", errors.New("staging destination already exists")
	}
	if err := root.Rename(name, final); err != nil {
		return "", err
	}
	name = final
	parent, err := root.Open(".")
	if err != nil {
		return "", err
	}
	syncErr := parent.Sync()
	closeErr := parent.Close()
	if err := errors.Join(syncErr, closeErr); err != nil {
		return "", err
	}
	complete = true
	return filepath.Join(directory, name), nil
}

// Walk from a held filesystem root and validate each directory before opening
// its child. Only root/the service UID may rename ancestors. Root-owned sticky
// temporary directories are allowed because they protect the next owned entry.
func protectedRoot(directory string) (*os.Root, error) {
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(directory, "/"), "/") {
		info, err := root.Lstat(part)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			root.Close()
			return nil, errors.New("invalid staging ancestor")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) ||
			(info.Mode().Perm()&0022 != 0 && !(owner.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
			root.Close()
			return nil, errors.New("unprotected staging ancestor")
		}
		child, err := root.OpenRoot(part)
		root.Close()
		if err != nil {
			return nil, err
		}
		current, err := child.Stat(".")
		if err != nil || !os.SameFile(info, current) {
			child.Close()
			return nil, errors.New("staging ancestor changed")
		}
		root = child
	}
	return root, nil
}

func syncTree(root *os.Root, name string) error {
	dir, err := root.Open(name)
	if err != nil {
		return err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			if err := syncTree(root, filepath.Join(name, entry.Name())); err != nil {
				return err
			}
		}
	}
	return dir.Sync()
}
