package vzsession

import (
	"context"
	"encoding/base64"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/aflock-ai/badger/testifysec/broker/vzbackend"
)

// Snapshot data is read through directory handles and included in the exact job
// bytes. No mutable workspace directory is ever mounted into the VM.
func snapshot(ctx context.Context, source string) ([]vzbackend.RunMaterial, error) {
	c, err := openCustody(source, false)
	if err != nil {
		return nil, err
	}
	defer c.close()
	s := snapshotState{ctx: ctx, files: []vzbackend.RunMaterial{}, names: map[string]string{}}
	if err = s.directory(c.root(), "", 0); err != nil {
		return nil, err
	}
	if err = c.check(); err != nil {
		return nil, err
	}
	sort.Slice(s.files, func(i, j int) bool { return s.files[i].Path < s.files[j].Path })
	return s.files, nil
}

type snapshotState struct {
	ctx     context.Context
	files   []vzbackend.RunMaterial
	names   map[string]string
	entries int
	bytes   int64
}

func (s *snapshotState) directory(root *os.Root, prefix string, depth int) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if depth > 32 {
		return refused("workspace_depth")
	}
	before, err := root.Stat(".")
	if err != nil {
		return err
	}
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, e := f.ReadDir(257 - s.entries)
	closeErr := f.Close()
	if e != nil && e != io.EOF {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	s.entries += len(entries)
	if s.entries > 256 {
		return refused("workspace_entries")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if err = s.ctx.Err(); err != nil {
			return err
		}
		if entry.Name() == ".git" {
			continue
		}
		if err = s.entry(root, entry.Name(), prefix, depth); err != nil {
			return err
		}
	}
	after, err := root.Stat(".")
	if err != nil || !stableFile(before, after) {
		return refused("workspace_changed")
	}
	return nil
}

func (s *snapshotState) entry(root *os.Root, name, prefix string, depth int) error {
	relative := prefix + name
	if !portable(relative) {
		return refused("workspace_path")
	}
	key := strings.ToLower(relative)
	if _, exists := s.names[key]; exists {
		return refused("workspace_alias")
	}
	s.names[key] = relative
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return s.descend(root, name, relative, depth, info)
	}
	return s.file(root, name, relative, info)
}

func (s *snapshotState) descend(root *os.Root, name, relative string, depth int, info os.FileInfo) error {
	if !safeDirectory(info) {
		return refused("workspace_directory")
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return err
	}
	defer child.Close()
	actual, err := child.Stat(".")
	if err != nil || !sameDirectory(info, actual) {
		return refused("workspace_changed")
	}
	if err = s.directory(child, relative+"/", depth+1); err != nil {
		return err
	}
	named, err := root.Lstat(name)
	if err != nil || !sameDirectory(info, named) {
		return refused("workspace_changed")
	}
	return nil
}

func (s *snapshotState) file(root *os.Root, name, relative string, info os.FileInfo) error {
	if len(s.files) >= 128 || !safeFile(info, false) || info.Size() > 64<<10 || info.Size()+s.bytes > 256<<10 {
		return refused("workspace_file")
	}
	raw, err := readFile(root, name, 64<<10, false, false)
	if err != nil {
		return err
	}
	current, err := root.Lstat(name)
	if err != nil || !stableFile(info, current) {
		return refused("workspace_changed")
	}
	s.bytes += int64(len(raw))
	if s.bytes > 256<<10 {
		return refused("workspace_bytes")
	}
	s.files = append(s.files, vzbackend.RunMaterial{Path: relative, SHA256: hash(raw), Size: int64(len(raw)), Executable: info.Mode().Perm()&0111 != 0, ContentBase64: base64.StdEncoding.EncodeToString(raw)})
	return nil
}

func portable(name string) bool {
	if name == "" || len(name) > 1024 || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.ContainsAny(name, `\:*?"<>|`) {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 32 {
		return false
	}
	for _, part := range parts {
		if !portablePart(part) {
			return false
		}
	}
	return true
}

func portablePart(part string) bool {
	if part == "" || part == "." || part == ".." || len(part) > 255 || strings.TrimRight(part, ". ") != part {
		return false
	}
	for _, r := range part {
		if r < 32 || r >= 127 {
			return false
		}
	}
	lower := strings.ToLower(part)
	if lower == ".git" || strings.HasPrefix(lower, "git~") {
		return false
	}
	stem, _, _ := strings.Cut(lower, ".")
	return !reservedDevice(stem)
}

func reservedDevice(stem string) bool {
	return stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" || len(stem) == 4 && (strings.HasPrefix(stem, "com") || strings.HasPrefix(stem, "lpt")) && stem[3] >= '0' && stem[3] <= '9'
}
