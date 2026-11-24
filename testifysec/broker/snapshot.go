package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// Walk held directory handles from /, refusing static symlinks and checking the
// opened identity at every step. os.Root prevents raced links escaping a handle.
func secureRoot(path string) (*os.Root, error) {
	if !cleanAbsolute(path) {
		return nil, deny("unsafe_path", "Expected clean absolute directory")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		before, err := root.Lstat(part)
		if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			root.Close()
			return nil, deny("unsafe_path", "Directory path contains a link or invalid component")
		}
		next, err := root.OpenRoot(part)
		if err != nil {
			root.Close()
			return nil, err
		}
		after, err := next.Stat(".")
		root.Close()
		if err != nil || !os.SameFile(before, after) {
			next.Close()
			return nil, deny("workspace_changed", "Directory changed during opening")
		}
		root = next
	}
	return root, nil
}
func stable(before, after os.FileInfo) bool {
	return os.SameFile(before, after) && before.Size() == after.Size() && before.ModTime() == after.ModTime() && changeTime(before) == changeTime(after)
}
func snapshot(ctx context.Context, source, destination string, l limits) ([]material, error) {
	root, err := secureRoot(source)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err = os.Mkdir(destination, 0700); err != nil {
		return nil, err
	}
	var materials []material
	var total int64
	entries := 0
	var copyDirectory func(*os.Root, string, string, int) error
	copyDirectory = func(directory *os.Root, target, prefix string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > 64 {
			return deny("workspace_limit", "Workspace nesting exceeds limit")
		}
		before, err := directory.Stat(".")
		if err != nil {
			return err
		}
		handle, err := directory.Open(".")
		if err != nil {
			return err
		}
		names, readErr := handle.ReadDir(l.WorkspaceFiles - entries + 1)
		handle.Close()
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		entries += len(names)
		if entries > l.WorkspaceFiles {
			return deny("workspace_limit", "Workspace entry budget exceeded")
		}
		sort.Slice(names, func(i, j int) bool { return names[i].Name() < names[j].Name() })
		for _, entry := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := entry.Name()
			if name == ".git" {
				continue
			}
			metadata, err := directory.Lstat(name)
			if err != nil {
				return err
			}
			relative := prefix + name
			if !artifactPath(relative) {
				return deny("unsafe_workspace", "Workspace contains an unsafe or nonportable artifact path")
			}
			if metadata.IsDir() {
				child, err := directory.OpenRoot(name)
				if err != nil {
					return err
				}
				opened, err := child.Stat(".")
				if err != nil || !os.SameFile(metadata, opened) {
					child.Close()
					return deny("workspace_changed", "Directory changed during snapshot")
				}
				if err = os.Mkdir(filepath.Join(target, name), 0700); err == nil {
					err = copyDirectory(child, filepath.Join(target, name), relative+"/", depth+1)
				}
				child.Close()
				if err != nil {
					return err
				}
				continue
			}
			stat, ok := metadata.Sys().(*syscall.Stat_t)
			if !metadata.Mode().IsRegular() || !ok || stat.Nlink != 1 {
				return deny("unsafe_workspace", "Workspace contains a link or special file")
			}
			if total+metadata.Size() > l.WorkspaceBytes {
				return deny("workspace_limit", "Workspace byte budget exceeded")
			}
			file, err := directory.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
			if err != nil {
				return err
			}
			opened, err := file.Stat()
			if err != nil || !stable(metadata, opened) || !opened.Mode().IsRegular() || opened.Sys().(*syscall.Stat_t).Nlink != 1 {
				file.Close()
				return deny("workspace_changed", "File changed during opening")
			}
			raw, err := io.ReadAll(io.LimitReader(file, l.WorkspaceBytes-total+1))
			after, statErr := file.Stat()
			file.Close()
			if err != nil {
				return err
			}
			if statErr != nil || !stable(opened, after) {
				return deny("workspace_changed", "File changed during snapshot")
			}
			if int64(len(raw))+total > l.WorkspaceBytes {
				return deny("workspace_limit", "Workspace byte budget exceeded")
			}
			executable := metadata.Mode().Perm()&0111 != 0
			mode := os.FileMode(0644)
			if executable {
				mode = 0755
			}
			if err = os.WriteFile(filepath.Join(target, name), raw, mode); err != nil {
				return err
			}
			total += int64(len(raw))
			materials = append(materials, material{relative, hash(raw), int64(len(raw)), executable})
		}
		after, err := directory.Stat(".")
		if err != nil || !stable(before, after) {
			return deny("workspace_changed", "Directory changed during snapshot")
		}
		return os.Chmod(target, 0755)
	}
	if err = copyDirectory(root, destination, "", 0); err != nil {
		return nil, err
	}
	if materials == nil {
		materials = []material{}
	}
	sort.Slice(materials, func(i, j int) bool { return materials[i].Path < materials[j].Path })
	return materials, nil
}
