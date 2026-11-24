// jade:ring local
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStagingDirectoryBudgetsBeforeArchiveOpen(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		files   []artifact
		failure string
	}{
		{name: "depth", files: []artifact{{Path: strings.Repeat("a/", 16) + "file"}}, failure: "path depth"},
		{name: "directories", files: func() []artifact {
			var files []artifact
			for i := 0; i < 3000; i++ {
				files = append(files, artifact{Path: fmt.Sprintf("d%d/sub/file", i)})
			}
			return files
		}(), failure: "directory budget"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := stageArchive(root, filepath.Join(root, "absent.tar"), manifest{Artifacts: test.files})
			if err == nil || !strings.Contains(err.Error(), test.failure) {
				t.Fatalf("expected budget refusal before archive access, got %v", err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatalf("budget refusal created output: %v %v", entries, err)
			}
		})
	}
}
