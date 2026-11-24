// jade:ring local

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestStrictAdmissionRejectsAmbiguousAndLossyJSON(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate":     `{"schema":"one","schema":"two"}`,
		"case alias":    `{"schema":"one","Schema":"two"}`,
		"surrogate":     `{"command":"\ud800"}`,
		"low surrogate": `{"command":"\udc00"}`,
		"null string":   `{"command":null}`,
		"unknown":       `{"mounts":[]}`,
		"trailing":      `{} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			var request executionRequest
			if err := strict([]byte(raw), &request); err == nil {
				t.Fatal("ambiguous request admitted")
			}
		})
	}
	var valid executionRequest
	if err := strict([]byte(`{"schema":"testifysec.hardened-opencode.exec/v1","workspace":"demo","command":"printf '\ud83d\ude00'"}`), &valid); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotLinksAndWideDirectoryFailClosed(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "source")
	os.Mkdir(source, 0700)
	secret := filepath.Join(root, "secret")
	os.WriteFile(secret, []byte("outside source"), 0600)
	link := filepath.Join(source, "escape")
	os.Symlink(secret, link)
	limit := limits{WorkspaceFiles: 4, WorkspaceBytes: 1024}
	if _, err = snapshot(context.Background(), source, filepath.Join(root, "symlink-copy"), limit); err == nil {
		t.Fatal("source symlink admitted")
	}
	os.Remove(link)
	os.Link(secret, link)
	if _, err = snapshot(context.Background(), source, filepath.Join(root, "hardlink-copy"), limit); err == nil {
		t.Fatal("source hardlink admitted")
	}
	os.Remove(link)
	for _, name := range []string{"one", "two", "three", "four", "five"} {
		os.WriteFile(filepath.Join(source, name), nil, 0600)
	}
	if _, err = snapshot(context.Background(), source, filepath.Join(root, "wide-copy"), limit); err == nil {
		t.Fatal("wide directory exceeded budget without refusal")
	}
}

func TestProfileCannotBeSilentlyIgnoredInDevelopment(t *testing.T) {
	if _, err := verifyAdmission(context.Background(), policy{DevelopmentAllowSameUID: true}, `{"payload":"claimed"}`); err == nil {
		t.Fatal("profile claim silently ignored")
	}
	if _, err := verifyAdmission(context.Background(), policy{}, ""); err == nil {
		t.Fatal("production profile bypass admitted")
	}
}
