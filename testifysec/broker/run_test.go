// jade:ring local

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tokenDir(t *testing.T, uid string, files map[string]string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(dir, uid), 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err = os.WriteFile(filepath.Join(dir, uid, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The worker's /run/badger: the admitted envelope and only this caller's connector tokens.
func TestProvisionRun(t *testing.T) {
	scratch, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := policy{ConnectorTokenDir: tokenDir(t, "2001", map[string]string{"jira.token": "jira-secret", "confluence.token": "wiki-secret"})}
	if err = os.Mkdir(filepath.Join(p.ConnectorTokenDir, "2002"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(p.ConnectorTokenDir, "2002", "gitlab.token"), []byte("not yours"), 0600); err != nil {
		t.Fatal(err)
	}
	run, err := provisionRun(p, scratch, `{"payloadType":"test-only"}`, 2001)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"profile/profile.dsse.json": `{"payloadType":"test-only"}`, "tokens/jira.token": "jira-secret", "tokens/confluence.token": "wiki-secret"} {
		info, err := os.Stat(filepath.Join(run, path))
		raw, _ := os.ReadFile(filepath.Join(run, path))
		if err != nil || info.Mode().Perm() != 0444 || string(raw) != want {
			t.Fatalf("%s: %v %v %q", path, err, info, raw)
		}
	}
	if _, err = os.Stat(filepath.Join(run, "tokens", "gitlab.token")); err == nil {
		t.Fatal("another caller's token provisioned")
	}
	config, err := configFor(policy{Limits: limits{WorkspaceMiB: 16}}, "/inputs-src", "/request-src", run, "hash")
	if err != nil {
		t.Fatal(err)
	}
	mounted := false
	for _, m := range config.HostConfig.Mounts {
		mounted = mounted || (m.Source == run && m.Target == "/run/badger" && m.ReadOnly)
	}
	if !mounted {
		t.Fatal("run directory not mounted read-only at /run/badger")
	}
	// A caller with no token directory gets none, and no token directory configured gets none.
	for _, q := range []policy{{ConnectorTokenDir: p.ConnectorTokenDir}, {}} {
		other, _ := filepath.EvalSymlinks(t.TempDir())
		run, err = provisionRun(q, other, "", 2003)
		entries, _ := os.ReadDir(filepath.Join(run, "tokens"))
		if err != nil || len(entries) != 0 {
			t.Fatalf("tokens for a caller without any: %v %d", err, len(entries))
		}
	}
}

func TestProvisionRunRefusesUnsafeTokens(t *testing.T) {
	for name, setup := range map[string]func(dir string){
		"readable by others": func(dir string) { os.Chmod(filepath.Join(dir, "2001", "jira.token"), 0644) },
		"not a token name":   func(dir string) { os.WriteFile(filepath.Join(dir, "2001", "Jira.TOKEN"), []byte("x"), 0600) },
		"symbolic link": func(dir string) {
			os.Remove(filepath.Join(dir, "2001", "jira.token"))
			os.Symlink("/etc/hosts", filepath.Join(dir, "2001", "jira.token"))
		},
		"hard link": func(dir string) { os.Link(filepath.Join(dir, "2001", "jira.token"), filepath.Join(dir, "jira-copy")) },
		"too large": func(dir string) {
			os.WriteFile(filepath.Join(dir, "2001", "jira.token"), []byte(strings.Repeat("x", 65<<10)), 0600)
		},
		"too many": func(dir string) {
			for i := 0; i < 16; i++ {
				os.WriteFile(filepath.Join(dir, "2001", strings.Repeat("a", i+1)+".token"), nil, 0600)
			}
		},
		"wide directory": func(dir string) { os.Chmod(filepath.Join(dir, "2001"), 0777) },
		"wide parent":    func(dir string) { os.Chmod(dir, 0777) },
	} {
		t.Run(name, func(t *testing.T) {
			p := policy{ConnectorTokenDir: tokenDir(t, "2001", map[string]string{"jira.token": "jira-secret"})}
			setup(p.ConnectorTokenDir)
			scratch, _ := filepath.EvalSymlinks(t.TempDir())
			if _, err := provisionRun(p, scratch, "", 2001); failure(err).Code != "unsafe_tokens" && failure(err).Code != "unsafe_path" {
				t.Fatalf("provisioned: %v", err)
			}
		})
	}
}

// Review: a refusal after a token was already copied leaves no token behind.
func TestProvisionRunRemovesTokensOnRefusal(t *testing.T) {
	p := policy{ConnectorTokenDir: tokenDir(t, "2001", map[string]string{"a.token": "copied first", "z.token": "refused"})}
	if err := os.Chmod(filepath.Join(p.ConnectorTokenDir, "2001", "z.token"), 0644); err != nil {
		t.Fatal(err)
	}
	scratch, _ := filepath.EvalSymlinks(t.TempDir())
	if _, err := provisionRun(p, scratch, "", 2001); failure(err).Code != "unsafe_tokens" {
		t.Fatalf("not refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(scratch, "run", "tokens")); !os.IsNotExist(err) {
		entries, _ := os.ReadDir(filepath.Join(scratch, "run", "tokens"))
		t.Fatalf("tokens left after a refusal: %d", len(entries))
	}
}
