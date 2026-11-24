package main

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/badger/testifysec/jade/core"
)

const manifest = `{"steps":[
 {"name":"build","mode":"run","argv":["sh","-c","exit 0"],"attestors":["git"]},
 {"name":"vulns","mode":"run","argv":["sh","-c","exit 0"],"needs":["build"]},
 {"name":"push-metadata","mode":"attest","argv":[],"attestors":["git","alps-evidence"]}]}`

// TestMain builds jade once: cilock runs it as each step's guard (jade step-guard), so a test
// that runs steps needs the real binary, not the test binary os.Executable would name.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "jade-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bin := filepath.Join(dir, "jade")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build jade: %v\n%s", err, out)
		os.Exit(1)
	}
	self = func() (string, error) { return bin, nil }
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// repo makes a committed git repository with a manifest, and returns its path.
func repo(t *testing.T, m string) string {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) {
		c := exec.Command("git", append([]string{"-c", "commit.gpgsign=false", "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q", "-b", "main")
	if err := os.MkdirAll(filepath.Join(dir, ".jade"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".jade", "workspace.json"), []byte(m), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-m", "init")
	return dir
}

func jade(t *testing.T, dir string, args ...string) (int, map[string]any, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, dir, &out, &errb)
	var obj map[string]any
	if strings.Contains(strings.Join(args, " "), "--json") {
		if err := json.Unmarshal(out.Bytes(), &obj); err != nil {
			t.Fatalf("--json must print exactly one JSON object; got %q (%v)", out.String(), err)
		}
	}
	return code, obj, out.String() + errb.String()
}

func TestPlanJSON(t *testing.T) {
	dir := repo(t, manifest)
	code, obj, _ := jade(t, dir, "plan", "--json", "--only", "vulns")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	steps := obj["steps"].([]any)
	if len(steps) != 2 || steps[0].(map[string]any)["name"] != "build" || steps[1].(map[string]any)["name"] != "vulns" {
		t.Fatalf("plan: %v", steps)
	}
	argv := steps[1].(map[string]any)["argv"].([]any)
	if argv[1] != "run" || argv[len(argv)-1] != "exit 0" {
		t.Fatalf("the plan shows the exact cilock argv: %v", argv)
	}
	if obj["schema_version"] != float64(1) {
		t.Fatalf("schema_version: %v", obj["schema_version"])
	}
}

func TestQuery(t *testing.T) {
	dir := repo(t, manifest)
	_, obj, _ := jade(t, dir, "query", "needs", "vulns", "--json")
	if got := obj["steps"].([]any); len(got) != 1 || got[0] != "build" {
		t.Fatalf("needs vulns: %v", got)
	}
	_, obj, _ = jade(t, dir, "query", "rdeps", "build", "--json")
	if got := obj["steps"].([]any); len(got) != 1 || got[0] != "vulns" {
		t.Fatalf("rdeps build: %v", got)
	}
	_, obj, _ = jade(t, dir, "query", "steps", "--json")
	if got := obj["steps"].([]any); len(got) != 3 {
		t.Fatalf("steps: %v", got)
	}
}

// Every failure in --json mode is one object with a code, message, remedy and retryable flag,
// and the exit code is from the closed set.
func TestErrorsAreStructured(t *testing.T) {
	dir := repo(t, manifest)
	cases := []struct {
		args []string
		exit int
		code string
	}{
		{[]string{"nope", "--json"}, 2, "usage.command"},
		{[]string{"plan", "--json", "--only", "nope"}, 2, "step.unknown"},
		{[]string{"query", "needs", "nope", "--json"}, 2, "step.unknown"},
		{[]string{"plan", "--json", "--bogus"}, 2, "usage.flag"},
	}
	for _, c := range cases {
		code, obj, _ := jade(t, dir, c.args...)
		if code != c.exit {
			t.Errorf("%v: exit %d, want %d", c.args, code, c.exit)
			continue
		}
		e, _ := obj["error"].(map[string]any)
		if e == nil || e["code"] != c.code || e["remedy"] == "" || e["message"] == "" {
			t.Errorf("%v: error %v, want code %s with message and remedy", c.args, obj["error"], c.code)
		}
		if _, ok := e["retryable"]; !ok {
			t.Errorf("%v: no retryable flag", c.args)
		}
	}
}

func TestMissingManifest(t *testing.T) {
	dir := t.TempDir()
	c := exec.Command("git", "init", "-q")
	c.Dir = dir
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	code, obj, _ := jade(t, dir, "plan", "--json")
	if code != 2 || obj["error"].(map[string]any)["code"] != "manifest.missing" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Preflight refuses a dirty tree, before running anything, with exit 3.
func TestMintRefusesDirtyTree(t *testing.T) {
	dir := repo(t, manifest)
	if err := os.WriteFile(filepath.Join(dir, "stray.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	if code != 3 || obj["error"].(map[string]any)["code"] != "preflight.dirty" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
	if ev := obj["evidence"].([]any); len(ev) != 0 {
		t.Fatalf("a refused mint records nothing: %v", ev)
	}
}

// Preflight refuses a subdirectory: a mint there would attest only that subtree.
func TestMintRefusesSubdirectory(t *testing.T) {
	dir := repo(t, manifest)
	sub := filepath.Join(dir, ".jade")
	code, obj, _ := jade(t, sub, "mint", "--json", "--cilock", "/bin/echo")
	if code != 3 || obj["error"].(map[string]any)["code"] != "preflight.not-root" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// With /bin/echo standing in for cilock, a clean mint runs every planned step, logs each to a
// file, and records evidence naming HEAD.
func TestMintRunsPlan(t *testing.T) {
	dir := repo(t, manifest)
	code, obj, all := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo", "--only", "vulns")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, all)
	}
	ev := obj["evidence"].([]any)
	if len(ev) != 2 {
		t.Fatalf("evidence: %v", ev)
	}
	head := obj["head"].(string)
	for _, e := range ev {
		if e.(map[string]any)["commit"] != head {
			t.Fatalf("evidence names %v, not HEAD %s", e, head)
		}
	}
	logs := obj["logs"].(map[string]any)
	b, err := os.ReadFile(logs["vulns"].(string))
	if err != nil || !strings.Contains(string(b), "run --step vulns") {
		t.Fatalf("the vulns log holds the step's output: %q %v", b, err)
	}
}

// Codex on #27: log files are named by jade, inside its own log directory, whatever the step is called.
func TestMintLogsStayInLogDir(t *testing.T) {
	dir := repo(t, manifest)
	_, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	logs := obj["logs"].(map[string]any)
	var logDir string
	for name, p := range logs {
		path := p.(string)
		if strings.Contains(filepath.Base(path), name) && name != "build" && name != "vulns" && name != "push-metadata" {
			t.Fatalf("log for %s named from the step: %s", name, path)
		}
		if logDir == "" {
			logDir = filepath.Dir(path)
		}
		if filepath.Dir(path) != logDir {
			t.Fatalf("logs in different directories: %v", logs)
		}
	}
}

// A failing step exits 1 and names the step and its log.
func TestMintStepFails(t *testing.T) {
	dir := repo(t, manifest)
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/usr/bin/false")
	if code != 1 || obj["error"].(map[string]any)["code"] != "step.failed" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
	if !strings.Contains(obj["error"].(map[string]any)["message"].(string), "build") {
		t.Fatalf("the error names the failing step: %v", obj["error"])
	}
}

// Codex on #27: a tracked file hidden from git status by skip-worktree or assume-unchanged is a
// concealed change, and the mint refuses it, the manifest included.
func TestMintRefusesHiddenChanges(t *testing.T) {
	for _, flag := range []string{"--skip-worktree", "--assume-unchanged"} {
		dir := repo(t, manifest)
		noop := `{"steps":[{"name":"build","mode":"run","argv":["true"]}]}`
		if err := os.WriteFile(filepath.Join(dir, ".jade", "workspace.json"), []byte(noop), 0o644); err != nil {
			t.Fatal(err)
		}
		c := exec.Command("git", "update-index", flag, ".jade/workspace.json")
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", flag, err, out)
		}
		code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
		if code != 3 || obj["error"].(map[string]any)["code"] != "preflight.hidden" {
			t.Fatalf("%s: exit %d obj %v", flag, code, obj)
		}
	}
}

// Codex on #27: the mint is bound to one commit. The manifest is read from the commit HEAD named
// when the mint began, and a checkout after that is refused before any step runs.
func TestMintBindsManifestToStartingCommit(t *testing.T) {
	dir := repo(t, manifest)
	git := func(args ...string) string {
		c := exec.Command("git", append([]string{"-c", "commit.gpgsign=false", "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...)
		c.Dir = dir
		out, err := c.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	first := git("rev-parse", "HEAD")
	git("commit", "-q", "--allow-empty", "-m", "second")
	// The mint pinned the first commit, then someone checked out the second.
	m, _, e := manifestAt(dir, first)
	if e != nil {
		t.Fatal(e)
	}
	g := &gitRunner{root: dir, wd: dir, cilock: "/bin/echo", logDir: t.TempDir(), logs: map[string]string{}, head: first}
	res := core.Mint(m, nil, g)
	if res.Exit != 3 || res.Error.Code != "head.moved" || len(res.Evidence) != 0 {
		t.Fatalf("exit %d error %v evidence %v", res.Exit, res.Error, res.Evidence)
	}
	if len(g.logs) != 0 {
		t.Fatalf("no step may run: %v", g.logs)
	}
}

// gitIn runs git in dir with a fixed identity and returns its trimmed output.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := exec.Command("git", append([]string{"-c", "commit.gpgsign=false", "-c", "user.name=t", "-c", "user.email=t@t",
		"-c", "protocol.file.allow=always"}, args...)...)
	c.Dir = dir
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// Codex on #27: a replace ref can swap the HEAD commit's tree while rev-parse HEAD still names
// the original. jade reads git with replacements off, so the swapped checkout is a dirty tree.
func TestMintIgnoresReplaceRefs(t *testing.T) {
	dir := repo(t, manifest)
	orig := gitIn(t, dir, "rev-parse", "HEAD")
	noop := `{"steps":[{"name":"build","mode":"run","argv":["true"]}]}`
	if err := os.WriteFile(filepath.Join(dir, ".jade", "workspace.json"), []byte(noop), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "commit", "-q", "-am", "noop")
	swapped := gitIn(t, dir, "rev-parse", "HEAD")
	gitIn(t, dir, "replace", orig, swapped)
	gitIn(t, dir, "reset", "-q", "--hard", orig)
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	if code != 3 || obj["error"].(map[string]any)["code"] != "preflight.dirty" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
	if ev := obj["evidence"].([]any); len(ev) != 0 {
		t.Fatalf("a replaced checkout records nothing: %v", ev)
	}
}

// Codex on #27: a file hidden from git status inside a submodule is refused too.
func TestMintRefusesHiddenChangesInSubmodules(t *testing.T) {
	sub := t.TempDir()
	gitIn(t, sub, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(sub, "check.sh"), []byte("exit 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, sub, "add", ".")
	gitIn(t, sub, "commit", "-q", "-m", "check")
	dir := repo(t, manifest)
	gitIn(t, dir, "submodule", "add", "-q", sub, "sub")
	gitIn(t, dir, "commit", "-q", "-m", "sub")
	if err := os.WriteFile(filepath.Join(dir, "sub", "check.sh"), []byte("exit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, filepath.Join(dir, "sub"), "update-index", "--assume-unchanged", "check.sh")
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	if code != 3 || obj["error"].(map[string]any)["code"] != "preflight.hidden" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: a submodule path is data, never code. One named to inject a sed command is
// still checked, and nothing it names runs.
func TestSubmoduleNameIsNotCode(t *testing.T) {
	sub := t.TempDir()
	gitIn(t, sub, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(sub, "check.sh"), []byte("exit 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, sub, "add", ".")
	gitIn(t, sub, "commit", "-q", "-m", "check")
	dir := repo(t, manifest)
	name := `x#;e touch JADE_PWNED #`
	gitIn(t, dir, "submodule", "add", "-q", sub, name)
	gitIn(t, dir, "commit", "-q", "-m", "sub")
	if err := os.WriteFile(filepath.Join(dir, name, "check.sh"), []byte("exit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, filepath.Join(dir, name), "update-index", "--assume-unchanged", "check.sh")
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e := obj["error"].(map[string]any)
	if code != 3 || e["code"] != "preflight.hidden" || !strings.Contains(e["message"].(string), name+"/check.sh") {
		t.Fatalf("exit %d obj %v", code, obj)
	}
	if _, err := os.Stat(filepath.Join(dir, "JADE_PWNED")); err == nil {
		t.Fatal("a submodule name ran as a command")
	}
}

// Codex on #27: a clean filter can make git status report an edited file as unchanged. jade
// hashes every tracked file's bytes itself, so the edit is found. The control shows git status
// is fooled first, so the test cannot pass for another reason.
func TestMintSeesThroughCleanFilters(t *testing.T) {
	dir := repo(t, manifest)
	if err := os.WriteFile(filepath.Join(dir, "check.sh"), []byte("exit 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", "check.sh")
	gitIn(t, dir, "commit", "-q", "-m", "check")
	if err := os.WriteFile(filepath.Join(dir, ".git", "info", "attributes"), []byte("check.sh filter=hide\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "config", "filter.hide.clean", `sh -c 'cat >/dev/null; printf "exit 1\n"'`)
	if err := os.WriteFile(filepath.Join(dir, "check.sh"), []byte("exit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := gitIn(t, dir, "status", "--porcelain", "--untracked-files=all"); st != "" {
		t.Fatalf("control: the filter should hide the edit from git status, got %q", st)
	}
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.dirty" || !strings.Contains(e["message"].(string), "check.sh") {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: a remedy is a command an agent may run as given, so every path in it is quoted.
func TestRemedyQuotesFileNames(t *testing.T) {
	dir := repo(t, manifest)
	name := "a;id;#"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", name)
	gitIn(t, dir, "commit", "-q", "-m", "odd name")
	gitIn(t, dir, "update-index", "--assume-unchanged", "--", name)
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.hidden" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
	if r := e["remedy"].(string); !strings.Contains(r, "-- 'a;id;#'") {
		t.Fatalf("remedy does not quote the file name after --: %s", r)
	}
}

// Codex on #27: checking the tree never runs a filter the repository's config names. The spy
// filter would create a marker if git ran it; the edit is still found by hashing.
func TestChecksRunNoFilters(t *testing.T) {
	dir := repo(t, manifest)
	marker := filepath.Join(t.TempDir(), "filter-ran")
	if err := os.WriteFile(filepath.Join(dir, "check.sh"), []byte("exit 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", "check.sh")
	gitIn(t, dir, "commit", "-q", "-m", "check")
	if err := os.WriteFile(filepath.Join(dir, ".git", "info", "attributes"), []byte("* filter=spy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "config", "filter.spy.clean", "sh -c 'touch "+marker+"; cat'")
	gitIn(t, dir, "config", "filter.spy.smudge", "sh -c 'touch "+marker+"; cat'")
	if err := os.WriteFile(filepath.Join(dir, "check.sh"), []byte("exit 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"doctor", "--json", "--cilock", "/bin/echo"}, {"mint", "--json", "--cilock", "/bin/echo"}} {
		code, obj, _ := jade(t, dir, args...)
		if code != 3 {
			t.Fatalf("%v: exit %d obj %v", args, code, obj)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("%v ran a configured filter", args)
		}
	}
	// Control: git status does run it.
	gitIn(t, dir, "status", "--porcelain")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("control: git status should have run the spy filter")
	}
}

// Codex on #27: an ignored file is accepted only when a .gitignore committed at the bound commit
// ignores it. A rule in .git/info/exclude, the global excludes file, or an uncommitted .gitignore
// could hide an input the steps read, so a file it ignores is refused.
func TestIgnoredFilesNeedCommittedRules(t *testing.T) {
	setups := map[string]func(dir string){
		"info/exclude": func(dir string) {
			write(t, filepath.Join(dir, "input.sh"), "exit 0\n")
			write(t, filepath.Join(dir, ".git", "info", "exclude"), "input.sh\n")
		},
		"core.excludesFile": func(dir string) {
			ex := filepath.Join(t.TempDir(), "excludes")
			write(t, ex, "input.sh\n")
			gitIn(t, dir, "config", "core.excludesFile", ex)
			write(t, filepath.Join(dir, "input.sh"), "exit 0\n")
		},
		"an uncommitted .gitignore": func(dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "d"), 0o755); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(dir, "d", ".gitignore"), "*\n")
			write(t, filepath.Join(dir, "d", "input.sh"), "exit 0\n")
		},
	}
	for name, setup := range setups {
		dir := repo(t, manifest)
		setup(dir)
		if st := gitIn(t, dir, "status", "--porcelain", "--untracked-files=all"); st != "" {
			t.Fatalf("%s: control: git status should see nothing, got %q", name, st)
		}
		code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
		e, _ := obj["error"].(map[string]any)
		if code != 3 || e == nil || e["code"] != "preflight.dirty" {
			t.Fatalf("%s: exit %d obj %v", name, code, obj)
		}
	}
	// A file a committed .gitignore ignores is fine: build output, caches.
	dir := repo(t, manifest)
	write(t, filepath.Join(dir, ".gitignore"), "out/\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore out")
	if err := os.MkdirAll(filepath.Join(dir, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "out", "bin"), "x")
	if code, obj, all := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo"); code != 0 {
		t.Fatalf("committed ignore rule: exit %d obj %v %s", code, obj, all)
	}
	// husky's shape: a generated directory with its own "*" .gitignore, inside a directory with
	// nothing else untracked, ignored by a committed rule. git collapses the parent to "hooks/".
	write(t, filepath.Join(dir, ".gitignore"), "out/\nhooks/_/\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore hooks/_")
	if err := os.MkdirAll(filepath.Join(dir, "hooks", "_"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "hooks", "_", ".gitignore"), "*\n")
	write(t, filepath.Join(dir, "hooks", "_", "h"), "x")
	if code, obj, all := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo"); code != 0 {
		t.Fatalf("generated self-ignoring directory under a committed rule: exit %d obj %v %s", code, obj, all)
	}
}

// Codex on #27: jade never fetches. In a partial clone a missing manifest blob is an error, not
// a request to the remote. The spy upload-pack shows whether the remote was contacted; the
// control shows plain git would contact it.
func TestNoLazyFetch(t *testing.T) {
	remote := repo(t, manifest)
	gitIn(t, remote, "config", "uploadpack.allowFilter", "true")
	parent := t.TempDir()
	clone := filepath.Join(parent, "clone")
	gitIn(t, parent, "clone", "-q", "--no-checkout", "--filter=blob:none", "file://"+remote, clone)
	marker := filepath.Join(parent, "fetched")
	spy := filepath.Join(parent, "spy-upload-pack")
	write(t, spy, "#!/bin/sh\ntouch "+marker+"\nexec git-upload-pack \"$@\"\n")
	if err := os.Chmod(spy, 0o755); err != nil {
		t.Fatal(err)
	}
	gitIn(t, clone, "config", "remote.origin.uploadpack", spy)
	code, obj, _ := jade(t, clone, "mint", "--json", "--cilock", "/bin/echo")
	if code == 0 {
		t.Fatalf("mint passed in a checkout with no files: %v", obj)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("jade contacted the remote")
	}
	gitIn(t, clone, "cat-file", "blob", "HEAD:.jade/workspace.json")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("control: plain git should have fetched through the spy")
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Codex on #27: paths are literal, never pathspec magic. A directory named ":(glob)hidden" with
// its own "*" .gitignore is still an uncommitted rule hiding an input.
func TestIgnoredPathsAreLiteral(t *testing.T) {
	dir := repo(t, manifest)
	odd := filepath.Join(dir, ":(glob)hidden")
	if err := os.MkdirAll(odd, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(odd, ".gitignore"), "*\n")
	write(t, filepath.Join(odd, "input.sh"), "exit 0\n")
	if st := gitIn(t, dir, "status", "--porcelain", "--untracked-files=all"); st != "" {
		t.Fatalf("control: git status should see nothing, got %q", st)
	}
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.dirty" || !strings.Contains(e["message"].(string), "which is not committed") {
		t.Fatalf("exit %d obj %v", code, obj)
	}
	// The same name ignored by a committed rule is accepted: the path was checked, not skipped.
	if err := os.RemoveAll(odd); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, ".gitignore"), ":(glob)hidden/\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore it")
	if err := os.MkdirAll(odd, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(odd, "out"), "x")
	if code, obj, all := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo"); code != 0 {
		t.Fatalf("committed rule for a magic-looking name: exit %d obj %v %s", code, obj, all)
	}
}

// Codex on #27: a negated committed rule (!d/) is not a reason to ignore anything, and a name
// with leading whitespace is that exact name. Both hid an uncommitted "*" .gitignore.
func TestIgnoredNegationAndWhitespace(t *testing.T) {
	setups := map[string]func(dir string) string{
		"a negated committed rule": func(dir string) string {
			write(t, filepath.Join(dir, ".gitignore"), "!d/\n")
			gitIn(t, dir, "add", ".gitignore")
			gitIn(t, dir, "commit", "-q", "-m", "negate")
			return "d"
		},
		"a leading space": func(dir string) string { return " d" },
	}
	for name, setup := range setups {
		dir := repo(t, manifest)
		sub := filepath.Join(dir, setup(dir))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(sub, ".gitignore"), "*\n")
		write(t, filepath.Join(sub, "input.sh"), "exit 0\n")
		if st := gitIn(t, dir, "status", "--porcelain", "--untracked-files=all"); st != "" {
			t.Fatalf("%s: control: git status should see nothing, got %q", name, st)
		}
		code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
		e, _ := obj["error"].(map[string]any)
		if code != 3 || e == nil || e["code"] != "preflight.dirty" {
			t.Fatalf("%s: exit %d obj %v", name, code, obj)
		}
	}
}

// Codex on #27: a staged gitlink change is found even when the submodule is configured
// ignore=all, which makes plain diff-index skip it. The submodule's checkout still matches HEAD.
func TestStagedSubmoduleChangeWithIgnoreAll(t *testing.T) {
	sub := t.TempDir()
	gitIn(t, sub, "init", "-q", "-b", "main")
	write(t, filepath.Join(sub, "f"), "1\n")
	gitIn(t, sub, "add", ".")
	gitIn(t, sub, "commit", "-q", "-m", "one")
	dir := repo(t, manifest)
	gitIn(t, dir, "submodule", "add", "-q", sub, "sub")
	gitIn(t, dir, "commit", "-q", "-m", "sub")
	inner := filepath.Join(dir, "sub")
	first := gitIn(t, inner, "rev-parse", "HEAD")
	write(t, filepath.Join(inner, "f"), "2\n")
	gitIn(t, inner, "commit", "-q", "-am", "two")
	gitIn(t, dir, "add", "sub")
	gitIn(t, inner, "checkout", "-q", first)
	gitIn(t, dir, "config", "submodule.sub.ignore", "all")
	c := exec.Command("git", "diff-index", "--cached", "--quiet", "HEAD")
	c.Dir = dir
	if err := c.Run(); err != nil {
		t.Fatalf("control: with ignore=all, diff-index should miss the staged gitlink: %v", err)
	}
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.dirty" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: the missing-manifest remedy quotes the repository path.
func TestMissingManifestRemedyQuotesPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo;id;#")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "init", "-q")
	_, obj, _ := jade(t, dir, "plan", "--json")
	e, _ := obj["error"].(map[string]any)
	if e == nil || e["code"] != "manifest.missing" {
		t.Fatalf("obj %v", obj)
	}
	if r := e["remedy"].(string); strings.Contains(r, "repo;id;#/") && !strings.Contains(r, "'") {
		t.Fatalf("remedy does not quote the path: %s", r)
	}
}

// Codex on #27: a local core.ignorecase=true hides an untracked "makefile" beside a committed
// "Makefile" from ls-files. jade lists case-sensitively. Only a case-sensitive filesystem can
// hold both names, so this runs on Linux (CI) and skips on a default macOS volume.
func TestListingIsCaseSensitive(t *testing.T) {
	dir := repo(t, manifest)
	write(t, filepath.Join(dir, "Makefile"), "all:\n\ttrue\n")
	if _, err := os.Stat(filepath.Join(dir, "makefile")); err == nil {
		t.Skip("case-insensitive filesystem")
	}
	gitIn(t, dir, "add", "Makefile")
	gitIn(t, dir, "commit", "-q", "-m", "make")
	gitIn(t, dir, "config", "core.ignorecase", "true")
	write(t, filepath.Join(dir, "makefile"), "all:\n\tid\n")
	if out := gitIn(t, dir, "ls-files", "--others", "--exclude-standard"); out != "" {
		t.Fatalf("control: ignorecase should hide makefile from ls-files, got %q", out)
	}
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.dirty" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: core.excludesFile pointed at a committed nested .gitignore applies its rules at
// the repository root, outside that file's scope. jade reads no global excludes file at all.
func TestExcludesFileCannotBorrowCommittedRules(t *testing.T) {
	dir := repo(t, manifest)
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "rules", ".gitignore"), "/input.sh\n")
	gitIn(t, dir, "add", "rules/.gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "rules")
	gitIn(t, dir, "config", "core.excludesFile", "rules/.gitignore")
	write(t, filepath.Join(dir, "input.sh"), "exit 0\n")
	if st := gitIn(t, dir, "status", "--porcelain", "--untracked-files=all"); st != "" {
		t.Fatalf("control: git status should see nothing, got %q", st)
	}
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.dirty" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: the steps get jade's git restrictions too (no lazy fetch, no replace refs), and
// none of the repository-selection variables a hook may have exported. A stand-in cilock
// records the environment each step runs with.
func TestStepsGetGitRestrictions(t *testing.T) {
	dir := repo(t, manifest)
	envFile := filepath.Join(t.TempDir(), "env")
	fake := filepath.Join(t.TempDir(), "cilock")
	write(t, fake, "#!/bin/sh\nenv >>"+envFile+"\n")
	if err := os.Chmod(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_DIR", filepath.Join(dir, ".git"))
	t.Setenv("GIT_INDEX_FILE", filepath.Join(t.TempDir(), "index"))
	code, obj, all := jade(t, dir, "mint", "--json", "--cilock", fake)
	if code != 0 {
		t.Fatalf("exit %d obj %v %s", code, obj, all)
	}
	b, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	env := "\n" + string(b)
	for _, want := range []string{"\nGIT_NO_LAZY_FETCH=1\n", "\nGIT_NO_REPLACE_OBJECTS=1\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("step env lacks %q", strings.TrimSpace(want))
		}
	}
	for _, banned := range []string{"\nGIT_DIR=", "\nGIT_INDEX_FILE="} {
		if strings.Contains(env, banned) {
			t.Errorf("step env carries %q", strings.TrimSpace(banned))
		}
	}
}

// Codex on #27: an exported GIT_DIR (from a hook, say) must not make a submodule's git calls read
// the parent repository; a clean checkout with a submodule mints.
func TestSubmoduleIgnoresExportedGitDir(t *testing.T) {
	sub := t.TempDir()
	gitIn(t, sub, "init", "-q", "-b", "main")
	write(t, filepath.Join(sub, "f"), "1\n")
	gitIn(t, sub, "add", ".")
	gitIn(t, sub, "commit", "-q", "-m", "one")
	dir := repo(t, manifest)
	gitIn(t, dir, "submodule", "add", "-q", sub, "sub")
	gitIn(t, dir, "commit", "-q", "-m", "sub")
	t.Setenv("GIT_DIR", filepath.Join(dir, ".git"))
	if code, obj, all := jade(t, dir, "doctor", "--json", "--cilock", "/bin/echo"); code != 0 {
		t.Fatalf("exit %d obj %v %s", code, obj, all)
	}
}

// Codex on #27: a submodule's core.worktree can point git's untracked-file checks at another
// clean checkout while jade hashes the real one. Every repository jade checks must have the
// directory jade hashes as its worktree.
func TestSubmoduleWorktreeIsPinned(t *testing.T) {
	sub := t.TempDir()
	gitIn(t, sub, "init", "-q", "-b", "main")
	write(t, filepath.Join(sub, "f"), "1\n")
	gitIn(t, sub, "add", ".")
	gitIn(t, sub, "commit", "-q", "-m", "one")
	dir := repo(t, manifest)
	gitIn(t, dir, "submodule", "add", "-q", sub, "sub")
	gitIn(t, dir, "commit", "-q", "-m", "sub")
	decoy := filepath.Join(t.TempDir(), "decoy")
	gitIn(t, t.TempDir(), "clone", "-q", sub, decoy)
	inner := filepath.Join(dir, "sub")
	gitIn(t, inner, "config", "core.worktree", decoy)
	write(t, filepath.Join(inner, "extra.sh"), "id\n")
	if out := gitIn(t, inner, "ls-files", "--others", "--exclude-standard"); out != "" {
		t.Fatalf("control: core.worktree should hide extra.sh from ls-files, got %q", out)
	}
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.dirty" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: a committed directory replaced by a symlink to an outside copy of its files
// hashes the same leaf by leaf, and a committed ignore rule for the name hides the link from
// git. Every directory the commit has must be a real directory.
func TestCommittedDirectoryIsNotASymlink(t *testing.T) {
	dir := repo(t, manifest)
	if err := os.MkdirAll(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "d", "run.sh"), "exit 1\n")
	write(t, filepath.Join(dir, ".gitignore"), "d\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "add", "-f", "d/run.sh")
	gitIn(t, dir, "commit", "-q", "-m", "d")
	outside := filepath.Join(t.TempDir(), "d")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(outside, "run.sh"), "exit 1\n")
	write(t, filepath.Join(outside, "extra.sh"), "id\n")
	if err := os.RemoveAll(filepath.Join(dir, "d")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "d")); err != nil {
		t.Fatal(err)
	}
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.dirty" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: git warns about a directory it cannot read and still exits 0, so its listings
// silently skip it. A searchable but unreadable untracked directory hid a file a step could open
// by name. A listing with anything on stderr refuses the tree.
func TestUnreadableDirectoryRefuses(t *testing.T) {
	dir := repo(t, manifest)
	hidden := filepath.Join(dir, "u")
	if err := os.MkdirAll(hidden, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(hidden, "input.sh"), "id\n")
	if err := os.Chmod(hidden, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(hidden, 0o755) })
	if _, err := os.ReadDir(hidden); err == nil {
		t.Skip("running with privileges that read 0111 directories")
	}
	c := exec.Command("git", "ls-files", "--others", "--exclude-standard", "-z")
	c.Dir = dir
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil || len(out) != 0 || stderr.Len() == 0 {
		t.Fatalf("control: git should warn, list nothing and exit 0: err=%v out=%q stderr=%q", err, out, stderr.String())
	}
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.dirty" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: evidence is bound to the pinned commit even if the checkout moves mid-step. jade
// mints in its own snapshot of that commit; a stand-in cilock commits in the user's checkout
// during every step and records the commit and directory it actually runs in.
func TestMintRunsInPrivateSnapshot(t *testing.T) {
	dir := repo(t, manifest)
	pinned := gitIn(t, dir, "rev-parse", "HEAD")
	rec := filepath.Join(t.TempDir(), "rec")
	fake := filepath.Join(t.TempDir(), "cilock")
	write(t, fake, "#!/bin/sh\necho \"$(pwd -P)|$(git rev-parse HEAD)\" >>"+rec+"\n"+
		"git -C "+dir+" -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -q --allow-empty -m moved\n")
	if err := os.Chmod(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	code, obj, all := jade(t, dir, "mint", "--json", "--cilock", fake)
	if code != 0 {
		t.Fatalf("exit %d obj %v %s", code, obj, all)
	}
	if moved := gitIn(t, dir, "rev-parse", "HEAD"); moved == pinned {
		t.Fatal("control: the stand-in should have moved the user's HEAD")
	}
	b, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 steps recorded, got %q", lines)
	}
	realDir, _ := filepath.EvalSymlinks(dir)
	for _, l := range lines {
		where, commit, _ := strings.Cut(l, "|")
		if commit != pinned {
			t.Errorf("a step ran at %s, not the pinned %s", commit, pinned)
		}
		if where == realDir {
			t.Errorf("a step ran in the user's checkout")
		}
		if _, err := os.Stat(where); err == nil {
			t.Errorf("the snapshot %s was left behind", where)
		}
	}
	for _, e := range obj["evidence"].([]any) {
		if e.(map[string]any)["commit"] != pinned {
			t.Errorf("evidence names %v", e)
		}
	}
}

// A commit with submodules cannot be snapshotted without fetching them, so the mint refuses it.
func TestMintRefusesSubmodulesInSnapshot(t *testing.T) {
	sub := t.TempDir()
	gitIn(t, sub, "init", "-q", "-b", "main")
	write(t, filepath.Join(sub, "f"), "1\n")
	gitIn(t, sub, "add", ".")
	gitIn(t, sub, "commit", "-q", "-m", "one")
	dir := repo(t, manifest)
	gitIn(t, dir, "submodule", "add", "-q", sub, "sub")
	gitIn(t, dir, "commit", "-q", "-m", "sub")
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "snapshot.submodule" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: a relative --cilock names a file in the caller's directory, and an ignored local
// binary is not in the snapshot, so jade resolves it before the steps change directory.
func TestRelativeCilockResolvedBeforeSnapshot(t *testing.T) {
	dir := repo(t, manifest)
	write(t, filepath.Join(dir, ".gitignore"), "tools/\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore tools")
	if err := os.MkdirAll(filepath.Join(dir, "tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "tools", "cilock"), "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Join(dir, "tools", "cilock"), 0o755); err != nil {
		t.Fatal(err)
	}
	if code, obj, all := jade(t, dir, "mint", "--json", "--cilock", "tools/cilock"); code != 0 {
		t.Fatalf("exit %d obj %v %s", code, obj, all)
	}
}

// Codex on #27: a step's own git commands get jade's restrictions too. A local core.fsmonitor and
// core.hooksPath would run on the step's git status and git commit; neither may.
func TestStepGitRunsNoHooksOrMonitor(t *testing.T) {
	dir := repo(t, manifest)
	marks := t.TempDir()
	spy := filepath.Join(marks, "spy")
	write(t, spy, "#!/bin/sh\ntouch "+filepath.Join(marks, "ran-$(basename \"$0\")")+"\n")
	if err := os.Chmod(spy, 0o755); err != nil {
		t.Fatal(err)
	}
	hooks := filepath.Join(marks, "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"pre-commit", "post-commit"} {
		if err := os.Symlink(spy, filepath.Join(hooks, h)); err != nil {
			t.Fatal(err)
		}
	}
	gitIn(t, dir, "config", "core.hooksPath", hooks)
	fake := filepath.Join(marks, "cilock")
	write(t, fake, "#!/bin/sh\ngit status --porcelain >/dev/null 2>&1\n"+
		"git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -q --allow-empty -m x >/dev/null 2>&1\nexit 0\n")
	if err := os.Chmod(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	// Control: plain git in this repository does run the hooks.
	gitIn(t, dir, "commit", "-q", "--allow-empty", "-m", "control")
	if _, err := os.Stat(filepath.Join(marks, "ran-pre-commit")); err != nil {
		t.Fatal("control: the pre-commit hook should run for plain git")
	}
	os.Remove(filepath.Join(marks, "ran-pre-commit"))
	os.Remove(filepath.Join(marks, "ran-post-commit"))
	gitIn(t, dir, "config", "core.fsmonitor", spy)
	jade(t, dir, "mint", "--json", "--cilock", fake)
	for _, m := range []string{"ran-pre-commit", "ran-post-commit", "ran-spy"} {
		if _, err := os.Stat(filepath.Join(marks, m)); err == nil {
			t.Errorf("a step's git ran %s", m)
		}
	}
}

// Codex on #27: jade never picks up a cilock from the checkout on its own. An uncommitted
// .bin/cilock (ignored by a committed rule) that exits 0 would report success with no checks
// run; only an explicit --cilock names a binary other than cilock on PATH.
func TestNoImplicitLocalCilock(t *testing.T) {
	dir := repo(t, manifest)
	write(t, filepath.Join(dir, ".gitignore"), ".bin/\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore .bin")
	if err := os.MkdirAll(filepath.Join(dir, ".bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, ".bin", "cilock"), "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Join(dir, ".bin", "cilock"), 0o755); err != nil {
		t.Fatal(err)
	}
	// PATH holds git and nothing else, so no cilock is on it.
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	onlyGit := t.TempDir()
	if err := os.Symlink(realGit, filepath.Join(onlyGit, "git")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", onlyGit)
	code, obj, _ := jade(t, dir, "mint", "--json")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.no-cilock" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: a PATH entry inside the checkout is still an implicit checkout binary. Without
// --cilock, a cilock that resolves (symlinks followed) into the checkout is refused, whether its
// directory is on PATH directly or a symlink outside points at it.
func TestImplicitCilockInsideCheckoutRefused(t *testing.T) {
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	for _, how := range []string{"on PATH", "via a symlink"} {
		dir := repo(t, manifest)
		write(t, filepath.Join(dir, ".gitignore"), ".bin/\n")
		gitIn(t, dir, "add", ".gitignore")
		gitIn(t, dir, "commit", "-q", "-m", "ignore .bin")
		if err := os.MkdirAll(filepath.Join(dir, ".bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		fake := filepath.Join(dir, ".bin", "cilock")
		write(t, fake, "#!/bin/sh\nexit 0\n")
		if err := os.Chmod(fake, 0o755); err != nil {
			t.Fatal(err)
		}
		bin := t.TempDir()
		if err := os.Symlink(realGit, filepath.Join(bin, "git")); err != nil {
			t.Fatal(err)
		}
		path := bin + string(os.PathListSeparator) + filepath.Join(dir, ".bin")
		if how == "via a symlink" {
			if err := os.Symlink(fake, filepath.Join(bin, "cilock")); err != nil {
				t.Fatal(err)
			}
			path = bin
		}
		t.Setenv("PATH", path)
		code, obj, _ := jade(t, dir, "mint", "--json")
		e, _ := obj["error"].(map[string]any)
		if code != 3 || e == nil || e["code"] != "preflight.cilock-in-checkout" {
			t.Fatalf("%s: exit %d obj %v", how, code, obj)
		}
	}
}

// runner is a stand-in cilock that runs the command after "--", as cilock run does, and appends
// its exit code to rec, as cilock's command-run attestation would record it.
func runner(t *testing.T, rec string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cilock")
	// An attest step has no "--" and no command: nothing to run, as with cilock attest.
	write(t, p, "#!/bin/sh\nwhile [ $# -gt 0 ] && [ \"$1\" != -- ]; do shift; done\n[ $# -gt 0 ] || exit 0\nshift\n\"$@\"\nrc=$?\necho $rc >>"+rec+"\nexit $rc\n")
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// Codex on #27: cilock uploads a step's evidence before jade can look at the tree, so the check
// runs inside the attested command: a step that edits a tracked file and exits 0 is recorded as
// a failed command, and the mint refuses it.
func TestStepGuardFailsTheAttestedCommand(t *testing.T) {
	m := `{"steps":[{"name":"mutate","mode":"run","argv":["/bin/sh","-c","echo x >>tracked.txt"]}]}`
	dir := repo(t, m)
	write(t, filepath.Join(dir, "tracked.txt"), "a\n")
	gitIn(t, dir, "add", "tracked.txt")
	gitIn(t, dir, "commit", "-q", "-m", "tracked")
	rec := filepath.Join(t.TempDir(), "rec")
	code, obj, all := jade(t, dir, "mint", "--json", "--cilock", runner(t, rec))
	if code == 0 {
		t.Fatalf("mint passed: %v %s", obj, all)
	}
	b, _ := os.ReadFile(rec)
	if got := strings.TrimSpace(string(b)); got == "0" || got == "" {
		t.Fatalf("the attested command exited %q; it must fail when the step changed the tree", got)
	}
}

// Codex on #27: a step's PATH holds no directory inside the user's checkout, so an ignored
// node_modules/.bin/check there cannot stand in for the check the step names.
func TestStepPathExcludesCheckout(t *testing.T) {
	m := `{"steps":[{"name":"check","mode":"run","argv":["/bin/sh","-c","check"]}]}`
	dir := repo(t, m)
	write(t, filepath.Join(dir, ".gitignore"), "node_modules/\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore")
	nm := filepath.Join(dir, "node_modules", ".bin")
	if err := os.MkdirAll(nm, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(nm, "check"), "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Join(nm, "check"), 0o755); err != nil {
		t.Fatal(err)
	}
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.Symlink(realGit, filepath.Join(bin, "git")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+nm)
	rec := filepath.Join(t.TempDir(), "rec")
	code, obj, all := jade(t, dir, "mint", "--json", "--cilock", runner(t, rec))
	if code == 0 {
		t.Fatalf("the checkout's node_modules/.bin/check ran in place of the step's check: %v %s", obj, all)
	}
}

// Codex on #27: the snapshot is its own repository, so the user's repository-local git config
// and info/attributes never reach a step: a local clean filter does not run on a step's git
// status, with a clean starting tree. The control shows plain git runs it.
func TestSnapshotHasNoLocalGitConfig(t *testing.T) {
	dir := repo(t, manifest)
	marker := filepath.Join(t.TempDir(), "filter-ran")
	write(t, filepath.Join(dir, ".git", "info", "attributes"), "* filter=spy\n")
	gitIn(t, dir, "config", "filter.spy.clean", "sh -c 'touch "+marker+"; cat'")
	// No filter.spy.process: with git 2.47 (the worker step image) a process filter that exits makes the control's own
	// git add fatal ("the remote end hung up"), so only the clean filter is planted.
	fake := filepath.Join(t.TempDir(), "cilock")
	write(t, fake, "#!/bin/sh\ntouch fresh-file\ngit status --porcelain >/dev/null 2>&1\ngit add -A >/dev/null 2>&1\nrm -f fresh-file\ngit reset -q >/dev/null 2>&1\nexit 0\n")
	if err := os.Chmod(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	jade(t, dir, "mint", "--json", "--cilock", fake)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a step's git ran the user's local filter")
	}
	write(t, filepath.Join(dir, "x"), "x\n")
	gitIn(t, dir, "add", "x")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("control: plain git should run the local filter")
	}
}

// Codex on #27: a git on PATH inside the checkout is refused before any git runs, so an ignored
// .bin/git wrapper never executes.
func TestGitInsideCheckoutRefusedBeforeRunning(t *testing.T) {
	dir := repo(t, manifest)
	write(t, filepath.Join(dir, ".gitignore"), ".bin/\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore .bin")
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "wrapper-ran")
	if err := os.MkdirAll(filepath.Join(dir, ".bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, ".bin", "git"), "#!/bin/sh\ntouch "+marker+"\nexec "+realGit+" \"$@\"\n")
	if err := os.Chmod(filepath.Join(dir, ".bin", "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Join(dir, ".bin")+string(os.PathListSeparator)+filepath.Dir(realGit))
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.git-in-checkout" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the checkout's git wrapper ran")
	}
}

// Codex on #27: a remote URL is copied into the snapshot as one value. One with a newline could
// smuggle another setting (include.path) into the snapshot's config, so it is refused.
func TestSnapshotRefusesRemoteURLWithNewline(t *testing.T) {
	dir := repo(t, manifest)
	evil := filepath.Join(t.TempDir(), "evil.cfg")
	write(t, evil, "[core]\n\tattributesFile = /dev/null\n")
	gitIn(t, dir, "config", "remote.origin.url", "https://example.invalid/r.git\ninclude.path "+evil)
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "snapshot.remote" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: a relative PATH entry is resolved from the step's directory, the snapshot, so
// one that climbs back into the user's checkout is dropped too.
func TestStepPathDropsRelativeEntryIntoCheckout(t *testing.T) {
	m := `{"steps":[{"name":"check","mode":"run","argv":["/bin/sh","-c","check"]}]}`
	dir := repo(t, m)
	write(t, filepath.Join(dir, ".gitignore"), ".bin/\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore")
	bin := filepath.Join(dir, ".bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(bin, "check"), "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Join(bin, "check"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The snapshot is <TempDir>/jade-snapshot-*/tree, two levels below the real TempDir.
	tmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realBin, err := filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(filepath.Join(tmp, "a", "b"), realBin)
	if err != nil {
		t.Fatal(err)
	}
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	gitDir := t.TempDir()
	if err := os.Symlink(realGit, filepath.Join(gitDir, "git")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", gitDir+string(os.PathListSeparator)+rel)
	rec := filepath.Join(t.TempDir(), "rec")
	if code, obj, all := jade(t, dir, "mint", "--json", "--cilock", runner(t, rec)); code == 0 {
		t.Fatalf("the checkout's .bin/check ran through %s: %v %s", rel, obj, all)
	}
}

// Codex on #27: the snapshot uses the source repository's object format, so a SHA-256 repository
// mints.
func TestSnapshotSHA256Repository(t *testing.T) {
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q", "-b", "main", "--object-format=sha256")
	if err := os.MkdirAll(filepath.Join(dir, ".jade"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, ".jade", "workspace.json"), manifest)
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-q", "-m", "init")
	if code, obj, all := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo"); code != 0 {
		t.Fatalf("exit %d obj %v %s", code, obj, all)
	}
}

// Codex on #27: a kept relative PATH entry is passed on as an absolute path, so a step that
// changes directory cannot make it resolve somewhere else, such as into the user's checkout.
func TestStepPathRelativeEntryIsMadeAbsolute(t *testing.T) {
	m := `{"steps":[{"name":"check","mode":"run","argv":["/bin/sh","-c","cd out && check"]}]}`
	dir := repo(t, m)
	write(t, filepath.Join(dir, ".gitignore"), ".bin/\n")
	if err := os.MkdirAll(filepath.Join(dir, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "out", "keep"), "\n")
	gitIn(t, dir, "add", ".gitignore", "out/keep")
	gitIn(t, dir, "commit", "-q", "-m", "out")
	bin := filepath.Join(dir, ".bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(bin, "check"), "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Join(bin, "check"), 0o755); err != nil {
		t.Fatal(err)
	}
	// From <TempDir>/jade-snapshot-*/tree/out this reaches the checkout's .bin; from the snapshot
	// root, one level up, it reaches somewhere that does not exist.
	tmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realBin, err := filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(filepath.Join(tmp, "a", "b", "out"), realBin)
	if err != nil {
		t.Fatal(err)
	}
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	gitDir := t.TempDir()
	if err := os.Symlink(realGit, filepath.Join(gitDir, "git")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", gitDir+string(os.PathListSeparator)+rel)
	rec := filepath.Join(t.TempDir(), "rec")
	if code, obj, all := jade(t, dir, "mint", "--json", "--cilock", runner(t, rec)); code == 0 {
		t.Fatalf("the checkout's .bin/check ran after cd: %v %s", obj, all)
	}
}

// Strict step environment (Bazel's strict action env): a step gets an allowlisted environment
// and a fixed PATH, nothing else from the caller. Codex on #27: an inherited BASH_ENV pointing
// at an ignored checkout file ran before the step's own command and passed it.
func TestStrictEnvDropsBashEnv(t *testing.T) {
	m := `{"steps":[{"name":"fail","mode":"run","argv":["bash","-c","exit 1"]}]}`
	dir := repo(t, m)
	write(t, filepath.Join(dir, ".gitignore"), "rc\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore rc")
	write(t, filepath.Join(dir, "rc"), "exit 0\n")
	t.Setenv("BASH_ENV", filepath.Join(dir, "rc"))
	rec := filepath.Join(t.TempDir(), "rec")
	if code, obj, all := jade(t, dir, "mint", "--json", "--cilock", runner(t, rec)); code == 0 {
		t.Fatalf("BASH_ENV turned a failing step into a pass: %v %s", obj, all)
	}
}

// Codex on #27: a directory outside the checkout on the caller's PATH, holding a symlink into
// the checkout, is not on a step's PATH: the caller's PATH is not used at all.
func TestStrictEnvIgnoresCallerPath(t *testing.T) {
	m := `{"steps":[{"name":"check","mode":"run","argv":["/bin/sh","-c","check"]}]}`
	dir := repo(t, m)
	write(t, filepath.Join(dir, ".gitignore"), "node_modules/\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore")
	nm := filepath.Join(dir, "node_modules", ".bin")
	if err := os.MkdirAll(nm, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(nm, "check"), "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Join(nm, "check"), 0o755); err != nil {
		t.Fatal(err)
	}
	ext := t.TempDir()
	if err := os.Symlink(filepath.Join(nm, "check"), filepath.Join(ext, "check")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", ext+string(os.PathListSeparator)+os.Getenv("PATH"))
	rec := filepath.Join(t.TempDir(), "rec")
	if code, obj, all := jade(t, dir, "mint", "--json", "--cilock", runner(t, rec)); code == 0 {
		t.Fatalf("a symlink on the caller's PATH reached the checkout's check: %v %s", obj, all)
	}
}

// The committed manifest names what a step may have beyond the defaults: env.pass variables
// and env.path directories. Both reach the step; without them, neither does.
func TestManifestEnvPassAndPath(t *testing.T) {
	tools := t.TempDir()
	write(t, filepath.Join(tools, "tool"), "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Join(tools, "tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JADE_TEST_VAR", "yes")
	step := `{"name":"s","mode":"run","argv":["/bin/sh","-c","test \"$JADE_TEST_VAR\" = yes && tool"]}`
	for _, c := range []struct {
		env  string
		want int
	}{
		{`"env":{"pass":["JADE_TEST_VAR"],"path":["` + tools + `"]},`, 0},
		{`"env":{"path":["` + tools + `"]},`, 1},
		{`"env":{"pass":["JADE_TEST_VAR"]},`, 1},
	} {
		dir := repo(t, `{`+c.env+`"steps":[`+step+`]}`)
		rec := filepath.Join(t.TempDir(), "rec")
		code, obj, all := jade(t, dir, "mint", "--json", "--cilock", runner(t, rec))
		if (code == 0) != (c.want == 0) {
			t.Errorf("%s: exit %d, want success=%v: %v %s", c.env, code, c.want == 0, obj, all)
		}
	}
}

// Codex on #27: GITHUB_WORKSPACE names the checkout a CI job cloned; a step gets the snapshot
// instead, so cd "$GITHUB_WORKSPACE" cannot reach ignored files in the original checkout.
func TestGithubWorkspaceIsTheSnapshot(t *testing.T) {
	m := `{"steps":[{"name":"s","mode":"run","argv":["/bin/sh","-c","cd \"$GITHUB_WORKSPACE\" && ./check"]}]}`
	dir := repo(t, m)
	write(t, filepath.Join(dir, ".gitignore"), "check\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore")
	write(t, filepath.Join(dir, "check"), "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Join(dir, "check"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_WORKSPACE", dir)
	rec := filepath.Join(t.TempDir(), "rec")
	if code, obj, all := jade(t, dir, "mint", "--json", "--cilock", runner(t, rec)); code == 0 {
		t.Fatalf("a step reached the original checkout through GITHUB_WORKSPACE: %v %s", obj, all)
	}
}

// Codex on #27: an env.path entry is passed on as the directory it resolved to, so retargeting
// a symlink after the check (here an ignored link in the checkout, repointed by the step itself)
// changes nothing; an entry that does not resolve is dropped.
func TestEnvPathPassedResolved(t *testing.T) {
	dir := repo(t, manifest)
	ext := t.TempDir()
	write(t, filepath.Join(ext, "tool"), "#!/bin/sh\nexit 1\n")
	if err := os.Chmod(filepath.Join(ext, "tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, ".bin", "tool"), "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Join(dir, ".bin", "tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "toolsdir")
	if err := os.Symlink(ext, link); err != nil {
		t.Fatal(err)
	}
	m := `{"env":{"path":["` + link + `"]},"steps":[{"name":"s","mode":"run","argv":["/bin/sh","-c",` +
		`"ln -sfn ` + filepath.Join(dir, ".bin") + ` ` + link + ` && tool"]}]}`
	write(t, filepath.Join(dir, ".gitignore"), ".bin/\ntoolsdir\n")
	write(t, filepath.Join(dir, ".jade", "workspace.json"), m)
	gitIn(t, dir, "add", ".gitignore", ".jade/workspace.json")
	gitIn(t, dir, "commit", "-q", "-m", "env.path through a link")
	rec := filepath.Join(t.TempDir(), "rec")
	if code, obj, all := jade(t, dir, "mint", "--json", "--cilock", runner(t, rec)); code == 0 {
		t.Fatalf("retargeting the env.path link reached the checkout's tool: %v %s", obj, all)
	}
}

// Codex on #27: cilock is run by the path it resolved to at preflight, so retargeting a checkout
// symlink the PATH lookup went through (here, by the first step) cannot swap in a fake for the
// later steps.
func TestCilockRunByResolvedPath(t *testing.T) {
	m := `{"steps":[{"name":"a","mode":"run","argv":["/bin/sh","-c","ln -sfn \"$FAKE\" \"$LINK\""]},` +
		`{"name":"b","mode":"run","argv":["/bin/sh","-c","exit 1"]}],"env":{"pass":["FAKE","LINK"]}}`
	dir := repo(t, m)
	write(t, filepath.Join(dir, ".gitignore"), ".bin/\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore")
	bin := filepath.Join(dir, ".bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(bin, "fake")
	write(t, fake, "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	real := runner(t, filepath.Join(t.TempDir(), "rec"))
	link := filepath.Join(bin, "cilock")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	onlyGit := t.TempDir()
	if err := os.Symlink(realGit, filepath.Join(onlyGit, "git")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", onlyGit+string(os.PathListSeparator)+bin)
	t.Setenv("FAKE", fake)
	t.Setenv("LINK", link)
	if code, obj, all := jade(t, dir, "mint", "--json"); code == 0 {
		t.Fatalf("a retargeted cilock link ran the fake for step b: %v %s", obj, all)
	}
}

// Codex on #27: the guard cilock runs is a private copy of jade in the snapshot's directory, so
// replacing the jade binary the mint was started from (an ignored .bin/jade, say) mid-mint
// cannot substitute a guard that skips the step.
func TestGuardIsAPrivateCopy(t *testing.T) {
	rec := filepath.Join(t.TempDir(), "rec")
	dir := repo(t, manifest)
	code, obj, all := jade(t, dir, "mint", "--json", "--cilock", runner(t, rec))
	if code != 0 {
		t.Fatalf("exit %d %v %s", code, obj, all)
	}
	exe, _ := self()
	g := &gitRunner{}
	if got := guardPath(g, exe); got != exe {
		t.Fatalf("without a snapshot the guard is jade itself, got %s", got)
	}
	g.snapParent = t.TempDir()
	if got := guardPath(g, exe); !strings.HasPrefix(got, g.snapParent) {
		t.Fatalf("with a snapshot the guard is a copy inside it, got %s", got)
	}
}

// Codex on #27: jade's own git calls get no dynamic-loader variables, so LD_PRELOAD or
// LD_LIBRARY_PATH naming checkout content cannot load into git. A git wrapper outside the
// checkout records what it was given.
func TestGitGetsNoLoaderVariables(t *testing.T) {
	dir := repo(t, manifest)
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	wrapDir := t.TempDir()
	rec := filepath.Join(t.TempDir(), "rec")
	write(t, filepath.Join(wrapDir, "git"), "#!/bin/sh\nenv | grep -E '^(LD_|DYLD_)' >>"+rec+"\nexec "+realGit+" \"$@\"\n")
	if err := os.Chmod(filepath.Join(wrapDir, "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", wrapDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("LD_LIBRARY_PATH", filepath.Join(dir, "lib"))
	jade(t, dir, "doctor", "--json", "--cilock", "/bin/echo")
	if b, _ := os.ReadFile(rec); len(b) != 0 {
		t.Fatalf("jade's git saw loader variables: %s", b)
	}
}

// Codex on #27: a mint refuses to run from a jade binary inside the checkout (an ignored
// .bin/jade): it could be replaced before the guard copy is made. jade belongs outside the
// repository, like git and cilock.
func TestMintRefusesJadeInsideCheckout(t *testing.T) {
	dir := repo(t, manifest)
	write(t, filepath.Join(dir, ".gitignore"), ".bin/\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore")
	exe, _ := self()
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(dir, ".bin", "jade")
	if err := os.WriteFile(local, b, 0o755); err != nil {
		t.Fatal(err)
	}
	saved := self
	self = func() (string, error) { return local, nil }
	t.Cleanup(func() { self = saved })
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.jade-in-checkout" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: jade run from a symlink to a checkout subdirectory still finds the checkout
// before running git, so a .bin/git there is refused unrun.
func TestResolveGitFollowsSymlinkedWorkdir(t *testing.T) {
	dir := repo(t, manifest)
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "sub", "keep"), "\n")
	write(t, filepath.Join(dir, ".gitignore"), ".bin/\n")
	gitIn(t, dir, "add", ".gitignore", "sub/keep")
	gitIn(t, dir, "commit", "-q", "-m", "sub")
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "wrapper-ran")
	if err := os.MkdirAll(filepath.Join(dir, ".bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, ".bin", "git"), "#!/bin/sh\ntouch "+marker+"\nexec "+realGit+" \"$@\"\n")
	if err := os.Chmod(filepath.Join(dir, ".bin", "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(filepath.Join(dir, "sub"), link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Join(dir, ".bin")+string(os.PathListSeparator)+filepath.Dir(realGit))
	code, obj, _ := jade(t, link, "doctor", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.git-in-checkout" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the checkout's git wrapper ran")
	}
}

// Codex on #27: jade's own git calls get the strict allowlisted environment too, so a git that
// is a bash wrapper (outside the checkout, so allowed) does not source BASH_ENV from the checkout.
func TestGitGetsStrictEnv(t *testing.T) {
	dir := repo(t, manifest)
	write(t, filepath.Join(dir, ".gitignore"), "rc\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore")
	marker := filepath.Join(t.TempDir(), "rc-ran")
	write(t, filepath.Join(dir, "rc"), "touch "+marker+"\n")
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	wrapDir := t.TempDir()
	write(t, filepath.Join(wrapDir, "git"), "#!"+bash+"\nexec "+realGit+" \"$@\"\n")
	if err := os.Chmod(filepath.Join(wrapDir, "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", wrapDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("BASH_ENV", filepath.Join(dir, "rc"))
	jade(t, dir, "doctor", "--json", "--cilock", "/bin/echo")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("jade's git sourced BASH_ENV from the checkout")
	}
}

// Codex on #27: jade verifies the commit and every tree object it reads against their IDs. A
// loose tree object rewritten under its original ID (with the index and checkout made to match)
// fools git status but is refused.
func TestTamperedTreeObjectRefused(t *testing.T) {
	dir := repo(t, manifest)
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "sub", "check.sh"), "exit 1\n")
	gitIn(t, dir, "add", "sub/check.sh")
	gitIn(t, dir, "commit", "-q", "-m", "sub")
	orig := gitIn(t, dir, "rev-parse", "HEAD:sub")
	evilBlob := func() string {
		c := exec.Command("git", "hash-object", "-w", "--stdin")
		c.Dir = dir
		c.Stdin = strings.NewReader("exit 0\n")
		out, err := c.Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}()
	c := exec.Command("git", "mktree")
	c.Dir = dir
	c.Stdin = strings.NewReader("100644 blob " + evilBlob + "\tcheck.sh\n")
	out, err := c.Output()
	if err != nil {
		t.Fatal(err)
	}
	evilTree := strings.TrimSpace(string(out))
	objPath := func(id string) string { return filepath.Join(dir, ".git", "objects", id[:2], id[2:]) }
	b, err := os.ReadFile(objPath(evilTree))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(objPath(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objPath(orig), b, 0o444); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "sub", "check.sh"), "exit 0\n")
	gitIn(t, dir, "read-tree", "HEAD")
	gitIn(t, dir, "update-index", "--refresh")
	if st := gitIn(t, dir, "status", "--porcelain", "--untracked-files=all"); st != "" {
		t.Fatalf("control: the tampered tree should fool git status, got %q", st)
	}
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "objects.corrupt" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: the manifest a mint runs must be the commit's, byte for byte. Once the snapshot
// is built and verified, the bytes jade parsed are compared with the snapshot's own
// .jade/workspace.json; a manifest read from a swapped blob is refused.
func TestMintRefusesManifestNotInSnapshot(t *testing.T) {
	dir := repo(t, manifest)
	head := gitIn(t, dir, "rev-parse", "HEAD")
	if e := resolveGit(dir); e != nil {
		t.Fatal(e)
	}
	g := &gitRunner{root: dir, wd: dir, cilock: "/bin/echo", head: head, mint: true,
		manifest: []byte(`{"steps":[{"name":"noop","mode":"run","argv":["true"]}]}`)}
	defer g.removeSnapshot()
	e := g.Preflight()
	if e == nil || e.Code != "manifest.changed" {
		t.Fatalf("got %v, want manifest.changed", e)
	}
}

// Codex on #27: an object of the wrong type under a tree's ID is refused promptly, however large:
// jade stops git rather than waiting on it while git waits to write the unread body.
func TestOversizedWrongTypeObjectRefusedPromptly(t *testing.T) {
	dir := repo(t, manifest)
	tree := gitIn(t, dir, "rev-parse", "HEAD:.jade")
	content := bytes.Repeat([]byte("x"), 200<<10)
	var raw bytes.Buffer
	zw := zlib.NewWriter(&raw)
	fmt.Fprintf(zw, "blob %d\x00", len(content))
	zw.Write(content)
	zw.Close()
	p := filepath.Join(dir, ".git", "objects", tree[:2], tree[2:])
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, raw.Bytes(), 0o444); err != nil {
		t.Fatal(err)
	}
	done := make(chan map[string]any, 1)
	go func() {
		var out, errb bytes.Buffer
		run([]string{"doctor", "--json", "--cilock", "/bin/echo"}, dir, &out, &errb)
		var obj map[string]any
		json.Unmarshal(out.Bytes(), &obj)
		done <- obj
	}()
	select {
	case obj := <-done:
		e, _ := obj["error"].(map[string]any)
		if e == nil || e["code"] != "objects.corrupt" {
			t.Fatalf("obj %v", obj)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("jade hung on a wrong-type object")
	}
}

// Codex on #27: a planted .git in a subdirectory does not hide the real checkout above it; every
// enclosing directory with a .git is a checkout the git binary must be outside of.
func TestResolveGitChecksEveryEnclosingCheckout(t *testing.T) {
	dir := repo(t, manifest)
	if err := os.MkdirAll(filepath.Join(dir, "sub", ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "wrapper-ran")
	if err := os.MkdirAll(filepath.Join(dir, ".bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, ".bin", "git"), "#!/bin/sh\ntouch "+marker+"\nexec "+realGit+" \"$@\"\n")
	if err := os.Chmod(filepath.Join(dir, ".bin", "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Join(dir, ".bin")+string(os.PathListSeparator)+filepath.Dir(realGit))
	code, obj, _ := jade(t, filepath.Join(dir, "sub"), "doctor", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.git-in-checkout" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the checkout's git wrapper ran")
	}
}

// Codex on #27: the snapshot is never made inside the checkout: with TMPDIR there, tools that
// search ancestor directories (node_modules) would find the checkout's ignored files.
func TestSnapshotRefusesTmpdirInsideCheckout(t *testing.T) {
	dir := repo(t, manifest)
	write(t, filepath.Join(dir, ".gitignore"), "tmp/\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore tmp")
	if err := os.MkdirAll(filepath.Join(dir, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", filepath.Join(dir, "tmp"))
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "snapshot.tmpdir" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: the snapshot holds its own verified copy of the pinned commit's objects, so
// replacing a blob in the user's object store mid-mint (here by step a) does not change what a
// later step reads through git (step b's git show HEAD:f).
func TestSnapshotObjectsArePrivate(t *testing.T) {
	m := `{"env":{"pass":["EVIL","OBJ"]},"steps":[` +
		`{"name":"a","mode":"run","argv":["/bin/sh","-c","cp -f \"$EVIL\" \"$OBJ\""]},` +
		`{"name":"b","mode":"run","argv":["/bin/sh","-c","test \"$(git show HEAD:f)\" = original"]}]}`
	dir := repo(t, m)
	write(t, filepath.Join(dir, "f"), "original\n")
	gitIn(t, dir, "add", "f")
	gitIn(t, dir, "commit", "-q", "-m", "f")
	id := gitIn(t, dir, "rev-parse", "HEAD:f")
	evil := []byte("tampered\n")
	var raw bytes.Buffer
	zw := zlib.NewWriter(&raw)
	fmt.Fprintf(zw, "blob %d\x00", len(evil))
	zw.Write(evil)
	zw.Close()
	evilPath := filepath.Join(t.TempDir(), "evil")
	if err := os.WriteFile(evilPath, raw.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EVIL", evilPath)
	t.Setenv("OBJ", filepath.Join(dir, ".git", "objects", id[:2], id[2:]))
	rec := filepath.Join(t.TempDir(), "rec")
	if code, obj, all := jade(t, dir, "mint", "--json", "--cilock", runner(t, rec)); code != 0 {
		t.Fatalf("a step read the tampered source blob: %v %s", obj, all)
	}
	if got := gitIn(t, dir, "cat-file", "blob", id); got != "tampered" {
		t.Fatalf("control: the source blob should now be tampered, got %q", got)
	}
}

// Codex on #27: an implicit cilock inside any enclosing checkout is refused, not only inside the
// repository being minted (a repository nested in another checkout).
func TestImplicitCilockInEnclosingCheckoutRefused(t *testing.T) {
	outer := t.TempDir()
	gitIn(t, outer, "init", "-q", "-b", "main")
	if err := os.MkdirAll(filepath.Join(outer, ".bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(outer, ".bin", "cilock"), "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Join(outer, ".bin", "cilock"), 0o755); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(outer, "inner")
	if err := os.MkdirAll(filepath.Join(inner, ".jade"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitIn(t, inner, "init", "-q", "-b", "main")
	write(t, filepath.Join(inner, ".jade", "workspace.json"), manifest)
	gitIn(t, inner, "add", ".")
	gitIn(t, inner, "commit", "-q", "-m", "init")
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	onlyGit := t.TempDir()
	if err := os.Symlink(realGit, filepath.Join(onlyGit, "git")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", onlyGit+string(os.PathListSeparator)+filepath.Join(outer, ".bin"))
	code, obj, _ := jade(t, inner, "mint", "--json")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "preflight.cilock-in-checkout" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// nested makes outer (a git checkout with an ignored .bin/tool exiting 0 and a tmp/) holding
// inner, a committed repository with manifest m. It returns outer and inner.
func nested(t *testing.T, m string) (string, string) {
	t.Helper()
	outer := t.TempDir()
	gitIn(t, outer, "init", "-q", "-b", "main")
	for _, d := range []string{".bin", "tmp", filepath.Join("inner", ".jade")} {
		if err := os.MkdirAll(filepath.Join(outer, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(outer, ".bin", "tool"), "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(filepath.Join(outer, ".bin", "tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(outer, "inner")
	gitIn(t, inner, "init", "-q", "-b", "main")
	write(t, filepath.Join(inner, ".jade", "workspace.json"), m)
	gitIn(t, inner, "add", ".")
	gitIn(t, inner, "commit", "-q", "-m", "init")
	return outer, inner
}

// Codex on #27: a TMPDIR inside a checkout enclosing the minted repository is refused too.
func TestTmpdirInsideEnclosingCheckoutRefused(t *testing.T) {
	outer, inner := nested(t, manifest)
	t.Setenv("TMPDIR", filepath.Join(outer, "tmp"))
	code, obj, _ := jade(t, inner, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "snapshot.tmpdir" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: an env.path directory inside a checkout enclosing the minted repository is
// dropped from a step's PATH, like one inside the repository itself.
func TestEnvPathInsideEnclosingCheckoutDropped(t *testing.T) {
	outer := t.TempDir()
	m := `{"env":{"path":["` + filepath.Join(outer, ".bin") + `"]},"steps":[{"name":"s","mode":"run","argv":["/bin/sh","-c","tool"]}]}`
	_ = os.RemoveAll(outer)
	o, inner := nested(t, m)
	if err := os.Rename(o, outer); err != nil {
		t.Fatal(err)
	}
	inner = filepath.Join(outer, "inner")
	rec := filepath.Join(t.TempDir(), "rec")
	if code, obj, all := jade(t, inner, "mint", "--json", "--cilock", runner(t, rec)); code == 0 {
		t.Fatalf("the outer checkout's .bin/tool ran: %v %s", obj, all)
	}
}

// Codex on #27: a tree entry written with a zero-padded mode (040000, which git accepts) is a
// tree all the same; its children are hashed too, so tampering one is caught.
func TestZeroPaddedTreeModeIsTraversed(t *testing.T) {
	dir := repo(t, manifest)
	run := func(stdin string, args ...string) string {
		c := exec.Command("git", args...)
		c.Dir = dir
		c.Stdin = strings.NewReader(stdin)
		out, err := c.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	b1 := run("ok\n", "hash-object", "-w", "--stdin")
	b2 := run("evil\n", "hash-object", "-w", "--stdin")
	t1 := run("100644 blob "+b1+"\tf\n", "mktree")
	t2 := run("100644 blob "+b2+"\tf\n", "mktree")
	id, _ := hex.DecodeString(t1)
	rootBody := append([]byte("040000 sub\x00"), id...)
	root := objectID("sha1", "tree", rootBody)
	objects := filepath.Join(dir, ".git", "objects")
	if err := writeLoose(objects, "tree", root, rootBody); err != nil {
		t.Fatal(err)
	}
	commit := run("", "-c", "user.name=t", "-c", "user.email=t@t", "commit-tree", root, "-m", "padded")
	g := &gitRunner{root: dir}
	if e := g.verifyObjects(dir, commit, "sha1", nil); e != nil {
		t.Fatalf("an intact padded tree was refused: %v", e)
	}
	// Tamper the child tree: t1's ID now holds t2's tree.
	raw, err := os.ReadFile(filepath.Join(objects, t2[:2], t2[2:]))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(objects, t1[:2], t1[2:])
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, raw, 0o444); err != nil {
		t.Fatal(err)
	}
	if e := g.verifyObjects(dir, commit, "sha1", nil); e == nil || e.Code != "objects.corrupt" {
		t.Fatalf("a tampered child of a padded tree entry passed: %v", e)
	}
}

// Codex on #27: the git jade runs is the path it validated: resolved once, checked, executed.
func TestResolveGitRunsTheValidatedPath(t *testing.T) {
	dir := repo(t, manifest)
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	linkDir := t.TempDir()
	if err := os.Symlink(realGit, filepath.Join(linkDir, "git")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", linkDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if e := resolveGit(dir); e != nil {
		t.Fatal(e)
	}
	if resolved, _ := filepath.EvalSymlinks(gitBin); resolved != gitBin {
		t.Fatalf("gitBin %s is not a resolved path (%s)", gitBin, resolved)
	}
}

// Codex on #27: git searches packs, the alternates' packs included, before loose objects, so the
// snapshot reads from its own copy of the object store, taken when the mint starts. Here step a
// deletes every pack in the user's store; later steps still read the commit and its history.
func TestSnapshotObjectStoreIsACopy(t *testing.T) {
	m := `{"env":{"pass":["PACKS"]},"steps":[` +
		`{"name":"a","mode":"run","argv":["/bin/sh","-c","rm -f \"$PACKS\"/*"]},` +
		`{"name":"b","mode":"run","argv":["/bin/sh","-c","test \"$(git show HEAD:f)\" = two && test \"$(git show HEAD~1:f)\" = one"]}]}`
	dir := repo(t, m)
	write(t, filepath.Join(dir, "f"), "one\n")
	gitIn(t, dir, "add", "f")
	gitIn(t, dir, "commit", "-q", "-m", "one")
	write(t, filepath.Join(dir, "f"), "two\n")
	gitIn(t, dir, "commit", "-q", "-am", "two")
	gitIn(t, dir, "repack", "-a", "-d", "-q")
	gitIn(t, dir, "prune-packed")
	packs := filepath.Join(dir, ".git", "objects", "pack")
	t.Setenv("PACKS", packs)
	rec := filepath.Join(t.TempDir(), "rec")
	if code, obj, all := jade(t, dir, "mint", "--json", "--cilock", runner(t, rec)); code != 0 {
		t.Fatalf("the snapshot depended on the user's packs: %v %s", obj, all)
	}
	if left, _ := os.ReadDir(packs); len(left) != 0 {
		t.Fatalf("control: step a should have removed the packs, %d left", len(left))
	}
}

// Codex on #27: a symlink anywhere in the object store would keep the snapshot's copy tied to
// files outside it, so a store containing one is refused.
func TestSnapshotRefusesSymlinkedObjectStore(t *testing.T) {
	dir := repo(t, manifest)
	gitIn(t, dir, "repack", "-a", "-d", "-q")
	pack := filepath.Join(dir, ".git", "objects", "pack")
	moved := filepath.Join(t.TempDir(), "pack")
	if err := os.Rename(pack, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, pack); err != nil {
		t.Fatal(err)
	}
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "snapshot.symlink" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: history is verified too. A parent commit rewritten under its original ID to name
// HEAD's tree makes git diff HEAD^ HEAD empty; the snapshot's full object check refuses it.
func TestForgedParentCommitRefused(t *testing.T) {
	dir := repo(t, manifest)
	write(t, filepath.Join(dir, "f"), "one\n")
	gitIn(t, dir, "add", "f")
	gitIn(t, dir, "commit", "-q", "-m", "one")
	write(t, filepath.Join(dir, "f"), "two\n")
	gitIn(t, dir, "commit", "-q", "-am", "two")
	parent := gitIn(t, dir, "rev-parse", "HEAD^")
	headTree := gitIn(t, dir, "rev-parse", "HEAD^{tree}")
	body := gitIn(t, dir, "cat-file", "commit", parent) + "\n"
	first, rest, _ := strings.Cut(body, "\n")
	if !strings.HasPrefix(first, "tree ") {
		t.Fatalf("unexpected commit %q", body)
	}
	forged := []byte("tree " + headTree + "\n" + rest)
	var raw bytes.Buffer
	zw := zlib.NewWriter(&raw)
	fmt.Fprintf(zw, "commit %d\x00", len(forged))
	zw.Write(forged)
	zw.Close()
	p := filepath.Join(dir, ".git", "objects", parent[:2], parent[2:])
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, raw.Bytes(), 0o444); err != nil {
		t.Fatal(err)
	}
	if d := gitIn(t, dir, "diff", "--stat", "HEAD^", "HEAD"); d != "" {
		t.Fatalf("control: the forged parent should make the diff empty, got %q", d)
	}
	code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
	e, _ := obj["error"].(map[string]any)
	if code != 3 || e == nil || e["code"] != "objects.corrupt" {
		t.Fatalf("exit %d obj %v", code, obj)
	}
}

// Codex on #27: the checks on the object store run on the snapshot's own copy, after it is made,
// so a symlink or alternates file that appears in the source between a check and the copy is
// still refused. afterClone stands in for that race, planting both in the copy.
func TestCopiedStoreIsCheckedAfterTheCopy(t *testing.T) {
	for _, plant := range []string{"symlink", "alternates"} {
		dir := repo(t, manifest)
		outside := t.TempDir()
		afterClone = func(store string) {
			switch plant {
			case "symlink":
				os.Symlink(outside, filepath.Join(store, "pack", "elsewhere"))
			case "alternates":
				os.MkdirAll(filepath.Join(store, "info"), 0o755)
				os.WriteFile(filepath.Join(store, "info", "alternates"), []byte(outside+"\n"), 0o644)
			}
		}
		code, obj, _ := jade(t, dir, "mint", "--json", "--cilock", "/bin/echo")
		afterClone = nil
		e, _ := obj["error"].(map[string]any)
		want := "snapshot." + plant
		if code != 3 || e == nil || e["code"] != want {
			t.Fatalf("%s: exit %d obj %v, want %s", plant, code, obj, want)
		}
	}
}

// Codex on #27: a symlinked TMPDIR is resolved once and the snapshot is made under the resolved
// directory, so retargeting the link afterwards (here an ignored link in the checkout pointing
// outside it) cannot point jade at a different snapshot or guard.
func TestSnapshotUsesResolvedTmpdir(t *testing.T) {
	dir := repo(t, manifest)
	write(t, filepath.Join(dir, ".gitignore"), "tmplink\n")
	gitIn(t, dir, "add", ".gitignore")
	gitIn(t, dir, "commit", "-q", "-m", "ignore")
	ext := t.TempDir()
	realExt, err := filepath.EvalSymlinks(ext)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "tmplink")
	if err := os.Symlink(ext, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", link)
	if e := resolveGit(dir); e != nil {
		t.Fatal(e)
	}
	g := &gitRunner{root: dir, head: gitIn(t, dir, "rev-parse", "HEAD")}
	defer g.removeSnapshot()
	if e := g.snapshot(); e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(g.snapParent, realExt+string(filepath.Separator)) {
		t.Fatalf("snapshot at %s, not under the resolved TMPDIR %s", g.snapParent, realExt)
	}
	if g := guardPath(g, "jade"); !strings.HasPrefix(g, realExt) {
		t.Fatalf("guard at %s", g)
	}
}

// Codex on #27: a shallow clone, as CI makes, mints: the snapshot carries the shallow boundary
// before fsck, so the commits the clone left out are not reported missing.
func TestMintFromShallowClone(t *testing.T) {
	src := repo(t, manifest)
	write(t, filepath.Join(src, "f"), "one\n")
	gitIn(t, src, "add", "f")
	gitIn(t, src, "commit", "-q", "-m", "one")
	write(t, filepath.Join(src, "f"), "two\n")
	gitIn(t, src, "commit", "-q", "-am", "two")
	parent := t.TempDir()
	clone := filepath.Join(parent, "clone")
	gitIn(t, parent, "clone", "-q", "--depth", "1", "file://"+src, clone)
	if code, obj, all := jade(t, clone, "mint", "--json", "--cilock", "/bin/echo"); code != 0 {
		t.Fatalf("exit %d obj %v %s", code, obj, all)
	}
}
