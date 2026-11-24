// Command jade runs the checks a push must prove and records their evidence with cilock, from
// the steps declared in .jade/workspace.json. It is built for AI agents first: every command takes
// --json and then prints one JSON object; exit codes are 0 done, 1 a check failed, 2 usage or
// manifest error, 3 refused before running, 4 transient; every failure names the next command.
// Design: DESIGN.md. Model: testifysec/formal/jade. Only the Go standard library.
package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/aflock-ai/badger/testifysec/jade/core"
)

const manifestPath = ".jade/workspace.json"

func main() {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(core.ExitRefused)
	}
	os.Exit(run(os.Args[1:], wd, os.Stdout, os.Stderr))
}

// output prints a result: one JSON object in --json mode, otherwise lines for a person.
type output struct {
	json   bool
	stdout io.Writer
	stderr io.Writer
}

func (o output) emit(obj map[string]any, human func(io.Writer)) {
	obj["schema_version"] = core.SchemaVersion
	if o.json {
		b, _ := json.Marshal(obj)
		fmt.Fprintln(o.stdout, string(b))
		return
	}
	human(o.stdout)
}

func (o output) fail(e *core.Error, extra map[string]any) int {
	obj := map[string]any{"exit_code": e.Exit, "error": e}
	for k, v := range extra {
		obj[k] = v
	}
	o.emit(obj, func(w io.Writer) {})
	if !o.json {
		fmt.Fprintf(o.stderr, "jade: %s (%s)\nnext: %s\n", e.Message, e.Code, e.Remedy)
	}
	return e.Exit
}

func run(args []string, wd string, stdout, stderr io.Writer) int {
	o := output{json: hasFlag(args, "--json"), stdout: stdout, stderr: stderr}
	if len(args) == 0 {
		return o.fail(usageErr("usage.command", "no command given"), nil)
	}
	if args[0] != "help" && args[0] != "-h" && args[0] != "--help" {
		if e := resolveGit(wd); e != nil {
			return o.fail(e, nil)
		}
	}
	switch args[0] {
	case "plan":
		return cmdPlan(args[1:], wd, o)
	case "mint":
		return cmdMint(args[1:], wd, o)
	case "query":
		return cmdQuery(args[1:], wd, o)
	case "doctor":
		return cmdDoctor(args[1:], wd, o)
	case "step-guard": // internal: what cilock runs for each run step (see guarded)
		return cmdStepGuard(args[1:], wd, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, help)
		return core.ExitOK
	default:
		return o.fail(usageErr("usage.command", "unknown command "+args[0]), nil)
	}
}

const help = `jade: run and record the checks a push must prove (.jade/workspace.json)

  jade plan   [--only STEP]... [--json]      what would run, with exact argv; runs nothing
  jade mint   [--only STEP]... [--json] [--cilock PATH]
                                             preflight, then run each step with cilock, stopping
                                             at the first failure
  jade query  steps | needs STEP | rdeps STEP [--json]
  jade doctor [--json] [--cilock PATH]       is this checkout ready to mint?

exit codes: 0 done, 1 a check failed, 2 usage or manifest error, 3 refused before running,
4 transient (retry). With --json every result is one object with schema_version, exit_code and,
on failure, error.code, error.message, error.remedy and error.retryable.
`

func usageErr(code, msg string) *core.Error {
	return &core.Error{Code: code, Message: msg, Remedy: "run: jade help", Exit: core.ExitUsage}
}

func hasFlag(args []string, f string) bool {
	for _, a := range args {
		if a == f {
			return true
		}
	}
	return false
}

// listFlag collects a repeatable flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

type opts struct {
	json   bool
	only   listFlag
	cilock string
	rest   []string
}

func parse(name string, args []string, withOnly, withCilock bool) (opts, *core.Error) {
	var op opts
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&op.json, "json", false, "")
	if withOnly {
		fs.Var(&op.only, "only", "")
	}
	if withCilock {
		fs.StringVar(&op.cilock, "cilock", "", "")
	}
	// Flags may follow positional arguments: parse, take one positional, repeat.
	for {
		if err := fs.Parse(args); err != nil {
			return op, usageErr("usage.flag", err.Error())
		}
		if fs.NArg() == 0 {
			break
		}
		op.rest = append(op.rest, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return op, nil
}

// repoRoot is the repository's top directory, or an error when wd is not in one.
func repoRoot(wd string) (string, error) {
	c := gitCmd("rev-parse", "--show-toplevel")
	c.Dir = wd
	out, err := c.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func loadManifest(wd string) (*core.Manifest, string, *core.Error) {
	root, err := repoRoot(wd)
	if err != nil {
		return nil, "", &core.Error{Code: "preflight.no-repo", Message: wd + " is not inside a git repository",
			Remedy: "run jade from inside the repository", Exit: core.ExitRefused}
	}
	m, lerr := core.Load(filepath.Join(root, manifestPath))
	if lerr != nil {
		var e *core.Error
		errors.As(lerr, &e)
		return nil, root, e
	}
	if verr := m.Validate(); verr != nil {
		var e *core.Error
		errors.As(verr, &e)
		return nil, root, e
	}
	return m, root, nil
}

// manifestAt reads the manifest as committed at head, never the working copy: what a mint runs
// is what that commit says.
func manifestAt(root, head string) (*core.Manifest, []byte, *core.Error) {
	c := gitCmd("cat-file", "blob", head+":"+manifestPath)
	c.Dir = root
	b, err := c.Output()
	if err != nil {
		return nil, nil, &core.Error{Code: "manifest.missing", Message: manifestPath + " is not committed at " + head,
			Remedy: "commit " + manifestPath + ", then run: jade mint", Exit: core.ExitUsage}
	}
	m, perr := core.Parse(b)
	if perr == nil {
		perr = m.Validate()
	}
	if perr != nil {
		var e *core.Error
		errors.As(perr, &e)
		return nil, nil, e
	}
	return m, b, nil
}

// cilockPath is the cilock binary as an absolute path when it can be found: steps run in the
// snapshot, so a relative --cilock (relative to where jade was run) or a name found on PATH is
// resolved here, before anything changes directory. Without --cilock it is cilock on PATH, never
// a file in the checkout: an uncommitted .bin/cilock that exits 0 would record nothing and pass.
func cilockPath(flagValue, wd string) string {
	p := flagValue
	if p == "" {
		p = "cilock"
	}
	if strings.Contains(p, "/") {
		if !filepath.IsAbs(p) {
			p = filepath.Join(wd, p)
		}
		return p
	}
	if found, err := exec.LookPath(p); err == nil {
		if abs, err := filepath.Abs(found); err == nil {
			return abs
		}
	}
	return p
}

func cmdPlan(args []string, wd string, o output) int {
	op, e := parse("plan", args, true, true)
	if e != nil {
		return o.fail(e, nil)
	}
	m, _, e := loadManifest(wd)
	if e != nil {
		return o.fail(e, nil)
	}
	plan, err := m.Plan(op.only)
	if err != nil {
		var pe *core.Error
		errors.As(err, &pe)
		return o.fail(pe, nil)
	}
	cilock := cilockPath(op.cilock, wd)
	type planned struct {
		Name string   `json:"name"`
		Mode string   `json:"mode"`
		Argv []string `json:"argv"`
	}
	var steps []planned
	for _, s := range plan {
		steps = append(steps, planned{s.Name, string(s.Mode), core.Argv(cilock, guarded(s, selfPath()))})
	}
	o.emit(map[string]any{"exit_code": core.ExitOK, "steps": steps}, func(w io.Writer) {
		for i, s := range steps {
			fmt.Fprintf(w, "%d. %s: %s\n", i+1, s.Name, core.Describe(s.Argv))
		}
	})
	return core.ExitOK
}

func cmdQuery(args []string, wd string, o output) int {
	op, e := parse("query", args, false, false)
	if e != nil {
		return o.fail(e, nil)
	}
	m, _, e := loadManifest(wd)
	if e != nil {
		return o.fail(e, nil)
	}
	if len(op.rest) == 0 {
		return o.fail(usageErr("usage.query", "query needs steps, needs STEP or rdeps STEP"), nil)
	}
	byName := map[string]core.Step{}
	for _, s := range m.Steps {
		byName[s.Name] = s
	}
	var result []string
	switch op.rest[0] {
	case "steps":
		for _, s := range m.Steps {
			result = append(result, s.Name)
		}
	case "needs", "rdeps":
		if len(op.rest) != 2 {
			return o.fail(usageErr("usage.query", "query "+op.rest[0]+" takes one step name"), nil)
		}
		target := op.rest[1]
		if _, ok := byName[target]; !ok {
			return o.fail(&core.Error{Code: "step.unknown", Message: "step " + target + " is not in the manifest",
				Remedy: "run: jade query steps", Exit: core.ExitUsage}, nil)
		}
		if op.rest[0] == "needs" {
			plan, _ := m.Plan([]string{target})
			for _, s := range plan {
				if s.Name != target {
					result = append(result, s.Name)
				}
			}
		} else {
			// Everything whose plan includes target, in file order.
			for _, s := range m.Steps {
				if s.Name == target {
					continue
				}
				plan, _ := m.Plan([]string{s.Name})
				for _, p := range plan {
					if p.Name == target {
						result = append(result, s.Name)
						break
					}
				}
			}
		}
	default:
		return o.fail(usageErr("usage.query", "unknown query "+op.rest[0]), nil)
	}
	if result == nil {
		result = []string{}
	}
	o.emit(map[string]any{"exit_code": core.ExitOK, "steps": result}, func(w io.Writer) {
		for _, s := range result {
			fmt.Fprintln(w, s)
		}
	})
	return core.ExitOK
}

// gitRunner is core.Runner against a real checkout: preflight reads git, each step runs cilock
// with its output in a log file.
type gitRunner struct {
	root, wd, cilock, logDir string
	head                     string   // the commit the mint is bound to, read once before anything else
	mint                     bool     // a mint (not doctor): Preflight ends by writing the snapshot
	cilockImplicit           bool     // no --cilock: cilock came from PATH and must not be the checkout's
	env                      core.Env // the manifest's env: what steps get beyond the strict defaults
	manifest                 []byte   // the manifest bytes the mint parsed, checked against the snapshot
	selfExe                  string   // this jade, resolved and checked; the guard is copied from it
	work, snapParent         string   // the snapshot the steps run in, and its private parent directory
	logs                     map[string]string
	stream                   io.Writer
}

// gitStrict is prepended to every git call, and a command-line -c outranks every config file:
// no filesystem monitor or cache may answer for the tree, a file whose ctime or inode changed is
// re-read, names compare case-sensitively (core.ignoreCase would hide "makefile" beside a
// committed "Makefile"), and no global excludes file is read (it applies its rules from the root,
// even one pointed at a committed nested .gitignore), so only .gitignore files and
// .git/info/exclude can ignore anything, and ignoredByCommittedRules refuses the latter.
var gitStrict = []string{"-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
	"-c", "core.checkStat=default", "-c", "core.trustctime=true", "-c", "core.ignoreStat=false",
	"-c", "core.ignoreCase=false", "-c", "core.excludesFile=/dev/null", "-c", "core.hooksPath=/dev/null"}

// noReplace turns off git replace refs, for jade's git calls and for every step: with them on,
// a replacement can swap HEAD's tree while rev-parse HEAD still names the original commit.
const noReplace = "GIT_NO_REPLACE_OBJECTS=1"

// repoLocal is git's own list (git rev-parse --local-env-vars): variables that choose which
// repository, index or object store git reads. One exported by a hook would point jade, a step,
// or a submodule's git at another repository, so none is passed on.
var repoLocal = []string{"GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS",
	"GIT_CONFIG_COUNT", "GIT_OBJECT_DIRECTORY", "GIT_DIR", "GIT_WORK_TREE", "GIT_IMPLICIT_WORK_TREE",
	"GIT_GRAFT_FILE", "GIT_INDEX_FILE", "GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE", "GIT_PREFIX",
	"GIT_SHALLOW_FILE", "GIT_COMMON_DIR"}

// gitEnv is the environment for jade's own git calls: the same allowlist steps get (passEnv),
// nothing else from the caller, so neither a loader variable (LD_*, DYLD_*) nor a shell startup
// file (BASH_ENV) reaches a git that is, say, a bash wrapper. PATH is strictPath behind git's
// own directory. Replace refs and lazy fetching are off (in a partial clone a missing object is
// an error, never a request to the remote).
func gitEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if (slices.Contains(passEnv, k) || slices.ContainsFunc(passEnvPrefix, func(p string) bool { return strings.HasPrefix(k, p) })) &&
			!slices.Contains(repoLocal, k) && !strings.HasPrefix(k, "GIT_CONFIG_") {
			env = append(env, kv)
		}
	}
	path := strictPath
	if filepath.IsAbs(gitBin) {
		path = filepath.Dir(gitBin) + string(os.PathListSeparator) + path
	}
	return append(env, "PATH="+path, noReplace, "GIT_NO_LAZY_FETCH=1")
}

// strictPath is a step's PATH before the manifest adds to it: Bazel's strict action env default.
const strictPath = "/bin:/usr/bin:/usr/local/bin"

// passEnv is what a step inherits from the caller without the manifest asking: identity, locale
// and terminal, and the variables cilock needs to sign (its own CILOCK_*, and a CI runner's OIDC
// and context variables). Everything else (BASH_ENV, NODE_OPTIONS, LD_PRELOAD, GOFLAGS, the
// caller's PATH) is dropped unless the committed manifest names it in env.pass.
var passEnv = []string{"HOME", "USER", "LOGNAME", "TMPDIR", "TERM", "TZ", "LANG", "SSH_AUTH_SOCK", "CI"}
var passEnvPrefix = []string{"LC_", "CILOCK_", "GITHUB_", "ACTIONS_ID_TOKEN_REQUEST_"}

// stepEnv is a step's whole environment, built rather than inherited (Bazel's strict action
// env): passEnv and the manifest's env.pass from the caller, PATH as strictPath plus env.path
// (minus anything inside the checkout, see pathOutside), and git's restrictions: no
// repository-local variables, no replace refs or lazy fetching, and gitStrict as
// GIT_CONFIG_COUNT/KEY/VALUE, which git ranks with -c, so a step's own git runs no configured
// fsmonitor or hook.
func stepEnv(checkout, base string, extra core.Env) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if slices.Contains(passEnv, k) || slices.Contains(extra.Pass, k) ||
			slices.ContainsFunc(passEnvPrefix, func(p string) bool { return strings.HasPrefix(k, p) }) {
			if !slices.Contains(repoLocal, k) && !strings.HasPrefix(k, "GIT_CONFIG_") && k != "PATH" {
				env = append(env, kv)
			}
		}
		// A CI job's workspace is the checkout it cloned; for a step it is the snapshot, so cd
		// "$GITHUB_WORKSPACE" lands on the verified tree, not the original checkout.
		if k == "GITHUB_WORKSPACE" {
			env = append(slices.DeleteFunc(env, func(e string) bool { return strings.HasPrefix(e, "GITHUB_WORKSPACE=") }),
				"GITHUB_WORKSPACE="+base)
		}
	}
	path := strictPath
	for _, d := range extra.Path {
		if strings.HasPrefix(d, "~/") {
			d = filepath.Join(os.Getenv("HOME"), d[2:])
		}
		path += string(os.PathListSeparator) + d
	}
	env = append(env, "PATH="+pathOutside(path, checkout, base), noReplace, "GIT_NO_LAZY_FETCH=1")
	n := 0
	for i := 0; i+1 < len(gitStrict); i += 2 {
		k, v, _ := strings.Cut(gitStrict[i+1], "=")
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", n, k), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", n, v))
		n++
	}
	return append(env, fmt.Sprintf("GIT_CONFIG_COUNT=%d", n))
}

// pathOutside is PATH without the directories that resolve (symlinks followed) into checkout or
// any checkout enclosing it (see insideAnyCheckout):
// the snapshot does not protect the user's checkout, so an ignored node_modules/.bin/check there
// could stand in for the check a committed step names. Relative entries are resolved against
// base, the directory the step starts in, checked, and passed on as that absolute path.
func pathOutside(path, checkout, base string) string {
	var keep []string
	for _, d := range filepath.SplitList(path) {
		// Kept entries are passed on absolute: a relative one would resolve differently once a
		// step changes directory, possibly into the checkout.
		resolved := d
		if !filepath.IsAbs(d) {
			resolved = filepath.Join(base, d)
		}
		// Kept entries are the directories they resolve to now, so retargeting a symlink after
		// this check changes nothing; an entry that does not resolve is dropped.
		real, err := filepath.EvalSymlinks(resolved)
		if err == nil && !insideAnyCheckout(checkout, real) {
			keep = append(keep, real)
		}
	}
	return strings.Join(keep, string(os.PathListSeparator))
}

// inside reports whether p resolves (symlinks followed) to dir or below it. A path that does not
// resolve is not inside anything.
func inside(dir, p string) bool {
	top, errTop := filepath.EvalSymlinks(dir)
	real, errReal := filepath.EvalSymlinks(p)
	if errTop != nil || errReal != nil {
		return false
	}
	rel, err := filepath.Rel(top, real)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// self is the jade binary, which cilock runs as each step's guard. Tests point it at a built jade.
var self = os.Executable

// guarded is s with its command wrapped as GUARD step-guard -- COMMAND, so the tree check runs
// inside the command cilock attests (see cmdStepGuard). An attest step has no command.
func guarded(s core.Step, guard string) core.Step {
	if s.Mode != core.ModeRun {
		return s
	}
	s.Argv = append([]string{guard, "step-guard", "--"}, s.Argv...)
	return s
}

// selfPath is the running jade, or "jade" if the OS cannot say.
func selfPath() string {
	exe, err := self()
	if err != nil {
		return "jade"
	}
	return exe
}

// guardPath is the jade binary cilock runs as the guard: during a mint, the private copy
// snapshot made in its 0700 directory, so replacing the binary the mint was started from (an
// ignored .bin/jade, say) cannot substitute a guard that skips the step; otherwise jade itself.
func guardPath(g *gitRunner, exe string) string {
	if g.snapParent == "" {
		return exe
	}
	return filepath.Join(g.snapParent, "jade-guard")
}

// cmdStepGuard runs a step's command, then checks that the snapshot is still clean at the pinned
// commit (JADE_HEAD) before exiting. cilock 4.5.0 uploads a step's evidence when the command ends
// and cannot defer that, so the check has to be part of the command it records: a step that
// edits a tracked file, or commits, and exits 0 is recorded as a failed command (exit 3), and
// that evidence cannot satisfy a policy that requires the step to pass. Otherwise the step's own
// exit code is passed through.
func cmdStepGuard(args []string, wd string, stderr io.Writer) int {
	head := os.Getenv("JADE_HEAD")
	if len(args) < 2 || args[0] != "--" || head == "" {
		fmt.Fprintln(stderr, "jade step-guard: internal to jade mint: JADE_HEAD=<commit> jade step-guard -- COMMAND...")
		return core.ExitUsage
	}
	c := exec.Command(args[1], args[2:]...)
	c.Dir = wd
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	rc := 0
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() > 0 {
			rc = ee.ExitCode()
		} else {
			fmt.Fprintln(stderr, "jade step-guard:", err)
			rc = 1
		}
	}
	g := &gitRunner{root: wd, head: head}
	if now, err := g.gitIn(wd, "rev-parse", "HEAD"); err != nil || now != head {
		fmt.Fprintf(stderr, "jade step-guard: HEAD moved from %s to %s during the step; failing it\n", head, now)
		return core.ExitRefused
	}
	if e := g.clean(wd, "after the step"); e != nil {
		fmt.Fprintf(stderr, "jade step-guard: %s; failing the step\n", e.Message)
		return core.ExitRefused
	}
	return rc
}

// insideAnyCheckout reports whether p resolves into any checkout enclosing start: every directory
// from start's real location up to / that has a .git, not just the nearest (a .git planted in a
// subdirectory must not hide the checkout above it, and a repository may sit inside another).
// It runs no git.
func insideAnyCheckout(start, p string) bool {
	if real, err := filepath.EvalSymlinks(start); err == nil {
		start = real
	}
	for d := start; ; d = filepath.Dir(d) {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil && inside(d, p) {
			return true
		}
		if filepath.Dir(d) == d {
			return false
		}
	}
}

// gitBin is the git jade runs, an absolute path resolved by resolveGit before any git command.
var gitBin = "git"

// resolveGit finds git on PATH and refuses one inside the checkout, before running any git: an
// ignored .bin/git first on PATH would otherwise run with jade's first call. The checkout is
// found by walking up from wd to the nearest .git, which needs no git.
func resolveGit(wd string) *core.Error {
	// Resolve once, check that path, run that path: no second lookup a symlink could answer
	// differently.
	p, err := exec.LookPath("git")
	if err == nil {
		p, err = filepath.Abs(p)
	}
	if err == nil {
		p, err = filepath.EvalSymlinks(p)
	}
	if err != nil {
		return &core.Error{Code: "preflight.no-git", Message: "git not found on PATH", Remedy: "install git, then run: jade doctor",
			Exit: core.ExitRefused}
	}
	if insideAnyCheckout(wd, p) {
		return &core.Error{Code: "preflight.git-in-checkout", Message: "the git on PATH is inside the checkout: " + p,
			Remedy: "put a git installed outside the repository first on PATH, then run: jade doctor", Exit: core.ExitRefused}
	}
	gitBin = p
	return nil
}

// gitCmd is every git command jade runs: strict config, gitEnv, and literal pathspecs, so a file
// named ":(glob)x" is that file and not pattern magic.
func gitCmd(args ...string) *exec.Cmd {
	c := exec.Command(gitBin, append(append([]string{}, gitStrict...), args...)...)
	c.Env = append(gitEnv(), "GIT_LITERAL_PATHSPECS=1")
	return c
}

func (g *gitRunner) git(args ...string) (string, error) { return g.gitIn(g.root, args...) }

func (g *gitRunner) gitIn(dir string, args ...string) (string, error) {
	out, err := g.gitRaw(dir, args...)
	return strings.TrimSpace(out), err
}

// gitRaw is gitIn without trimming, for -z listings: a file name can begin or end with spaces.
// A listing is complete or it is an error: git warns about a directory it cannot read and still
// exits 0, leaving that directory out, so anything on stderr fails the call.
func (g *gitRunner) gitRaw(dir string, args ...string) (string, error) {
	c := gitCmd(args...)
	c.Dir = dir
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err == nil && stderr.Len() > 0 {
		err = fmt.Errorf("git %s: %s", args[0], strings.TrimSpace(stderr.String()))
	}
	return string(out), err
}

func (g *gitRunner) Preflight() *core.Error {
	a, errA := filepath.EvalSymlinks(g.root)
	b, errB := filepath.EvalSymlinks(g.wd)
	if errA != nil || errB != nil || a != b {
		return &core.Error{Code: "preflight.not-root", Message: "jade mint runs from the repository root " + g.root + ", not " + g.wd,
			Remedy: "run: " + core.Describe([]string{"cd", g.root}) + " && jade mint", Exit: core.ExitRefused}
	}
	gitDir, err := g.git("rev-parse", "--absolute-git-dir")
	if err != nil {
		return &core.Error{Code: "preflight.no-repo", Message: "cannot locate the git directory", Remedy: "run jade inside the repository", Exit: core.ExitRefused}
	}
	for _, marker := range []string{"MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply"} {
		if _, err := os.Stat(filepath.Join(gitDir, marker)); err == nil {
			return &core.Error{Code: "preflight.in-progress", Message: marker + " exists: a merge, rebase, cherry-pick or revert is in progress",
				Remedy: "finish or abort it, then run: jade mint", Exit: core.ExitRefused}
		}
	}
	if e := g.clean(g.root, "before the mint"); e != nil {
		return e
	}
	found, err := exec.LookPath(g.cilock)
	if err != nil {
		return &core.Error{Code: "preflight.no-cilock", Message: "cilock not found: " + g.cilock,
			Remedy: "install cilock (https://cilock.dev/install.sh), then run: jade doctor", Exit: core.ExitRefused}
	}
	// From here on cilock is run by the file this check resolved, so retargeting a symlink the
	// lookup went through cannot swap it later.
	if real, err := filepath.EvalSymlinks(found); err == nil {
		g.cilock = real
	}
	// A cilock found on PATH must not be the checkout's own file, whether its directory is on
	// PATH or a symlink points into the checkout: an uncommitted fake that exits 0 would record
	// nothing and pass. Naming one with --cilock is an explicit choice and is allowed.
	if g.cilockImplicit {
		if _, err := filepath.EvalSymlinks(g.cilock); err != nil || insideAnyCheckout(g.root, g.cilock) {
			return &core.Error{Code: "preflight.cilock-in-checkout", Message: "the cilock on PATH is inside the checkout: " + g.cilock,
				Remedy: "install cilock outside the repository and put that first on PATH, or name one with --cilock",
				Exit:   core.ExitRefused}
		}
	}
	if g.mint {
		// The guard is a copy of this jade, made from its path; one inside the checkout (an
		// ignored .bin/jade) could be replaced before the copy. jade lives outside the
		// repository, like git and cilock.
		exe := selfPath()
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		g.selfExe = exe
		if insideAnyCheckout(g.root, exe) {
			return &core.Error{Code: "preflight.jade-in-checkout", Message: "jade is running from inside the checkout: " + exe,
				Remedy: "install jade outside the repository (go -C testifysec/jade build -o ~/.local/bin/jade .), then run: jade mint",
				Exit:   core.ExitRefused}
		}
		if e := g.snapshot(); e != nil {
			return e
		}
		// The manifest was read from the object store before the snapshot existed. The snapshot's
		// copy was written from a blob that verifyTree rehashed under a hash-checked tree chain,
		// so the bytes jade runs must equal it.
		if g.manifest != nil {
			b, err := os.ReadFile(filepath.Join(g.work, manifestPath))
			if err != nil || !bytes.Equal(b, g.manifest) {
				return &core.Error{Code: "manifest.changed", Message: "the manifest jade read is not the one in the verified commit",
					Remedy: "something changed the repository's objects during the mint; re-clone it, then run: jade mint",
					Exit:   core.ExitRefused}
			}
		}
	}
	return nil
}

// snapshot writes the pinned commit into a fresh repository of its own, in a private (0700)
// temporary directory, and the steps run there. cilock uploads each step's evidence as the step
// ends, so a commit or checkout in the user's checkout mid-step would otherwise be recorded and
// published before jade could refuse it; nothing else knows the snapshot's path. It is not a
// linked worktree: that would share the user's repository-local config, info/attributes, hooks
// and refs (filters, replace refs) with every step's git. The snapshot reads the user's objects
// through objects/info/alternates, has HEAD detached at the pinned commit, and copies only the
// remote URLs. git writes no file (a checkout would run filters): jade writes each from its raw
// blob, builds the index with read-tree, then verifies the result like any other tree.
// Submodules would have to be fetched, so a commit with one is refused.
func (g *gitRunner) snapshot() *core.Error {
	refuse := func(code, msg string) *core.Error {
		return &core.Error{Code: code, Message: msg, Remedy: "fix the cause, then run: jade mint", Exit: core.ExitRefused}
	}
	// Never inside the checkout: tools that search ancestor directories (node_modules, say)
	// would find its ignored files from the snapshot.
	tmp, err := tempDir()
	if err != nil {
		return core.Transient("cannot resolve the temporary directory: " + err.Error())
	}
	if insideAnyCheckout(g.root, tmp) {
		return refuse("snapshot.tmpdir", "the temporary directory "+tmp+" is inside the checkout")
	}
	parent, err := os.MkdirTemp(tmp, "jade-snapshot-")
	if err != nil {
		return core.Transient("cannot create a snapshot directory: " + err.Error())
	}
	g.snapParent = parent
	// The guard is a private copy of this jade (see guardPath).
	exe, err := g.selfExe, error(nil)
	if exe == "" {
		exe, err = self()
	}
	if err == nil {
		var b []byte
		if b, err = os.ReadFile(exe); err == nil {
			err = os.WriteFile(guardPath(g, exe), b, 0o700)
		}
	}
	if err != nil {
		return core.Transient("cannot copy jade into the snapshot directory: " + err.Error())
	}
	work := filepath.Join(parent, "tree")
	if err := os.Mkdir(work, 0o700); err != nil {
		return core.Transient("cannot create a snapshot directory: " + err.Error())
	}
	common, err := g.gitIn(g.root, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return refuse("snapshot.create", "cannot locate the repository's objects")
	}
	format, err := g.gitIn(g.root, "rev-parse", "--show-object-format")
	if err != nil {
		return refuse("snapshot.create", "cannot read the repository's object format")
	}
	if _, err := g.gitIn(work, "init", "--quiet", "--template=", "--object-format="+format); err != nil {
		return refuse("snapshot.create", "cannot create the snapshot repository: "+err.Error())
	}
	dotGit := filepath.Join(work, ".git")
	if err := os.MkdirAll(filepath.Join(dotGit, "objects", "info"), 0o755); err != nil {
		return refuse("snapshot.create", err.Error())
	}
	// The snapshot's alternates are a copy of the user's object store taken now, not the store
	// itself: git searches every pack, the alternates' included, before loose objects, so a pack
	// changed or removed mid-mint would otherwise change what a step reads. The copy is a
	// copy-on-write clone where the filesystem has one (APFS, reflink), so it costs little.
	src := filepath.Join(common, "objects")
	store := filepath.Join(parent, "objects")
	if err := cloneDir(src, store); err != nil {
		return refuse("snapshot.create", "cannot copy the object store: "+err.Error())
	}
	if afterClone != nil {
		afterClone(store)
	}
	// Checked on the copy, the only store the snapshot uses, after it is made: a check on the
	// source could be raced. An alternates file would borrow objects from a mutable store, and cp
	// -R copies a symlink as a symlink, which would keep the copy tied to files outside it.
	if _, err := os.Lstat(filepath.Join(store, "info", "alternates")); err == nil {
		return refuse("snapshot.alternates", "the repository borrows objects from elsewhere (objects/info/alternates); jade will not mint from it")
	}
	if err := filepath.WalkDir(store, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", strings.TrimPrefix(path, store+"/"))
		}
		return nil
	}); err != nil {
		return refuse("snapshot.symlink", "the object store holds a symlink jade will not use: "+err.Error())
	}
	if err := os.WriteFile(filepath.Join(dotGit, "objects", "info", "alternates"), []byte(store+"\n"), 0o644); err != nil {
		return refuse("snapshot.create", err.Error())
	}
	// The shallow boundary comes first, so nothing that walks history treats the commits a
	// shallow clone left out as missing.
	if b, err := os.ReadFile(filepath.Join(common, "shallow")); err == nil {
		if err := os.WriteFile(filepath.Join(dotGit, "shallow"), b, 0o644); err != nil {
			return refuse("snapshot.create", err.Error())
		}
	}
	// Steps read history too (git diff HEAD^ HEAD, merge bases), so every object in the copy is
	// rehashed, not just the pinned commit's: a parent rewritten under its own ID would otherwise
	// hide a change. git fsck --full rehashes loose and packed objects (about 6s for badger).
	fsck := gitCmd("fsck", "--full", "--no-dangling", "--no-progress")
	fsck.Dir = work
	if out, err := fsck.CombinedOutput(); err != nil {
		return &core.Error{Code: "objects.corrupt", Message: "the repository's objects do not match their IDs: " + firstLine(strings.TrimSpace(string(out))),
			Remedy: "re-clone the repository, then run: jade mint", Exit: core.ExitRefused}
	}
	// The pinned commit's objects are copied into the snapshot's own store, each rehashed against
	// its ID on the way: git reads its own store before the alternates, so a later change to the
	// user's object store cannot change what a step reads at HEAD. History older than the commit
	// still comes through the alternates.
	objects := filepath.Join(dotGit, "objects")
	if e := g.verifyObjects(work, g.head, format, func(kind, id string, body []byte) error {
		return writeLoose(objects, kind, id, body)
	}); e != nil {
		return e
	}
	if _, err := g.gitIn(work, "update-ref", "--no-deref", "HEAD", g.head); err != nil {
		return refuse("snapshot.create", "cannot point the snapshot at "+g.head+": "+err.Error())
	}
	// -z: each record is key, newline, value, NUL, so a value cannot pose as another setting. A
	// name or URL with anything but printable characters is refused, not copied.
	urls, _ := g.gitRaw(g.root, "config", "-z", "--get-regexp", `^remote\..*\.url$`)
	for _, rec := range strings.Split(urls, "\x00") {
		if rec == "" {
			continue
		}
		key, url, ok := strings.Cut(rec, "\n")
		name := strings.TrimSuffix(strings.TrimPrefix(key, "remote."), ".url")
		if !ok || !remoteName.MatchString(name) || strings.ContainsFunc(url, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return refuse("snapshot.remote", "a remote's name or URL holds characters jade will not copy: "+strconv.Quote(key))
		}
		if _, err := g.gitIn(work, "config", key, url); err != nil {
			return refuse("snapshot.create", "cannot copy remote "+name)
		}
		if _, err := g.gitIn(work, "config", "remote."+name+".fetch", "+refs/heads/*:refs/remotes/"+name+"/*"); err != nil {
			return refuse("snapshot.create", "cannot copy remote "+name)
		}
	}
	g.work = work
	listing, err := g.gitRaw(work, "ls-tree", "-r", "-t", "-z", "--full-tree", g.head)
	if err != nil {
		return refuse("snapshot.create", "cannot list "+g.head)
	}
	type entry struct{ mode, id, path string }
	var entries []entry
	var blobs []string
	for _, raw := range strings.Split(listing, "\x00") {
		meta, path, ok := strings.Cut(raw, "\t")
		if !ok {
			continue
		}
		f := strings.Fields(meta)
		if len(f) != 3 || !safePath(path) {
			return refuse("snapshot.path", "the commit has a path jade will not write: "+path)
		}
		if f[0] == "160000" {
			return refuse("snapshot.submodule", path+" is a submodule; jade mint does not fetch submodules into its snapshot")
		}
		entries = append(entries, entry{f[0], f[2], path})
		if f[0] != "040000" {
			blobs = append(blobs, f[2])
		}
	}
	cat := gitCmd("cat-file", "--batch")
	cat.Dir = work
	cat.Stdin = strings.NewReader(strings.Join(blobs, "\n") + "\n")
	stdout, err := cat.StdoutPipe()
	if err != nil {
		return core.Transient("cannot read blobs: " + err.Error())
	}
	if err := cat.Start(); err != nil {
		return core.Transient("cannot read blobs: " + err.Error())
	}
	r := bufio.NewReader(stdout)
	for _, e := range entries {
		full := filepath.Join(work, filepath.FromSlash(e.path))
		if e.mode == "040000" {
			if err := os.Mkdir(full, 0o755); err != nil {
				return refuse("snapshot.write", "cannot create "+e.path+": "+err.Error())
			}
			continue
		}
		header, err := r.ReadString('\n')
		var id, kind string
		var size int
		if err == nil {
			_, err = fmt.Sscanf(header, "%s %s %d", &id, &kind, &size)
		}
		if err != nil || id != e.id || kind != "blob" {
			return refuse("snapshot.write", "cannot read the blob for "+e.path)
		}
		content := make([]byte, size+1) // the blob and its trailing newline
		if _, err := io.ReadFull(r, content); err != nil {
			return refuse("snapshot.write", "cannot read the blob for "+e.path)
		}
		content = content[:size]
		if objectID(format, "blob", content) != e.id {
			return refuse("objects.corrupt", "the blob for "+e.path+" does not hash to "+e.id)
		}
		if err := writeLoose(objects, "blob", e.id, content); err != nil {
			return refuse("snapshot.write", "cannot copy the blob for "+e.path+": "+err.Error())
		}
		switch e.mode {
		case "120000":
			err = os.Symlink(string(content), full)
		case "100755", "100644":
			perm := os.FileMode(0o644)
			if e.mode == "100755" {
				perm = 0o755
			}
			var f *os.File
			if f, err = os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm); err == nil {
				_, err = f.Write(content)
				if cerr := f.Close(); err == nil {
					err = cerr
				}
			}
		default:
			err = fmt.Errorf("unsupported mode %s", e.mode)
		}
		if err != nil {
			return refuse("snapshot.write", "cannot write "+e.path+": "+err.Error())
		}
	}
	if err := cat.Wait(); err != nil {
		return refuse("snapshot.write", "cannot read blobs: "+err.Error())
	}
	if _, err := g.gitIn(work, "read-tree", g.head); err != nil {
		return refuse("snapshot.create", "cannot build the snapshot's index: "+err.Error())
	}
	return g.clean(work, "in the new snapshot")
}

// remoteName is what jade copies as a remote name into the snapshot's config.
var remoteName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// verifyObjects checks that the commit and every tree under it are what their IDs say: git reads
// objects without rehashing them, so a loose tree object rewritten under its original ID (with
// the index and checkout made to match) would list different files for the same commit. Each
// object is read raw and hashed here; blobs are hashed against the files on disk by verifyTree.
func (g *gitRunner) verifyObjects(dir, commit, format string, store func(kind, id string, body []byte) error) *core.Error {
	corrupt := func(msg string) *core.Error {
		return &core.Error{Code: "objects.corrupt", Message: msg,
			Remedy: "the repository's object store does not match its IDs; re-clone it, then run: jade mint", Exit: core.ExitRefused}
	}
	id, err := g.gitIn(dir, "rev-parse", "--verify", "--quiet", commit+"^{commit}")
	if err != nil {
		return corrupt("cannot resolve " + commit)
	}
	cat := gitCmd("cat-file", "--batch")
	cat.Dir = dir
	in, err := cat.StdinPipe()
	if err != nil {
		return core.Transient("cannot read objects: " + err.Error())
	}
	outPipe, err := cat.StdoutPipe()
	if err != nil {
		return core.Transient("cannot read objects: " + err.Error())
	}
	if err := cat.Start(); err != nil {
		return core.Transient("cannot read objects: " + err.Error())
	}
	// Stop git before waiting on it: after a refusal its output may be unread, and git would
	// block writing it while jade waited.
	defer func() { in.Close(); cat.Process.Kill(); cat.Wait() }()
	r := bufio.NewReader(outPipe)
	idLen := 20
	if format == "sha256" {
		idLen = 32
	}
	read := func(want, kind string) ([]byte, *core.Error) {
		if _, err := fmt.Fprintln(in, want); err != nil {
			return nil, corrupt("cannot read object " + want)
		}
		header, err := r.ReadString('\n')
		var gotID, gotKind string
		var size int
		if err == nil {
			_, err = fmt.Sscanf(header, "%s %s %d", &gotID, &gotKind, &size)
		}
		if err != nil || gotID != want || gotKind != kind {
			return nil, corrupt("object " + want + " is not a readable " + kind)
		}
		body := make([]byte, size+1)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, corrupt("cannot read object " + want)
		}
		body = body[:size]
		var h hash.Hash = sha1.New()
		if format == "sha256" {
			h = sha256.New()
		}
		fmt.Fprintf(h, "%s %d\x00", kind, size)
		h.Write(body)
		if hex.EncodeToString(h.Sum(nil)) != want {
			return nil, corrupt("the " + kind + " stored as " + want + " does not hash to that ID")
		}
		if store != nil {
			if err := store(kind, want, body); err != nil {
				return nil, corrupt("cannot copy " + kind + " " + want + ": " + err.Error())
			}
		}
		return body, nil
	}
	body, e := read(id, "commit")
	if e != nil {
		return e
	}
	first, _, _ := strings.Cut(string(body), "\n")
	root, ok := strings.CutPrefix(first, "tree ")
	if !ok {
		return corrupt("commit " + id + " names no tree")
	}
	queue, seen := []string{root}, map[string]bool{root: true}
	for len(queue) > 0 {
		t := queue[0]
		queue = queue[1:]
		body, e := read(t, "tree")
		if e != nil {
			return e
		}
		for len(body) > 0 {
			sp := bytes.IndexByte(body, ' ')
			nul := bytes.IndexByte(body, 0)
			if sp < 0 || nul < sp || len(body) < nul+1+idLen {
				return corrupt("tree " + t + " is malformed")
			}
			// The mode's file-type bits decide: git also accepts a zero-padded "040000" for a tree.
			mode, err := strconv.ParseUint(string(body[:sp]), 8, 32)
			if err != nil {
				return corrupt("tree " + t + " has a malformed mode")
			}
			sub := hex.EncodeToString(body[nul+1 : nul+1+idLen])
			body = body[nul+1+idLen:]
			if mode&0o170000 == 0o040000 && !seen[sub] {
				seen[sub] = true
				queue = append(queue, sub)
			}
		}
	}
	return nil
}

// objectID is the ID git gives an object of kind with body, in format (sha1 or sha256).
func objectID(format, kind string, body []byte) string {
	var h hash.Hash = sha1.New()
	if format == "sha256" {
		h = sha256.New()
	}
	fmt.Fprintf(h, "%s %d\x00", kind, len(body))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// writeLoose stores one object, already checked against id, as a loose object in objects.
func writeLoose(objects, kind, id string, body []byte) error {
	path := filepath.Join(objects, id[:2], id[2:])
	if _, err := os.Lstat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	fmt.Fprintf(zw, "%s %d\x00", kind, len(body))
	zw.Write(body)
	if err := zw.Close(); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o444); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// tempDir is the temporary directory resolved once: everything jade creates there is created
// under this path, so retargeting a symlink in TMPDIR afterwards cannot point jade elsewhere.
func tempDir() (string, error) {
	return filepath.EvalSymlinks(os.TempDir())
}

// afterClone, when set, runs right after the object store is copied. Tests use it to stand in for
// a change racing the copy.
var afterClone func(store string)

// cloneDir copies the directory src to dst (which must not exist), as a copy-on-write clone when
// the filesystem supports one (cp -c on macOS, --reflink on Linux), else as a plain copy.
func cloneDir(src, dst string) error {
	attempts := [][]string{{"-c", "-R"}, {"-R", "--reflink=auto"}, {"-R"}}
	var last error
	for _, flags := range attempts {
		c := exec.Command("/bin/cp", append(flags, src, dst)...)
		c.Env = gitEnv()
		out, err := c.CombinedOutput()
		if err == nil {
			return nil
		}
		last = fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		os.RemoveAll(dst)
	}
	return last
}

// firstLine is s up to its first newline.
func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// safePath is the subset of git's own path rules jade needs before writing a file: relative, no
// empty, "." or ".." component, and no .git component in any case.
func safePath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") {
		return false
	}
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." || c == ".." || strings.EqualFold(c, ".git") {
			return false
		}
	}
	return true
}

// removeSnapshot deletes the snapshot, whatever the mint's outcome.
func (g *gitRunner) removeSnapshot() {
	if g.snapParent != "" {
		os.RemoveAll(g.snapParent)
	}
}

// ignoredByCommittedRules accepts the files git ignores in dir only when the rule that ignores
// each is in a .gitignore committed at the bound commit (and so already hashed by verifyTree). A
// rule in .git/info/exclude, the global excludes file or an uncommitted .gitignore is local and
// mutable: it could hide an input a step reads, so a file it ignores is refused.
func (g *gitRunner) ignoredByCommittedRules(dir, rel string, committed map[string]bool) *core.Error {
	dirty := func(msg string) *core.Error {
		return &core.Error{Code: "preflight.dirty", Message: msg,
			Remedy: "remove it, or ignore it in a committed .gitignore, then run: jade mint", Exit: core.ExitRefused}
	}
	ignored, err := g.gitRaw(dir, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z")
	if err != nil {
		return dirty("cannot list the ignored files of " + dir)
	}
	paths := strings.FieldsFunc(ignored, func(r rune) bool { return r == 0 })
	return g.ignoredByCommittedRulesList(dir, rel, committed, paths, map[string]bool{})
}

func (g *gitRunner) ignoredByCommittedRulesList(dir, rel string, committed map[string]bool, paths []string,
	expanded map[string]bool) *core.Error {
	dirty := func(msg string) *core.Error {
		return &core.Error{Code: "preflight.dirty", Message: msg,
			Remedy: "remove it, or ignore it in a committed .gitignore, then run: jade mint", Exit: core.ExitRefused}
	}
	if len(paths) == 0 {
		return nil
	}
	// check-ignore refuses pathspec magic of any kind, :(literal) included, so it runs without
	// GIT_LITERAL_PATHSPECS and every path is sent as ./path: a leading ./ is never magic.
	c := gitCmd("check-ignore", "-v", "-z", "--stdin", "--no-index")
	c.Env = slices.DeleteFunc(c.Env, func(kv string) bool { return kv == "GIT_LITERAL_PATHSPECS=1" })
	c.Dir = dir
	c.Stdin = strings.NewReader("./" + strings.Join(paths, "\x00./") + "\x00")
	out, err := c.Output()
	// Exit 1 means some path matched nothing, which the loop below catches; anything else is an
	// error, and an unchecked path is not an accepted one.
	if exit, ok := err.(*exec.ExitError); err != nil && (!ok || exit.ExitCode() != 1) {
		return dirty("cannot check why files are ignored in " + dir)
	}
	// -v -z prints source, line, pattern and path, NUL-terminated, for each matched path.
	f := strings.Split(string(out), "\x00")
	why := map[string]string{}
	for i := 0; i+3 < len(f); i += 4 {
		// A negated pattern (!x) is the rule that un-ignores x: no reason to ignore it.
		if !strings.HasPrefix(f[i+2], "!") {
			why[strings.TrimPrefix(f[i+3], "./")] = f[i]
		}
	}
	for i := 0; i < len(paths); i++ {
		p := paths[i]
		source, ok := why[p]
		if !ok && strings.HasSuffix(p, "/") && !expanded[p] {
			// git collapses a directory holding only ignored files into one entry no rule
			// names; check its files one by one instead.
			expanded[p] = true
			inner, err := g.gitRaw(dir, "ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", p)
			if err != nil {
				return dirty("cannot list the ignored files of " + rel + p)
			}
			more := strings.FieldsFunc(inner, func(r rune) bool { return r == 0 })
			if len(more) == 0 {
				return dirty("cannot tell which rule ignores " + rel + p)
			}
			if e := g.ignoredByCommittedRulesList(dir, rel, committed, more, expanded); e != nil {
				return e
			}
			continue
		}
		if !ok {
			return dirty("cannot tell which rule ignores " + rel + p)
		}
		if !committed[source] {
			return dirty(rel + p + " is ignored by " + source + ", which is not committed")
		}
	}
	return nil
}

// clean is the tree check shared by preflight and every step: verifyTree on the bound commit.
func (g *gitRunner) clean(dir, when string) *core.Error {
	head := g.head
	if head == "" {
		head = "HEAD"
	}
	if e := g.verifyTree(dir, "", head); e != nil {
		e.Message += " (" + when + ")"
		return e
	}
	return nil
}

// verifyTree checks the checkout at dir against commit without asking git whether files changed:
// git status can be configured to lie (clean filters, eol conversion, stat tricks) and runs
// whatever filter the local config names. Here git only reads the index and object ids, and
// every tracked file is hashed in Go the way git stores a blob. Refused: a file flagged
// skip-worktree or assume-unchanged, a staged change, an untracked file, or any byte, mode or
// symlink that differs. Submodules are checked at the commit the parent records, recursively;
// rel is dir's path from the repository root, for messages.
func (g *gitRunner) verifyTree(dir, rel, commit string) *core.Error {
	dirty := func(msg string) *core.Error {
		return &core.Error{Code: "preflight.dirty", Message: msg,
			Remedy: "commit or restore the file, then run: jade mint", Exit: core.ExitRefused}
	}
	// Every git call below must describe dir itself: a local core.worktree (a submodule's, say)
	// can point git's untracked and ignored listings at another, clean checkout while the bytes
	// hashed here are dir's.
	top, err := g.gitIn(dir, "rev-parse", "--show-toplevel")
	a, errA := filepath.EvalSymlinks(top)
	b, errB := filepath.EvalSymlinks(dir)
	if err != nil || errA != nil || errB != nil || a != b {
		return dirty("git's worktree for ./" + rel + " is " + top + ", not " + dir)
	}
	format, err := g.gitIn(dir, "rev-parse", "--show-object-format")
	if err != nil || (format != "sha1" && format != "sha256") {
		return dirty("cannot read the object format of " + dir)
	}
	if e := g.verifyObjects(dir, commit, format, nil); e != nil {
		return e
	}
	tags, err := g.gitRaw(dir, "ls-files", "-v", "-z")
	if err != nil {
		return dirty("cannot list the tracked files of " + dir)
	}
	for _, entry := range strings.Split(tags, "\x00") {
		// ls-files -v tags: S is skip-worktree, a lowercase tag is assume-unchanged.
		if len(entry) > 2 && (entry[0] == 'S' || (entry[0] >= 'a' && entry[0] <= 'z')) {
			p := entry[2:]
			return &core.Error{Code: "preflight.hidden", Message: "a tracked file is hidden from git status: " + rel + p,
				Remedy: "run: " + core.Describe([]string{"git", "-C", dir, "update-index", "--no-skip-worktree",
					"--no-assume-unchanged", "--", p}) + ", then run: jade mint",
				Exit: core.ExitRefused}
		}
	}
	if _, err := g.gitIn(dir, "diff-index", "--cached", "--quiet", "--no-ext-diff", "--ignore-submodules=none", commit, "--"); err != nil {
		return dirty("the index has staged changes in " + dir)
	}
	untracked, err := g.gitRaw(dir, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil || untracked != "" {
		first, _, _ := strings.Cut(untracked, "\x00")
		return dirty("untracked file: " + rel + first)
	}
	listing, err := g.gitRaw(dir, "ls-tree", "-r", "-t", "-z", "--full-tree", commit)
	committedIgnores := map[string]bool{}
	if err != nil {
		return dirty("cannot list the files of " + commit)
	}
	for _, entry := range strings.Split(listing, "\x00") {
		meta, path, ok := strings.Cut(entry, "\t")
		if !ok {
			continue
		}
		f := strings.Fields(meta) // mode, type, object id
		if len(f) != 3 {
			return dirty("unexpected ls-tree entry: " + meta)
		}
		mode, id, full := f[0], f[2], filepath.Join(dir, path)
		if filepath.Base(path) == ".gitignore" {
			committedIgnores[path] = true
		}
		// Every directory the commit has (-t lists them) and every submodule root must be a real
		// directory: a symlink in its place would make the file checks below follow it to files
		// outside the checkout that hash the same.
		if mode == "040000" || mode == "160000" {
			info, err := os.Lstat(full)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return dirty(rel + path + " is no longer a directory")
			}
			if mode == "040000" {
				continue
			}
		}
		if mode == "160000" {
			if head, err := g.gitIn(full, "rev-parse", "HEAD"); err != nil || head != id {
				return dirty("submodule " + rel + path + " is not checked out at " + id)
			}
			if e := g.verifyTree(full, rel+path+"/", id); e != nil {
				return e
			}
			continue
		}
		var content []byte
		info, err := os.Lstat(full)
		switch {
		case err != nil:
			return dirty(rel + path + " is missing")
		case mode == "120000":
			if info.Mode()&os.ModeSymlink == 0 {
				return dirty(rel + path + " is no longer a symlink")
			}
			target, _ := os.Readlink(full)
			content = []byte(target)
		case !info.Mode().IsRegular():
			return dirty(rel + path + " is no longer a regular file")
		case (mode == "100755") != (info.Mode().Perm()&0o111 != 0):
			return dirty(rel + path + " changed its executable bit")
		default:
			if content, err = os.ReadFile(full); err != nil {
				return dirty("cannot read " + rel + path)
			}
		}
		var h hash.Hash = sha1.New()
		if format == "sha256" {
			h = sha256.New()
		}
		fmt.Fprintf(h, "blob %d\x00", len(content))
		h.Write(content)
		if hex.EncodeToString(h.Sum(nil)) != id {
			return dirty(rel + path + " differs from " + commit)
		}
	}
	return g.ignoredByCommittedRules(dir, rel, committedIgnores)
}

// Head is the commit the mint is bound to. Whether the checkout is still at it is Unchanged's job,
// which runs before the first step.
func (g *gitRunner) Head() (string, error) { return g.head, nil }

// Unchanged is checked before every step: HEAD still the commit the mint began on, and the tree
// still clean, so nothing a step records can name another commit because of a change between steps.
func (g *gitRunner) Unchanged(head string) *core.Error {
	now, err := g.gitIn(g.work, "rev-parse", "HEAD")
	if err != nil || now != head {
		return &core.Error{Code: "head.moved", Message: fmt.Sprintf("the snapshot's HEAD moved from %s to %s", head, now),
			Remedy: "something else is using jade's private snapshot; stop it, then run: jade mint", Exit: core.ExitRefused}
	}
	if e := g.clean(g.work, "between steps"); e != nil {
		e.Remedy = "do not edit files while minting; " + e.Remedy
		return e
	}
	return nil
}

func (g *gitRunner) Run(s core.Step) error {
	// jade names the log; the step name never reaches a path.
	path := filepath.Join(g.logDir, fmt.Sprintf("step-%02d.log", len(g.logs)+1))
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	g.logs[s.Name] = path
	argv := core.Argv(g.cilock, guarded(s, guardPath(g, selfPath())))
	c := exec.Command(argv[0], argv[1:]...)
	c.Env = append(stepEnv(g.root, g.work, g.env), "JADE_HEAD="+g.head)
	c.Dir = g.work
	var w io.Writer = f
	if g.stream != nil {
		w = io.MultiWriter(f, g.stream)
	}
	c.Stdout, c.Stderr = w, w
	if err := c.Run(); err != nil {
		return fmt.Errorf("%v (log: %s)", err, path)
	}
	return nil
}

func cmdMint(args []string, wd string, o output) int {
	op, e := parse("mint", args, true, true)
	if e != nil {
		return o.fail(e, nil)
	}
	root, err := repoRoot(wd)
	if err != nil {
		return o.fail(&core.Error{Code: "preflight.no-repo", Message: wd + " is not inside a git repository",
			Remedy: "run jade from inside the repository", Exit: core.ExitRefused}, nil)
	}
	// HEAD first, then the manifest from that commit: the mint is bound to one commit before it
	// reads anything, so a checkout after this point is caught by the first Unchanged check.
	c := gitCmd("rev-parse", "HEAD")
	c.Dir = root
	out, err := c.Output()
	if err != nil {
		return o.fail(&core.Error{Code: "head.unreadable", Message: "cannot read HEAD", Remedy: "commit at least once, then run: jade mint",
			Exit: core.ExitRefused}, nil)
	}
	head := strings.TrimSpace(string(out))
	m, mb, e := manifestAt(root, head)
	if e != nil {
		return o.fail(e, nil)
	}
	tmp, err := tempDir()
	if err != nil {
		return o.fail(core.Transient("cannot resolve the temporary directory: "+err.Error()), nil)
	}
	logDir, err := os.MkdirTemp(tmp, "jade-mint-")
	if err != nil {
		return o.fail(core.Transient("cannot create a log directory: "+err.Error()), nil)
	}
	g := &gitRunner{root: root, wd: wd, cilock: cilockPath(op.cilock, wd), logDir: logDir, logs: map[string]string{}, head: head, mint: true,
		cilockImplicit: op.cilock == "", env: m.Env, manifest: mb}
	if !o.json {
		g.stream = o.stderr
	}
	defer g.removeSnapshot()
	res := core.Mint(m, op.only, g)
	obj := map[string]any{"exit_code": res.Exit, "head": res.Head, "plan": res.Plan, "evidence": res.Evidence, "logs": g.logs}
	if res.Error != nil {
		return o.fail(res.Error, obj)
	}
	o.emit(obj, func(w io.Writer) {
		fmt.Fprintf(w, "jade mint: %d steps recorded for %s\n", len(res.Evidence), res.Head)
	})
	return res.Exit
}

func cmdDoctor(args []string, wd string, o output) int {
	op, e := parse("doctor", args, false, true)
	if e != nil {
		return o.fail(e, nil)
	}
	m, root, e := loadManifest(wd)
	if e != nil {
		return o.fail(e, nil)
	}
	g := &gitRunner{root: root, wd: wd, cilock: cilockPath(op.cilock, wd), cilockImplicit: op.cilock == ""}
	if pe := g.Preflight(); pe != nil {
		return o.fail(pe, map[string]any{"steps": len(m.Steps)})
	}
	o.emit(map[string]any{"exit_code": core.ExitOK, "steps": len(m.Steps), "cilock": g.cilock}, func(w io.Writer) {
		fmt.Fprintf(w, "ready: %d steps, cilock %s\n", len(m.Steps), g.cilock)
	})
	return core.ExitOK
}
