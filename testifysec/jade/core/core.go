// Package core is jade's manifest, plan and mint, and the result contract an agent reads.
// It follows testifysec/formal/jade (Lean): each function names the definition it implements.
// It uses only the Go standard library.
package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// stepName is what a step may be called: an identifier an agent types, never a path.
var stepName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// SchemaVersion is the version of the JSON a jade command prints.
const SchemaVersion = 1

// Exit codes, the closed set of JadeCore.exitCode.
const (
	ExitOK        = 0 // done
	ExitFailed    = 1 // a check ran and failed
	ExitUsage     = 2 // usage or manifest error
	ExitRefused   = 3 // refused before running, or HEAD moved
	ExitTransient = 4 // retrying unchanged can help
)

// Error is every non-success result: a stable code, one sentence, the next action, and whether
// retrying unchanged can help (JadeCore.remedy, JadeCore.retryable).
type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Remedy    string `json:"remedy"`
	Retryable bool   `json:"retryable"`
	Exit      int    `json:"-"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func usage(code, msg, remedy string) *Error {
	return &Error{Code: code, Message: msg, Remedy: remedy, Exit: ExitUsage}
}

// Transient is a failure retrying unchanged can fix.
func Transient(msg string) *Error {
	return &Error{Code: "transient", Message: msg, Remedy: "retry the same command", Retryable: true, Exit: ExitTransient}
}

// Mode is JadeCore.Mode.
type Mode string

const (
	ModeRun    Mode = "run"
	ModeAttest Mode = "attest"
)

// Step is JadeCore.Step. Field names follow Judge's deploy/pushgate/push-gate.steps.json, so that
// file loads unchanged; argv_pin and release are carried, not interpreted.
type Step struct {
	Name               string   `json:"name"`
	Mode               Mode     `json:"mode"`
	Argv               []string `json:"argv"`
	ArgvPin            string   `json:"argv_pin,omitempty"`
	Attestors          []string `json:"attestors,omitempty"`
	ProductIncludeGlob string   `json:"product_include_glob,omitempty"`
	ProductExcludeGlob string   `json:"product_exclude_glob,omitempty"`
	Release            string   `json:"release,omitempty"`
	Needs              []string `json:"needs,omitempty"`
}

// Layer is one layer of a stack: a branch on a base, and its acceptance command.
type Layer struct {
	Name   string   `json:"name"`
	Branch string   `json:"branch"`
	Base   string   `json:"base"`
	Accept []string `json:"accept"`
}

// Env is what a step may have beyond jade's strict defaults (see the README's threat model):
// variables passed through from the caller by name, and directories added to PATH.
type Env struct {
	Pass []string `json:"pass,omitempty"`
	Path []string `json:"path,omitempty"`
}

// Manifest is JadeCore.Manifest: .jade/workspace.json.
type Manifest struct {
	SchemaVersion int     `json:"schema_version,omitempty"`
	Env           Env     `json:"env,omitempty"`
	Steps         []Step  `json:"steps"`
	Layers        []Layer `json:"layers,omitempty"`
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Parse decodes a manifest, refusing unknown fields: a typo must not silently drop a guard.
func Parse(b []byte) (*Manifest, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var m Manifest
	if err := d.Decode(&m); err != nil {
		return nil, usage("manifest.parse", "the manifest is not valid: "+err.Error(), "fix .jade/workspace.json, then run: jade plan")
	}
	// Only whitespace may follow the value: the next token must be EOF. Decoder.More alone
	// lets a stray ] or } through.
	if _, err := d.Token(); err != io.EOF {
		return nil, usage("manifest.parse", "the manifest has data after its JSON value", "fix .jade/workspace.json, then run: jade plan")
	}
	if m.SchemaVersion > 1 {
		return nil, usage("manifest.version", fmt.Sprintf("schema_version %d is newer than this jade understands (1)", m.SchemaVersion),
			"update jade, then run: jade plan")
	}
	return &m, nil
}

// Load reads and parses a manifest file.
func Load(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, usage("manifest.missing", path+" does not exist", "create "+Describe([]string{path})+", then run: jade plan")
		}
		return nil, usage("manifest.read", err.Error(), "check "+Describe([]string{path})+" is readable, then run: jade plan")
	}
	return Parse(b)
}

// Validate is JadeCore.valid: names are unique and non-empty, attest steps carry no command and run
// steps carry one, and every step comes after the steps it needs (JadeCore.orderedAux).
func (m *Manifest) Validate() error {
	if len(m.Steps) == 0 {
		return usage("manifest.empty", "the manifest has no steps", "add steps to .jade/workspace.json, then run: jade plan")
	}
	for _, n := range m.Env.Pass {
		if !envName.MatchString(n) {
			return usage("manifest.env", fmt.Sprintf("env.pass %q is not a variable name", n), "fix env.pass in .jade/workspace.json")
		}
	}
	for _, d := range m.Env.Path {
		if !(strings.HasPrefix(d, "/") || strings.HasPrefix(d, "~/")) || strings.ContainsRune(d, ':') {
			return usage("manifest.env", fmt.Sprintf("env.path %q is not an absolute directory (or ~/...)", d),
				"fix env.path in .jade/workspace.json")
		}
	}
	seen := map[string]bool{}
	for _, s := range m.Steps {
		if !stepName.MatchString(s.Name) {
			return usage("manifest.name", fmt.Sprintf("step name %q is not an identifier (letters, digits, '.', '_', '-'; starting with a letter or digit)", s.Name),
				"rename the step in .jade/workspace.json")
		}
		if seen[s.Name] {
			return usage("manifest.duplicate", "two steps are named "+s.Name, "rename one of the steps named "+s.Name)
		}
		switch s.Mode {
		case ModeAttest:
			if len(s.Argv) != 0 {
				return usage("manifest.mode", "attest step "+s.Name+" has a command", "remove argv from "+s.Name+", or make it a run step")
			}
		case ModeRun:
			if len(s.Argv) == 0 {
				return usage("manifest.mode", "run step "+s.Name+" has no command", "give "+s.Name+" an argv, or make it an attest step")
			}
		default:
			return usage("manifest.mode", fmt.Sprintf("step %s has mode %q; want run or attest", s.Name, s.Mode), "set mode to run or attest")
		}
		for _, n := range s.Needs {
			if !seen[n] {
				return usage("manifest.order", fmt.Sprintf("step %s needs %s, which is not listed before it", s.Name, n),
					"list "+n+" before "+s.Name+" in .jade/workspace.json (file order is run order)")
			}
		}
		seen[s.Name] = true
	}
	return nil
}

// Plan is JadeCore.plan: with no selection, every step; otherwise the selected steps and everything
// they need, in file order, by one backward pass (JadeCore.planAux).
func (m *Manifest) Plan(only []string) ([]Step, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, s := range m.Steps {
		known[s.Name] = true
	}
	for _, o := range only {
		if !known[o] {
			return nil, usage("step.unknown", "step "+o+" is not in the manifest", "run: jade query steps")
		}
	}
	if len(only) == 0 {
		return append([]Step(nil), m.Steps...), nil
	}
	selected := map[string]bool{}
	for _, o := range only {
		selected[o] = true
	}
	wanted := map[string]bool{}
	var kept []Step
	for i := len(m.Steps) - 1; i >= 0; i-- {
		s := m.Steps[i]
		if selected[s.Name] || wanted[s.Name] {
			kept = append(kept, s)
			for _, n := range s.Needs {
				wanted[n] = true
			}
		}
	}
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	return kept, nil
}

// Runner is the outside world a mint needs: the repository checks, HEAD, and running one step.
// Unchanged reports whether HEAD is still head and the tree still clean; Mint asks it before every
// step, so a change between steps is caught before the next step records anything.
type Runner interface {
	Preflight() *Error
	Head() (string, error)
	Unchanged(head string) *Error
	Run(s Step) error
}

// Evidence is one recorded step and the commit it names.
type Evidence struct {
	Step   string `json:"step"`
	Commit string `json:"commit"`
}

// Result is what a mint reports (JadeCore.Outcome), as an agent reads it.
type Result struct {
	SchemaVersion int        `json:"schema_version"`
	Exit          int        `json:"exit_code"`
	Head          string     `json:"head,omitempty"`
	Plan          []string   `json:"plan,omitempty"`
	Evidence      []Evidence `json:"evidence"`
	Error         *Error     `json:"error,omitempty"`
}

func fail(e *Error, head string, plan []string, ev []Evidence) Result {
	return Result{SchemaVersion: SchemaVersion, Exit: e.Exit, Head: head, Plan: plan, Evidence: ev, Error: e}
}

// Mint is JadeCore.mint: validate and plan, preflight, then run the plan, stopping at the first
// step after which HEAD is no longer the commit it began on (checked first) or at the first
// failure (JadeCore.runSteps). Every piece of evidence names that commit.
func Mint(m *Manifest, only []string, r Runner) Result {
	plan, err := m.Plan(only)
	if err != nil {
		var e *Error
		if !errors.As(err, &e) {
			e = usage("manifest.invalid", err.Error(), "fix .jade/workspace.json, then run: jade plan")
		}
		return fail(e, "", nil, []Evidence{})
	}
	planNames := make([]string, 0, len(plan))
	for _, s := range plan {
		planNames = append(planNames, s.Name)
	}
	if e := r.Preflight(); e != nil {
		return fail(e, "", planNames, []Evidence{})
	}
	head, herr := r.Head()
	if herr != nil {
		return fail(&Error{Code: "head.unreadable", Message: "cannot read HEAD: " + herr.Error(),
			Remedy: "run jade from inside the repository", Exit: ExitRefused}, "", planNames, []Evidence{})
	}
	ev := []Evidence{}
	for _, s := range plan {
		if e := r.Unchanged(head); e != nil {
			return fail(e, head, planNames, ev)
		}
		rerr := r.Run(s)
		// The repository is checked first (JadeCore.runSteps): a step after which HEAD moved or the
		// tree is no longer clean stops the mint with exit 3 whether or not it also failed, and its
		// evidence is not accepted. cilock may already have uploaded that step's evidence (4.5.0
		// uploads as the step ends and cannot defer), but it cannot name another commit: the git
		// attestor runs before the command (prematerial), against a snapshot checked clean at the
		// pinned commit just before the step. What it records is the step changing its own tree.
		if e := r.Unchanged(head); e != nil {
			if e.Code == "head.moved" {
				e.Message = fmt.Sprintf("HEAD moved during %s; its evidence would name another commit", s.Name)
			} else {
				e.Message = fmt.Sprintf("the tree changed during %s: %s", s.Name, e.Message)
			}
			return fail(e, head, planNames, ev)
		}
		if rerr != nil {
			return fail(&Error{Code: "step.failed", Message: fmt.Sprintf("step %s failed: %v", s.Name, rerr),
				Remedy: "fix what step " + s.Name + " reports, commit, then run: jade mint", Exit: ExitFailed}, head, planNames, ev)
		}
		ev = append(ev, Evidence{Step: s.Name, Commit: head})
	}
	return Result{SchemaVersion: SchemaVersion, Exit: ExitOK, Head: head, Plan: planNames, Evidence: ev}
}

// Argv is the cilock command line for one step: `cilock run` around its argv, or `cilock attest`.
func Argv(cilock string, s Step) []string {
	verb := "run"
	if s.Mode == ModeAttest {
		verb = "attest"
	}
	out := []string{cilock, verb, "--step", s.Name}
	for _, a := range s.Attestors {
		out = append(out, "-a", a)
	}
	if s.ProductIncludeGlob != "" {
		out = append(out, "--attestor-product-include-glob", s.ProductIncludeGlob)
	}
	if s.ProductExcludeGlob != "" {
		out = append(out, "--attestor-product-exclude-glob", s.ProductExcludeGlob)
	}
	if s.Mode == ModeRun {
		out = append(out, "--")
		out = append(out, s.Argv...)
	}
	return out
}

// Describe is a one-line, shell-quoted rendering of an argv, for plans and logs.
func Describe(argv []string) string {
	q := make([]string, 0, len(argv))
	for _, a := range argv {
		if !shellSafe(a) {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		q = append(q, a)
	}
	return strings.Join(q, " ")
}

// shellSafe is an allowlist: an argument made only of these characters means the same to a
// shell unquoted. Anything else (operators, globs, ~, #, !, whitespace, quotes) is quoted.
func shellSafe(a string) bool {
	if a == "" || a[0] == '=' { // zsh expands a leading = to a command's path
		return false
	}
	for _, r := range a {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-_./=:,@%+", r):
		default:
			return false
		}
	}
	return true
}
