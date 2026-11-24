package core

import (
	"errors"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func step(name string, needs ...string) Step {
	return Step{Name: name, Mode: ModeRun, Argv: []string{"sh", name}, Needs: needs}
}

func badger() *Manifest {
	return &Manifest{Steps: []Step{
		step("build"), step("tests", "build"), step("quality"), step("vulns", "build"),
		{Name: "push-metadata", Mode: ModeAttest},
	}}
}

func names(steps []Step) []string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.Name)
	}
	return out
}

// Validate is JadeCore.valid: unique names, attest steps carry no command and run steps carry one,
// and every step comes after the steps it needs.
func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		m    Manifest
		code string // "" means valid
	}{
		{"badger", *badger(), ""},
		{"needs listed after", Manifest{Steps: []Step{step("vulns", "build"), step("build")}}, "manifest.order"},
		{"unknown need", Manifest{Steps: []Step{step("vulns", "nope")}}, "manifest.order"},
		{"needs itself", Manifest{Steps: []Step{step("a", "a")}}, "manifest.order"},
		{"duplicate name", Manifest{Steps: []Step{step("build"), step("build")}}, "manifest.duplicate"},
		{"attest with a command", Manifest{Steps: []Step{{Name: "m", Mode: ModeAttest, Argv: []string{"x"}}}}, "manifest.mode"},
		{"run without a command", Manifest{Steps: []Step{{Name: "m", Mode: ModeRun}}}, "manifest.mode"},
		{"unknown mode", Manifest{Steps: []Step{{Name: "m", Mode: "exec", Argv: []string{"x"}}}}, "manifest.mode"},
		{"empty name", Manifest{Steps: []Step{{Mode: ModeRun, Argv: []string{"x"}}}}, "manifest.name"},
		// Codex on #27: a name is an identifier, never a path.
		{"path traversal name", Manifest{Steps: []Step{step("../victim")}}, "manifest.name"},
		{"slash in name", Manifest{Steps: []Step{step("a/b")}}, "manifest.name"},
		{"leading dot", Manifest{Steps: []Step{step(".hidden")}}, "manifest.name"},
		{"space in name", Manifest{Steps: []Step{step("a b")}}, "manifest.name"},
		{"no steps", Manifest{}, "manifest.empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.m.Validate()
			if c.code == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			var e *Error
			if !errors.As(err, &e) || e.Code != c.code {
				t.Fatalf("want error code %s, got %v", c.code, err)
			}
			if e.Exit != ExitUsage || e.Remedy == "" {
				t.Fatalf("a manifest error must exit %d with a remedy; got exit %d remedy %q", ExitUsage, e.Exit, e.Remedy)
			}
		})
	}
}

// Parse refuses unknown fields: a typo must not silently drop a guard.
func TestParseRefusesUnknownFields(t *testing.T) {
	_, err := Parse([]byte(`{"steps":[{"name":"b","mode":"run","argv":["x"],"needz":["a"]}]}`))
	var e *Error
	if !errors.As(err, &e) || e.Code != "manifest.parse" {
		t.Fatalf("want manifest.parse, got %v", err)
	}
}

// Judge's deploy/pushgate/push-gate.steps.json loads unchanged.
func TestJudgeStepsFileLoads(t *testing.T) {
	m, err := Load("testdata/judge-push-gate.steps.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := names(m.Steps); !reflect.DeepEqual(got, []string{"push-gate", "gomod-drift", "push-tests", "push-metadata", "local-ring"}) {
		t.Fatalf("steps: %v", got)
	}
	if m.Steps[0].ArgvPin != "exact" || m.Steps[0].Release != "judge-push-gate" {
		t.Fatalf("argv_pin and release are carried: %+v", m.Steps[0])
	}
}

// Plan is JadeCore.plan: the selected steps and everything they need, in file order.
func TestPlan(t *testing.T) {
	m := badger()
	cases := []struct {
		only []string
		want []string
	}{
		{nil, []string{"build", "tests", "quality", "vulns", "push-metadata"}},
		{[]string{"vulns"}, []string{"build", "vulns"}},
		{[]string{"tests", "vulns"}, []string{"build", "tests", "vulns"}},
		{[]string{"push-metadata"}, []string{"push-metadata"}},
	}
	for _, c := range cases {
		got, err := m.Plan(c.only)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(names(got), c.want) {
			t.Errorf("Plan(%v) = %v, want %v", c.only, names(got), c.want)
		}
	}
}

func TestPlanUnknownStep(t *testing.T) {
	_, err := badger().Plan([]string{"nope"})
	var e *Error
	if !errors.As(err, &e) || e.Code != "step.unknown" || e.Exit != ExitUsage {
		t.Fatalf("want step.unknown exit 2, got %v", err)
	}
}

// Property (JadeCore.plan_closed, selected_kept, planAux_sublist): for random valid manifests and
// selections, the plan keeps every selected step and every need of a kept step, in file order.
func TestPlanClosedProperty(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		n := 1 + r.Intn(12)
		var m Manifest
		for j := 0; j < n; j++ {
			s := step(string(rune('a' + j)))
			for k := 0; k < j; k++ {
				if r.Intn(4) == 0 {
					s.Needs = append(s.Needs, string(rune('a'+k)))
				}
			}
			m.Steps = append(m.Steps, s)
		}
		var only []string
		for j := 0; j < n; j++ {
			if r.Intn(5) == 0 {
				only = append(only, string(rune('a'+j)))
			}
		}
		if len(only) == 0 {
			continue
		}
		plan, err := m.Plan(only)
		if err != nil {
			t.Fatal(err)
		}
		kept := map[string]bool{}
		pos := map[string]int{}
		for i, s := range plan {
			kept[s.Name] = true
			pos[s.Name] = i
		}
		for _, o := range only {
			if !kept[o] {
				t.Fatalf("selected %s not kept: %v", o, names(plan))
			}
		}
		for _, s := range plan {
			for _, need := range s.Needs {
				if !kept[need] || pos[need] > pos[s.Name] {
					t.Fatalf("%s needs %s, which is missing or later: %v", s.Name, need, names(plan))
				}
			}
		}
		last := -1
		for _, s := range plan {
			idx := strings.IndexByte("abcdefghijkl", s.Name[0])
			if idx <= last {
				t.Fatalf("plan out of file order: %v", names(plan))
			}
			last = idx
		}
	}
}

// fakeRunner reports a pass or a failure per step and can move HEAD after a step.
type fakeRunner struct {
	fail        map[string]bool
	moveAt      map[string]string
	moveOnCheck map[int]string // at the Nth pre-step check (1-based), HEAD has become this
	checks      int
	dirtyAfter  map[string]bool // running this step leaves tracked files modified
	dirty       bool
	head        string
	ran         []string
	preflit     *Error
}

func (f *fakeRunner) Preflight() *Error     { return f.preflit }
func (f *fakeRunner) Head() (string, error) { return f.head, nil }
func (f *fakeRunner) Unchanged(head string) *Error {
	f.checks++
	if h, ok := f.moveOnCheck[f.checks]; ok {
		f.head = h
	}
	if f.head != head {
		return &Error{Code: "head.moved", Message: "moved", Remedy: "re-mint", Exit: ExitRefused}
	}
	if f.dirty {
		return &Error{Code: "preflight.dirty", Message: "dirty", Remedy: "clean", Exit: ExitRefused}
	}
	return nil
}
func (f *fakeRunner) Run(s Step) error {
	f.ran = append(f.ran, s.Name)
	if f.dirtyAfter[s.Name] {
		f.dirty = true
	}
	if h, ok := f.moveAt[s.Name]; ok {
		f.head = h
	}
	if f.fail[s.Name] {
		return errors.New("exit status 1")
	}
	return nil
}

// JadeCore.fail_fast and evidence_names_head: the first failing step stops the mint; evidence names
// the starting HEAD; nothing after the failure runs.
func TestMintFailFast(t *testing.T) {
	f := &fakeRunner{head: "c1", fail: map[string]bool{"quality": true}}
	res := Mint(badger(), nil, f)
	if res.Exit != ExitFailed || res.Error == nil || res.Error.Code != "step.failed" {
		t.Fatalf("want step.failed exit 1: %+v", res)
	}
	if !reflect.DeepEqual(f.ran, []string{"build", "tests", "quality"}) {
		t.Fatalf("ran %v; nothing after quality may run", f.ran)
	}
	if len(res.Evidence) != 2 {
		t.Fatalf("evidence for exactly the steps before the failure: %+v", res.Evidence)
	}
	for _, e := range res.Evidence {
		if e.Commit != "c1" {
			t.Fatalf("evidence names %s, not the starting HEAD c1", e.Commit)
		}
	}
}

func TestMintDone(t *testing.T) {
	f := &fakeRunner{head: "c1"}
	res := Mint(badger(), []string{"vulns"}, f)
	if res.Exit != ExitOK || res.Error != nil {
		t.Fatalf("want success: %+v", res)
	}
	if !reflect.DeepEqual(f.ran, []string{"build", "vulns"}) {
		t.Fatalf("ran %v", f.ran)
	}
}

// JadeCore.moved_head_stops: HEAD moving during a step stops the mint with exit 3.
func TestMintHeadMoved(t *testing.T) {
	f := &fakeRunner{head: "c1", moveAt: map[string]string{"tests": "c2"}}
	res := Mint(badger(), nil, f)
	if res.Exit != ExitRefused || res.Error == nil || res.Error.Code != "head.moved" {
		t.Fatalf("want head.moved exit 3: %+v", res)
	}
	if !reflect.DeepEqual(f.ran, []string{"build", "tests"}) {
		t.Fatalf("ran %v", f.ran)
	}
}

// Codex on #27: a change to HEAD between one step's end and the next step's start is caught by a
// check before the next step, so that step records nothing. HEAD here moves after tests' own
// post-step check passed and before quality starts.
func TestMintChecksBeforeEachStep(t *testing.T) {
	// Checks run before and after each step: build 1,2; tests 3,4; quality's pre-step check is 5.
	f := &fakeRunner{head: "c1", moveOnCheck: map[int]string{5: "c9"}}
	res := Mint(badger(), nil, f)
	if res.Exit != ExitRefused || res.Error == nil || res.Error.Code != "head.moved" {
		t.Fatalf("want head.moved exit 3: %+v", res)
	}
	if !reflect.DeepEqual(f.ran, []string{"build", "tests"}) {
		t.Fatalf("ran %v; quality must not start after HEAD moved", f.ran)
	}
}

// Codex on #27: a step that leaves tracked files modified, even the last one and even when it
// passes, stops the mint with exit 3 and its evidence is not accepted.
func TestMintRefusesDirtyTreeAfterStep(t *testing.T) {
	f := &fakeRunner{head: "c1", dirtyAfter: map[string]bool{"push-metadata": true}}
	res := Mint(badger(), nil, f)
	if res.Exit != ExitRefused || res.Error == nil || res.Error.Code != "preflight.dirty" {
		t.Fatalf("want preflight.dirty exit 3: %+v", res)
	}
	for _, e := range res.Evidence {
		if e.Step == "push-metadata" {
			t.Fatalf("evidence accepted from the step that dirtied the tree: %+v", res.Evidence)
		}
	}
}

// Codex on #26: a step that both fails and moves HEAD reports the moved HEAD (exit 3), so an agent
// is told the commit changed; evidence covers only the steps before it.
func TestMintFailedAndMovedReportsMove(t *testing.T) {
	f := &fakeRunner{head: "c1", fail: map[string]bool{"tests": true}, moveAt: map[string]string{"tests": "c2"}}
	res := Mint(badger(), nil, f)
	if res.Exit != ExitRefused || res.Error == nil || res.Error.Code != "head.moved" {
		t.Fatalf("want head.moved exit 3: %+v", res)
	}
	if len(res.Evidence) != 1 || res.Evidence[0].Step != "build" {
		t.Fatalf("evidence for exactly the steps before: %+v", res.Evidence)
	}
}

// JadeCore.refusal_runs_nothing and invalid_runs_nothing.
func TestMintRefusesBeforeRunning(t *testing.T) {
	f := &fakeRunner{head: "c1", preflit: &Error{Code: "preflight.dirty", Exit: ExitRefused, Remedy: "commit"}}
	res := Mint(badger(), nil, f)
	if res.Exit != ExitRefused || len(f.ran) != 0 {
		t.Fatalf("a refused preflight runs nothing: %+v ran %v", res, f.ran)
	}
	g := &fakeRunner{head: "c1"}
	res = Mint(&Manifest{Steps: []Step{step("vulns", "build")}}, nil, g)
	if res.Exit != ExitUsage || len(g.ran) != 0 {
		t.Fatalf("an invalid manifest runs nothing: %+v ran %v", res, g.ran)
	}
}

// JadeCore.exitCode_closed, remedy_iff_failure, retryable_iff_transient_code over every error the
// core can return.
func TestResultContract(t *testing.T) {
	var all []*Error
	for _, m := range []Manifest{{}, {Steps: []Step{step("b"), step("b")}}, {Steps: []Step{{Name: "m", Mode: ModeRun}}}, {Steps: []Step{step("v", "b")}}} {
		var e *Error
		if errors.As(m.Validate(), &e) {
			all = append(all, e)
		}
	}
	_, err := badger().Plan([]string{"nope"})
	var e *Error
	errors.As(err, &e)
	all = append(all, e)
	f := &fakeRunner{head: "c1", fail: map[string]bool{"build": true}}
	all = append(all, Mint(badger(), nil, f).Error)
	g := &fakeRunner{head: "c1", moveAt: map[string]string{"build": "c2"}}
	all = append(all, Mint(badger(), nil, g).Error)
	all = append(all, Transient("network down"))
	for _, e := range all {
		if e == nil {
			t.Fatal("missing error")
		}
		if e.Exit < 1 || e.Exit > 4 {
			t.Errorf("%s exits %d, outside 1..4", e.Code, e.Exit)
		}
		if e.Remedy == "" || e.Message == "" || e.Code == "" {
			t.Errorf("%s lacks code, message or remedy: %+v", e.Code, e)
		}
		if e.Retryable != (e.Exit == ExitTransient) {
			t.Errorf("%s: retryable %v but exit %d", e.Code, e.Retryable, e.Exit)
		}
	}
	ok := Mint(badger(), []string{"push-metadata"}, &fakeRunner{head: "c1"})
	if ok.Exit != ExitOK || ok.Error != nil {
		t.Fatalf("success carries no error: %+v", ok)
	}
}

// Codex on #27: Describe's output is safe to paste into a shell. Anything outside a small safe
// set is single-quoted, so an operator in an argument stays part of that argument.
func TestDescribeQuotesEverythingUnsafe(t *testing.T) {
	cases := map[string]string{
		"ok;id":        `'ok;id'`,
		"a|b":          `'a|b'`,
		"a&b":          `'a&b'`,
		">out":         `'>out'`,
		"<in":          `'<in'`,
		"a(b)":         `'a(b)'`,
		"~":            `'~'`,
		"#x":           `'#x'`,
		"!x":           `'!x'`,
		"it's":         `'it'\''s'`,
		"":             `''`,
		"=ls":          `'=ls'`,
		"run":          `run`,
		"--step=vulns": `--step=vulns`,
		".pushgate/x":  `.pushgate/x`,
	}
	for in, want := range cases {
		if got := Describe([]string{in}); got != want {
			t.Errorf("Describe(%q) = %s, want %s", in, got, want)
		}
	}
}

// env.pass names are variable names; env.path entries are absolute (or ~/); anything else is a
// manifest error.
func TestValidateEnv(t *testing.T) {
	step := `"steps":[{"name":"a","mode":"run","argv":["true"]}]`
	for env, ok := range map[string]bool{
		`{"pass":["GOFLAGS","A_1"],"path":["/opt/homebrew/bin","~/.bun/bin"]}`: true,
		`{"pass":["1BAD"]}`:         false,
		`{"pass":["A=B"]}`:          false,
		`{"path":["node_modules"]}`: false,
		`{"path":["~other/bin"]}`:   false,
		`{"path":["/a:/b"]}`:        false,
		`{"unknown":true}`:          false,
	} {
		m, err := Parse([]byte(`{"env":` + env + `,` + step + `}`))
		if err == nil {
			err = m.Validate()
		}
		if (err == nil) != ok {
			t.Errorf("env %s: err %v, want ok=%v", env, err, ok)
		}
	}
}

// Codex on #27 (suggestion): anything after the manifest's JSON value is refused, including a
// stray ] or }, which Decoder.More alone does not catch.
func TestParseRefusesTrailingData(t *testing.T) {
	ok := `{"steps":[{"name":"a","mode":"run","argv":["true"]}]}`
	for _, tail := range []string{"]", "}", " }", "{}", "x"} {
		if _, err := Parse([]byte(ok + tail)); err == nil {
			t.Errorf("trailing %q was accepted", tail)
		}
	}
	for _, tail := range []string{"", "\n", "  \n\t"} {
		if _, err := Parse([]byte(ok + tail)); err != nil {
			t.Errorf("trailing whitespace %q was refused: %v", tail, err)
		}
	}
}
