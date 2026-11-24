/-!
# jade core: the manifest, the plan, the mint, and the agent result contract

A specification of `testifysec/jade` (see `testifysec/jade/DESIGN.md`). It models the rules, not the
Go that implements them; `README.md` maps each definition to its code.

* The manifest lists steps; a step may **need** others. The file order is the run order, and a
  manifest is valid only when every step comes after the steps it needs. That one rule makes the
  graph acyclic and the plan deterministic, with no sort.
* `plan only` keeps the selected steps and everything they need, transitively, in file order.
* A mint first checks the repository (preflight), then runs the plan, stopping at the first failure
  or at a moved HEAD. Every piece of evidence names the commit HEAD was at when the mint began.
* Every outcome maps to exactly one exit code from a closed set, and every non-zero outcome
  carries a remedy an agent can act on.
-/

namespace JadeCore

abbrev Name := String
abbrev Commit := String

inductive Mode | run | attest
  deriving DecidableEq, Repr

structure Step where
  name  : Name
  mode  : Mode
  argv  : List String
  needs : List Name
  deriving DecidableEq, Repr

abbrev Manifest := List Step

def names (m : Manifest) : List Name := m.map Step.name

/-- A step's needs all appear among the steps before it. -/
def needsBefore (before : List Step) (s : Step) : Bool :=
  s.needs.all fun n => (names before).contains n

/-- Every step's needs appear before it, in file order. -/
def orderedAux : List Step → List Step → Bool
  | _,      []      => true
  | before, s :: ss => needsBefore before s && orderedAux (before ++ [s]) ss

/-- The load checks: names are unique, `attest` steps carry no command and `run` steps carry one,
and every step comes after the steps it needs. -/
def valid (m : Manifest) : Bool :=
  (names m).Nodup &&
  m.all (fun s => match s.mode with
    | .attest => s.argv.isEmpty
    | .run    => !s.argv.isEmpty) &&
  orderedAux [] m

/-- The plan for `--only` (empty means every step): walking the file backwards, keep a step when it
was selected or a kept later step needs it. The result is in file order. -/
def planAux (only : List Name) : List Step → List Step × List Name
  | []      => ([], [])
  | s :: ss =>
    let (kept, wanted) := planAux only ss
    if only.contains s.name || wanted.contains s.name then
      (s :: kept, s.needs ++ wanted)
    else
      (kept, wanted)

def plan (m : Manifest) (only : List Name) : List Step :=
  if only.isEmpty then m else (planAux only m).1

/-! ## The mint -/

/-- What preflight reads from the repository. -/
structure Repo where
  atRoot     : Bool
  clean      : Bool
  inProgress : Bool
  cilock     : Bool
  deriving DecidableEq, Repr

inductive Refusal | notAtRoot | dirty | operationInProgress | noCilock
  deriving DecidableEq, Repr

/-- The first failing check, in a fixed order, or none. -/
def preflight (r : Repo) : Option Refusal :=
  if !r.atRoot then some .notAtRoot
  else if !r.clean then some .dirty
  else if r.inProgress then some .operationInProgress
  else if !r.cilock then some .noCilock
  else none

/-- What running one step reports: its exit, HEAD afterwards, and whether the tree is still clean. -/
structure StepRun where
  passed : Bool
  headAfter : Commit
  cleanAfter : Bool
  deriving DecidableEq, Repr

inductive Outcome
  | done (evidence : List (Name × Commit))
  | stepFailed (step : Name) (evidence : List (Name × Commit))
  | headMoved (step : Name) (from_ to : Commit) (evidence : List (Name × Commit))
  | treeChanged (step : Name) (evidence : List (Name × Commit))
  | refused (why : Refusal)
  | invalidManifest
  | unknownStep (n : Name)
  | transient (what : String)
  deriving Repr

/-- Run the plan. `exec` is what running a step reports; the mint stops at the first step after
which HEAD is no longer `head` (checked first), or at the first failure. Evidence is recorded
against `head`, and only for steps that passed with HEAD unmoved. -/
def runSteps (exec : Name → StepRun) (head : Commit) : List Step → List (Name × Commit) → Outcome
  | [],      ev => .done ev.reverse
  | s :: ss, ev =>
    let r := exec s.name
    -- HEAD is checked first: a step that moved HEAD stops the mint with exit 3, whether or not it
    -- also failed, so an agent is always told the commit changed under it.
    if r.headAfter != head then .headMoved s.name head r.headAfter ev.reverse
    else if !r.cleanAfter then .treeChanged s.name ev.reverse
    else if !r.passed then .stepFailed s.name (ev.reverse)
    else runSteps exec head ss ((s.name, head) :: ev)

def mint (m : Manifest) (only : List Name) (repo : Repo) (head : Commit) (exec : Name → StepRun) :
    Outcome :=
  if !valid m then .invalidManifest
  else match only.find? (fun n => !(names m).contains n) with
    | some n => .unknownStep n
    | none =>
      match preflight repo with
      | some why => .refused why
      | none => runSteps exec head (plan m only) []

/-! ## The agent result contract -/

/-- The closed set of exit codes. -/
def exitCode : Outcome → Nat
  | .done _            => 0
  | .stepFailed ..     => 1
  | .invalidManifest   => 2
  | .unknownStep _     => 2
  | .refused _         => 3
  | .headMoved ..      => 3
  | .treeChanged ..    => 3
  | .transient _       => 4

def retryable : Outcome → Bool
  | .transient _ => true
  | _            => false

/-- What an agent is told to do next. `none` only for success. -/
def remedy : Outcome → Option String
  | .done _                      => none
  | .stepFailed s _              => some s!"fix what step {s} reports, commit, then run: jade mint"
  | .invalidManifest             => some "fix .jade/workspace.json, then run: jade plan"
  | .unknownStep n               => some s!"step {n} is not in the manifest; run: jade query steps"
  | .refused .notAtRoot          => some "run jade from the repository root"
  | .refused .dirty              => some "commit or remove the changes, then run: jade mint"
  | .refused .operationInProgress => some "finish or abort the merge, rebase or cherry-pick, then run: jade mint"
  | .refused .noCilock           => some "install cilock (curl -fsSL https://cilock.dev/install.sh), then run: jade doctor"
  | .headMoved _ _ _ _           => some "HEAD moved during the mint; do not commit while minting, then run: jade mint"
  | .treeChanged s _             => some s!"step {s} left the tree changed; commit or remove the changes, then run: jade mint"
  | .transient _                 => some "retry the same command"

end JadeCore
