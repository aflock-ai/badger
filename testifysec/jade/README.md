# jade

Runs the checks a push must prove and records their evidence with cilock, from the steps declared
in `.jade/workspace.json`. Built for AI agents first; readable by people. Design: `DESIGN.md`.
Model: `testifysec/formal/jade` (Lean). Dependencies: the Go standard library, nothing else.

```sh
go -C testifysec/jade build -o ~/.local/bin/jade .   # outside the repository: mint refuses a jade inside it
jade plan   [--only STEP]... [--json]                 # what would run, exact argv; runs nothing
jade mint   [--only STEP]... [--json] [--cilock PATH] # preflight, then each step, fail fast
jade query  steps | needs STEP | rdeps STEP [--json]
jade doctor [--json]                                  # ready to mint?
```

## The contract an agent can rely on

- `--json` prints exactly one JSON object on stdout, with `schema_version` and `exit_code`.
- Exit codes: 0 done, 1 a check failed, 2 usage or manifest error, 3 refused before running (or
  HEAD moved during a mint), 4 transient.
- Every failure carries `error.code` (stable), `error.message` (one sentence), `error.remedy`
  (what to run next) and `error.retryable` (true only for exit 4).
- A mint records evidence only against the commit HEAD was at when it began, stops at the first
  failing step, and writes each step's output to a log file listed under `logs`.

## The manifest

```json
{"env": {"pass": ["NODE_ENV"], "path": ["/opt/homebrew/bin", "~/.bun/bin", "~/go/bin"]},
 "steps": [
  {"name": "build", "mode": "run", "argv": ["sh", ".pushgate/steps/build.sh"],
   "attestors": ["git", "alps-evidence"], "product_include_glob": ".pushgate-out/*"},
  {"name": "vulns", "mode": "run", "argv": ["bash", ".pushgate/steps/vulns.sh"],
   "attestors": ["git", "alps-evidence", "sarif"], "needs": ["build"]},
  {"name": "push-metadata", "mode": "attest", "argv": [], "attestors": ["git", "alps-evidence"]}
]}
```

File order is run order: a step must come after the steps it needs. Unknown fields are refused.
Judge's `deploy/pushgate/push-gate.steps.json` loads unchanged (`core/testdata`).

Steps get a strict environment, built rather than inherited (Bazel's strict action env): `HOME`,
`USER`, `LOGNAME`, `TMPDIR`, `TERM`, `TZ`, `LANG`, `LC_*`, `SSH_AUTH_SOCK`, `CI`, and what cilock
needs to sign (`CILOCK_*`, `GITHUB_*`, `ACTIONS_ID_TOKEN_REQUEST_*`), and `PATH` set to
`/bin:/usr/bin:/usr/local/bin`. Nothing else comes from the caller: not `BASH_ENV`,
`NODE_OPTIONS`, `LD_PRELOAD`, `GOFLAGS`, nor the caller's `PATH`. A step that needs more says so in
the committed manifest: `env.pass` names variables to pass through, and `env.path` adds absolute
(or `~/`) directories to `PATH`; each is passed as the directory it resolves to when the mint
starts, and one inside the checkout, or one that does not resolve, is dropped. In CI,
`GITHUB_WORKSPACE` is set to the snapshot.

## Threat model

jade makes evidence that a commit passed its checks. It defends against what can differ from the
reviewed commit on the machine that mints:

- uncommitted content in the checkout: edited, staged, untracked or ignored files, including
  ignored binaries and tool directories (`node_modules/.bin`, `.bin/`);
- the repository's local git state: config (filters, fsmonitor, hooks, excludes, `core.worktree`,
  `ignoreCase`), `info/attributes`, `info/exclude`, replace refs, partial-clone fetching;
- the object store: the commit and every tree are rehashed from their raw bytes and must match
  their IDs (git does not check), and every blob is checked through the files written from it;
- a commit, checkout or edit made while a mint runs;
- a step that changes its own tree, which is recorded as a failed command.

It trusts the operator's own setup outside the checkout: the jade, git and cilock binaries it
resolves (refused if they resolve into the checkout), the directories on a step's `PATH` and the
programs in them (the strict defaults and the manifest's `env.path`), the variables `env.pass`
names, and the user's global git config. jade's own git calls get the same allowlisted environment as
steps. "Inside the checkout" means inside any enclosing directory with a `.git`, so with a
dotfiles repository at `~/.git`, git and cilock must live outside your home directory's
repository too. The temporary directory must be outside the checkout (`snapshot.tmpdir`). Someone who can change those can already replace cilock
itself; jade does not try to defend against the account that runs it.

## Limits

`jade mint` reads HEAD once, before anything else, and runs the manifest as committed at that
commit, never the working copy. Your checkout must be clean, and jade checks that without asking
`git status`, which can be configured to lie and runs whatever filter the local config names. git
only reads the index and object ids: no tracked file may be marked `skip-worktree` or
`assume-unchanged` (`preflight.hidden`), nothing may be staged or untracked, an ignored file must
be ignored by a `.gitignore` committed at that commit (not `.git/info/exclude`, the global excludes
file or an uncommitted `.gitignore`), and every file the commit tracks, submodules included, is read
from disk and hashed as a git blob in Go and must match (about 0.7s on badger's 7,000 files).

The steps do not run in your checkout. jade writes the pinned commit into a repository of its
own in a private temporary directory (about 11s for badger), verifies it the same way, runs every
step there, checks it again before and after each step, and deletes it when the mint ends. The
snapshot holds its own copy of the pinned commit's objects (commit, trees and blobs, each
rehashed against its ID), reads older history from a copy of your object store taken when the
mint starts (a copy-on-write clone on APFS or a reflink filesystem; a store holding a symlink is
refused) in which every object, history included, is rehashed by `git fsck --full`, has HEAD
detached at the pinned commit and your remote URLs, and nothing else: no repository-local config, `info/attributes`,
hooks or refs of yours reach a step's git. git itself must be installed outside the checkout
(`preflight.git-in-checkout`).
cilock uploads each step's evidence as the step finishes, so evidence recorded in your checkout
would name whatever HEAD was at that moment; in the snapshot, a commit or checkout you make
mid-mint changes nothing the steps see. git writes none of the snapshot's files (a checkout would
run local smudge filters and hooks): jade writes each from its raw blob. Two consequences:

- Steps start from a fresh checkout. Nothing ignored is there (no `node_modules`, no build
  output), so a step that needs dependencies installs them itself.
- A commit with submodules is refused (`snapshot.submodule`): jade does not fetch them.

cilock 4.5.0 uploads a step's evidence when its command ends and cannot defer that, so the tree
check that matters is inside the command it records. jade runs each `run` step as
`cilock run ... -- jade step-guard -- COMMAND`: the guard runs the step's command, then checks the
snapshot is still clean at the pinned commit, and exits 3 if it is not. A step that edits a tracked
file or commits and exits 0 is therefore recorded as a failed command, which no policy that
requires the step to pass accepts. `jade plan` shows the wrapped argv exactly.

A step's PATH has every directory that resolves into your checkout removed, so an ignored
`node_modules/.bin` there cannot stand in for a tool the step names.

For jade's git calls and every step, git never fetches (`GIT_NO_LAZY_FETCH=1`), replace refs are
off (`GIT_NO_REPLACE_OBJECTS=1`), hooks are off, and no repository-selection variable (`GIT_DIR`
and the rest of `git rev-parse --local-env-vars`) is passed on. Every remedy that names a path
quotes it.

Step names are identifiers (`[A-Za-z0-9][A-Za-z0-9._-]*`), never paths, and jade names each
step's log file itself.
