# jade core: a lean, agent-first build-and-gate CLI

**Status:** design, 2026-09-30. Asked for as a more generic version of Judge's `jade` for
badger. The design takes cues from Bazel, puts AI agents first as users, keeps dependencies to the
Go standard library, and is proved in Lean before it is built.

## Why

Judge's `jade` is about 80 commands and 711 non-test Go files, most of them about Judge's own
infrastructure (ECR, CDK, Kratos, services). Badger needs a small part of it:

- run the checks a push must prove (`.pushgate/steps/*`) and record their evidence (`jade mint`);
- work a stack of layers bottom-up, each with its acceptance command (`testifysec/STACK.md`);
- tell an agent exactly what to do next when something fails.

Two facts from Judge shape this. `jade`'s stack and merge-queue code already uses only the standard
library and cobra, and keeps its state in git refs, so it is portable. And Judge's `CLAUDE.md` says
`jade mint` reads `deploy/pushgate/push-gate.steps.json`, but no code does: the manifest exists and
the mint still hard-codes its steps. The core makes the manifest the only source.

## Non-goals

- Replacing Judge's `jade`. Judge's `jade` can call this core later; nothing here depends on Judge.
- A build system. Bazel's ideas are borrowed where they help an agent. Its build graph,
  sandboxing and remote execution are not.
- Evidence caching across commits. Pushgate binds every collection to the pushed commit, so a
  step's evidence can never be reused for another commit; "up to date" is per commit only.

## Ideas taken from Bazel

| Bazel | Here |
|---|---|
| Targets declared in files, not in code | Steps and layers are declared in `.jade/workspace.json` |
| Explicit `deps` form an acyclic graph | A step names the steps it needs; the plan is a topological order; a cycle is a load error |
| Actions have fixed argv and a fixed environment | A step's argv is fixed in the manifest; it runs from the repository root with an allow-listed environment |
| `bazel query` over the graph | `jade query` answers what a target needs and what needs it, without running anything |
| Stable, labelled targets (`//pkg:name`) | Step and layer names are the only identifiers an agent ever types |
| Output is reproducible for the same inputs | The plan for a manifest and a commit is a pure function; `--plan` prints it without running |

## The agent UX contract

Agents are the primary users. Humans get the same output, readable.

1. **Every command takes `--json`** and then prints exactly one JSON object on stdout, with
   `schemaVersion`. Nothing else goes to stdout in `--json` mode.
2. **Exit codes are a closed set**, the same for every command:

   | code | meaning | retrying unchanged helps? |
   |---|---|---|
   | 0 | done | n/a |
   | 1 | a check ran and failed (the code or evidence is wrong) | no |
   | 2 | usage or manifest error (the request is wrong) | no |
   | 3 | refused before running (dirty tree, wrong directory, rebase in progress, missing tool) | after the remedy |
   | 4 | transient (network, a service unavailable) | yes |

3. **Every non-zero result carries a remedy**: `error.code` (a stable string), `error.message`
   (one sentence), `error.remedy` (the exact argv to run next, or a single instruction when no
   command can fix it), and `error.retryable`. An agent never has to parse prose.
4. **No prompts, no pager, no colour** unless stdout is a terminal. Nothing waits for input.
5. **Plan before act.** `--plan` prints what would run, with exact argv, and exits 0 without side
   effects.
6. **Small output.** Step output streams to a log file whose path is in the result; the result
   carries the last lines of a failing step, not the whole log.
7. **Idempotent where it can be.** Re-running a finished mint for the same commit re-runs it
   (evidence is cheap to re-record and must be fresh), and says so; nothing is half-applied.

## The manifest: `.jade/workspace.json`

```json
{
  "schema_version": 1,
  "steps": [
    {"name": "build", "mode": "run", "argv": ["sh", ".pushgate/steps/build.sh"],
     "attestors": ["git", "alps-evidence"], "product_include_glob": ".pushgate-out/*"},
    {"name": "vulns", "mode": "run", "argv": ["bash", ".pushgate/steps/vulns.sh"],
     "attestors": ["git", "alps-evidence", "sarif"], "product_include_glob": ".pushgate-out/*",
     "needs": ["build"]},
    {"name": "push-metadata", "mode": "attest", "argv": [], "attestors": ["git", "alps-evidence"]}
  ],
  "layers": [
    {"name": "hardened-native", "branch": "hardened-native", "base": "hardened-opencode",
     "accept": ["python3", "testifysec/native/uat.py", "--report", "REPORT.json"]}
  ]
}
```

- `mode` is `run` (wrap argv) or `attest` (record the attestors, no command; argv must be empty).
- `needs` names other steps; the graph must be acyclic and every name must exist.
- Field names are Judge's `push-gate.steps.json` spelling (snake_case), and every field that file
  uses is accepted, so it loads unchanged: `argv_pin` and `release` are carried and shown, not
  interpreted. `schema_version` is optional there and defaults to 1.
- Unknown fields are an error: a typo must not silently drop a guard.

## Commands (first slice)

| command | does |
|---|---|
| `jade plan` | load, validate, print the ordered steps with exact argv |
| `jade mint [--only STEP]` | preflight, then run each step with cilock, in order, stopping at the first failure |
| `jade query needs STEP` / `jade query rdeps STEP` | the graph, read-only |
| `jade doctor` | readiness: cilock present and recent enough, tree clean, agent enrolled |

Stacks (`jade stack ...`) come in the next slice, ported from Judge's `jade stack` (already
stdlib-only apart from cobra).

## Mint semantics (what the Lean model states)

1. **Preflight is exhaustive.** A mint refuses (exit 3) unless run from the repository root, with
   a clean tree (untracked files included), and no merge, rebase, cherry-pick or revert in progress.
2. **The plan is a topological order of the selected steps and their needs.** `--only STEP` runs
   STEP and everything it needs, never less.
3. **All evidence names one commit.** HEAD is read once before the first step and checked after
   every step; if it moved, the mint stops (exit 3) and names both commits.
4. **Fail fast.** The first failing step stops the mint; no later step runs.
5. **Every result is classified.** Each outcome maps to exactly one exit code, and every non-zero
   outcome carries a remedy.

## Dependencies

The Go standard library only: `flag`, `encoding/json`, `os/exec`, `path/filepath`. No cobra, no
YAML, no TOML. The manifest is JSON because the standard library reads it and Judge's steps file is
already JSON.

## Where it lives

`testifysec/jade` in badger, a Go module of its own.
The Lean model is `testifysec/formal/jade`.
