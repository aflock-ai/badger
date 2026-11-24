# jade core model (Lean 4)

A machine-checked specification of `testifysec/jade` (design: `testifysec/jade/DESIGN.md`): the
manifest, the plan, the mint, and the result contract an agent reads.

```sh
cd testifysec/formal/jade && lake build     # Lean 4.34.1 via elan; no Mathlib
```

17 theorems and 8 decided examples. No `sorry` or `native_decide`; `#print axioms` shows only
`propext` and `Quot.sound`.

## What is proved

**The manifest and the plan**
- A valid manifest lists every step after the steps it needs (`valid_needs_before`), so the graph
  is acyclic and file order is run order.
- `--only` keeps every selected step (`selected_kept`) and everything a kept step needs, however
  deep (`plan_closed` with `valid_needs_before`), in file order, inventing nothing
  (`planAux_sublist`).

**The mint**
- Preflight passes exactly when the tree is at the root, clean, with no merge, rebase or
  cherry-pick in progress and cilock present (`preflight_none_iff`).
- An invalid manifest, or a refused preflight, runs nothing (`invalid_runs_nothing`,
  `refusal_runs_nothing`).
- Every piece of evidence names the commit HEAD was at when the mint began
  (`evidence_names_head`).
- The first failing step stops the mint with evidence for exactly the steps before it
  (`fail_fast`). A HEAD that moves during a step stops it with exit 3 whether the step passed or
  failed: HEAD is checked first, so an agent is always told the commit changed
  (`moved_head_stops`).

**The agent result contract**
- Exit codes are the closed set 0..4 (`exitCode_closed`).
- There is a remedy exactly when the result is not success (`remedy_iff_failure`).
- Only a transient result is retryable, and it exits 4 (`retryable_iff_transient_code`).

## Examples

Badger's own steps: `--only vulns` runs `build` then `vulns`, nothing else. A step listed before
what it needs, a duplicate name, an attest step with a command and a run step without one are all
rejected at load.
