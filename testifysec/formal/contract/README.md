# The platform contract (Lean 4)

Badger plugs into a platform: the TestifySec platform, badger's own lightweight portal, or anyone
else's. This directory is the machine-checked model of what that platform and badger owe each
other, and the conformance vectors that let any implementation prove it keeps the contract.

Three surfaces are pinned today:

- **Classification labels.** `marking.Dominates` and `marking.Join` (testifysec/connectors), and
  the banner a connector puts on every result.
- **Session flow.** A session's label is the join of everything it read; content goes only to a
  sink whose accreditation dominates that label (testifysec/CONNECTORS.md). Specified, not built.
- **Profile admission.** The device admits a signed profile only if it was signed by the trust
  root, is assigned to this tenant, deployment and profile, is inside its window, and is not older
  than one already admitted (testifysec/broker).

Two management backends implement the contract: the open-source lightweight portal and a
platform (`Backends.lean`). The workstation is identical under both; switching is replacing the
pinned trust root. The portal's HTTP API is not pinned yet; `Portal.lean` holds the sequence rule
and the questions the API has to answer.

```sh
sh testifysec/formal/contract/check.sh           # what the pushgate "formal" step runs
sh testifysec/formal/contract/check.sh --write   # regenerate vectors/contract-vectors.json
```

Lean 4.34.1, core only (no Mathlib, no dependencies, builds offline in seconds). The checks are
the pushgate step's, not this directory's (`.pushgate/steps/formal.sh`, `formal-audit.lean`,
`formal-cite.py`, `formal-extract.py`, `formal-order.py`, `formal-harness/`), so a commit cannot weaken them by
editing its own scripts or tests.

**The boundary, plainly.** The step guarantees that a commit cannot skip, fake, or tamper across
phases with its checks: it reads only the commit's git objects, builds each module from its
committed source with lean itself (no Lake), fails if any .olean changes after its own compile,
and between phases kills every process the commit's code left running (in the runner's container
only, never on a host), writing what a later phase reads fresh. The commit's own code acting
maliciously within its own build or test phase (an `#eval` or `initialize` in the model while it
compiles, an `init()` in the Go under test) is out of scope for this step and covered by diff
review, as is a commit that weakens the model's own statements. Per-phase containers (#175) are
the follow-up that narrows this. Run on a host (`check.sh`), nothing is reaped and the step says
so.

## Files

| File | What it is |
|---|---|
| `Model.lean` | Labels, FGI, assignments, profiles, envelopes, refusal codes. Tokens are numbers. |
| `Spec.lean` | The contract as executable definitions: `Dom`, `lub`, the session, `validate`, `admit`. |
| `AsBuilt.lean` | Today's Go, transcribed and cited (`-- cite: path:a-b sha256:…`). |
| `Proofs.lean` | Every property, for every input. |
| `Mutants.lean` | Each guard switched off, with the case that breaks its theorem. |
| `Portal.lean` | Stub: platform-assigned, strictly increasing sequences; open questions. |
| `Backends.lean` | The backend as a parameter: certificate-chain admission, activation and reset records, the persisted high-water; portal and platform as two instances. |
| `NotCovered.lean` | What the model abstracts away. |
| `Vectors.lean`, `Main.lean` | `lake exe contract-vectors`, which writes `vectors/contract-vectors.json`. |
| `check.sh` | Runs the pushgate step locally (`--write` regenerates vectors and citation digests first). |

## What is proved

| Property | Theorem |
|---|---|
| Dominance is reflexive, transitive, and antisymmetric up to set equality | `dom_refl`, `dom_trans`, `dom_antisymm` |
| The join dominates both sides and is dominated by anything that does | `lub_upper_left`, `lub_upper_right`, `lub_least` |
| A delivered send's sink dominates every label read before it (no write down) | `no_write_down` |
| A join with no banner (controlled-unclassified with FGI, atomic-energy or non-IC markings) is refused, exactly; a session whose join is refused sends nothing | `AsBuilt.refusedGo_iff`, `AsBuilt.joinChecked_bannerable`, `refused_delivers_nothing` |
| Go's `Dominates` is exactly `Dom` on the labels the banners mean | `AsBuilt.domGo_iff`, `AsBuilt.domGo_trans` |
| Go's `Join` is never below the least upper bound, so it dominates both sides | `AsBuilt.joinGo_above_lub`, `AsBuilt.joinGo_upper_left/right` |
| A result's banner is exactly the connector's marking | `AsBuilt.result_is_connector` |
| The session composed from Go's `Join` and `Dominates` never writes down, whatever `Join` refuses for banner length | `AsBuilt.flowGo_no_write_down` |
| A banner-length refusal (`ErrBannerTooLong`) only removes a join, never changes it | `AsBuilt.joinChecked_long_only_refuses` |
| An admitted profile was validly signed, only by trust-root keys | `admit_signed` |
| It is the assigned tenant, deployment, profile, payload and manifest | `admit_assigned` |
| A profile for one tenant never activates for another | `admit_tenant` |
| Now is inside its window | `admit_window` |
| No envelope, or a bad signature, is never admitted (fail closed) | `admit_required`, `admit_unsigned` |
| A sequence below the high-water mark is refused; admitted sequences never decrease | `admit_rollback`, `admitted_monotone` |
| Platform-assigned sequences strictly increase, so a new version is never a rollback | `Portal.publish_increasing`, `Portal.next_not_rollback` |

### Open source or platform: the backend is a parameter

`Backends.step` is the workstation: it takes the pinned roots, this device's tenant, deployment,
profile and key, its persisted high-waters and a signed artifact. It never sees a backend.

| Property | Theorem |
|---|---|
| An accepted artifact chains to a pinned root with the signer identity, and its signed window lies inside the leaf | `step_chained`, `step_inside_leaf`, `step_window` |
| It is for this tenant and deployment, and this profile or this device | `step_assigned` |
| An activation strictly raises the activation high-water; only a reset signed for this device lowers one; a refusal changes nothing | `activation_raises`, `hw_lowered_only_by_reset`, `refusal_keeps_state` |
| Parametricity: two backends with the same root are indistinguishable to the workstation, so every workstation theorem (these, `admit_*`, `admitted_monotone`, `no_write_down`, `result_is_connector`) holds for any backend | `workstation_parametric` |
| Any conforming backend's activation is admitted | `conforming_backend_admitted` |
| Substitutability: after a switch, artifacts under the old root are refused and the new root's admitted; mixed trust only when both roots are pinned | `switch_refuses_old`, `switch_admits_new`, `mixed_trust_admits_both`, `chain_iff_pinned` |
| Migration: a new backend that restarts its sequence is refused and the device keeps its pin (no silent rollback); one that carries the floor above the high-water is admitted | `migration_restart_refused`, `migration_carried_admitted` |
| Central evidence, Pushgate and the device-identity kind change no trust and no signed artifact | `extras_not_load_bearing`, `identity_not_load_bearing` |
| A revoked device is served nothing | `revoked_gets_nothing` |
| The portal and a platform give every backend vector the same outcome | `Vectors.backends_agree` |

For the flow and banner checks parametricity is structural: they take no backend or trust
argument at all. For admission it is `workstation_parametric`. **The migration requirement:** the
new backend's activation floor for each deployment must start above the highest activation
sequence any device in it has admitted; otherwise every device refuses it, safely but completely.

## What the model found

- **`Dominates` was not transitive, and a session could write down.** A marking naming FGI
  countries held concealed FGI (`SECRET//FGI FRA` dominated `SECRET//FGI`), and concealed FGI holds
  any named list, so content marked FGI GBR could reach a sink accredited for FGI FRA only
  (`Mutants.fgi_old_write_down`).
  Fixed in the connectors change this stacks on: concealed FGI
  is held only by concealed FGI (dominance.go). The vectors fail if it comes back.
- **`Join` is not always the least upper bound.** Disjoint REL TO lists become NF where the least
  bound is release to USA only (`asbuilt_join_not_least_rel`). That is the safe direction (proved:
  `joinGo_above_lub`); 6 of the 546 joins that are not refused hit it, and one flow vector shows a send the contract
  allows that Go's join denies. DISPLAY ONLY used to meet by token, so FVEY and GBR shared nothing;
  it is now an audience compared and joined by country, exactly (`asbuilt_join_least_disp`).
- **Result banners.** A connector carries one classification, its administrator-set marking, and
  every result carries it (`result_is_connector`). Content markings are no longer read; the session
  high-water is the join over the connectors a session read from.
- **No device keeps a high-water sequence.** The verifier is stateless; rollback is stopped only
  by the administrator's payload pin (`asbuilt_pin_blocks_rollback`, assuming digests do not
  collide), and re-pinning an older profile rolls the device back (`asbuilt_repin_rolls_back`).
  The contract requires the high-water check (`Spec.admit`); its vectors (`admissionSequence`)
  wait for an implementation.
- **The schema-1 verifier (broker/admission.go) checks the tenant** (#160,
  `asbuilt_v1_checks_tenant`), deployment and profile against its own policy, as the schema-2
  verifier (broker/vzbackend) does. A request with no profile is admitted only by a broker built
  with `-tags uatnoprofile` (`asbuilt_v1_uat_no_profile`); a release build never admits one
  (`asbuilt_v1_release_needs_profile`).

## Mutants

| Mutant | Kills |
|---|---|
| `fgi_old_not_transitive`, `fgi_old_write_down`: the shipped FGI rule | `domGo_trans`, `flowGo_no_write_down` |
| `last_read_write_down`: the session label is the last read | `no_write_down` |
| `meet_ignored`: the join keeps the first release list | `lub_upper_right` |
| `cats_dropped`: the join drops categories below confidential | `lub_upper_left` |
| `concealed_lost`: concealed FGI joined with a list keeps the list | `lub_upper_left` |
| `no_high_water`: admit whatever validates (today's Go) | `admitted_monotone` |
| `no_tenant_check`: skip the assignment check | `admit_tenant` |
| `no_window`: skip the window | `admit_window` |
| `any_signer`: admit a signer outside the trust root | `admit_signed` |
| `join_ignores_caveats`: Join never refuses | `joinChecked_bannerable` |
| `trust_any_root`: a workstation that accepts any backend's root | `switch_refuses_old` |
| `restart_rolls_back`: a migration that also resets the device's high-water | `migration_restart_refused` |
| `serves_revoked`: a backend that skips revocation | `revoked_gets_nothing` |

Each mutant is a concrete case decided by the kernel, beside the passing case for the real
definition. The Go harnesses were also mutated by hand before committing: reverting the FGI fix
fails `TestContractVectorsDominates` and `TestContractVectorsFlow`, making disjoint REL TO lists
join to REL TO USA fails `TestContractVectorsJoin`, and checking metadata before the assignment
fails `TestContractVectorsAdmission` on the refusal order.

## The vectors

`vectors/contract-vectors.json` (schema `badger.contract.vectors/v1`) is generated, never edited.
Every expected value is computed by the definitions the theorems are about.

| Surface | Count | Each vector | Replayed by |
|---|---|---|---|
| `markings` | 24 | a marking as the Go struct holds it (controls as portion marks, NF, OC) | |
| `dominates` | 576 | every ordered pair, and whether `a` may hold `b` | `marking` `TestContractVectorsDominates` |
| `join` | 576 | every ordered pair: refused (no banner), or Go's join as transcribed and whether it is the least bound | `TestContractVectorsJoin` |
| `flow` | 9 | a session of reads and sends; Go-composed decisions and the contract's | `TestContractVectorsFlow` |
| `admission` | 27 | a verifier output and the refusal code it must produce, in order | `vzbackend` `TestContractVectorsAdmission` |
| `admissionSequence` | 4 | a device high-water trace and what it admits | no implementation yet |
| `backends` | 16 | a backend swap, mixed trust, migration or reset case, with the outcome under the portal and under a platform (they must agree) | no implementation yet (chain admission and activation records are PRs 3 and 4) |
| `serve` | 3 | an enrolled, revoked or unknown device, and whether each backend serves it | no implementation yet |

`tetragraphs` carries FVEY's members; `TestContractVectorsTables` checks them against tokens.json.
Times are seconds relative to the verifier's own clock, and no boundary sits at "now".

## How a platform checks itself against the contract

The vectors are plain JSON, so any implementation replays them without Lean or badger's Go:

1. Pin a badger commit and the sha256 of `testifysec/formal/contract/vectors/contract-vectors.json`
   at that commit in the platform's own repository. Fetch it by that commit (a raw file URL or a
   checkout of the badger submodule) and refuse it if the digest differs.
2. In the platform's CI, a test reads the file and, per surface: builds each marking and checks its
   `Dominates` and `Join` (compare join results as sets), runs each `flow` session through its
   gateway check and requires `expect` exactly (and never a send `contract` denies), and feeds
   each `admission` case to its admission layer and requires the refusal code. A platform that
   issues profiles also replays `admissionSequence` against its device or issuer, and `backends`
   and `serve` with itself as "own": the expected outcome is the same for every backend.
3. Bumping the badger pin is the only way the expectations change, and a failing test on the bump
   is the contract telling the platform it drifted.

Badger's Go harnesses (`.pushgate/steps/formal-harness/`, the runner's own, copied into scratch
copies of the packages by the step) read the vectors from `CONTRACT_VECTORS`, so a copy fetched by
URL can be replayed against this code too. The TypeScript port of the marking order (CONNECTORS.md) should replay the
same file rather than keep its own table.

## Not modelled

See `NotCovered.lean`: parsing and rendering, the full token tables, cryptography and verifier
custody, strict JSON and clock boundaries, digest injectivity (a hypothesis), the unbuilt gateway
check and device high-water, certificate-chain crypto and timestamping, high-water persistence,
and the portal API. One item is open, not abstracted: a platform whose signing leaves live minutes
cannot sign a 7-day activation under the window-inside-the-leaf rule, so admission needs trusted
timestamps or the platform needs 7-day leaves for these artifacts.
