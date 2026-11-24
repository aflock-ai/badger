# VEX ratchet model (Lean 4)

A machine-checked specification of how a push to aflock-ai/badger may carry known
vulnerabilities: a ratchet baseline that only shrinks, plus OpenVEX exemptions an agent may
record. It is written against how the platform actually evaluates a push. It compares
two designs: what works on today's engine, and one engine change that would let a VEX kept
in Archivista serve later commits.

```sh
cd testifysec/formal/vex && lake build     # Lean 4.34.1 via elan; no Mathlib
```

`VexRatchet/Model.lean` defines the rules. `VexRatchet/Theorems.lean` proves them: 18
theorems and 11 decided examples. No proof uses `sorry` or `native_decide`, and
`#print axioms` shows only `propext` and `Quot.sound`.

## How the platform evaluates a push (what the model encodes)

| Model | Real system |
|---|---|
| `discover s (c :: [P.repoSubject])` | the push is evaluated by the full policy engine, seeded with the commit and a stable repository subject, sha256 of `https://judge.testifysec.io/v0.1/repository:<url>` (`judge-api/pkg/policyverify/release.go`, `runRelease`, `releaseSubjects`) |
| `bound`, `Envelope.commit` | commit binding (`BindCommit`, `rookery/attestation/policy/commit_binding.go`). A step witness, and an external envelope, count only when bound to the pushed commit: a collection whose git attestations all name it, or a bare predicate whose signed subject names it through a declared `commitSubject` |
| `commit := none` | a platform-signed VSA: its subjects are `artifact:<digest>` (`plugins/attestors/policyverify/policyverify.go`), so no `commitSubject` can bind it |
| `externalStatements`, `latestTime` | an external with a `timestampConstraint` is decided by its latest admitted envelopes, at the TSA-verified time (`rookery/attestation/policy/external_latest.go`) |
| `Policy.repoScoped` | **proposed, not in the engine**: a repository-scoped external, admitted through the repository subject instead of the commit, only while its TSA time is fresh |
| `Body.scan … inline` | the vulns step's own output, which includes the statements read from `.vex/*.openvex.json` in the same run |

## What is proved

**Which statements exempt**
- Only `not_affected` with a justification, or `fixed` (`exempts_iff`, and the three
  `*_never_exempts` lemmas).
- A statement covers exactly one vulnerability in one package (`statement_exempts_iff`).

**Today's engine**
- A standalone VEX counts only when bound to the pushed commit (`admitted_today_is_bound`).
- **A VEX recorded at another commit is refused, however it was found**
  (`other_commit_vex_refused_today`). A VEX kept in Archivista cannot serve a later push.
- **An envelope bound to no commit never binds** (`unbound_envelope_never_bound`). Nested VSA
  chaining through the platform verify door cannot serve a bound push.
- A VEX signed by another tenant, the platform or a person is never admitted
  (`foreign_vex_refused`).

**With the proposed repository scope**
- An unbound VEX needs the repository subject (`repo_scoped_admission`).
- Only the latest admitted VEX document contributes statements. A newer document supersedes
  older ones, which is how an exemption is revoked (`external_from_latest`).
- Documents tied for the latest time must agree: a statement counts only if every one of
  them carries it, so a revocation signed at the same moment as an exemption still revokes
  it (`tie_needs_agreement`). This follows the engine, where every admitted envelope at the
  latest time must pass.

**Either way**
- A stale or untimestamped VEX is refused, even one bound to the pushed commit
  (`stale_vex_refused`).
- An empty VEX document is admitted, so a newer empty document revokes every earlier
  exemption.
- A push is accepted only on a scan bound to the pushed commit, recorded by this tenant's
  agent, whose every advisory is allowed. The repository scope widens where VEX may come
  from; it never lets another commit's scan witness the push (`push_needs_own_scan`).
- One new advisory that nothing allows fails the push (`new_advisory_fails`).
- Fixing advisories never turns a pass into a fail (`fixing_keeps_pass`).
- A repository VEX statement older than `maxAge` by its own timestamp exempts nothing
  (`stale_inline_exempts_nothing`).

**`Example` replays the motivating case:** a VEX recorded on day 0 while `main` was at `c1`,
and a push of `c2` on day 90.

| Design | Day 90 | Day 366 |
|---|---|---|
| VEX kept in Archivista, today's engine | refused (binding) | n/a |
| VEX in `.vex/`, read in the push's own run | accepted | n/a |
| VEX in Archivista, repository scope | accepted | refused (stale) |
| …after a newer VEX document dropped the statement | refused (revoked) | n/a |
| …after a newer, empty VEX document | refused (revoked) | n/a |
| …after an empty document signed at the same moment | refused (revoked) | n/a |
| VEX bound to the pushed commit itself | accepted | refused (stale) |

Another commit's clean scan never witnesses the push, even with the repository scope.

## What is assumed, not proved

- **Agents are trusted to author VEX and to run the scan honestly** (the accepted
  tradeoff). An agent can exempt any vulnerability with a VEX, and can record a scan that
  omits advisories. Scan honesty rests on the agent's enrolled identity.
- **The repository-file design has a self-asserted age.** `Statement.issued` is written by the
  VEX's author, so `maxAge` bounds only what the author claims. Git history is the record.
  The repository-scoped design reads the TSA time instead.
- Signatures are unforgeable, the TSA is honest, and time is in whole days.

## What this means for badger

1. **Today:** keep VEX in `.vex/*.openvex.json`. The vulns step reads them in the push's own
   run, so they are bound to the commit, and the evidence that lands in Archivista records
   every statement each push relied on.
2. **Engine change worth making:** a repository-scoped external. The seed already exists
   (`releaseSubjects`), and `commitSubject` is the same shape of opt-in. The change is to
   admit, for an external that declares it, an envelope signed under the repository subject.
   It must be required together with a `timestampConstraint`, and must never apply to steps.
