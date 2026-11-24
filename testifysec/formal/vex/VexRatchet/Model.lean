/-!
# VEX exemptions for the badger vulnerability ratchet

A specification of how a push to aflock-ai/badger may carry known vulnerabilities, written
against how the platform actually evaluates a push. It models the rules, not the code;
`README.md` maps each definition to the code it stands for.

Four facts from the real system shape the model:

* The platform evaluates a push with the full policy engine, seeded with the pushed commit
  and a stable repository subject (`judge-api/pkg/policyverify/release.go`, `runRelease`,
  `releaseSubjects`). `discover s (c :: [P.repoSubject])` is that search.
* The evaluation is commit-bound (`BindCommit`, `rookery/attestation/policy/commit_binding.go`).
  A step witness, and an external envelope, count only when bound to the pushed commit: a
  collection whose git attestations all name it, or a bare predicate whose signed subject
  names it through a declared `commitSubject`. `Envelope.commit` is that binding; a
  platform-signed VSA names its subjects `artifact:<digest>` and so is bound to nothing.
* An external with a `timestampConstraint` is decided by its latest admitted envelopes
  (`rookery/attestation/policy/external_latest.go`), read at the TSA-verified time.
* Engine behaviour this model PROPOSES and the engine does not have: a repository-scoped
  external (`Policy.repoScoped`), admitted through the repository subject instead of the
  commit, only while fresh.
-/

namespace VexRatchet

abbrev Subject := String
abbrev Commit  := String
abbrev VulnId  := String
abbrev Pkg     := String

/-- Who signed an envelope. Agents belong to a platform tenant. -/
inductive Principal where
  | agent (tenant : String) (id : String)
  | platform
  | human (email : String)
  deriving DecidableEq, Repr

/-- One advisory against one package: bun audit's (package, GHSA) pair, or a reachable
govulncheck finding's (module, GO id) pair. -/
structure Advisory where
  vuln : VulnId
  pkg  : Pkg
  deriving DecidableEq, Repr

/-- The OpenVEX justifications for `not_affected`. -/
inductive Justification where
  | componentNotPresent
  | vulnerableCodeNotPresent
  | vulnerableCodeNotInExecutePath
  | vulnerableCodeCannotBeControlledByAdversary
  | inlineMitigationsAlreadyExist
  deriving DecidableEq, Repr

/-- OpenVEX statuses. `notAffected none` is a `not_affected` statement with no justification. -/
inductive Status where
  | notAffected (j : Option Justification)
  | fixed
  | affected
  | underInvestigation
  deriving DecidableEq, Repr

/-- A VEX statement. `issued` is the document's own timestamp: written by its author, not
verified by anyone. -/
structure Statement where
  vuln   : VulnId
  pkg    : Pkg
  status : Status
  issued : Nat
  deriving DecidableEq, Repr

/-- What an envelope attests. `scan` is a push's vulnerability evidence: the advisories found
and the VEX statements read from the repository's `.vex/` files in the same run. `vex` is a
standalone OpenVEX document. `vsa` is a verification summary. -/
inductive Body where
  | scan (advisories : List Advisory) (inline : List Statement)
  | vex  (statements : List Statement)
  | vsa  (passed : Bool)
  deriving DecidableEq, Repr

/-- A signed envelope in the tenant's evidence store (Archivista). `commit` is the commit it
is bound to, if any; `tsa` is the TSA-verified signing time in days. -/
structure Envelope where
  body     : Body
  commit   : Option Commit
  subjects : List Subject
  signer   : Principal
  tsa      : Option Nat
  deriving DecidableEq, Repr

abbrev Store := List Envelope

/-- Evidence discovery: every envelope that names one of the seed subjects. -/
def discover (s : Store) (seeds : List Subject) : List Envelope :=
  s.filter (fun e => e.subjects.any (fun x => seeds.contains x))

/-- The push policy for one repository. `baseline` is the ratchet; `maxAge` bounds how old a
VEX may be; `repoSubject` is the repository subject the platform seeds every push with;
`repoScoped` switches on the proposed repository-scoped VEX external. -/
structure Policy where
  tenant      : String
  baseline    : List Advisory
  maxAge      : Nat
  repoSubject : Subject
  repoScoped  : Bool
  deriving DecidableEq, Repr

/-- Only `not_affected` with a justification, or `fixed`, exempts an advisory. -/
def Status.exempts : Status → Bool
  | .notAffected (some _) => true
  | .fixed                => true
  | _                     => false

def agentOf (tenant : String) : Principal → Bool
  | .agent t _ => t == tenant
  | _          => false

/-- `t` is no later than `now` and no more than `maxAge` before it. -/
def within (maxAge now t : Nat) : Bool := decide (t ≤ now) && decide (now ≤ t + maxAge)

def fresh (maxAge now : Nat) : Option Nat → Bool
  | some t => within maxAge now t
  | none   => false

/-- The commit binding: an envelope counts for commit `c` only when bound to exactly `c`. -/
def bound (c : Commit) (e : Envelope) : Bool := e.commit == some c

/-- A statement exempts exactly this vulnerability in exactly this package. -/
def Statement.exempts (a : Advisory) (st : Statement) : Bool :=
  st.vuln == a.vuln && st.pkg == a.pkg && st.status.exempts

def vexStatements (e : Envelope) : List Statement :=
  match e.body with
  | .vex sts => sts
  | _        => []

/-- The envelope is a VEX document, possibly with no statements: an empty document is how
every earlier exemption is revoked. -/
def isVex (e : Envelope) : Bool :=
  match e.body with
  | .vex _ => true
  | _      => false

/-- A standalone VEX is admitted for commit `c` when this tenant's agent signed it, its TSA
time is fresh, and either the commit binding holds (today) or, with the proposed repository
scope, it names the repository subject. Freshness applies either way. -/
def admitted (P : Policy) (now : Nat) (c : Commit) (e : Envelope) : Bool :=
  agentOf P.tenant e.signer && isVex e && fresh P.maxAge now e.tsa &&
  (bound c e || (P.repoScoped && e.subjects.contains P.repoSubject))

/-- The latest TSA time among some envelopes. -/
def latestTime (es : List Envelope) : Option Nat :=
  es.foldl (fun acc e => match acc, e.tsa with
    | some a, some b => some (max a b)
    | none,   t      => t
    | a,      none   => a) none

/-- The external's statements: those every admitted VEX document at the latest TSA time
carries. A newer document supersedes older ones, which is how an exemption is revoked; two
documents at the same latest time must agree, so a revocation signed at the same moment as an
exemption still revokes it (the engine's rule: every admitted envelope at the latest time must
pass, `external_latest.go`). -/
def externalStatements (P : Policy) (found : List Envelope) (now : Nat) (c : Commit) :
    List Statement :=
  let adm := found.filter (admitted P now c)
  let t := latestTime adm
  let latest := adm.filter (fun e => e.tsa == t && t.isSome)
  (latest.flatMap vexStatements).filter (fun st => latest.all (fun e => (vexStatements e).contains st))

/-- A statement read from the repository in the push's own run applies while its author's
timestamp is younger than `maxAge`. -/
def inlineApplies (P : Policy) (now : Nat) (a : Advisory) (st : Statement) : Bool :=
  st.exempts a && within P.maxAge now st.issued

/-- The ratchet: an advisory is allowed when main already carried it, or a VEX exempts it. -/
def covered (P : Policy) (ext inline : List Statement) (now : Nat) (a : Advisory) : Bool :=
  P.baseline.contains a || inline.any (inlineApplies P now a) || ext.any (Statement.exempts a)

/-- The vulns step for commit `c`: a scan bound to `c`, recorded by this tenant's agent, whose
every advisory is allowed. -/
def scanPasses (P : Policy) (ext : List Statement) (now : Nat) (c : Commit) (e : Envelope) : Bool :=
  bound c e && agentOf P.tenant e.signer &&
  match e.body with
  | .scan advs inline => advs.all (covered P ext inline now)
  | _                 => false

/-- The platform's verdict on a push of `c` at time `now`. -/
def pushAccepts (P : Policy) (s : Store) (c : Commit) (now : Nat) : Bool :=
  let found := discover s (c :: [P.repoSubject])
  let ext := externalStatements P found now c
  found.any (scanPasses P ext now c)

end VexRatchet
