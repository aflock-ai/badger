/-!
# Broker policy

The broker decides which CI pipelines may call which models. An edge proxy in front of it has
already verified the pipeline's OIDC token (signature under pinned keys, issuer, audience,
validity window, lifetime cap) and forwards the verified payload on a listener only the edge can
reach. This file is what the broker does with that payload.

Implemented in `policy.go` (`Evaluate`, `Validate`) and `server.go` (the two listeners).
`testdata/decisions.json` is a corpus of cases that `policy_test.go`, `formal/mirror.py` and the
generated `BadgerBroker/Corpus.lean` all decide; the three must agree with the recorded answers.

## Assumptions (accepted, not proved)

* **B1 edge.** Every payload that arrives on the edge listener was verified by the edge, and only
  the edge can open a connection to that listener (network policy). The broker re-checks issuer,
  audience and expiry anyway; it cannot re-check the signature, which the edge consumed.
* **B2 claims.** The CI system sets `project_path`, `ref`, `ref_type`, `ref_protected`,
  `pipeline_source`, `ci_config_ref_uri` and `user_login` truthfully. Only people allowed to push
  or merge to a protected branch can run a pipeline whose token says `ref_protected = "true"`.
  For a named (unprotected) branch entry, `user_login` decides, so it is trusted too.
* **B3 clock.** `now` is the broker clock with the configured skew already applied.
-/

namespace BadgerBroker

/-- `aud` is one string or a list. Only the one-string form can match. -/
inductive Aud where
  | one (aud : String)
  | many (auds : List String)
  deriving DecidableEq, Repr

/-- The verified payload as the broker parses it. A missing optional claim is `""`. -/
structure Claims where
  iss            : String
  aud            : Aud
  exp            : Nat
  iat            : Nat
  projectPath    : String
  ref            : String
  refType        : String
  refProtected   : String
  pipelineSource : String
  ciConfigRefUri : String
  userLogin      : String
  deriving DecidableEq, Repr

/-- `protectedBranch` admits only tokens that say the branch is protected. `namedBranch` admits
one named, unprotected branch (anyone with push access can change its code), so it must name the
people who may trigger it and an expiry (`wellFormed`). If the branch becomes protected, the entry
stops matching and should be replaced by a protected-branch entry. -/
inductive Kind where
  | protectedBranch | namedBranch
  deriving DecidableEq, Repr

structure Entry where
  id           : String
  kind         : Kind
  projectPath  : String
  ref          : String
  sources      : List String
  models       : List String
  triggerUsers : List String
  expiresAt    : Option Nat
  mintedBefore : Option Nat
  enabled      : Bool
  deriving DecidableEq, Repr

/-- A broker principal. Pipelines only: people never come through this file. -/
inductive Principal where
  | ci (project : String) (branch : Option String)
  deriving DecidableEq, Repr

/-- The principal comes from the entry that matched, never from a header. A protected-branch
entry keeps the plain `ci:<project>` name; a named-branch entry carries its branch. -/
def Entry.principal (e : Entry) : Principal :=
  match e.kind with
  | .protectedBranch => .ci e.projectPath none
  | .namedBranch     => .ci e.projectPath (some e.ref)

/-- The usage and audit key. `wellFormed` forbids `@` in project paths, so the two forms never
collide (`render` is injective on well-formed policies; checked by `Validate`). -/
def Principal.render : Principal → String
  | .ci p none     => "ci:" ++ p
  | .ci p (some b) => "ci:" ++ p ++ "@" ++ b

/-- Operator-only configuration. Nothing in the admin API can change any of it
(`PolicyAdmin.lean`, `operator_immutable`). `configRef` is the template for the only CI config
an entry accepts: the project's own CI file on that branch. -/
structure OperatorCfg where
  issuer       : String
  audience     : String
  configRef    : String → String → String
  routedModels : List String
  sources      : List String
  adminRoles   : List String
  twoPerson    : Bool
  maxNamedTtl  : Nat

def notExpired (now : Nat) (e : Entry) : Bool :=
  match e.expiresAt with
  | none   => true
  | some t => decide (now < t)

/-- `mintedBefore`: only tokens issued (`iat`) before this instant. An edge that cannot see the
request time can still bound an entry's life this way; the broker also has `expiresAt`, checked
against its own clock. -/
def mintedOk (e : Entry) (c : Claims) : Bool :=
  match e.mintedBefore with
  | none   => true
  | some t => decide (c.iat < t)

def triggerOk (e : Entry) (c : Claims) : Bool :=
  e.triggerUsers.isEmpty || e.triggerUsers.contains c.userLogin

def protectionOk (e : Entry) (c : Claims) : Bool :=
  match e.kind with
  | .protectedBranch => c.refProtected == "true"
  | .namedBranch     => c.refProtected == "false"

/-- An entry matches a token from its own project, on its own branch, defined by that branch's
own CI file, from a listed source, triggered by a listed person if the entry names any, while
the entry is enabled and unexpired. -/
def entryMatches (o : OperatorCfg) (now : Nat) (c : Claims) (e : Entry) : Bool :=
  e.enabled && notExpired now e && c.projectPath == e.projectPath && c.ref == e.ref
    && c.refType == "branch" && protectionOk e c
    && c.ciConfigRefUri == o.configRef e.projectPath e.ref
    && e.sources.contains c.pipelineSource && triggerOk e c && mintedOk e c

inductive Op where
  | chat | other
  deriving DecidableEq, Repr

inductive Reason where
  | noPolicy | badClaims | wrongIssuer | wrongAudience | tokenExpired | wrongOperation
  | noMatch | modelMissing | modelNotAllowed
  deriving DecidableEq, Repr

inductive Decision where
  | allow (principal : Principal) (entryId : String) (model : String)
  | deny (reason : Reason)
  deriving DecidableEq, Repr

/-- The broker's decision for one pipeline request. `claims = none` is a missing or unparseable
payload; `policy = none` is a store that failed to load. Each `deny` is final. -/
def evaluate (o : OperatorCfg) (policy : Option (List Entry)) (now : Nat) (claims : Option Claims)
    (op : Op) (model : Option String) : Decision :=
  match policy with
  | none => .deny .noPolicy
  | some entries =>
  match claims with
  | none => .deny .badClaims
  | some c =>
    if c.iss != o.issuer then .deny .wrongIssuer
    else if c.aud != .one o.audience then .deny .wrongAudience
    else if !decide (now < c.exp) then .deny .tokenExpired
    else if op != .chat then .deny .wrongOperation
    else match entries.find? (entryMatches o now c) with
    | none => .deny .noMatch
    | some e =>
      match model with
      | none => .deny .modelMissing
      | some m =>
        if e.models.contains m && o.routedModels.contains m then .allow e.principal e.id m
        else .deny .modelNotAllowed

/-! ## Well-formed policies (`Validate` in policy.go) -/

def noAt (s : String) : Bool := !s.toList.contains '@'

/-- Per-entry rules. A named-branch entry must name trigger users and expire within the
operator's limit of `now` (the write time). -/
def entryOk (o : OperatorCfg) (now : Nat) (e : Entry) : Bool :=
  noAt e.projectPath && noAt e.ref && e.projectPath != "" && e.ref != ""
    && !e.sources.isEmpty && e.sources.all (o.sources.contains ·)
    && !e.models.isEmpty && e.models.all (o.routedModels.contains ·)
    && !e.triggerUsers.contains ""
    && (match e.kind with
        | .protectedBranch => true
        | .namedBranch =>
          !e.triggerUsers.isEmpty &&
          (match e.expiresAt with
           | none => false
           | some t => decide (t ≤ now + o.maxNamedTtl)))

/-- Whole-policy rules: every entry is fine; ids, principals and (project, branch) pairs are
unique, so at most one entry can match a token (`at_most_one_match`). -/
def wellFormed (o : OperatorCfg) (now : Nat) (entries : List Entry) : Prop :=
  (∀ e ∈ entries, entryOk o now e = true) ∧
  (entries.map (·.id)).Nodup ∧
  (entries.map (·.principal)).Nodup ∧
  (entries.map (fun e => (e.projectPath, e.ref))).Nodup

instance (o : OperatorCfg) (now : Nat) (es : List Entry) : Decidable (wellFormed o now es) := by
  unfold wellFormed; infer_instance

/-! ## Workspace tokens and the broker's listeners (`server.go`, `tokens.go`)

`internal` (8080) is the listener workspaces reach. It serves a person only by a per-workspace
broker token the provisioner issued for that workspace's owner; it ignores the principal header
and refuses anything that carries a pipeline payload. `edge` (8081) is reachable only from the
edge (B1). It serves pipelines by the verified payload and people by the principal header the
edge sets after sign-in; a request that carries a payload is a pipeline request whatever else
it carries. -/

/-- One issued workspace token (the store keeps its SHA-256, never the token). -/
structure TokenRec where
  workspace : String
  token     : String
  principal : String
  exp       : Nat
  /-- Issued by device sign-in (`DeviceTokens.lean`) rather than the provisioner. -/
  device    : Bool := false
  deriving DecidableEq, Repr

/-- `strings.HasPrefix(h, "ci:")`. -/
def ciForm (h : String) : Bool := h.toList.take 3 == ['c', 'i', ':']

/-- The person a presented workspace token speaks for: its record's principal, if the token is
registered, unexpired, still a listed person and not a pipeline name. -/
def authToken (reg : List TokenRec) (humans : List String) (now : Nat) : Option String → Option String
  | none => none
  | some t =>
    match reg.find? (·.token == t) with
    | some r => if decide (now < r.exp) && humans.contains r.principal && !ciForm r.principal
        then some r.principal else none
    | none => none

inductive Listener where
  | internal | edge
  deriving DecidableEq, Repr

inductive BPath where
  | chat | usage | models | root | other
  deriving DecidableEq, Repr

structure BReq where
  listener   : Listener
  principals : List String
  token      : Option String
  claims     : Option (Option Claims)
  path       : BPath
  post       : Bool
  model      : Option String
  deriving Repr

inductive Served where
  | served (accountedTo : String) (model : Option String)
  | refused
  deriving DecidableEq, Repr

def opOf (r : BReq) : Op := if r.path == .chat && r.post then .chat else .other

def serve (o : OperatorCfg) (policy : Option (List Entry)) (humans : List String)
    (reg : List TokenRec) (now : Nat) (r : BReq) : Served :=
  match r.listener with
  | .edge =>
    match r.claims with
    | some pc =>
      match evaluate o policy now pc (opOf r) r.model with
      | .allow p _ m => .served p.render (some m)
      | .deny _ => .refused
    | none =>
      match r.principals with
      | [h] => if ciForm h then .refused else if humans.contains h then .served h r.model else .refused
      | _ => .refused
  | .internal =>
    match r.claims with
    | some _ => .refused
    | none =>
      match authToken reg humans now r.token with
      | some p => .served p r.model
      | none => .refused

end BadgerBroker
