/-
  Onboarding.Spec: the onboarding lifecycle as an executable transition function.

  `stepG g s e` is the portal's answer to event `e` in state `s`: an outcome and the next state.
  `g : Guards` names every check the theorems rest on. `Guards.spec` (every check on, no extra
  permission) is the specification; `step` is `stepG Guards.spec`. Mutants.lean switches one
  guard at a time and shows the case that breaks the matching theorem.

  The shape of every step:
    1. Authorize: the actor's role (PORTAL.md's table) must permit the event. Otherwise refused,
       state unchanged.
    2. Reads (`pull`, `list`, `readAudit`) never change state.
    3. A write either is refused (state unchanged) or succeeds and appends exactly one audit
       record naming actor, action, subject, and the subject's state before and after.

  Lookups never assume identifiers are unique. Where a check reads "the user u", it requires the
  condition of every entry with that id (`allUser`), and updates touch every entry with that id.
  `invite` and `enroll` refuse known identifiers, so duplicates never arise, but no theorem
  depends on that.
-/
import Onboarding.Model

namespace Onboarding

open MarkingOrder

variable {M : Type} [MarkingOrder M]

/-! ## A deployment's markings -/

/-- The deployment's model gateway is accredited for every connector marking in it, so nothing a
    connector returns is above what the gateway may receive (CONNECTORS.md: no write down). -/
def accredited (D : Deployment M) : Bool := D.connectors.all (fun m => dom D.gateway m)

/-- The deployment's ceiling: the join of its gateway and connector markings. -/
def ceiling (D : Deployment M) : M := D.connectors.foldl join D.gateway

/-! ## Guards -/

/-- Every check the theorems rest on. `Guards.spec` is the specification. -/
structure Guards where
  deploymentChecksGateway : Bool := true
  /-- false: approving a role grant leaves that role's bootstrap running. -/
  grantEndsBootstrap : Bool := true
  /-- false: a bootstrap role comes back whenever no active person holds it (the revival rule
      the portal had before #204). -/
  bootstrapEndsForGood : Bool := true
  /-- false: offboarding a bootstrap principal that is not a person is refused (not found), so it
      keeps its role. -/
  offboardEndsBootstrap : Bool := true
  /-- false: approving a grant ends the role's bootstrap without giving anyone the role. -/
  grantSetsRole : Bool := true
  pullChecksOwner : Bool := true
  pullChecksProof : Bool := true
  offboardRevokesDevices : Bool := true
  offboardDropsRole : Bool := true
  /-- false: offboarding revokes every device, not only the person's. -/
  offboardRevokesOnlyOwn : Bool := true
  approveChecksRequester : Bool := true
  approveChecksSubject : Bool := true
  deviceApproveChecksOwner : Bool := true
  enrollChecksPossession : Bool := true
  /-- false: a person may enroll a key in someone else's name. -/
  enrollOwnerIsActor : Bool := true
  auditsOffboard : Bool := true
  /-- false: the record goes in front of the log instead of after it. -/
  auditAppends : Bool := true
  auditorMayRevoke : Bool := false
  approverMayRequest : Bool := false
  adminMayApprove : Bool := false

def Guards.spec : Guards := {}

/-! ## Who may do what (PORTAL.md "Authentication and roles" and the API table) -/

/-- admin: author, assign, connectors and gateways, devices, people. approver: approve or reject.
    auditor: read everything. -/
def permits (g : Guards) : Role → Ev M → Bool
  | .admin, .invite .. | .admin, .request .. | .admin, .assign .. | .admin, .unassign ..
  | .admin, .dropRole .. | .admin, .setDeployment .. | .admin, .approveDevice ..
  | .admin, .revokeDevice .. | .admin, .offboard .. | .admin, .list | .admin, .readAudit => true
  | .admin, .approve .. | .admin, .reject .. => g.adminMayApprove
  | .approver, .approve .. | .approver, .reject .. | .approver, .list => true
  | .approver, .request .. => g.approverMayRequest
  | .auditor, .list | .auditor, .readAudit => true
  | .auditor, .revokeDevice .. => g.auditorMayRevoke
  | _, _ => false

def entryRole (x : User) : Option Role := if x.status = .active then x.role else none

/-- Some active person holds role `r`. -/
def heldByActive (s : State M) (r : Role) : Bool :=
  s.users.any (fun x => decide (x.status = .active) && x.role == some r)

/-- A configured bootstrap principal's role: held only until that role's bootstrap has ended.
    (The mutant `bootstrapEndsForGood := false` brings it back whenever no active person holds
    the role.) -/
def bootRole (g : Guards) (s : State M) (a : UserId) : Option Role :=
  if a ∈ s.bootOff then none else
  match s.bootstrap.find? (fun p => p.1 == a) with
  | some p =>
    if g.bootstrapEndsForGood then (if p.2 ∈ s.ended then none else some p.2)
    else (if heldByActive s p.2 then none else some p.2)
  | none => none

/-- A known person's role if active; otherwise a bootstrap principal's role. -/
def roleOfG (g : Guards) (s : State M) (a : UserId) : Option Role :=
  match s.users.find? (fun x => x.id == a) with
  | some x => entryRole x
  | none => bootRole g s a

def roleOf (s : State M) (a : UserId) : Option Role := roleOfG Guards.spec s a

omit [MarkingOrder M] in
@[simp] theorem roleOfG_spec (s : State M) (a : UserId) : roleOfG Guards.spec s a = roleOf s a :=
  rfl

/-- Who may enroll a device: any active person enrolling their own key, except an auditor,
    whose role permits no write at all. -/
def mayEnroll (s : State M) (a : UserId) : Bool :=
  (s.users.find? (fun x => x.id == a)).any
    (fun x => decide (x.status = .active) && x.role != some .auditor)

def authorized (g : Guards) (s : State M) : Event M → Bool
  | ⟨.user a, .enroll ..⟩ => mayEnroll s a
  | ⟨.user a, ev⟩ =>
    match roleOfG g s a with
    | some r => permits g r ev
    | none => false
  | ⟨.idp, .offboard ..⟩ => true
  | ⟨.device _, .pull ..⟩ => true
  | _ => false

def denial (s : State M) : Event M → Refusal
  | ⟨.user a, _⟩ => if roleOf s a = none then .unauthenticated else .forbidden
  | _ => .forbidden

def isRead : Ev M → Bool
  | .pull .. | .list | .readAudit => true
  | _ => false

/-! ## Lookups -/

def hasUser (s : State M) (u : UserId) : Bool := s.users.any (fun x => x.id == u)

def allUser (s : State M) (u : UserId) (p : User → Bool) : Bool :=
  s.users.all (fun x => x.id != u || p x)

def updUser (s : State M) (u : UserId) (f : User → User) : List User :=
  s.users.map (fun x => if x.id = u then f x else x)

def hasDevice (s : State M) (d : DevId) : Bool := s.devices.any (fun x => x.id == d)

def allDevice (s : State M) (d : DevId) (p : Device → Bool) : Bool :=
  s.devices.all (fun x => x.id != d || p x)

def updDevice (s : State M) (d : DevId) (f : Device → Device) : List Device :=
  s.devices.map (fun x => if x.id = d then f x else x)

def hasDep (s : State M) (dep : DepId) : Bool := s.deployments.any (fun D => D.id == dep)

def isUser : Principal → UserId → Bool
  | .user a, u => a == u
  | _, _ => false

/-- The person behind a principal (0 for the IdP or a device; such actors never reach the
    writes that read it, `authorized`). -/
def actorId : Principal → UserId
  | .user a => a
  | _ => 0

/-- `u` is a configured bootstrap principal. -/
def isBoot (s : State M) (u : UserId) : Bool := s.bootstrap.any (fun p => p.1 == u)

def isActive (x : User) : Bool := decide (x.status = .active)

/-! ## Serving a device -/

/-- The device's owner exists and every entry for the owner is an active member of the device's
    deployment. -/
def ownerOk (s : State M) (dv : Device) : Bool :=
  hasUser s dv.owner && allUser s dv.owner (fun u => isActive u && decide (dv.dep ∈ u.deps))

def deviceOk (g : Guards) (s : State M) (dv : Device) : Bool :=
  decide (dv.status = .approved) && (!g.pullChecksOwner || ownerOk s dv)

/-- Whether a pull by device key `d` with this proof is answered with the profile and
    activation. Otherwise the answer is 403 and nothing else. -/
def serve (g : Guards) (s : State M) (d : DevId) (proof : Bool) : Bool :=
  (!g.pullChecksProof || proof) && hasDevice s d && allDevice s d (deviceOk g s)

/-! ## Writes -/

/-- Apply an approved request. A role grant ends that role's bootstrap in the same step, before
    the role takes effect. -/
def applyReq (g : Guards) (s : State M) : Req → Except Refusal (State M)
  | .activate u =>
    if hasUser s u && allUser s u (fun x => decide (x.status = .pending)) then
      .ok { s with users := updUser s u (fun x => { x with status := .active }) }
    else .error .invalidState
  | .grant u r =>
    if hasUser s u && allUser s u isActive then
      let us := if g.grantSetsRole then updUser s u (fun x => { x with role := some r }) else s.users
      .ok { s with users := us,
                   ended := if g.grantEndsBootstrap then r :: s.ended else s.ended }
    else .error .invalidState
  | .publish dep =>
    if hasDep s dep then
      let ds := s.deployments.map
        (fun D => if D.id = dep then { D with activation := D.activation + 1 } else D)
      .ok { s with deployments := ds }
    else .error .notFound

def subjectIs : Principal → Subject → Bool
  | .user a, .user u => a == u
  | _, _ => false

/-- What a write is about. -/
def subjectOf (s : State M) : Event M → Subject
  | ⟨_, .invite u⟩ | ⟨_, .assign u _⟩ | ⟨_, .unassign u _⟩ | ⟨_, .dropRole u⟩
  | ⟨_, .offboard u⟩ => .user u
  | ⟨_, .request r⟩ => r.subject
  | ⟨_, .approve p⟩ | ⟨_, .reject p⟩ =>
    match s.pending.find? (fun q => q.id == p) with
    | some q => q.req.subject
    | none => .user 0
  | ⟨_, .setDeployment dep _ _⟩ => .deployment dep
  | ⟨_, .enroll d ..⟩ => .device d
  | ⟨_, .approveDevice d⟩ | ⟨_, .revokeDevice d⟩ => .device d
  | _ => .user 0

/-- The state change of an authorized write, before the audit record. -/
def exec (g : Guards) (s : State M) : Event M → Except Refusal (State M)
  | ⟨a, .invite u⟩ =>
    if hasUser s u || bootRole g s u != none then .error .conflict
    else .ok { s with
      users := s.users ++ [⟨u, .pending, none, []⟩]
      pending := s.pending ++ [⟨s.nextPending, .activate u, a⟩]
      nextPending := s.nextPending + 1 }
  | ⟨a, .request r⟩ =>
    match r with
    | .activate _ => .error .invalidRequest
    | .grant u r' =>
      if s.users.any (fun x => x.id == u && x.role == some r') then .error .invalidState
      else .ok { s with pending := s.pending ++ [⟨s.nextPending, .grant u r', a⟩],
                        nextPending := s.nextPending + 1 }
    | r => .ok { s with pending := s.pending ++ [⟨s.nextPending, r, a⟩],
                        nextPending := s.nextPending + 1 }
  | ⟨a, .approve p⟩ =>
    match s.pending.find? (fun q => q.id == p) with
    | none => if p ∈ s.decided then .error .conflict else .error .notFound
    | some q =>
      if g.approveChecksRequester && q.requester == a then .error .separation
      else if g.approveChecksSubject && subjectIs a q.req.subject then .error .separation
      else match applyReq g s q.req with
        | .error c => .error c
        | .ok s1 =>
          let ps := s1.pending.filter (fun x => x != q)
          .ok { s1 with pending := ps, decided := p :: s1.decided }
  | ⟨_, .reject p⟩ =>
    match s.pending.find? (fun q => q.id == p) with
    | none => if p ∈ s.decided then .error .conflict else .error .notFound
    | some q =>
      let ps := s.pending.filter (fun x => x != q)
      .ok { s with pending := ps, decided := p :: s.decided }
  | ⟨_, .assign u dep⟩ =>
    if !hasUser s u || !hasDep s dep then .error .notFound
    else if !allUser s u isActive then .error .invalidState
    else .ok { s with users := updUser s u (fun x => { x with deps := dep :: x.deps }) }
  | ⟨_, .unassign u dep⟩ =>
    if !hasUser s u then .error .notFound
    else .ok { s with users := updUser s u (fun x => { x with deps := x.deps.filter (· != dep) }) }
  | ⟨_, .dropRole u⟩ =>
    if !hasUser s u then .error .notFound
    else .ok { s with users := updUser s u (fun x => { x with role := none }) }
  | ⟨_, .setDeployment dep cs gw⟩ =>
    if g.deploymentChecksGateway && !accredited (⟨dep, cs, gw, 0⟩ : Deployment M)
    then .error .notAccredited
    else if hasDep s dep then
      let ds := s.deployments.map
        (fun D => if D.id = dep then { D with connectors := cs, gateway := gw } else D)
      .ok { s with deployments := ds }
    else .ok { s with deployments := s.deployments ++ [⟨dep, cs, gw, 0⟩] }
  | ⟨a, .enroll d o dep proof⟩ =>
    if hasDevice s d then .error .conflict
    else if g.enrollOwnerIsActor && !isUser a o then .error .forbidden
    else if g.enrollChecksPossession && !proof then .error .noProof
    else if !hasUser s o || !allUser s o (fun x => isActive x && decide (dep ∈ x.deps)) then
      .error .invalidState
    else .ok { s with devices := s.devices ++ [⟨d, o, dep, .pending, proof, actorId a, none⟩] }
  | ⟨a, .approveDevice d⟩ =>
    if !hasDevice s d then .error .notFound
    else if !allDevice s d (fun x => decide (x.status = .pending)) then .error .invalidState
    else if g.deviceApproveChecksOwner && !allDevice s d (fun x => actorId a != x.owner) then
      .error .separation
    else if !allDevice s d (ownerOk s) then .error .invalidState
    else
      let ds := updDevice s d (fun x => { x with status := .approved, approvedBy := some (actorId a) })
      .ok { s with devices := ds }
  | ⟨_, .revokeDevice d⟩ =>
    if !hasDevice s d then .error .notFound
    else .ok { s with devices := updDevice s d (fun x => { x with status := .revoked }) }
  | ⟨a, .offboard u⟩ =>
    if !hasUser s u && !(g.offboardEndsBootstrap && isBoot s u) then .error .notFound
    -- An admin may not remove a bootstrap principal that has not handed over (it would stop all
    -- approvals); the IdP always may.
    else if a != .idp && !hasUser s u && bootRole g s u != none then .error .conflict
    else .ok { s with
      users := updUser s u (fun x => { x with
        status := .offboarded
        role := if g.offboardDropsRole then none else x.role
        deps := [] })
      devices := if g.offboardRevokesDevices then
          s.devices.map (fun x =>
            if !g.offboardRevokesOnlyOwn || x.owner == u then { x with status := .revoked } else x)
        else s.devices
      pending := s.pending.filter (fun q => !(q.req.subject == .user u || q.requester == .user u))
      bootOff := if isBoot s u then u :: s.bootOff else s.bootOff }
  | _ => .error .invalidRequest

/-! ## Audit -/

def relU : Subject → User → Bool
  | .user u, x => x.id == u
  | _, _ => false

def relD : Subject → Device → Bool
  | .user u, x => x.owner == u
  | .device d, x => x.id == d
  | _, _ => false

def relDep : Subject → Deployment M → Bool
  | .deployment dep, D => D.id == dep
  | _, _ => false

def relP : Subject → Pending → Bool
  | .user u, q => q.req.subject == .user u || q.requester == .user u
  | x, q => q.req.subject == x

/-- The subject's slice of the state: its own entries, a person's devices and requests, a
    deployment's publish requests. -/
def snap (s : State M) (x : Subject) : Snap M :=
  ⟨s.users.filter (relU x), s.devices.filter (relD x), s.deployments.filter (relDep x),
   s.pending.filter (relP x), s.ended, s.bootOff⟩

/-- Everything outside the subject's slice. -/
def rest (s : State M) (x : Subject) : Snap M :=
  ⟨s.users.filter (fun y => !relU x y), s.devices.filter (fun y => !relD x y),
   s.deployments.filter (fun y => !relDep x y), s.pending.filter (fun y => !relP x y), [], []⟩

def record (s s1 : State M) (e : Event M) : Record M :=
  ⟨e.actor, e.ev.kind, subjectOf s e, snap s (subjectOf s e), snap s1 (subjectOf s e)⟩

def isOffboard : Ev M → Bool
  | .offboard .. => true
  | _ => false

/-- The new state with its audit record. Whatever `exec` did to the log is discarded: the log is
    the old log plus one record. -/
def logged (g : Guards) (s s1 : State M) (e : Event M) : State M :=
  { s1 with audit :=
      if !g.auditsOffboard && isOffboard e.ev then s.audit
      else if g.auditAppends then s.audit ++ [record s s1 e]
      else record s s1 e :: s.audit }

/-! ## The step -/

def stepG (g : Guards) (s : State M) (e : Event M) : Out × State M :=
  if !authorized g s e then (.refused (denial s e), s)
  else if isRead e.ev then
    match e with
    | ⟨.device d, .pull p⟩ => (if serve g s d p then .served else .refused .forbidden, s)
    | _ => (.ok, s)
  else match exec g s e with
    | .error c => (.refused c, s)
    | .ok s1 => (.ok, logged g s s1 e)

def step (s : State M) (e : Event M) : Out × State M := stepG Guards.spec s e

def runG (g : Guards) (s : State M) : List (Event M) → State M
  | [] => s
  | e :: es => runG g (stepG g s e).2 es

def run (s : State M) (es : List (Event M)) : State M := runG Guards.spec s es

/-- Outcomes of a trace, in order. -/
def outsG (g : Guards) (s : State M) : List (Event M) → List Out
  | [] => []
  | e :: es => (stepG g s e).1 :: outsG g (stepG g s e).2 es

/-- The installed state: no people, only the configured bootstrap principals, each holding its
    role until the first person is granted that role. -/
def install (bootstrap : List (UserId × Role)) : State M :=
  { users := [], devices := [], deployments := [], pending := [], nextPending := 0,
    bootstrap := bootstrap, ended := [], bootOff := [], decided := [], audit := [] }

/-- The portal's config rule: one subject per bootstrap role and one role per subject. -/
def BootstrapWF (bs : List (UserId × Role)) : Prop :=
  ∀ p ∈ bs, ∀ q ∈ bs, p.1 = q.1 ∨ p.2 = q.2 → p = q

/-! ## Properties (statements; proved in Proofs.lean, broken in Mutants.lean) -/

/-- Every membership is held by an active person. -/
def Members (s : State M) : Prop := ∀ u ∈ s.users, ∀ dep ∈ u.deps, u.status = .active

/-- Every deployment's gateway is accredited for all its connectors. -/
def Accredited (s : State M) : Prop := ∀ D ∈ s.deployments, accredited D = true

/-- A role held by a person has ended its bootstrap. -/
def HeldEnded (s : State M) : Prop := ∀ u ∈ s.users, ∀ r, u.role = some r → r ∈ s.ended

/-- What a served device and its owner satisfy. -/
def ServedOk (s : State M) (d : DevId) : Prop :=
  (∃ dv ∈ s.devices, dv.id = d) ∧
  ∀ dv ∈ s.devices, dv.id = d → dv.status = .approved ∧
    (∃ u ∈ s.users, u.id = dv.owner) ∧
    ∀ u ∈ s.users, u.id = dv.owner → u.status = .active ∧ dv.dep ∈ u.deps

/-- An offboarded person holds no role and no membership, and every device they own is revoked. -/
def OffboardedInert (s : State M) : Prop :=
  ∀ u ∈ s.users, u.status = .offboarded →
    u.role = none ∧ u.deps = [] ∧ ∀ dv ∈ s.devices, dv.owner = u.id → dv.status = .revoked

instance (s : State M) : Decidable (Members s) := by unfold Members; infer_instance
instance (s : State M) : Decidable (Accredited s) := by unfold Accredited; infer_instance
instance (s : State M) : Decidable (HeldEnded s) := by unfold HeldEnded; infer_instance
instance (s : State M) (d : DevId) : Decidable (ServedOk s d) := by unfold ServedOk; infer_instance
instance (s : State M) : Decidable (OffboardedInert s) := by
  unfold OffboardedInert; infer_instance

/-- Every device was enrolled by its owner, and every approved device was approved by someone
    other than its owner. -/
def Bound (s : State M) : Prop :=
  ∀ dv ∈ s.devices, dv.enrolledBy = dv.owner ∧
    (dv.status = .approved → ∃ x, dv.approvedBy = some x ∧ x ≠ dv.owner)

instance (s : State M) : Decidable (Bound s) := by unfold Bound; infer_instance

end Onboarding
