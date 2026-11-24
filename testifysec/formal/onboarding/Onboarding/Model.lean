/-
  Onboarding.Model: the vocabulary of user and device onboarding in the management portal
  (testifysec/PORTAL.md).

  The portal decides who may administer it, which people belong to which deployment, and which
  devices may pull a deployment's signed profile. This model covers that lifecycle: a person is
  provisioned from the enclave's identity provider, approved, given a role or a deployment
  membership, enrolls a device with a cilock device key, and is eventually offboarded.

  Identifiers (people, device keys, deployments, pending requests) are numbers: only equality
  matters. Classification markings sit only on connectors, gateways and deployments; no person
  carries one (a person's authorized classification level is an external service's decision,
  NotCovered.lean).
  Markings are a parameter (`MarkingOrder`): any preorder with an upper-bound join. The
  contract model (testifysec/formal/contract) proves Go's `marking.Dominates` and `Join` satisfy
  these laws; once it merges, the vectors instantiate this model with that order. Until then
  `Levels.lean` gives a small concrete order (level plus compartments) for the kernel-decided
  cases and the vectors.
-/
namespace Onboarding

/-- The marking order the model is parametric in. `dom a b`: a sink accredited for `a` may
    receive content marked `b`. `join` is any upper bound; the model never needs it to be
    least (Go's `Join` is not always least, and errs high). -/
class MarkingOrder (M : Type) where
  dom : M → M → Bool
  join : M → M → M
  dom_refl : ∀ a, dom a a = true
  dom_trans : ∀ {a b c}, dom a b = true → dom b c = true → dom a c = true
  join_left : ∀ a b, dom (join a b) a = true
  join_right : ∀ a b, dom (join a b) b = true

abbrev UserId := Nat
abbrev DevId := Nat
abbrev DepId := Nat

/-- PORTAL.md: a principal has one role. -/
inductive Role where
  | admin
  | approver
  | auditor
  deriving DecidableEq, Repr

inductive UStatus where
  | pending
  | active
  | offboarded
  deriving DecidableEq, Repr

/-- PORTAL.md: pending → enrolled → revoked. `approved` is "enrolled". -/
inductive DStatus where
  | pending
  | approved
  | revoked
  deriving DecidableEq, Repr

/-- A person, as the portal knows them. The identity itself (certificate subject or OIDC
    subject) is the number `id`; that it is the right person is the IdP's and PKI's job. There is
    no per-person authorized classification level: an external service decides it
    (NotCovered.lean). -/
structure User where
  id : UserId
  status : UStatus
  role : Option Role
  /-- Deployments this person is a member of. -/
  deps : List DepId

/-- A cilock-enrolled device key (keyed by the key's SPKI digest), its owner and its deployment
    (PORTAL.md: deployment = device group). -/
structure Device where
  id : DevId
  owner : UserId
  dep : DepId
  status : DStatus
  /-- Enrollment carried a valid proof of possession of the device key. -/
  possession : Bool
  /-- The authenticated person who enrolled the key. -/
  enrolledBy : UserId
  /-- The admin who approved it, once approved. -/
  approvedBy : Option UserId
  deriving DecidableEq, Repr

/-- A deployment: the markings of its connectors and its model gateway's accreditation. -/
structure Deployment (M : Type) where
  id : DepId
  connectors : List M
  gateway : M
  /-- The activation sequence (PORTAL.md activation records); raised only by an approved
      publish. -/
  activation : Nat

/-- What a principal is. `user` is a person authenticated by their own credential (CAC/PIV
    certificate or enclave OIDC), or a configured bootstrap principal; `idp` is the enclave
    identity provider acting as the source of truth for disabling a person; `device` is a device
    key proving possession. -/
inductive Principal where
  | user (u : UserId)
  | idp
  | device (d : DevId)
  deriving DecidableEq, Repr

/-- What an audit record or a pending request is about. -/
inductive Subject where
  | user (u : UserId)
  | device (d : DevId)
  | deployment (dep : DepId)
  deriving DecidableEq, Repr

/-- Requests that wait for a second person. -/
inductive Req where
  | activate (u : UserId)
  | grant (u : UserId) (r : Role)
  | publish (dep : DepId)
  deriving DecidableEq, Repr

def Req.subject : Req → Subject
  | .activate u => .user u
  | .grant u _ => .user u
  | .publish dep => .deployment dep

structure Pending where
  id : Nat
  req : Req
  requester : Principal
  deriving DecidableEq, Repr

inductive Ev (M : Type) where
  /-- An admin invites a person the IdP knows. -/
  | invite (u : UserId)
  /-- An admin asks for a role grant or a publish (activation); an approver decides. -/
  | request (r : Req)
  | approve (p : Nat)
  | reject (p : Nat)
  | assign (u : UserId) (dep : DepId)
  | unassign (u : UserId) (dep : DepId)
  | dropRole (u : UserId)
  | setDeployment (dep : DepId) (connectors : List M) (gateway : M)
  /-- A person, authenticated as the actor, enrolls device key `d` for `owner` into `dep`;
      `proof` is a valid proof of possession of the key. The owner must be the actor. -/
  | enroll (d : DevId) (owner : UserId) (dep : DepId) (proof : Bool)
  | approveDevice (d : DevId)
  | revokeDevice (d : DevId)
  /-- IdP disable or admin removal. -/
  | offboard (u : UserId)
  /-- A device pulls its profile and activation; `proof` is a valid nonce proof. -/
  | pull (proof : Bool)
  | list
  | readAudit

structure Event (M : Type) where
  actor : Principal
  ev : Ev M

/-- The action name an audit record carries. -/
def Ev.kind {M : Type} : Ev M → String
  | .invite .. => "invite" | .request .. => "request" | .approve .. => "approve"
  | .reject .. => "reject" | .assign .. => "assign" | .unassign .. => "unassign"
  | .dropRole .. => "drop-role"
  | .setDeployment .. => "set-deployment" | .enroll .. => "enroll"
  | .approveDevice .. => "approve-device" | .revokeDevice .. => "revoke-device"
  | .offboard .. => "offboard" | .pull .. => "pull" | .list => "list" | .readAudit => "read-audit"

/-- The part of the state an audit record shows before and after. -/
structure Snap (M : Type) where
  users : List User
  devices : List Device
  deployments : List (Deployment M)
  pending : List Pending
  /-- The roles whose bootstrap has ended (a global marker, shown in every record). -/
  ended : List Role
  /-- Bootstrap principals that have been offboarded (shown in every record). -/
  bootOff : List UserId

structure Record (M : Type) where
  actor : Principal
  action : String
  subject : Subject
  before : Snap M
  after : Snap M

structure State (M : Type) where
  users : List User
  devices : List Device
  deployments : List (Deployment M)
  pending : List Pending
  nextPending : Nat
  /-- The configured bootstrap principals (PORTAL.md: certificate subject to role in config). -/
  bootstrap : List (UserId × Role)
  /-- Roles whose bootstrap has ended for good: written the first time a person is granted the
      role, never cleared. -/
  ended : List Role
  /-- Bootstrap principals offboarded before or after their role ended: never act again as a
      bootstrap. -/
  bootOff : List UserId
  /-- Ids of requests an approver has already approved or rejected. -/
  decided : List Nat
  audit : List (Record M)

/-- Why a request is refused. The first two are the portal's existing codes. -/
inductive Refusal where
  | unauthenticated
  | forbidden
  | notFound
  | conflict
  | invalidState
  | separation
  | notAccredited
  | noProof
  | invalidRequest
  deriving DecidableEq, Repr

def Refusal.code : Refusal → String
  | .unauthenticated => "unauthenticated" | .forbidden => "forbidden" | .notFound => "not-found"
  | .conflict => "conflict" | .invalidState => "invalid-state"
  | .separation => "separation-of-duties" | .notAccredited => "not-accredited"
  | .noProof => "no-proof" | .invalidRequest => "invalid-request"

inductive Out where
  | ok
  | served
  | refused (r : Refusal)
  deriving DecidableEq, Repr

end Onboarding
