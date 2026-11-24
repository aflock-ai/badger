/-
  Onboarding.Mutants: each guard the theorems rest on, switched off (or a permission switched
  on), with the concrete trace that breaks the matching theorem in Proofs.lean. A theorem that
  still held with its guard removed would prove nothing about the guard. Every case is decided by
  the kernel, beside the same trace under the specification.

  Mutant (Guards field)                         Kills
  `gateway_unchecked` deploymentChecksGateway    `accredited_run`
  `pull_ignores_owner` pullChecksOwner           `served_requires`
  `pull_no_proof`     pullChecksProof            `served_requires`
  `enroll_no_possession` enrollChecksPossession  `served_possession`
  `enroll_for_another` enrollOwnerIsActor        `served_separated`
  `offboard_keeps_devices` offboardRevokesDevices `offboard_complete`
  `portal_as_specified` pullChecksOwner and offboardRevokesDevices off together (PORTAL.md's
                      pull checks only the device) `offboarded_never_served`
  `offboard_keeps_role` offboardDropsRole        `offboard_complete`, `offboarded_inert_run`
  `approve_own_request` approveChecksRequester   `approve_separated`
  `approve_own_elevation` approveChecksSubject   `approve_separated`
  `device_owner_approves` deviceApproveChecksOwner `device_approve_separated`, `served_separated`
  `admin_self_grant`  adminMayApprove with both approval checks off `single_actor_no_elevation`
  `bootstrap_revives` bootstrapEndsForGood       `bootstrap_never_revives`
  `grant_skips_marker` grantEndsBootstrap        `held_ended_run`, `grant_ends_bootstrap`
  `bootstrap_survives_offboard` offboardEndsBootstrap `offboard_bootstrap`
  `grant_strands_role` grantSetsRole             `ending_requires_holder`
  `offboard_unaudited` auditsOffboard            `audit_one_record`
  `audit_prepends`    auditAppends               `audit_prefix_run`
  `offboard_revokes_all` offboardRevokesOnlyOwn  `audit_frame`
  `auditor_can_revoke` auditorMayRevoke          `auditor_read_only`
  `approver_can_request` approverMayRequest      `approver_only_decides`
-/
import Onboarding.Spec
import Onboarding.Levels

set_option maxRecDepth 100000

namespace Onboarding.Mutants

open Onboarding

/-! ## The scenario -/

def by_ (a : UserId) (e : Ev Lv) : Event Lv := ⟨.user a, e⟩
def fromIdp (e : Ev Lv) : Event Lv := ⟨.idp, e⟩
def dev (d : DevId) (e : Ev Lv) : Event Lv := ⟨.device d, e⟩

/-- The config's bootstrap principals: 90 holds admin, 91 holds approver. -/
def boot : List (UserId × Role) := [(90, .admin), (91, .approver)]

/-- From install to a staffed portal: the bootstraps bring in admin 1 and approver 2, which ends
    both bootstraps; then 1 and 2 bring in auditor 3 and admin 4. Requests 0 to 7. -/
def setup : List (Event Lv) :=
  [ by_ 90 (.invite 1), by_ 91 (.approve 0), by_ 90 (.request (.grant 1 .admin)), by_ 91 (.approve 1),
    by_ 1 (.invite 2), by_ 91 (.approve 2), by_ 1 (.request (.grant 2 .approver)), by_ 91 (.approve 3),
    by_ 1 (.invite 3), by_ 2 (.approve 4), by_ 1 (.request (.grant 3 .auditor)), by_ 2 (.approve 5),
    by_ 1 (.invite 4), by_ 2 (.approve 6), by_ 1 (.request (.grant 4 .admin)), by_ 2 (.approve 7) ]

def seedG (g : Guards) : State Lv := runG g (install boot) setup
def seed : State Lv := seedG Guards.spec

/-- Request ids after the setup. -/
def P (n : Nat) : Nat := 8 + n

theorem seed_staffed :
    (outsG Guards.spec (install boot) setup).all (· == .ok) = true ∧ seed.nextPending = 8 ∧
    roleOf seed 1 = some .admin ∧ roleOf seed 2 = some .approver ∧
    roleOf seed 3 = some .auditor ∧ roleOf seed 4 = some .admin ∧
    roleOf seed 90 = none ∧ roleOf seed 91 = none := by decide

/-- Deployment 10 (one SECRET connector, SECRET gateway); person 5 invited, approved, assigned;
    device 100 enrolled by 5 and approved by admin 1. -/
def onboard : List (Event Lv) :=
  [ by_ 1 (.setDeployment 10 [S] S), by_ 1 (.invite 5), by_ 2 (.approve (P 0)),
    by_ 1 (.assign 5 10), by_ 5 (.enroll 100 5 10 true), by_ 1 (.approveDevice 100) ]

def base : State Lv := run seed onboard

theorem base_onboarded :
    outsG Guards.spec seed onboard = [.ok, .ok, .ok, .ok, .ok, .ok] ∧
    serve Guards.spec base 100 true = true := by decide

/-! ## Deployment markings -/

def gGateway : Guards := { deploymentChecksGateway := false }

/-- A deployment whose SECRET gateway would receive a TOP SECRET connector's content. -/
def lowGateway : List (Event Lv) := [by_ 1 (.setDeployment 11 [TS] S)]

theorem gateway_unchecked : ¬ Accredited (runG gGateway (seedG gGateway) lowGateway) := by decide

theorem gateway_checked :
    outsG Guards.spec seed lowGateway = [.refused .notAccredited] := by decide

/-! ## No profile to the unapproved -/

def gPullOwner : Guards := { pullChecksOwner := false }

/-- Person 5 leaves deployment 10; device 100 is still approved. -/
def leaveDep : List (Event Lv) := onboard ++ [by_ 1 (.unassign 5 10)]

theorem pull_ignores_owner :
    serve gPullOwner (runG gPullOwner (seedG gPullOwner) leaveDep) 100 true = true ∧
    ¬ ServedOk (runG gPullOwner (seedG gPullOwner) leaveDep) 100 := by decide

theorem pull_checks_owner : serve Guards.spec (run seed leaveDep) 100 true = false := by decide

def gPullProof : Guards := { pullChecksProof := false }

theorem pull_no_proof :
    serve gPullProof (runG gPullProof (seedG gPullProof) onboard) 100 false = true := by decide

def gPossession : Guards := { enrollChecksPossession := false }

/-- Device 101 enrolls with no proof of possession, is approved and pulls. -/
def noPop : List (Event Lv) :=
  onboard ++ [by_ 5 (.enroll 101 5 10 false), by_ 1 (.approveDevice 101)]

theorem enroll_no_possession :
    serve gPossession (runG gPossession (seedG gPossession) noPop) 101 true = true ∧
    ¬ (∀ dv ∈ (runG gPossession (seedG gPossession) noPop).devices, dv.possession = true) := by
  decide

theorem enroll_checks_possession :
    outsG Guards.spec seed noPop =
      [.ok, .ok, .ok, .ok, .ok, .ok, .refused .noProof, .refused .notFound] := by decide

def gAnyOwner : Guards := { enrollOwnerIsActor := false }

/-- Admin 1 enrolls its own key in person 5's name, then approves it: the owner check on approval
    passes (owner 5 is not admin 1), and the device pulls with 5's membership. -/
def proxyEnroll : List (Event Lv) :=
  onboard ++ [by_ 1 (.enroll 105 5 10 true), by_ 1 (.approveDevice 105)]

theorem enroll_for_another :
    serve gAnyOwner (runG gAnyOwner (seedG gAnyOwner) proxyEnroll) 105 true = true ∧
    ¬ Bound (runG gAnyOwner (seedG gAnyOwner) proxyEnroll) := by decide

theorem enroll_for_another_refused :
    outsG Guards.spec seed proxyEnroll =
      [.ok, .ok, .ok, .ok, .ok, .ok, .refused .forbidden, .refused .notFound] := by decide

/-! ## Offboarding -/

def leave : List (Event Lv) := onboard ++ [fromIdp (.offboard 5)]

def gKeepDevices : Guards := { offboardRevokesDevices := false }

theorem offboard_keeps_devices :
    (runG gKeepDevices (seedG gKeepDevices) leave).devices.map (·.status) = [.approved] := by
  decide

def gAsSpecified : Guards := { offboardRevokesDevices := false, pullChecksOwner := false }

theorem portal_as_specified :
    serve gAsSpecified (runG gAsSpecified (seedG gAsSpecified) leave) 100 true = true := by decide

theorem offboard_spec :
    (run seed leave).devices.map (·.status) = [.revoked] ∧
    serve Guards.spec (run seed leave) 100 true = false := by decide

def gKeepRole : Guards := { offboardDropsRole := false }

theorem offboard_keeps_role :
    ¬ OffboardedInert (runG gKeepRole (seedG gKeepRole) [fromIdp (.offboard 4)]) := by decide

/-! ## Separation of duties -/

/-- Admin 1 asks to publish deployment 10. Admin 4 asks to make 1 an approver; approver 2
    approves that. Now 1 approves its own publish. -/
def ownRequest : List (Event Lv) :=
  [ by_ 1 (.setDeployment 10 [S] S), by_ 1 (.request (.publish 10)),
    by_ 4 (.request (.grant 1 .approver)), by_ 2 (.approve (P 1)), by_ 1 (.approve (P 0)) ]

def gRequester : Guards := { approveChecksRequester := false }

theorem approve_own_request :
    (outsG gRequester (seedG gRequester) ownRequest).getLast? = some .ok ∧
    (runG gRequester (seedG gRequester) (ownRequest.take 4)).pending =
      [⟨P 0, .publish 10, .user 1⟩] := by decide

theorem own_request_refused :
    (outsG Guards.spec seed ownRequest).getLast? = some (.refused .separation) := by decide

/-- Admin 1 asks to make approver 2 an admin; 2 approves its own elevation. -/
def ownElevation : List (Event Lv) := [by_ 1 (.request (.grant 2 .admin)), by_ 2 (.approve (P 0))]

def gSubject : Guards := { approveChecksSubject := false }

theorem approve_own_elevation :
    (outsG gSubject (seedG gSubject) ownElevation).getLast? = some .ok ∧
    roleOfG gSubject (runG gSubject (seedG gSubject) ownElevation) 2 = some .admin := by decide

theorem own_elevation_refused :
    (outsG Guards.spec seed ownElevation).getLast? = some (.refused .separation) := by decide

/-- Admin 4 is also a developer in deployment 10 and approves its own device. -/
def ownDevice : List (Event Lv) :=
  onboard ++ [by_ 1 (.assign 4 10), by_ 4 (.enroll 102 4 10 true), by_ 4 (.approveDevice 102)]

def gDeviceOwner : Guards := { deviceApproveChecksOwner := false }

theorem device_owner_approves :
    (outsG gDeviceOwner (seedG gDeviceOwner) ownDevice).getLast? = some .ok ∧
    ¬ Bound (runG gDeviceOwner (seedG gDeviceOwner) ownDevice) := by decide

theorem own_device_refused :
    (outsG Guards.spec seed ownDevice).getLast? = some (.refused .separation) := by decide

/-- A lone admin asks for a grant to itself and approves it. -/
def selfGrant : List (Event Lv) := [by_ 1 (.request (.grant 1 .approver)), by_ 1 (.approve (P 0))]

def gSelfGrant : Guards :=
  { adminMayApprove := true, approveChecksRequester := false, approveChecksSubject := false }

theorem admin_self_grant :
    roleOfG gSelfGrant (runG gSelfGrant (seedG gSelfGrant) selfGrant) 1 = some .approver := by
  decide

theorem self_grant_refused : roleOf (run seed selfGrant) 1 = some .admin := by decide

/-! ## Bootstrap -/

/-- Every person admin is offboarded. Under the old revival rule, bootstrap 90 is admin again. -/
def noAdmins : List (Event Lv) := [fromIdp (.offboard 1), fromIdp (.offboard 4)]

def gRevive : Guards := { bootstrapEndsForGood := false }

theorem bootstrap_revives :
    Role.admin ∈ (runG gRevive (seedG gRevive) noAdmins).ended ∧
    (runG gRevive (seedG gRevive) noAdmins).users.find? (fun x => x.id == 90) = none ∧
    roleOfG gRevive (runG gRevive (seedG gRevive) noAdmins) 90 = some .admin := by decide

theorem bootstrap_stays_ended : roleOf (run seed noAdmins) 90 = none := by decide

def gNoMarker : Guards := { grantEndsBootstrap := false }

/-- Without the marker, bootstrap admin 90 keeps acting beside the people it made admins. -/
theorem grant_skips_marker :
    ¬ HeldEnded (seedG gNoMarker) ∧ roleOfG gNoMarker (seedG gNoMarker) 90 = some .admin := by
  decide

def gBootOff : Guards := { offboardEndsBootstrap := false }

/-- The IdP offboards bootstrap admin 90 before it has handed over; 90 then invites. -/
def bootLeave : List (Event Lv) := [fromIdp (.offboard 90), by_ 90 (.invite 1)]

theorem bootstrap_survives_offboard :
    outsG gBootOff (install boot) bootLeave = [.refused .notFound, .ok] ∧
    roleOfG gBootOff (runG gBootOff (install boot) bootLeave) 90 = some .admin := by decide

theorem bootstrap_offboarded :
    outsG Guards.spec (install boot) bootLeave = [.ok, .refused .unauthenticated] ∧
    roleOf (run (install boot) bootLeave) 90 = none := by decide

def gNoRole : Guards := { grantSetsRole := false }

/-- The bootstrap admin's grant of admin to person 1 ends the admin bootstrap without person 1
    getting the role: nobody is admin any more. -/
def strand : List (Event Lv) :=
  [by_ 90 (.invite 1), by_ 91 (.approve 0), by_ 90 (.request (.grant 1 .admin)), by_ 91 (.approve 1)]

theorem grant_strands_role :
    Role.admin ∈ (runG gNoRole (install boot) strand).ended ∧
    ¬ (∃ x ∈ (runG gNoRole (install boot) strand).users, x.role = some .admin) ∧
    roleOfG gNoRole (runG gNoRole (install boot) strand) 90 = none := by decide

theorem grant_gives_role : roleOf (run (install boot) strand) 1 = some .admin := by decide

/-! ## Audit -/

def gUnaudited : Guards := { auditsOffboard := false }

theorem offboard_unaudited :
    (stepG gUnaudited base (fromIdp (.offboard 5))).1 = .ok ∧
    (stepG gUnaudited base (fromIdp (.offboard 5))).2.audit.length = base.audit.length := by decide

def gPrepend : Guards := { auditAppends := false }

theorem audit_prepends :
    ¬ ((runG gPrepend (install boot) (setup.take 1)).audit.map (·.action) <+:
        (runG gPrepend (install boot) (setup.take 2)).audit.map (·.action)) := by decide

def gRevokeAll : Guards := { offboardRevokesOnlyOwn := false }

/-- Person 6 has device 103 in deployment 10. Offboarding 5 revokes 6's device too, a change
    outside the record's subject. -/
def twoOwners : List (Event Lv) :=
  onboard ++ [by_ 1 (.invite 6), by_ 2 (.approve (P 1)), by_ 1 (.assign 6 10),
    by_ 6 (.enroll 103 6 10 true), by_ 1 (.approveDevice 103)]

theorem offboard_revokes_all :
    let s := runG gRevokeAll (seedG gRevokeAll) twoOwners
    (rest s (.user 5)).devices.map (·.status) = [.approved] ∧
    (rest (stepG gRevokeAll s (fromIdp (.offboard 5))).2 (.user 5)).devices.map (·.status) =
      [.revoked] := by decide

/-! ## Least privilege -/

def gAuditor : Guards := { auditorMayRevoke := true }

theorem auditor_can_revoke :
    (stepG gAuditor base (by_ 3 (.revokeDevice 100))).2.devices.map (·.status) = [.revoked] ∧
    base.devices.map (·.status) = [.approved] := by decide

def gApprover : Guards := { approverMayRequest := true }

theorem approver_can_request :
    (stepG gApprover base (by_ 2 (.request (.publish 10)))).2.pending.length = 1 ∧
    base.pending.length = 0 := by decide

end Onboarding.Mutants
