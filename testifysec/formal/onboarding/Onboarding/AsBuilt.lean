/-
  Onboarding.AsBuilt: today's portal (testifysec/portal, PR #173 at 187545cf8e), transcribed.

  What exists today is the first slice: three routes, a static role map, and an audit record per
  signed version. There is no user, device, membership or approval object yet.

  -- cite: testifysec/portal/internal/web/web.go:69-72   route → roles
  -- cite: testifysec/portal/internal/web/web.go:41-51   role = config map[subject DN]
  -- cite: testifysec/portal/main.go:36,56-58            the map is the config's "roles"
  -- cite: testifysec/portal/internal/issue/issue.go:85-95  one "profile.sign" record, appended
                                                           before the version is stored

  Findings (facts about the slice, not requirements):
    * `asbuilt_roles_agree`: the route table agrees with the specification's role table on
      every event the slice implements (publish is admin-only, listing is open to all three
      roles).
    * `asbuilt_signs_alone`: one admin request signs a version immediately. The specification
      (and PORTAL.md's PR 10) makes publish a request an approver must approve
      (`request_does_not_publish`, `approve_separated`).
    * The principal registry is the config's DN-to-role map (`Slice`). Adding, removing or
      re-roling a principal is a config edit and a restart: no request, no second person, no
      audit record. `asbuilt_role_change_unaudited` and `asbuilt_offboard_unaudited` show a
      role change and a removal that leave the audit log untouched (the specification:
      `audit_one_record`); `asbuilt_self_elevation` shows one principal with write access to the
      config making itself admin and signing, with only the signature on the record (the
      specification: `single_actor_no_elevation`, `auditor_read_only`). The edit names no actor
      at all, so the log cannot say who did it.
-/
import Onboarding.Proofs

namespace Onboarding.AsBuilt

open Onboarding

/-- The slice's routes. -/
inductive Route where
  | page
  | listProfiles
  | createVersion
  | trust
  deriving DecidableEq, Repr

/-- web.go:69-72: `s.guard(handler, roles...)`. -/
def allowed : Route → Role → Bool
  | .page, _ | .listProfiles, _ => true
  | .createVersion, .admin => true
  | .trust, .admin | .trust, .auditor => true
  | _, _ => false

/-- Records a route appends when it succeeds (issue.go:85-95: one, before the store). -/
def records : Route → Nat
  | .createVersion => 1
  | _ => 0

theorem asbuilt_roles_agree {M : Type} (r : Role) (dep : DepId) :
    allowed .createVersion r = permits (M := M) Guards.spec r (.request (.publish dep)) ∧
    allowed .listProfiles r = permits (M := M) Guards.spec r .list := by
  cases r <;> exact ⟨rfl, rfl⟩

/-- Today: one admin, one request, one signed version. -/
theorem asbuilt_signs_alone : allowed .createVersion .admin = true ∧ records .createVersion = 1 :=
  ⟨rfl, rfl⟩

/-- The specification: an admin's publish request changes no deployment; only an approver's
    approval of it raises the activation. -/
theorem request_does_not_publish {M : Type} [MarkingOrder M] (s : State M) (a : UserId)
    (dep : DepId) : (step s ⟨.user a, .request (.publish dep)⟩).2.deployments = s.deployments := by
  rcases stepG_cases Guards.spec s ⟨.user a, .request (.publish dep)⟩ with ⟨h1, _⟩ | ⟨_, _, s1, hx, hs⟩
  · unfold step; rw [h1]
  · unfold step; rw [hs]
    simp only [exec, ok_eq_ok] at hx
    subst hx; rfl

/-! ## Today's principal registry: the config file -/

/-- The slice's state: the configured subject-to-role map (main.go:36), the number of audit
    records and the number of signed versions. -/
structure Slice where
  config : List (UserId × Role)
  audit : Nat
  versions : Nat
  deriving DecidableEq, Repr

def sliceRole (c : List (UserId × Role)) (a : UserId) : Option Role :=
  (c.find? (fun p => p.1 == a)).map (·.2)

inductive SliceEv where
  /-- Principal `a` calls a route (web.go:41-51: no role is 401, a wrong role is 403). -/
  | call (a : UserId) (r : Route)
  /-- Someone with write access to the config file edits it and restarts the portal. -/
  | configEdit (roles : List (UserId × Role))

def sliceStep (s : Slice) : SliceEv → Slice
  | .call a r =>
    match sliceRole s.config a with
    | some role =>
      if allowed r role then
        { s with audit := s.audit + records r,
                 versions := s.versions + (if r = .createVersion then 1 else 0) }
      else s
    | none => s
  | .configEdit c => { s with config := c }

def sliceRun (s : Slice) (es : List SliceEv) : Slice := es.foldl sliceStep s

/-- A role change in today's portal appends no audit record. -/
theorem asbuilt_role_change_unaudited (s : Slice) (c : List (UserId × Role)) :
    (sliceStep s (.configEdit c)).audit = s.audit := rfl

def today : Slice := { config := [(1, .admin), (2, .approver), (3, .auditor)], audit := 0, versions := 0 }

/-- Auditor 3, alone, with write access to the config: makes itself admin and signs a version.
    The log holds one record, the signature; the elevation left none. -/
theorem asbuilt_self_elevation :
    sliceRole today.config 3 = some .auditor ∧
    sliceRole (sliceRun today [.configEdit [(1, .admin), (2, .approver), (3, .admin)], .call 3 .createVersion]).config 3 =
      some .admin ∧
    (sliceRun today [.configEdit [(1, .admin), (2, .approver), (3, .admin)], .call 3 .createVersion]).versions = 1 ∧
    (sliceRun today [.configEdit [(1, .admin), (2, .approver), (3, .admin)], .call 3 .createVersion]).audit = 1 := by
  decide

/-- Removing a principal (today's offboarding) is a config edit: the principal loses access and
    the log records nothing. -/
theorem asbuilt_offboard_unaudited :
    sliceRole (sliceStep today (.configEdit [(2, .approver), (3, .auditor)])).config 1 = none ∧
    (sliceStep today (.configEdit [(2, .approver), (3, .auditor)])).audit = today.audit := by
  decide

end Onboarding.AsBuilt
