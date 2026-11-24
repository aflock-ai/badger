/-
  Onboarding.Proofs: the onboarding properties, for every state reachable from an installed
  portal, every event and every marking order.

  1. Deployments and bootstrap
    `members_run`            every membership is held by an active person
    `accredited_run`         every deployment's gateway is accredited for all its connectors
    `ceiling_accredited`     a gateway accredited for the join of the markings is accredited for
                             each of them
    `grant_ends_bootstrap`   approving a role grant ends that role's bootstrap in the same step
    `ended_run`              an ended bootstrap stays ended
    `held_ended_run`         a role any person holds has ended its bootstrap
    `bootstrap_never_revives` once ended, no later state (every holder offboarded included) gives
                             the role to a principal that is not a person
    `bootstrap_two_people`   under the config rule, the admin and approver bootstraps differ
    `offboard_bootstrap`     the IdP can always offboard a bootstrap principal, even one that is
                             not a person
    `offboarded_bootstrap_never_acts` and it never holds a bootstrap role again
    `ending_requires_holder` a bootstrap ends only in a step that leaves an active person holding
                             the role
    `redecide_conflict`      deciding an already-decided request is a conflict
  2. Serving
    `served_requires`        a served device is approved and every entry for its owner is an
                             active member of its deployment; the pull carried a valid proof
    `served_possession`      and its enrollment proved possession of the device key
    `served_separated`       and it was enrolled by its owner and approved by someone else
  3. Offboarding
    `offboard_complete`      after offboard u: u is offboarded with no role and no membership,
                             every device u owns is revoked and refused, and the one audit record
                             shows all of it
    `offboarded_inert_run`   in every reachable state an offboarded person holds no role or
                             membership and owns only revoked devices
    `offboarded_never_served` no reachable state serves an offboarded person's device
  4. Separation of duties
    `approve_separated`      an approval succeeds only for a request someone else made, about
                             someone else
    `device_approve_separated` an admin never approves a device they own
    `single_actor_no_elevation` a principal acting alone never gains a role
  5. Audit
    `audit_one_record`       a successful write appends exactly one record naming actor, action,
                             subject, and the subject before and after; anything else changes
                             nothing
    `audit_frame`            a write changes nothing outside its record's subject
    `audit_prefix_run`       the log only grows at the end
  6. Least privilege
    `unauthorized_unchanged` an event the actor's role does not permit changes nothing
    `auditor_read_only`, `approver_only_decides`, `admin_cannot_approve`
-/
import Onboarding.Spec

set_option linter.unusedSectionVars false

namespace Onboarding

open MarkingOrder

variable {M : Type} [MarkingOrder M]

/-! ## The invariant -/

structure Inv (s : State M) : Prop where
  members : Members s
  inert : OffboardedInert s
  possession : ∀ dv ∈ s.devices, dv.possession = true
  bound : Bound s
  accredited : Accredited s
  heldEnded : HeldEnded s

theorem inv_install (bs : List (UserId × Role)) : Inv (install (M := M) bs) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩ <;> intro x hx <;> simp [install] at hx

/-! ## Step structure -/

theorem logged_users (g : Guards) (s s1 : State M) (e : Event M) :
    (logged g s s1 e).users = s1.users := rfl
theorem logged_devices (g : Guards) (s s1 : State M) (e : Event M) :
    (logged g s s1 e).devices = s1.devices := rfl
theorem logged_deployments (g : Guards) (s s1 : State M) (e : Event M) :
    (logged g s s1 e).deployments = s1.deployments := rfl
theorem logged_pending (g : Guards) (s s1 : State M) (e : Event M) :
    (logged g s s1 e).pending = s1.pending := rfl

theorem snap_logged (g : Guards) (s s1 : State M) (e : Event M) (x : Subject) :
    snap (logged g s s1 e) x = snap s1 x := rfl

theorem rest_logged (g : Guards) (s s1 : State M) (e : Event M) (x : Subject) :
    rest (logged g s s1 e) x = rest s1 x := rfl

/-- Every step either leaves the state alone or is an authorized write that `exec` accepted,
    followed by its audit record. -/
theorem stepG_cases (g : Guards) (s : State M) (e : Event M) :
    ((stepG g s e).2 = s ∧ ((stepG g s e).1 ≠ .ok ∨ isRead e.ev = true)) ∨
    (authorized g s e = true ∧ isRead e.ev = false ∧
      ∃ s1, exec g s e = .ok s1 ∧ stepG g s e = (.ok, logged g s s1 e)) := by
  unfold stepG
  by_cases ha : authorized g s e = true
  · by_cases hr : isRead e.ev = true
    · left
      simp only [ha, hr, Bool.not_true, Bool.false_eq_true, ite_false, ite_true]
      split <;> simp_all
    · simp only [Bool.not_eq_true] at hr
      cases hx : exec g s e with
      | error c => left; simp [ha, hr]
      | ok s1 => right; simp [ha, hr]
  · left
    simp [ha]

/-! ## Invariant preservation -/

theorem accredited_ext (D D' : Deployment M) (hc : D'.connectors = D.connectors)
    (hg : D'.gateway = D.gateway) : accredited D' = accredited D := by
  simp [accredited, hc, hg]

theorem inv_frame {s s1 : State M} (h : Inv s) (hu : s1.users = s.users)
    (hd : s1.devices = s.devices) (hp : s1.deployments = s.deployments)
    (he : s1.ended = s.ended) : Inv s1 := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro u hu' dep hdep; rw [hu] at hu'; exact h1 u hu' dep hdep
  · intro u hu' ho; rw [hu] at hu'; rw [hd]; exact h2 u hu' ho
  · intro dv hdv; rw [hd] at hdv; exact h3 dv hdv
  · intro dv hdv; rw [hd] at hdv; exact h4 dv hdv
  · intro D hD; rw [hp] at hD; exact h5 D hD
  · intro u hu' r hr; rw [hu] at hu'; rw [he]; exact h6 u hu' r hr

/-- Changing only the users, by `f` on the entries named `u`, and possibly extending the ended
    roles to `e'`, keeps the invariant when `f` keeps it entry by entry. -/
theorem inv_updUser {s : State M} (h : Inv s) (u : UserId) (f : User → User) (e' : List Role)
    (hid : ∀ x, (f x).id = x.id) (he : ∀ r ∈ s.ended, r ∈ e')
    (hc : ∀ x ∈ s.users, x.id = u → ∀ dep ∈ (f x).deps, (f x).status = .active)
    (ho : ∀ x ∈ s.users, x.id = u → (f x).status = .offboarded →
      (f x).role = none ∧ (f x).deps = [] ∧ ∀ dv ∈ s.devices, dv.owner = x.id → dv.status = .revoked)
    (hr : ∀ x ∈ s.users, x.id = u → ∀ r, (f x).role = some r → r ∈ e') :
    Inv { s with users := updUser s u f, ended := e' } := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  refine ⟨?_, ?_, h3, h4, h5, ?_⟩
  · intro y hy dep hdep
    simp only [updUser, List.mem_map] at hy
    obtain ⟨x, hx, rfl⟩ := hy
    by_cases hxu : x.id = u
    · simp only [hxu, ite_true] at hdep ⊢; exact hc x hx hxu dep hdep
    · simp only [hxu, ite_false] at hdep ⊢; exact h1 x hx dep hdep
  · intro y hy hoff
    simp only [updUser, List.mem_map] at hy
    obtain ⟨x, hx, rfl⟩ := hy
    by_cases hxu : x.id = u
    · simp only [hxu, ite_true] at hoff ⊢
      have := ho x hx hxu hoff
      rw [← hid x] at this
      exact this
    · simp only [hxu, ite_false] at hoff ⊢; exact h2 x hx hoff
  · intro y hy r hrr
    simp only [updUser, List.mem_map] at hy
    obtain ⟨x, hx, rfl⟩ := hy
    by_cases hxu : x.id = u
    · simp only [hxu, ite_true] at hrr; exact hr x hx hxu r hrr
    · simp only [hxu, ite_false] at hrr; exact he r (h6 x hx r hrr)

theorem ite_error_eq_ok {ε α : Type} {c : Prop} [Decidable c] {r : ε} {x : Except ε α} {y : α} :
    ((if c then Except.error r else x) = Except.ok y) ↔ (¬ c ∧ x = Except.ok y) := by
  by_cases h : c <;> simp [h]

theorem ok_eq_ok {ε α : Type} {x y : α} : (Except.ok x : Except ε α) = Except.ok y ↔ x = y := by
  constructor
  · intro h; cases h; rfl
  · intro h; rw [h]

theorem mem_allUser {s : State M} {u : UserId} {p : User → Bool} (h : allUser s u p = true)
    {x : User} (hx : x ∈ s.users) (hxu : x.id = u) : p x = true := by
  simp only [allUser, List.all_eq_true] at h
  have := h x hx
  simpa [hxu] using this

theorem mem_allDevice {s : State M} {d : DevId} {p : Device → Bool} (h : allDevice s d p = true)
    {x : Device} (hx : x ∈ s.devices) (hxd : x.id = d) : p x = true := by
  simp only [allDevice, List.all_eq_true] at h
  have := h x hx
  simpa [hxd] using this

theorem inv_invite {s : State M} (h : Inv s) (a : Principal) (u : UserId)
    {s1 : State M} (hx : exec Guards.spec s ⟨a, .invite u⟩ = .ok s1) : Inv s1 := by
  simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
  obtain ⟨_, rfl⟩ := hx
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  refine ⟨?_, ?_, h3, h4, h5, ?_⟩
  · intro y hy dep hdep
    simp only [List.mem_append, List.mem_singleton] at hy
    rcases hy with hy | rfl
    · exact h1 y hy dep hdep
    · simp at hdep
  · intro y hy hoff
    simp only [List.mem_append, List.mem_singleton] at hy
    rcases hy with hy | rfl
    · exact h2 y hy hoff
    · simp at hoff
  · intro y hy r hr
    simp only [List.mem_append, List.mem_singleton] at hy
    rcases hy with hy | rfl
    · exact h6 y hy r hr
    · simp at hr

theorem inv_request {s : State M} (h : Inv s) (a : Principal) (r : Req)
    {s1 : State M} (hx : exec Guards.spec s ⟨a, .request r⟩ = .ok s1) : Inv s1 := by
  cases r with
  | activate _ => simp [exec] at hx
  | grant _ _ => simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx; obtain ⟨_, rfl⟩ := hx; exact inv_frame h rfl rfl rfl rfl
  | publish _ => simp only [exec, ok_eq_ok] at hx; subst hx; exact inv_frame h rfl rfl rfl rfl

theorem inv_reject {s : State M} (h : Inv s) (a : Principal) (p : Nat)
    {s1 : State M} (hx : exec Guards.spec s ⟨a, .reject p⟩ = .ok s1) : Inv s1 := by
  simp only [exec] at hx
  split at hx
  · split at hx <;> cases hx
  · simp only [ok_eq_ok] at hx; subst hx; exact inv_frame h rfl rfl rfl rfl

theorem inv_applyReq {s : State M} (h : Inv s) (r : Req) {s1 : State M}
    (hx : applyReq Guards.spec s r = .ok s1) : Inv s1 := by
  cases r with
  | activate u =>
    simp only [applyReq] at hx
    split at hx
    · rename_i hc
      simp only [ok_eq_ok] at hx; subst hx
      simp only [Bool.and_eq_true] at hc
      exact inv_updUser h u (fun x => { x with status := .active }) s.ended (fun _ => rfl)
        (fun _ h => h)
        (fun _ _ _ _ _ => rfl)
        (fun x hx hxu hoff => by simp at hoff)
        (fun x hx _ r hr => h.heldEnded x hx r hr)
    · cases hx
  | grant u r =>
    simp only [applyReq] at hx
    split at hx
    · rename_i hc
      simp only [ok_eq_ok, Guards.spec, ite_true] at hx; subst hx
      simp only [Bool.and_eq_true] at hc
      exact inv_updUser h u (fun x => { x with role := some r }) (r :: s.ended) (fun _ => rfl)
        (fun _ h => List.mem_cons_of_mem _ h)
        (fun x hx _ dep hdep => h.members x hx dep hdep)
        (fun x hx hxu hoff => by
          dsimp only at hoff
          have hp := mem_allUser hc.2 hx hxu
          simp [isActive, hoff] at hp)
        (fun x hx _ r' hr' => by simp at hr'; subst hr'; exact List.mem_cons_self ..)
    · cases hx
  | publish dep =>
    simp only [applyReq] at hx
    split at hx
    · simp only [ok_eq_ok] at hx; subst hx
      obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
      refine ⟨h1, h2, h3, h4, ?_, h6⟩
      intro D hD
      simp only [List.mem_map] at hD
      obtain ⟨D0, hD0, rfl⟩ := hD
      split <;> simp only [accredited] at * <;> exact h5 D0 hD0
    · cases hx

theorem inv_approve {s : State M} (h : Inv s) (a : Principal) (p : Nat)
    {s1 : State M} (hx : exec Guards.spec s ⟨a, .approve p⟩ = .ok s1) : Inv s1 := by
  simp only [exec] at hx
  split at hx
  · split at hx <;> cases hx
  · rename_i q _
    simp only [Guards.spec, Bool.true_and, ite_error_eq_ok] at hx
    obtain ⟨_, _, hx⟩ := hx
    split at hx
    · cases hx
    · rename_i s2 hs2
      simp only [ok_eq_ok] at hx; subst hx
      exact inv_frame (inv_applyReq h q.req hs2) rfl rfl rfl rfl

theorem inv_assign {s : State M} (h : Inv s) (a : Principal) (u dep : Nat)
    {s1 : State M} (hx : exec Guards.spec s ⟨a, .assign u dep⟩ = .ok s1) : Inv s1 := by
  simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
  obtain ⟨_, ha, rfl⟩ := hx
  simp at ha
  exact inv_updUser h u (fun x => { x with deps := dep :: x.deps }) s.ended (fun _ => rfl)
    (fun _ h => h)
    (fun x hx hxu _ _ => by
      show x.status = .active
      have hact := mem_allUser ha hx hxu
      simpa [isActive] using hact)
    (fun x hx hxu hoff => by
      dsimp only at hoff
      have hact := mem_allUser ha hx hxu
      simp [isActive, hoff] at hact)
    (fun x hx _ r hr => h.heldEnded x hx r hr)

theorem inv_unassign {s : State M} (h : Inv s) (a : Principal) (u dep : Nat)
    {s1 : State M} (hx : exec Guards.spec s ⟨a, .unassign u dep⟩ = .ok s1) : Inv s1 := by
  simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
  obtain ⟨_, rfl⟩ := hx
  exact inv_updUser h u (fun x => { x with deps := x.deps.filter (· != dep) }) s.ended
    (fun _ => rfl) (fun _ h => h)
    (fun x hx _ dep' hdep => by
      simp only [List.mem_filter] at hdep
      exact h.members x hx dep' hdep.1)
    (fun x hx _ hoff => by
      obtain ⟨hr, hd, hv⟩ := h.inert x hx hoff
      exact ⟨hr, by simp [hd], hv⟩)
    (fun x hx _ r hr => h.heldEnded x hx r hr)

theorem inv_dropRole {s : State M} (h : Inv s) (a : Principal) (u : Nat)
    {s1 : State M} (hx : exec Guards.spec s ⟨a, .dropRole u⟩ = .ok s1) : Inv s1 := by
  simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
  obtain ⟨_, rfl⟩ := hx
  exact inv_updUser h u (fun x => { x with role := none }) s.ended (fun _ => rfl) (fun _ h => h)
    (fun x hx _ dep' hdep => h.members x hx dep' hdep)
    (fun x hx _ hoff => by
      obtain ⟨_, hd, hv⟩ := h.inert x hx hoff
      exact ⟨rfl, hd, hv⟩)
    (fun x hx _ r hr => by simp at hr)

theorem inv_setDeployment {s : State M} (h : Inv s) (a : Principal) (dep : Nat) (cs : List M)
    (gw : M) {s1 : State M} (hx : exec Guards.spec s ⟨a, .setDeployment dep cs gw⟩ = .ok s1) :
    Inv s1 := by
  simp only [exec, Guards.spec, Bool.true_and, ite_error_eq_ok] at hx
  obtain ⟨hm, hx⟩ := hx
  have hacc : accredited (⟨dep, cs, gw, 0⟩ : Deployment M) = true := by simpa using hm
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  split at hx
  · simp only [ok_eq_ok] at hx; subst hx
    refine ⟨h1, h2, h3, h4, ?_, h6⟩
    intro D hD
    simp only [List.mem_map] at hD
    obtain ⟨D0, hD0, rfl⟩ := hD
    by_cases hd : D0.id = dep
    · simp only [hd, ite_true]
      exact (accredited_ext ⟨dep, cs, gw, 0⟩ _ rfl rfl).trans hacc
    · simp only [hd, ite_false]; exact h5 D0 hD0
  · simp only [ok_eq_ok] at hx; subst hx
    refine ⟨h1, h2, h3, h4, ?_, h6⟩
    intro D hD
    simp only [List.mem_append, List.mem_singleton] at hD
    rcases hD with hD | rfl
    · exact h5 D hD
    · exact hacc

theorem inv_enroll {s : State M} (h : Inv s) (a : Principal) (d : DevId) (o dep : Nat)
    (proof : Bool) {s1 : State M} (hx : exec Guards.spec s ⟨a, .enroll d o dep proof⟩ = .ok s1) :
    Inv s1 := by
  simp only [exec, Guards.spec, Bool.true_and, ite_error_eq_ok, ok_eq_ok] at hx
  obtain ⟨_, hown, hp, ho, rfl⟩ := hx
  have hao : actorId a = o := by
    have : isUser a o = true := by simpa using hown
    cases a <;> simp_all [isUser, actorId]
  simp only [Bool.or_eq_true, not_or] at ho
  have ho2 : allUser s o (fun x => isActive x && decide (dep ∈ x.deps)) = true := by simpa using ho.2
  have hp' : proof = true := by simpa using hp
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  refine ⟨h1, ?_, ?_, ?_, h5, h6⟩
  · intro u hu hoff
    obtain ⟨hr, hd, hv⟩ := h2 u hu hoff
    refine ⟨hr, hd, fun dv hdv hown => ?_⟩
    simp only [List.mem_append, List.mem_singleton] at hdv
    rcases hdv with hdv | rfl
    · exact hv dv hdv hown
    · have := mem_allUser ho2 hu hown.symm
      simp [isActive, hoff] at this
  · intro dv hdv
    simp only [List.mem_append, List.mem_singleton] at hdv
    rcases hdv with hdv | rfl
    · exact h3 dv hdv
    · exact hp'
  · intro dv hdv
    simp only [List.mem_append, List.mem_singleton] at hdv
    rcases hdv with hdv | rfl
    · exact h4 dv hdv
    · exact ⟨hao, fun h => nomatch h⟩

theorem inv_approveDevice {s : State M} (h : Inv s) (a : Principal) (d : Nat)
    {s1 : State M} (hx : exec Guards.spec s ⟨a, .approveDevice d⟩ = .ok s1) : Inv s1 := by
  simp only [exec, Guards.spec, Bool.true_and, ite_error_eq_ok, ok_eq_ok] at hx
  obtain ⟨_, hpend, hsep, _, rfl⟩ := hx
  simp at hpend
  have hsep' : allDevice s d (fun x => actorId a != x.owner) = true := by simpa using hsep
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  refine ⟨h1, ?_, ?_, ?_, h5, h6⟩
  · intro u hu hoff
    obtain ⟨hr, hd, hv⟩ := h2 u hu hoff
    refine ⟨hr, hd, fun dv hdv hown => ?_⟩
    simp only [updDevice, List.mem_map] at hdv
    obtain ⟨x, hx, rfl⟩ := hdv
    by_cases hxd : x.id = d
    · have hp := mem_allDevice hpend hx hxd
      have hr' := hv x hx (by simpa [hxd] using hown)
      simp [hr'] at hp
    · simp only [hxd, ite_false] at hown ⊢; exact hv x hx hown
  · intro dv hdv
    simp only [updDevice, List.mem_map] at hdv
    obtain ⟨x, hx, rfl⟩ := hdv
    by_cases hxd : x.id = d <;> simp [hxd, h3 x hx]
  · intro dv hdv
    simp only [updDevice, List.mem_map] at hdv
    obtain ⟨x, hx, rfl⟩ := hdv
    by_cases hxd : x.id = d
    · have hs := mem_allDevice hsep' hx hxd
      simp only [hxd, ite_true]
      refine ⟨(h4 x hx).1, fun _ => ⟨actorId a, rfl, by simpa using hs⟩⟩
    · simp only [hxd, ite_false]; exact h4 x hx

theorem inv_revokeDevice {s : State M} (h : Inv s) (a : Principal) (d : Nat)
    {s1 : State M} (hx : exec Guards.spec s ⟨a, .revokeDevice d⟩ = .ok s1) : Inv s1 := by
  simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
  obtain ⟨_, rfl⟩ := hx
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  refine ⟨h1, ?_, ?_, ?_, h5, h6⟩
  · intro u hu hoff
    obtain ⟨hr, hd, hv⟩ := h2 u hu hoff
    refine ⟨hr, hd, fun dv hdv hown => ?_⟩
    simp only [updDevice, List.mem_map] at hdv
    obtain ⟨x, hx, rfl⟩ := hdv
    by_cases hxd : x.id = d
    · simp [hxd]
    · simp only [hxd, ite_false] at hown ⊢; exact hv x hx hown
  · intro dv hdv
    simp only [updDevice, List.mem_map] at hdv
    obtain ⟨x, hx, rfl⟩ := hdv
    by_cases hxd : x.id = d <;> simp [hxd, h3 x hx]
  · intro dv hdv
    simp only [updDevice, List.mem_map] at hdv
    obtain ⟨x, hx, rfl⟩ := hdv
    by_cases hxd : x.id = d
    · simp only [hxd, ite_true]; exact ⟨(h4 x hx).1, fun h => nomatch h⟩
    · simp only [hxd, ite_false]; exact h4 x hx

theorem inv_offboard {s : State M} (h : Inv s) (a : Principal) (u : Nat)
    {s1 : State M} (hx : exec Guards.spec s ⟨a, .offboard u⟩ = .ok s1) : Inv s1 := by
  simp only [exec, Guards.spec, ite_error_eq_ok, ok_eq_ok, ite_true, Bool.not_true,
    Bool.false_or] at hx
  obtain ⟨_, _, rfl⟩ := hx
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  refine ⟨?_, ?_, ?_, ?_, h5, ?_⟩
  · intro y hy dep hdep
    simp only [updUser, List.mem_map] at hy
    obtain ⟨x, hx, rfl⟩ := hy
    by_cases hxu : x.id = u
    · simp [hxu] at hdep
    · simp only [hxu, ite_false] at hdep ⊢; exact h1 x hx dep hdep
  · intro y hy hoff
    simp only [updUser, List.mem_map] at hy
    obtain ⟨x, hx, rfl⟩ := hy
    by_cases hxu : x.id = u
    · rw [ite_eq_left_of_eq_true _ _ (eq_true hxu)]
      refine ⟨rfl, rfl, fun dv hdv hown => ?_⟩
      simp only [List.mem_map] at hdv
      obtain ⟨z, _, rfl⟩ := hdv
      by_cases hz : z.owner = u
      · simp [hz]
      · simp [hz] at hown; exact absurd (hown.trans hxu) hz
    · simp only [hxu, ite_false] at hoff ⊢
      obtain ⟨hr, hd, hv⟩ := h2 x hx hoff
      refine ⟨hr, hd, fun dv hdv hown => ?_⟩
      simp only [List.mem_map] at hdv
      obtain ⟨z, hz, rfl⟩ := hdv
      by_cases hzu : z.owner = u
      · simp [hzu]
      · simp only [beq_iff_eq, hzu, ite_false] at hown ⊢; exact hv z hz hown
  · intro dv hdv
    simp only [List.mem_map] at hdv
    obtain ⟨z, hz, rfl⟩ := hdv
    by_cases hzu : z.owner = u <;> simp [hzu, h3 z hz]
  · intro dv hdv
    simp only [List.mem_map] at hdv
    obtain ⟨z, hz, rfl⟩ := hdv
    by_cases hzu : z.owner = u
    · simp only [hzu, beq_self_eq_true, ite_true]; exact ⟨(h4 z hz).1.trans hzu, fun h => nomatch h⟩
    · have : (z.owner == u) = false := by simpa using hzu
      simp only [this]; exact h4 z hz
  · intro y hy r hr
    simp only [updUser, List.mem_map] at hy
    obtain ⟨x, hx, rfl⟩ := hy
    by_cases hxu : x.id = u
    · simp [hxu] at hr
    · simp only [hxu, ite_false] at hr; exact h6 x hx r hr

theorem exec_inv {s s1 : State M} (h : Inv s) {e : Event M}
    (hx : exec Guards.spec s e = .ok s1) : Inv s1 := by
  rcases e with ⟨a, ev⟩
  cases ev with
  | invite u => exact inv_invite h a u hx
  | request r => exact inv_request h a r hx
  | approve p => exact inv_approve h a p hx
  | reject p => exact inv_reject h a p hx
  | assign u dep => exact inv_assign h a u dep hx
  | unassign u dep => exact inv_unassign h a u dep hx
  | dropRole u => exact inv_dropRole h a u hx
  | setDeployment dep cs gw => exact inv_setDeployment h a dep cs gw hx
  | enroll d o dep proof => exact inv_enroll h a d o dep proof hx
  | approveDevice d => exact inv_approveDevice h a d hx
  | revokeDevice d => exact inv_revokeDevice h a d hx
  | offboard u => exact inv_offboard h a u hx
  | pull _ => simp [exec] at hx
  | list => simp [exec] at hx
  | readAudit => simp [exec] at hx

theorem inv_step {s : State M} (h : Inv s) (e : Event M) : Inv (step s e).2 := by
  rcases stepG_cases Guards.spec s e with ⟨h1, _⟩ | ⟨_, _, s1, hx, hs⟩
  · unfold step; rw [h1]; exact h
  · unfold step; rw [hs]
    exact inv_frame (exec_inv h hx) rfl rfl rfl rfl

theorem inv_run {s : State M} (h : Inv s) (es : List (Event M)) : Inv (run s es) := by
  induction es generalizing s with
  | nil => exact h
  | cons e es ih => exact ih (inv_step h e)

/-! ## 5. Audit -/

theorem record_fields (s s' : State M) (e : Event M) :
    (record s s' e).actor = e.actor ∧ (record s s' e).action = e.ev.kind ∧
    (record s s' e).subject = subjectOf s e ∧
    (record s s' e).before = snap s (subjectOf s e) ∧
    (record s s' e).after = snap s' (subjectOf s e) := ⟨rfl, rfl, rfl, rfl, rfl⟩

/-- A successful write appends exactly one record (actor, action, subject, the subject's slice
    before and after, `record_fields`); a refusal or a read changes nothing at all. -/
theorem audit_one_record (s : State M) (e : Event M) :
    ((step s e).1 = .ok → isRead e.ev = false →
      (step s e).2.audit = s.audit ++ [record s (step s e).2 e]) ∧
    ((step s e).1 ≠ .ok ∨ isRead e.ev = true → (step s e).2 = s) := by
  unfold step
  rcases stepG_cases Guards.spec s e with ⟨h1, h2⟩ | ⟨_, hr, s1, _, hs⟩
  · refine ⟨fun ho hr => ?_, fun _ => h1⟩
    rcases h2 with h2 | h2
    · exact absurd ho h2
    · simp [hr] at h2
  · rw [hs]
    refine ⟨fun _ _ => rfl, fun h => ?_⟩
    simp [hr] at h

theorem audit_prefix_step (s : State M) (e : Event M) : s.audit <+: (step s e).2.audit := by
  obtain ⟨h1, h2⟩ := audit_one_record s e
  by_cases ho : (step s e).1 = .ok
  · by_cases hr : isRead e.ev = true
    · rw [h2 (Or.inr hr)]; exact List.prefix_refl _
    · rw [h1 ho (by simpa using hr)]; exact List.prefix_append _ _
  · rw [h2 (Or.inl ho)]; exact List.prefix_refl _

/-- The log only grows at the end: no reachable state removes or reorders a record. -/
theorem audit_prefix_run (s : State M) (es : List (Event M)) : s.audit <+: (run s es).audit := by
  induction es generalizing s with
  | nil => exact List.prefix_refl _
  | cons e es ih => exact (audit_prefix_step s e).trans (ih _)

/-! ### Every change is inside the record -/

theorem filter_map_frame {α : Type} (l : List α) (f : α → α) (q : α → Bool)
    (hfix : ∀ x, q x = true → f x = x) (hq : ∀ x, q (f x) = q x) :
    (l.map f).filter q = l.filter q := by
  induction l with
  | nil => rfl
  | cons x l ih =>
    simp only [List.map_cons, List.filter_cons, hq, ih]
    by_cases h : q x = true
    · simp [h, hfix x h]
    · simp [h]

theorem filter_append_out {α : Type} (l : List α) (x : α) (q : α → Bool) (h : q x = false) :
    (l ++ [x]).filter q = l.filter q := by
  simp [List.filter_append, h]

theorem filter_filter_out {α : Type} (l : List α) (p q : α → Bool)
    (h : ∀ x, q x = true → p x = true) : (l.filter p).filter q = l.filter q := by
  induction l with
  | nil => rfl
  | cons x l ih =>
    by_cases hq : q x = true
    · simp [h x hq, hq, ih]
    · by_cases hp : p x = true
      · simp [hp, hq, ih]
      · simp [hp, hq, ih]

theorem rest_ext {s s1 : State M} {x : Subject}
    (hu : s1.users.filter (fun y => !relU x y) = s.users.filter (fun y => !relU x y))
    (hd : s1.devices.filter (fun y => !relD x y) = s.devices.filter (fun y => !relD x y))
    (hp : s1.deployments.filter (fun y => !relDep x y) = s.deployments.filter (fun y => !relDep x y))
    (hq : s1.pending.filter (fun y => !relP x y) = s.pending.filter (fun y => !relP x y)) :
    rest s x = rest s1 x := by
  simp only [rest, hu, hd, hp, hq]

theorem updUser_rest (s : State M) (u : UserId) (f : User → User)
    (hid : ∀ x, (f x).id = x.id) :
    (updUser s u f).filter (fun y => !relU (.user u) y) = s.users.filter (fun y => !relU (.user u) y) := by
  apply filter_map_frame
  · intro x hx; simp [relU] at hx; simp [hx]
  · intro x; by_cases h : x.id = u <;> simp [relU, h, hid]

theorem updDevice_rest (s : State M) (d : DevId) (f : Device → Device)
    (hid : ∀ x, (f x).id = x.id) :
    (updDevice s d f).filter (fun y => !relD (.device d) y) =
      s.devices.filter (fun y => !relD (.device d) y) := by
  apply filter_map_frame
  · intro x hx; simp [relD] at hx; simp [hx]
  · intro x; by_cases h : x.id = d <;> simp [relD, h, hid]

theorem applyReq_rest {s s1 : State M} {r : Req} (hx : applyReq Guards.spec s r = .ok s1) :
    rest s r.subject = rest s1 r.subject := by
  cases r with
  | activate u =>
    simp only [applyReq] at hx; split at hx
    · simp only [ok_eq_ok] at hx; subst hx
      exact rest_ext (updUser_rest s u _ (fun _ => rfl)) rfl rfl rfl
    · cases hx
  | grant u r =>
    simp only [applyReq] at hx; split at hx
    · simp only [ok_eq_ok] at hx; subst hx
      exact rest_ext (updUser_rest s u _ (fun _ => rfl)) rfl rfl rfl
    · cases hx
  | publish dep =>
    simp only [applyReq] at hx; split at hx
    · simp only [ok_eq_ok] at hx; subst hx
      refine rest_ext rfl rfl ?_ rfl
      apply filter_map_frame
      · intro D hD; simp [relDep, Req.subject] at hD; simp [hD]
      · intro D; by_cases h : D.id = dep <;> simp [relDep, Req.subject, h]
    · cases hx

theorem relP_self (q : Pending) : relP q.req.subject q = true := by
  cases h : q.req.subject <;> simp [relP, h]

theorem exec_rest {s s1 : State M} {e : Event M} (hx : exec Guards.spec s e = .ok s1) :
    rest s (subjectOf s e) = rest s1 (subjectOf s e) := by
  rcases e with ⟨a, ev⟩
  cases ev with
  | invite u =>
    simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
    obtain ⟨_, rfl⟩ := hx
    exact rest_ext (filter_append_out _ _ _ (by simp [relU, subjectOf])) rfl rfl
      (filter_append_out _ _ _ (by simp [relP, Req.subject, subjectOf]))
  | request r =>
    cases r with
    | activate _ => simp [exec] at hx
    | grant u r =>
      simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx; obtain ⟨_, rfl⟩ := hx
      exact rest_ext rfl rfl rfl (filter_append_out _ _ _ (by simp [subjectOf, relP, Req.subject]))
    | publish dep =>
      simp only [exec, ok_eq_ok] at hx; subst hx
      exact rest_ext rfl rfl rfl (filter_append_out _ _ _ (by simp [subjectOf, relP, Req.subject]))
  | approve p =>
    simp only [exec] at hx
    split at hx
    · split at hx <;> cases hx
    · rename_i q hq
      simp only [Guards.spec, Bool.true_and, ite_error_eq_ok] at hx
      obtain ⟨_, _, hx⟩ := hx
      split at hx
      · cases hx
      · rename_i s2 hs2
        simp only [ok_eq_ok] at hx; subst hx
        simp only [subjectOf, hq]
        have h2 := applyReq_rest hs2
        rw [h2]
        refine rest_ext rfl rfl rfl ?_
        apply filter_filter_out
        intro x hx
        simp only [Bool.not_eq_true'] at hx
        exact bne_iff_ne.2 (fun he => by subst he; rw [relP_self] at hx; cases hx)
  | reject p =>
    simp only [exec] at hx
    split at hx
    · split at hx <;> cases hx
    · rename_i q hq
      simp only [ok_eq_ok] at hx; subst hx
      simp only [subjectOf, hq]
      refine rest_ext rfl rfl rfl ?_
      apply filter_filter_out
      intro x hx
      simp only [Bool.not_eq_true'] at hx
      exact bne_iff_ne.2 (fun he => by subst he; rw [relP_self] at hx; cases hx)
  | assign u dep =>
    simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
    obtain ⟨_, _, _, rfl⟩ := hx
    exact rest_ext (updUser_rest s u _ (fun _ => rfl)) rfl rfl rfl
  | unassign u dep =>
    simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
    obtain ⟨_, rfl⟩ := hx
    exact rest_ext (updUser_rest s u _ (fun _ => rfl)) rfl rfl rfl
  | dropRole u =>
    simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
    obtain ⟨_, rfl⟩ := hx
    exact rest_ext (updUser_rest s u _ (fun _ => rfl)) rfl rfl rfl
  | setDeployment dep cs gw =>
    simp only [exec, Guards.spec, Bool.true_and, ite_error_eq_ok] at hx
    obtain ⟨_, hx⟩ := hx
    split at hx
    · simp only [ok_eq_ok] at hx; subst hx
      refine rest_ext rfl rfl ?_ rfl
      apply filter_map_frame
      · intro D hD; simp [relDep, subjectOf] at hD; simp [hD]
      · intro D; by_cases h : D.id = dep <;> simp [relDep, subjectOf, h]
    · simp only [ok_eq_ok] at hx; subst hx
      exact rest_ext rfl rfl (filter_append_out _ _ _ (by simp [relDep, subjectOf])) rfl
  | enroll d o dep proof =>
    simp only [exec, Guards.spec, Bool.true_and, ite_error_eq_ok, ok_eq_ok] at hx
    obtain ⟨_, _, _, _, rfl⟩ := hx
    exact rest_ext rfl (filter_append_out _ _ _ (by simp [relD, subjectOf])) rfl rfl
  | approveDevice d =>
    simp only [exec, Guards.spec, Bool.true_and, ite_error_eq_ok, ok_eq_ok] at hx
    obtain ⟨_, _, _, _, rfl⟩ := hx
    exact rest_ext rfl (updDevice_rest s d _ (fun _ => rfl)) rfl rfl
  | revokeDevice d =>
    simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
    obtain ⟨_, rfl⟩ := hx
    exact rest_ext rfl (updDevice_rest s d _ (fun _ => rfl)) rfl rfl
  | offboard u =>
    simp only [exec, Guards.spec, ite_error_eq_ok, ok_eq_ok, ite_true, Bool.not_true,
      Bool.false_or] at hx
    obtain ⟨_, _, rfl⟩ := hx
    refine rest_ext (updUser_rest s u _ (fun _ => rfl)) ?_ rfl ?_
    · apply filter_map_frame
      · intro x hx; simp [relD, subjectOf] at hx; simp [hx]
      · intro x; by_cases h : x.owner = u <;> simp [relD, subjectOf, h]
    · apply filter_filter_out
      intro x hx
      simpa [relP, subjectOf] using hx
  | pull _ => simp [exec] at hx
  | list => simp [exec] at hx
  | readAudit => simp [exec] at hx

/-- A successful write changes nothing outside its record's subject: every change the step made
    is in the record's before and after images. -/
theorem audit_frame (s : State M) (e : Event M) (h : (step s e).1 = .ok)
    (hr : isRead e.ev = false) :
    rest s (subjectOf s e) = rest (step s e).2 (subjectOf s e) := by
  unfold step at *
  rcases stepG_cases Guards.spec s e with ⟨_, h2⟩ | ⟨_, _, s1, hx, hs⟩
  · rcases h2 with h2 | h2
    · exact absurd h h2
    · simp [hr] at h2
  · rw [hs]; have := exec_rest hx; exact this

/-! ## 6. Least privilege -/

theorem unauthorized_unchanged (s : State M) (e : Event M)
    (h : authorized Guards.spec s e = false) : (step s e).2 = s := by
  simp [step, stepG, h]

/-- Reads never change state. -/
theorem read_unchanged (s : State M) (e : Event M) (h : isRead e.ev = true) :
    (step s e).2 = s := by
  rcases stepG_cases Guards.spec s e with ⟨h1, _⟩ | ⟨_, hr, _⟩
  · exact h1
  · simp [h] at hr

/-- An auditor may not enroll a device. -/
theorem mayEnroll_auditor (s : State M) (a : UserId) (h : roleOf s a = some .auditor) :
    mayEnroll s a = false := by
  unfold roleOf roleOfG at h
  unfold mayEnroll
  cases hf : s.users.find? (fun x => x.id == a) with
  | none => rfl
  | some x =>
    rw [hf] at h
    simp only [entryRole] at h
    by_cases hs : x.status = .active <;> simp_all

/-- A write by `a` changes state only when `a`'s role permits it, or `a` is an active person
    (not an auditor) enrolling a device. -/
theorem write_permitted (s : State M) (a : UserId) (ev : Ev M)
    (h : (step s ⟨.user a, ev⟩).2 ≠ s) :
    (∃ d o dep p, ev = .enroll d o dep p ∧ mayEnroll s a = true) ∨
    ∃ r, roleOf s a = some r ∧ permits Guards.spec r ev = true ∧ isRead ev = false := by
  rcases stepG_cases Guards.spec s ⟨.user a, ev⟩ with ⟨h1, _⟩ | ⟨ha, hr, _⟩
  · exact absurd h1 h
  · cases ev with
    | enroll d o dep p => exact Or.inl ⟨d, o, dep, p, rfl, by simpa [authorized] using ha⟩
    | _ =>
      right
      cases hr' : roleOf s a with
      | none => simp [authorized, hr'] at ha
      | some r => exact ⟨r, rfl, by simpa [authorized, hr'] using ha, hr⟩

/-- An auditor never changes state. -/
theorem auditor_read_only (s : State M) (a : UserId) (ev : Ev M)
    (h : roleOf s a = some .auditor) : (step s ⟨.user a, ev⟩).2 = s := by
  apply Classical.byContradiction
  intro hne
  rcases write_permitted s a ev hne with ⟨_, _, _, _, _, he⟩ | ⟨r, hr, hp, hread⟩
  · rw [mayEnroll_auditor s a h] at he; cases he
  · rw [h] at hr; cases hr
    cases ev <;> simp_all [permits, Guards.spec, isRead]

/-- An approver changes state only by approving or rejecting, or by enrolling a device (only
    ever its own: `served_separated`). It cannot author, publish, assign or revoke. -/
theorem approver_only_decides (s : State M) (a : UserId) (ev : Ev M)
    (h : roleOf s a = some .approver) (hne : (step s ⟨.user a, ev⟩).2 ≠ s) :
    (∃ p, ev = .approve p ∨ ev = .reject p) ∨ ∃ d o dep pr, ev = .enroll d o dep pr := by
  rcases write_permitted s a ev hne with ⟨d, o, dep, pr, he, _⟩ | ⟨r, hr, hp, hread⟩
  · exact Or.inr ⟨d, o, dep, pr, he⟩
  · left
    rw [h] at hr; cases hr
    cases ev <;> simp_all [permits, Guards.spec, isRead]

/-- An admin cannot approve or reject: that is the approver's click. -/
theorem admin_cannot_approve (s : State M) (a p : UserId) (h : roleOf s a = some .admin) :
    (step s ⟨.user a, .approve p⟩).2 = s ∧ (step s ⟨.user a, .reject p⟩).2 = s := by
  constructor <;> apply unauthorized_unchanged <;> simp only [authorized, roleOfG_spec, h] <;>
    simp [permits, Guards.spec]

/-! ## 1. Deployments and bootstrap -/

/-- In every reachable state every deployment's gateway is accredited for all its connectors. -/
theorem accredited_run (bs : List (UserId × Role)) (es : List (Event M)) :
    Accredited (run (install bs) es) :=
  (inv_run (inv_install bs) es).accredited

/-- Every membership is held by an active person. -/
theorem members_run (bs : List (UserId × Role)) (es : List (Event M)) :
    Members (run (install bs) es) :=
  (inv_run (inv_install bs) es).members

theorem foldl_join_dom (g : M) (cs : List M) :
    dom (cs.foldl join g) g = true ∧ ∀ c ∈ cs, dom (cs.foldl join g) c = true := by
  induction cs generalizing g with
  | nil => exact ⟨dom_refl g, fun _ h => nomatch h⟩
  | cons c cs ih =>
    obtain ⟨h1, h2⟩ := ih (join g c)
    refine ⟨dom_trans h1 (join_left g c), fun c' hc' => ?_⟩
    rcases List.mem_cons.1 hc' with rfl | hc'
    · exact dom_trans h1 (join_right g c')
    · exact h2 c' hc'

/-- A gateway accredited for the deployment's ceiling (the join of its markings) is accredited
    for every connector. Any upper-bound join will do, including Go's, which is sometimes above
    the least bound: a check against the ceiling is then stricter, never weaker. -/
theorem ceiling_accredited (D : Deployment M) (h : dom D.gateway (ceiling D) = true) :
    accredited D = true := by
  obtain ⟨_, h2⟩ := foldl_join_dom D.gateway D.connectors
  simp only [accredited, ceiling, List.all_eq_true] at *
  exact fun c hc => dom_trans h (h2 c hc)

/-! ## 2. Serving -/

/-- A pull is answered with the profile exactly when `serve` holds; otherwise 403. -/
theorem pull_served_iff (s : State M) (d : DevId) (p : Bool) :
    (step s ⟨.device d, .pull p⟩).1 = .served ↔ serve Guards.spec s d p = true := by
  by_cases h : serve Guards.spec s d p = true <;> simp [step, stepG, authorized, isRead, h]

theorem pull_unchanged (s : State M) (d : DevId) (p : Bool) :
    (step s ⟨.device d, .pull p⟩).2 = s := read_unchanged s _ rfl

/-- A served device is approved (enrolled, not revoked), its owner exists and every entry for
    the owner is an active member of the device's deployment, and the pull carried a valid
    proof of possession. -/
theorem served_requires (s : State M) (d : DevId) (p : Bool)
    (h : serve Guards.spec s d p = true) : p = true ∧ ServedOk s d := by
  simp only [serve, Guards.spec, Bool.not_true, Bool.false_or, Bool.and_eq_true] at h
  obtain ⟨⟨hp, hd⟩, ha⟩ := h
  refine ⟨hp, ?_, fun dv hdv hid => ?_⟩
  · simpa [hasDevice] using hd
  · have := mem_allDevice ha hdv hid
    simp only [deviceOk, Bool.not_true, Bool.false_or, Bool.and_eq_true, decide_eq_true_eq,
      ownerOk] at this
    obtain ⟨hst, ho, hall⟩ := this
    refine ⟨hst, by simpa [hasUser] using ho, fun u hu hid' => ?_⟩
    have := mem_allUser hall hu hid'
    simpa [isActive] using this

/-- And its enrollment proved possession of the device key. -/
theorem served_possession {s : State M} (hi : Inv s) (d : DevId) (p : Bool)
    (_ : serve Guards.spec s d p = true) :
    ∀ dv ∈ s.devices, dv.id = d → dv.possession = true :=
  fun dv hdv _ => hi.possession dv hdv

/-- In every reachable state every device was enrolled by its owner, and every approved device
    was approved by someone other than its owner. -/
theorem bound_run (bs : List (UserId × Role)) (es : List (Event M)) :
    Bound (run (install bs) es) :=
  (inv_run (inv_install bs) es).bound

/-- A served device was enrolled by its own (authenticated) owner and approved by someone
    else: no one can put a key in another person's name, or approve their own device by
    proxy. -/
theorem served_separated {s : State M} (hi : Inv s) (d : DevId) (p : Bool)
    (h : serve Guards.spec s d p = true) :
    ∀ dv ∈ s.devices, dv.id = d →
      dv.enrolledBy = dv.owner ∧ ∃ x, dv.approvedBy = some x ∧ x ≠ dv.owner :=
  fun dv hdv hid =>
    ⟨(hi.bound dv hdv).1, (hi.bound dv hdv).2 ((served_requires s d p h).2.2 dv hdv hid).1⟩

/-! ## 3. Offboarding -/

theorem offboard_exec (s : State M) (a : Principal) (u : UserId) {s1 : State M}
    (hx : exec Guards.spec s ⟨a, .offboard u⟩ = .ok s1) :
    (∀ x ∈ s1.users, x.id = u → x.status = .offboarded ∧ x.role = none ∧ x.deps = []) ∧
    (∀ dv ∈ s1.devices, dv.owner = u → dv.status = .revoked) := by
  simp only [exec, Guards.spec, ite_error_eq_ok, ok_eq_ok, ite_true, Bool.not_true,
    Bool.false_or] at hx
  obtain ⟨_, _, rfl⟩ := hx
  refine ⟨fun x hx hxu => ?_, fun dv hdv hown => ?_⟩
  · simp only [updUser, List.mem_map] at hx
    obtain ⟨y, _, rfl⟩ := hx
    by_cases hyu : y.id = u
    · rw [ite_eq_left_of_eq_true _ _ (eq_true hyu)]; exact ⟨rfl, rfl, rfl⟩
    · simp [hyu] at hxu
  · simp only [List.mem_map] at hdv
    obtain ⟨z, _, rfl⟩ := hdv
    by_cases hz : z.owner = u
    · simp [hz]
    · simp_all

theorem serve_revoked (g : Guards) (s : State M) (dv : Device) (hdv : dv ∈ s.devices)
    (hr : dv.status = .revoked) (p : Bool) : serve g s dv.id p = false := by
  simp only [serve, Bool.and_eq_false_iff]
  right
  simp only [allDevice, List.all_eq_false]
  exact ⟨dv, hdv, by simp [deviceOk, hr]⟩

/-- After offboarding `u`: every entry for `u` is offboarded with no role and no membership,
    every device `u` owns is revoked and refused at pull, and the step appended one record about
    `u` whose after-image shows all of it (`audit_frame`: nothing outside it changed). -/
theorem offboard_complete (s : State M) (a : Principal) (u : UserId)
    (h : (step s ⟨a, .offboard u⟩).1 = .ok) :
    let s' := (step s ⟨a, .offboard u⟩).2
    (∀ x ∈ s'.users, x.id = u → x.status = .offboarded ∧ x.role = none ∧ x.deps = []) ∧
    (∀ dv ∈ s'.devices, dv.owner = u → dv.status = .revoked) ∧
    (∀ dv ∈ s'.devices, dv.owner = u → ∀ p, serve Guards.spec s' dv.id p = false) ∧
    s'.audit = s.audit ++ [record s s' ⟨a, .offboard u⟩] ∧
    (record s s' ⟨a, .offboard u⟩).subject = .user u := by
  have haud := (audit_one_record s ⟨a, .offboard u⟩).1 h rfl
  dsimp only
  rcases stepG_cases Guards.spec s ⟨a, .offboard u⟩ with ⟨_, h2⟩ | ⟨_, _, s1, hx, hs⟩
  · rcases h2 with h2 | h2
    · exact absurd h h2
    · simp [isRead] at h2
  · have key : (step s ⟨a, .offboard u⟩).2 = logged Guards.spec s s1 ⟨a, .offboard u⟩ := by
      unfold step; rw [hs]
    obtain ⟨hu, hd⟩ := offboard_exec s a u hx
    rw [key] at haud ⊢
    refine ⟨hu, hd, fun dv hdv hown p => serve_revoked _ _ dv hdv (hd dv hdv hown) p, haud, rfl⟩

/-- In every reachable state, an offboarded person holds no role and no membership and owns
    only revoked devices. -/
theorem offboarded_inert_run (bs : List (UserId × Role)) (es : List (Event M)) :
    OffboardedInert (run (install bs) es) :=
  (inv_run (inv_install bs) es).inert

/-- No reachable state serves an offboarded person's device. -/
theorem offboarded_never_served (bs : List (UserId × Role)) (es : List (Event M)) :
    let s := run (install bs) es
    ∀ u ∈ s.users, u.status = .offboarded → ∀ dv ∈ s.devices, dv.owner = u.id →
      ∀ p, serve Guards.spec s dv.id p = false := by
  intro s u hu hoff dv hdv hown p
  exact serve_revoked _ _ dv hdv (((inv_run (inv_install bs) es).inert u hu hoff).2.2 dv hdv hown) p

/-! ## 4. Separation of duties -/

/-- An approval succeeds only for a pending request that someone else made and that is not
    about the approver, and only when an approver clicks. -/
theorem approve_separated (s : State M) (a : Principal) (p : Nat)
    (h : (step s ⟨a, .approve p⟩).1 = .ok) :
    (∃ x, a = .user x ∧ roleOf s x = some .approver) ∧
    ∃ q ∈ s.pending, q.id = p ∧ q.requester ≠ a ∧ subjectIs a q.req.subject = false := by
  unfold step at h
  rcases stepG_cases Guards.spec s ⟨a, .approve p⟩ with ⟨_, h2⟩ | ⟨ha, _, s1, hx, _⟩
  · rcases h2 with h2 | h2
    · exact absurd h h2
    · simp [isRead] at h2
  · refine ⟨?_, ?_⟩
    · cases a with
      | user x =>
        refine ⟨x, rfl, ?_⟩
        cases hr : roleOf s x with
        | none => simp [authorized, hr] at ha
        | some r =>
          simp only [authorized, roleOfG_spec, hr] at ha
          cases r <;> simp_all [permits, Guards.spec]
      | idp => simp [authorized] at ha
      | device _ => simp [authorized] at ha
    · simp only [exec] at hx
      split at hx
      · split at hx <;> cases hx
      · rename_i q hq
        simp only [Guards.spec, Bool.true_and, ite_error_eq_ok] at hx
        obtain ⟨h1, h2, _⟩ := hx
        refine ⟨q, List.mem_of_find?_eq_some hq, ?_, ?_, by simpa using h2⟩
        · simpa using List.find?_some hq
        · intro he; exact h1 (by simp [he])

/-- An admin never approves a device they own. -/
theorem device_approve_separated (s : State M) (a : UserId) (d : DevId)
    (h : (step s ⟨.user a, .approveDevice d⟩).1 = .ok) :
    ∀ dv ∈ s.devices, dv.id = d → dv.owner ≠ a := by
  unfold step at h
  rcases stepG_cases Guards.spec s ⟨.user a, .approveDevice d⟩ with ⟨_, h2⟩ | ⟨_, _, s1, hx, _⟩
  · rcases h2 with h2 | h2
    · exact absurd h h2
    · simp [isRead] at h2
  · simp only [exec, Guards.spec, Bool.true_and, ite_error_eq_ok] at hx
    obtain ⟨_, _, ho, _⟩ := hx
    have ho' : allDevice s d (fun x => actorId (.user a) != x.owner) = true := by simpa using ho
    intro dv hdv hid heq
    have := mem_allDevice ho' hdv hid
    simp [actorId, heq] at this

theorem find_updUser (s : State M) (u a : UserId) (f : User → User)
    (hid : ∀ x, (f x).id = x.id) :
    (updUser s u f).find? (fun x => x.id == a) =
      (s.users.find? (fun x => x.id == a)).map (fun x => if x.id = u then f x else x) := by
  simp only [updUser, List.find?_map]
  congr 1
  apply congrArg (fun p => s.users.find? p)
  funext x
  by_cases h : x.id = u <;> simp [Function.comp, h, hid]

theorem find_updUser_ne (s : State M) (u a : UserId) (f : User → User)
    (hid : ∀ x, (f x).id = x.id) (hne : u ≠ a) :
    (updUser s u f).find? (fun x => x.id == a) = s.users.find? (fun x => x.id == a) := by
  rw [find_updUser s u a f hid]
  cases hf : s.users.find? (fun x => x.id == a) with
  | none => rfl
  | some y =>
    have hy : y.id = a := by simpa using List.find?_some hf
    have : y.id ≠ u := fun e => hne (e.symm.trans hy)
    simp [this]

/-- What a bootstrap principal holds can only stay or end while the ended roles grow. -/
theorem bootRole_mono {s s' : State M} (a : UserId) (hb : s'.bootstrap = s.bootstrap)
    (he : ∀ r ∈ s.ended, r ∈ s'.ended) (ho : ∀ x ∈ s.bootOff, x ∈ s'.bootOff) :
    bootRole Guards.spec s' a = bootRole Guards.spec s a ∨ bootRole Guards.spec s' a = none := by
  unfold bootRole
  rw [hb]
  by_cases h0 : a ∈ s.bootOff
  · right; simp [ho _ h0]
  by_cases h0' : a ∈ s'.bootOff
  · right; simp [h0']
  simp only [h0, h0', ite_false]
  cases s.bootstrap.find? (fun p => p.1 == a) with
  | none => exact Or.inl rfl
  | some p =>
    simp only [Guards.spec, ite_true]
    by_cases h1 : p.2 ∈ s.ended
    · right; simp [he _ h1]
    · by_cases h2 : p.2 ∈ s'.ended <;> simp [h1, h2]

/-- How `roleOf` moves when the entry for `a` stays, appears without a role, or keeps or loses
    its role, the bootstrap config is unchanged and the ended roles grow. -/
theorem roleOf_mono {s s' : State M} (a : UserId) (hb : s'.bootstrap = s.bootstrap)
    (he : ∀ r ∈ s.ended, r ∈ s'.ended) (ho : ∀ x ∈ s.bootOff, x ∈ s'.bootOff)
    (hu : s'.users.find? (fun x => x.id == a) = s.users.find? (fun x => x.id == a) ∨
      (s.users.find? (fun x => x.id == a) = none ∧
        ∃ x, s'.users.find? (fun x => x.id == a) = some x ∧ entryRole x = none) ∨
      ∃ y y', s.users.find? (fun x => x.id == a) = some y ∧
        s'.users.find? (fun x => x.id == a) = some y' ∧
        (entryRole y' = entryRole y ∨ entryRole y' = none)) :
    roleOf s' a = roleOf s a ∨ roleOf s' a = none := by
  unfold roleOf roleOfG
  rcases hu with h | ⟨h0, x, h1, hx⟩ | ⟨y, y', h0, h1, hy⟩
  · rw [h]
    cases s.users.find? (fun x => x.id == a) with
    | none => exact bootRole_mono a hb he ho
    | some y => exact Or.inl rfl
  · rw [h0, h1]; exact Or.inr hx
  · rw [h0, h1]; exact hy

/-- The bootstrap config never changes; the ended roles and offboarded bootstraps only grow. -/
theorem exec_boot {s s1 : State M} {e : Event M} (hx : exec Guards.spec s e = .ok s1) :
    s1.bootstrap = s.bootstrap ∧ (∀ r ∈ s.ended, r ∈ s1.ended) ∧
      ∀ x ∈ s.bootOff, x ∈ s1.bootOff := by
  rcases e with ⟨a, ev⟩
  cases ev with
  | approve p =>
    simp only [exec] at hx
    split at hx
    · split at hx <;> cases hx
    · rename_i q _
      simp only [Guards.spec, Bool.true_and, ite_error_eq_ok] at hx
      obtain ⟨_, _, hx⟩ := hx
      split at hx
      · cases hx
      · rename_i s2 hs2
        simp only [ok_eq_ok] at hx; subst hx
        cases hq : q.req <;> rw [hq] at hs2 <;> simp only [applyReq] at hs2 <;> split at hs2 <;>
          cases hs2 <;> exact ⟨rfl, fun r h => by simp [h], fun _ h => h⟩
  | offboard u =>
    simp only [exec] at hx
    repeat' split at hx
    all_goals first
      | (cases hx; done)
      | (cases hx
         refine ⟨rfl, fun _ h => h, fun x h => ?_⟩
         first | simp [h] | (split <;> simp [h]))
  | _ =>
    simp only [exec] at hx
    repeat' split at hx
    all_goals (cases hx <;> exact ⟨rfl, fun _ h => h, fun _ h => h⟩)

theorem step_boot (s : State M) (e : Event M) :
    (step s e).2.bootstrap = s.bootstrap ∧ (∀ r ∈ s.ended, r ∈ (step s e).2.ended) ∧
      ∀ x ∈ s.bootOff, x ∈ (step s e).2.bootOff := by
  unfold step
  rcases stepG_cases Guards.spec s e with ⟨h1, _⟩ | ⟨_, _, s1, hx, hs⟩
  · rw [h1]; exact ⟨rfl, fun _ h => h, fun _ h => h⟩
  · rw [hs]; have := exec_boot hx; exact this

/-- Once a role's bootstrap has ended, it stays ended. -/
theorem ended_run (s : State M) (es : List (Event M)) (r : Role) (h : r ∈ s.ended) :
    r ∈ (run s es).ended := by
  induction es generalizing s with
  | nil => exact h
  | cons e es ih => exact ih _ ((step_boot s e).2.1 r h)

/-- Once a bootstrap principal is offboarded, it stays offboarded. -/
theorem bootOff_run (s : State M) (es : List (Event M)) (x : UserId) (h : x ∈ s.bootOff) :
    x ∈ (run s es).bootOff := by
  induction es generalizing s with
  | nil => exact h
  | cons e es ih => exact ih _ ((step_boot s e).2.2 x h)

/-- The IdP can always offboard a configured bootstrap principal, whether or not it is also a
    person, and from then on it is offboarded as a bootstrap. -/
theorem offboard_bootstrap (s : State M) (u : UserId) (hb : isBoot s u = true) :
    (step s ⟨.idp, .offboard u⟩).1 = .ok ∧ u ∈ (step s ⟨.idp, .offboard u⟩).2.bootOff := by
  simp [step, stepG, authorized, isRead, exec, Guards.spec, hb, logged]

/-- An offboarded bootstrap principal never acts as a bootstrap again: in every later state,
    unless it has since been invited and approved as a person, it holds no role. -/
theorem offboarded_bootstrap_never_acts (s : State M) (u : UserId) (h : u ∈ s.bootOff)
    (es : List (Event M)) (hn : (run s es).users.find? (fun x => x.id == u) = none) :
    roleOf (run s es) u = none := by
  have h' := bootOff_run s es u h
  unfold roleOf roleOfG bootRole
  rw [hn]
  simp [h']

/-- Approving a role grant ends that role's bootstrap in the same step, before anyone acts with
    the new role. -/
theorem grant_ends_bootstrap (s : State M) (a : Principal) (p : Nat)
    (h : (step s ⟨a, .approve p⟩).1 = .ok) :
    ∀ q, s.pending.find? (fun q => q.id == p) = some q →
      ∀ u r, q.req = .grant u r → r ∈ (step s ⟨a, .approve p⟩).2.ended := by
  intro q hq u r hr
  unfold step at *
  rcases stepG_cases Guards.spec s ⟨a, .approve p⟩ with ⟨_, h2⟩ | ⟨_, _, s1, hx, hs⟩
  · rcases h2 with h2 | h2
    · exact absurd h h2
    · simp [isRead] at h2
  · rw [hs]
    show r ∈ s1.ended
    simp only [exec] at hx
    rw [hq] at hx
    simp only [Guards.spec, Bool.true_and, ite_error_eq_ok] at hx
    obtain ⟨_, _, hx⟩ := hx
    split at hx
    · cases hx
    · rename_i s2 hs2
      cases hx
      rw [hr] at hs2
      simp only [applyReq] at hs2
      split at hs2
      · cases hs2; simp
      · cases hs2

/-- A write that ends a role's bootstrap leaves an active person holding that role. -/
theorem exec_ended {s s1 : State M} {e : Event M} (hx : exec Guards.spec s e = .ok s1) (r : Role)
    (h1 : r ∉ s.ended) (h2 : r ∈ s1.ended) :
    ∃ x ∈ s1.users, x.role = some r ∧ x.status = .active := by
  rcases e with ⟨a, ev⟩
  cases ev with
  | approve p =>
    simp only [exec] at hx
    split at hx
    · split at hx <;> cases hx
    · rename_i q _
      simp only [Guards.spec, Bool.true_and, ite_error_eq_ok] at hx
      obtain ⟨_, _, hx⟩ := hx
      split at hx
      · cases hx
      · rename_i s2 hs2
        cases hx
        cases hq : q.req with
        | grant u r' =>
          rw [hq] at hs2
          simp only [applyReq] at hs2
          split at hs2
          · rename_i hc
            cases hs2
            simp only [Bool.and_eq_true] at hc
            obtain ⟨y, hy, hyu⟩ : ∃ y ∈ s.users, y.id = u := by simpa [hasUser] using hc.1
            have hya := mem_allUser hc.2 hy hyu
            have hr : r = r' := by
              simp at h2
              rcases h2 with h2 | h2
              · exact h2
              · exact absurd h2 h1
            subst hr
            refine ⟨{ y with role := some r }, ?_, rfl, by simpa [isActive] using hya⟩
            simp only [ite_true, updUser, List.mem_map]
            exact ⟨y, hy, by simp [hyu]⟩
          · cases hs2
        | activate u =>
          rw [hq] at hs2; simp only [applyReq] at hs2
          split at hs2 <;> cases hs2 <;> exact absurd h2 h1
        | publish dep =>
          rw [hq] at hs2; simp only [applyReq] at hs2
          split at hs2 <;> cases hs2 <;> exact absurd h2 h1
  | _ =>
    simp only [exec] at hx
    repeat' split at hx
    all_goals (cases hx <;> exact absurd h2 h1)

/-- A role's bootstrap ends only in a step that leaves an active person holding the role, so
    ending it never strands the role with nobody (the portal's marker takes effect only with its
    holder's record). -/
theorem ending_requires_holder (s : State M) (e : Event M) (r : Role) (h1 : r ∉ s.ended)
    (h2 : r ∈ (step s e).2.ended) :
    ∃ x ∈ (step s e).2.users, x.role = some r ∧ x.status = .active := by
  unfold step at *
  rcases stepG_cases Guards.spec s e with ⟨h0, _⟩ | ⟨_, _, s1, hx, hs⟩
  · rw [h0] at h2; exact absurd h2 h1
  · rw [hs] at h2 ⊢; exact exec_ended hx r h1 h2

/-- Deciding a request that was already decided is a conflict, not a missing request. -/
theorem redecide_conflict (s : State M) (a : UserId) (p : Nat)
    (ha : roleOf s a = some .approver)
    (hn : s.pending.find? (fun q => q.id == p) = none) (hd : p ∈ s.decided) :
    (step s ⟨.user a, .approve p⟩).1 = .refused .conflict ∧
      (step s ⟨.user a, .reject p⟩).1 = .refused .conflict := by
  have h1 : authorized Guards.spec s ⟨.user a, .approve p⟩ = true := by
    simp only [authorized, roleOfG_spec, ha]; rfl
  have h2 : authorized Guards.spec s ⟨.user a, .reject p⟩ = true := by
    simp only [authorized, roleOfG_spec, ha]; rfl
  constructor
  · simp [step, stepG, h1, isRead, exec, hn, hd]
  · simp [step, stepG, h2, isRead, exec, hn, hd]

/-- In every reachable state, a role held by any person has ended its bootstrap. -/
theorem held_ended_run (bs : List (UserId × Role)) (es : List (Event M)) :
    HeldEnded (run (install bs) es) :=
  (inv_run (inv_install bs) es).heldEnded

/-- A principal with no person entry holds role `r` only while `r`'s bootstrap has not ended. -/
theorem bootstrap_ends (s : State M) (a : UserId) (r : Role)
    (hn : s.users.find? (fun x => x.id == a) = none) (he : r ∈ s.ended) :
    roleOf s a ≠ some r := by
  unfold roleOf roleOfG bootRole
  rw [hn]
  by_cases h0 : a ∈ s.bootOff
  · simp [h0]
  simp only [h0, ite_false]
  cases s.bootstrap.find? (fun p => p.1 == a) with
  | none => simp
  | some p =>
    simp only [Guards.spec, ite_true]
    by_cases hp : p.2 ∈ s.ended
    · simp [hp]
    · simp only [hp, ite_false, ne_eq, Option.some.injEq]
      intro e; exact hp (e ▸ he)

/-- The bootstrap never revives: once a role's bootstrap has ended, no later state, whatever
    happens (every holder offboarded included), gives that role to a principal that is not a
    person. -/
theorem bootstrap_never_revives (s : State M) (r : Role) (h : r ∈ s.ended) (es : List (Event M))
    (a : UserId) (hn : (run s es).users.find? (fun x => x.id == a) = none) :
    roleOf (run s es) a ≠ some r :=
  bootstrap_ends _ a r hn (ended_run s es r h)

/-- With the config rule (one subject per role, one role per subject), the admin and approver
    bootstraps are two different principals. -/
theorem bootstrap_two_people (bs : List (UserId × Role)) (hwf : BootstrapWF bs) (a b : UserId)
    (ha : (a, Role.admin) ∈ bs) (hb : (b, Role.approver) ∈ bs) : a ≠ b := by
  intro e
  subst e
  have := hwf _ ha _ hb (Or.inl rfl)
  simp at this

/-- One step by `a` never raises `a`'s own role: it stays what it was or is lost. -/
theorem no_self_elevation_step (s : State M) (a : UserId) (ev : Ev M) :
    roleOf (step s ⟨.user a, ev⟩).2 a = roleOf s a ∨ roleOf (step s ⟨.user a, ev⟩).2 a = none := by
  have hb := step_boot s ⟨.user a, ev⟩
  unfold step at *
  rcases stepG_cases Guards.spec s ⟨.user a, ev⟩ with ⟨h1, _⟩ | ⟨ha, _, s1, hx, hs⟩
  · rw [h1]; exact Or.inl rfl
  · rw [hs] at hb ⊢
    show roleOf s1 a = roleOf s a ∨ roleOf s1 a = none
    apply roleOf_mono a hb.1 hb.2.1 hb.2.2
    have same : s1.users = s.users →
        s1.users.find? (fun x => x.id == a) = s.users.find? (fun x => x.id == a) := by
      intro h; rw [h]
    have mine : ∀ (u : UserId) (f : User → User), (∀ x, (f x).id = x.id) →
        (∀ x, entryRole (f x) = entryRole x ∨ entryRole (f x) = none) →
        s1.users = updUser s u f →
        s1.users.find? (fun x => x.id == a) = s.users.find? (fun x => x.id == a) ∨
        (s.users.find? (fun x => x.id == a) = none ∧
          ∃ x, s1.users.find? (fun x => x.id == a) = some x ∧ entryRole x = none) ∨
        ∃ y y', s.users.find? (fun x => x.id == a) = some y ∧
          s1.users.find? (fun x => x.id == a) = some y' ∧
          (entryRole y' = entryRole y ∨ entryRole y' = none) := by
      intro u f hid hr hu
      rw [hu, find_updUser s u a f hid]
      cases hf : s.users.find? (fun x => x.id == a) with
      | none => left; simp
      | some y =>
        right; right
        refine ⟨y, _, rfl, rfl, ?_⟩
        by_cases h : y.id = u
        · simp only [h, ite_true]; exact hr y
        · simp [h]
    cases ev with
    | invite u =>
      simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
      obtain ⟨hu, rfl⟩ := hx
      by_cases hua : u = a
      · subst hua
        right; left
        have hu1 : ¬ hasUser s u = true := fun h => hu (by simp [h])
        have hn : s.users.find? (fun x => x.id == u) = none := by
          simp only [hasUser, List.any_eq_true, beq_iff_eq, not_exists, not_and] at hu1
          rw [List.find?_eq_none]; intro x hx; simpa using hu1 x hx
        refine ⟨hn, ⟨u, .pending, none, []⟩, ?_, by simp [entryRole]⟩
        show (s.users ++ [(⟨u, .pending, none, []⟩ : User)]).find? (fun x : User => x.id == u) = _
        simp [List.find?_append, hn]
      · left
        show (s.users ++ [(⟨u, .pending, none, []⟩ : User)]).find? (fun x : User => x.id == a) =
          s.users.find? (fun x => x.id == a)
        rw [List.find?_append]
        cases s.users.find? (fun x => x.id == a) with
        | some y => rfl
        | none => simp [hua]
    | request r =>
      cases r with
      | activate _ => simp [exec] at hx
      | grant _ _ => simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx; obtain ⟨_, rfl⟩ := hx; exact Or.inl rfl
      | publish _ => simp only [exec, ok_eq_ok] at hx; subst hx; exact Or.inl rfl
    | approve p =>
      simp only [exec] at hx
      split at hx
      · split at hx <;> cases hx
      · rename_i q _
        simp only [Guards.spec, Bool.true_and, ite_error_eq_ok] at hx
        obtain ⟨_, hsub, hx⟩ := hx
        split at hx
        · cases hx
        · rename_i s2 hs2
          simp only [ok_eq_ok] at hx; subst hx
          left
          show s2.users.find? (fun x => x.id == a) = s.users.find? (fun x => x.id == a)
          cases hq : q.req with
          | activate u =>
            rw [hq] at hs2 hsub
            simp only [applyReq] at hs2
            split at hs2
            · simp only [ok_eq_ok] at hs2; subst hs2
              exact find_updUser_ne s u a _ (fun _ => rfl)
                (fun e => by rw [e] at hsub; simp [subjectIs, Req.subject] at hsub)
            · cases hs2
          | grant u r =>
            rw [hq] at hs2 hsub
            simp only [applyReq] at hs2
            split at hs2
            · simp only [ok_eq_ok] at hs2; subst hs2
              exact find_updUser_ne s u a _ (fun _ => rfl)
                (fun e => by rw [e] at hsub; simp [subjectIs, Req.subject] at hsub)
            · cases hs2
          | publish dep =>
            rw [hq] at hs2
            simp only [applyReq] at hs2
            split at hs2
            · simp only [ok_eq_ok] at hs2; subst hs2; rfl
            · cases hs2
    | reject p =>
      simp only [exec] at hx
      split at hx
      · split at hx <;> cases hx
      · simp only [ok_eq_ok] at hx; subst hx; exact Or.inl rfl
    | assign u dep =>
      simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
      obtain ⟨_, _, rfl⟩ := hx
      exact mine u (fun x => { x with deps := dep :: x.deps }) (fun _ => rfl) (fun _ => Or.inl rfl) rfl
    | unassign u dep =>
      simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
      obtain ⟨_, rfl⟩ := hx
      exact mine u (fun x => { x with deps := x.deps.filter (· != dep) }) (fun _ => rfl)
        (fun _ => Or.inl rfl) rfl
    | dropRole u =>
      simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
      obtain ⟨_, rfl⟩ := hx
      exact mine u (fun x => { x with role := none }) (fun _ => rfl)
        (fun _ => Or.inr (by simp [entryRole])) rfl
    | setDeployment dep cs gw =>
      simp only [exec, Guards.spec, Bool.true_and, ite_error_eq_ok] at hx
      obtain ⟨_, hx⟩ := hx
      split at hx <;> (simp only [ok_eq_ok] at hx; subst hx; exact Or.inl rfl)
    | enroll d o dep proof =>
      simp only [exec, Guards.spec, Bool.true_and, ite_error_eq_ok, ok_eq_ok] at hx
      obtain ⟨_, _, _, _, rfl⟩ := hx
      exact Or.inl rfl
    | approveDevice d =>
      simp only [exec, Guards.spec, Bool.true_and, ite_error_eq_ok, ok_eq_ok] at hx
      obtain ⟨_, _, _, _, rfl⟩ := hx
      exact Or.inl rfl
    | revokeDevice d =>
      simp only [exec, ite_error_eq_ok, ok_eq_ok] at hx
      obtain ⟨_, rfl⟩ := hx
      exact Or.inl rfl
    | offboard u =>
      simp only [exec, Guards.spec, ite_error_eq_ok, ok_eq_ok, ite_true, Bool.not_true,
        Bool.false_or] at hx
      obtain ⟨_, _, rfl⟩ := hx
      exact mine u (fun x => { x with status := .offboarded, role := none, deps := [] })
        (fun _ => rfl) (fun _ => Or.inr (by simp [entryRole])) rfl
    | pull _ => simp [exec] at hx
    | list => simp [exec] at hx
    | readAudit => simp [exec] at hx

/-- A principal acting alone, over any number of steps, never gains a role: its role stays what
    it was or is lost. Raising one takes a second person, an approver. -/
theorem single_actor_no_elevation (s : State M) (a : UserId) (es : List (Event M))
    (h : ∀ e ∈ es, e.actor = .user a) :
    roleOf (run s es) a = roleOf s a ∨ roleOf (run s es) a = none := by
  induction es generalizing s with
  | nil => exact Or.inl rfl
  | cons e es ih =>
    obtain ⟨ac, ev⟩ := e
    have hac : ac = .user a := h _ (List.mem_cons_self ..)
    subst hac
    have ih1 := ih (step s ⟨.user a, ev⟩).2 (fun e he => h e (List.mem_cons_of_mem _ he))
    have h1 := no_self_elevation_step s a ev
    show roleOf (run (step s ⟨.user a, ev⟩).2 es) a = roleOf s a ∨
      roleOf (run (step s ⟨.user a, ev⟩).2 es) a = none
    rcases ih1 with ih1 | ih1
    · rw [ih1]; exact h1
    · exact Or.inr ih1

end Onboarding
