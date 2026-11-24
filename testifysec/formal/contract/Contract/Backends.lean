/-
  Contract.Backends: the management backend as a parameter.

  Badger runs with one of two management backends: the lightweight portal (open source, one
  service in the customer's enclave) or a platform (the same open management API plus extras).
  Both implement the same contract: issue a profile, issue an activation record per deployment,
  enroll and revoke devices, and issue a high-water reset for one device. They differ only in
    * the trust root their signing leaves chain to (the enclave CA, or the platform's CA);
    * the kind of device identity (an enclave PKI certificate, or a hardware-bound key);
    * optional extras (central evidence, Pushgate) the workstation never reads.

  The workstation side follows the portal design (testifysec/PORTAL.md, decided there):
    * admission verifies a certificate chain to a pinned root, not a pinned key, and requires the
      artifact's whole signed window to lie inside the signing leaf's validity;
    * a signed activation record per deployment moves the pinned profile digest;
    * the device keeps a persisted activation and profile high-water, and only a backend-signed
      reset record bound to this device's key lowers it.

  `step` is the workstation. Its arguments are a `Trust` (the pinned roots and this device's
  tenant, deployment, profile and key), its own state, the clock and a signed artifact. It never
  sees a `Backend`: whatever a backend is, the workstation knows it only through the root it
  pins and the artifacts it signs. The theorems below make that precise.

  Proved
    `step_chained`, `step_assigned`, `step_window`, `step_inside_leaf`   what an accepted
        artifact must be, for any trust
    `activation_raises`, `hw_lowered_only_by_reset`, `refusal_keeps_state` the high-water rules
    `workstation_parametric`   the workstation's trust is a function of the root alone
    `conforming_backend_admitted`   any conforming backend's activation is admitted
    `switch_refuses_old`, `switch_admits_new`, `mixed_trust_admits_both`, `chain_iff_pinned`
    `migration_restart_refused`, `migration_carried_admitted`
    `extras_not_load_bearing`, `identity_not_load_bearing`
    `revoked_gets_nothing`
  Mutants
    `trust_any_root`         a workstation that accepts any root (kills `switch_refuses_old`)
    `restart_rolls_back`     a migration that resets the device's high-water (kills
                             `migration_restart_refused`: the pin moves back silently)
    `serves_revoked`         a backend that skips revocation (kills `revoked_gets_nothing`)
-/
import Contract.Proofs
import Contract.Portal

namespace Contract.Backends

open Contract

/-! ## Backends -/

inductive IdentityKind where
  | enclavePki   -- a device certificate from the customer's own CA
  | hardwareKey  -- a TPM or Secure Enclave key enrolled through cilock
  deriving DecidableEq, Repr

structure Extras where
  centralEvidence : Bool
  pushgate        : Bool
  deriving DecidableEq, Repr

/-- A signing leaf certificate. `root` is the CA it chains to (intermediates abstracted);
    `identityOk` is the signer identity constraint (subject or SAN, extended key usage). -/
structure Leaf where
  key        : Nat
  root       : Nat
  identityOk : Bool
  notBefore  : Int
  notAfter   : Int
  deriving DecidableEq, Repr

inductive Body where
  /-- "Deployment `dep` runs profile digest `digest` at profile sequence `pseq`; this is
      activation `seq` of that deployment." -/
  | activation (tenant dep profile digest pseq seq : Nat)
  /-- "Device `device` may lower its high-waters to these floors; this is reset `rseq`." -/
  | reset (tenant dep device rseq pfloor afloor : Nat)
  deriving DecidableEq, Repr

structure Signed where
  body      : Body
  notBefore : Int
  expires   : Int
  leaf      : Leaf
  /-- the signature over the body verifies under the leaf's key (crypto abstracted) -/
  sigValid  : Bool
  deriving DecidableEq, Repr

structure Backend where
  root     : Nat
  identity : IdentityKind
  extras   : Extras
  /-- the leaf it currently signs with -/
  leaf     : Leaf
  /-- the activation sequence floor it starts from -/
  floor    : Nat
  enrolled : List Nat
  revoked  : List Nat
  deriving DecidableEq, Repr

/-- A backend keeps the contract's signing rule: its leaf chains to its own root and carries the
    signer identity admission requires. -/
def Conforms (b : Backend) : Prop := b.leaf.root = b.root ∧ b.leaf.identityOk = true

def Backend.activation (b : Backend) (tenant dep profile digest pseq : Nat) (last : Option Nat)
    (nb exp : Int) : Signed :=
  { body := .activation tenant dep profile digest pseq (Portal.nextSeq b.floor last),
    notBefore := nb, expires := exp, leaf := b.leaf, sigValid := true }

def Backend.reset (b : Backend) (tenant dep device rseq pfloor afloor : Nat) (nb exp : Int) : Signed :=
  { body := .reset tenant dep device rseq pfloor afloor, notBefore := nb, expires := exp,
    leaf := b.leaf, sigValid := true }

/-- The pull endpoint: an enrolled, unrevoked device gets the artifact; anyone else nothing. -/
def Backend.serve (b : Backend) (device : Nat) (x : Signed) : Option Signed :=
  if device ∈ b.enrolled ∧ device ∉ b.revoked then some x else none

/-! ## The workstation -/

structure Trust where
  roots  : List Nat
  tenant : Nat
  dep    : Nat
  profile : Nat
  device : Nat
  deriving DecidableEq, Repr

/-- What a workstation pinned for a backend: its root, nothing else about it. -/
def trustOf (b : Backend) (tenant dep profile device : Nat) : Trust :=
  { roots := [b.root], tenant, dep, profile, device }

structure DState where
  profileHw    : Nat
  activationHw : Nat
  resetHw      : Nat
  pin          : Option Nat
  deriving DecidableEq, Repr

inductive Refuse where
  | chain       -- bad signature, unpinned root, wrong identity, or window outside the leaf
  | expired
  | assignment  -- another tenant, deployment, profile or device
  | rollback    -- not above the high-water
  deriving DecidableEq, Repr

/-- The chain rule: valid signature, a pinned root, the identity constraint, and the whole
    signed window inside the leaf's validity. -/
def ChainOk (t : Trust) (x : Signed) : Prop :=
  x.sigValid = true ∧ x.leaf.root ∈ t.roots ∧ x.leaf.identityOk = true ∧
  x.leaf.notBefore ≤ x.notBefore ∧ x.expires ≤ x.leaf.notAfter

instance (t : Trust) (x : Signed) : Decidable (ChainOk t x) := by unfold ChainOk; infer_instance

def step (t : Trust) (s : DState) (now : Int) (x : Signed) : Except Refuse DState :=
  if ¬ ChainOk t x then .error .chain
  else if ¬ (x.notBefore ≤ now ∧ now < x.expires) then .error .expired
  else match x.body with
    | .activation tn dp pf dg ps sq =>
      if ¬ (tn = t.tenant ∧ dp = t.dep ∧ pf = t.profile) then .error .assignment
      else if ¬ (s.activationHw < sq ∧ s.profileHw ≤ ps) then .error .rollback
      else .ok { s with activationHw := sq, profileHw := ps, pin := some dg }
    | .reset tn dp dv rs pfl afl =>
      if ¬ (tn = t.tenant ∧ dp = t.dep ∧ dv = t.device) then .error .assignment
      else if ¬ s.resetHw < rs then .error .rollback
      else .ok { s with resetHw := rs, profileHw := pfl, activationHw := afl }

/-- The outcome only: `none` admitted. -/
def outcome : Except Refuse DState → Option Refuse
  | .ok _ => none
  | .error r => some r

/-- A refused artifact leaves the state as it was. -/
def apply (t : Trust) (s : DState) (now : Int) (x : Signed) : DState :=
  match step t s now x with
  | .ok s' => s'
  | .error _ => s

/-! ## What an accepted artifact is, for any trust -/

theorem step_ok_parts {t : Trust} {s s' : DState} {now : Int} {x : Signed}
    (h : step t s now x = .ok s') : ChainOk t x ∧ x.notBefore ≤ now ∧ now < x.expires := by
  unfold step at h
  by_cases c : ChainOk t x
  · by_cases w : x.notBefore ≤ now ∧ now < x.expires
    · exact ⟨c, w⟩
    · rw [ite_eq_right (Classical.not_not.2 c), ite_eq_left w] at h; cases h
  · rw [ite_eq_left c] at h; cases h

/-- Accepted means signed by a leaf that chains to a pinned root, with the identity constraint. -/
theorem step_chained {t : Trust} {s s' : DState} {now : Int} {x : Signed}
    (h : step t s now x = .ok s') :
    x.sigValid = true ∧ x.leaf.root ∈ t.roots ∧ x.leaf.identityOk = true :=
  let c := (step_ok_parts h).1; ⟨c.1, c.2.1, c.2.2.1⟩

/-- And its signed window lies inside the leaf: a stolen leaf key's signatures die with the leaf. -/
theorem step_inside_leaf {t : Trust} {s s' : DState} {now : Int} {x : Signed}
    (h : step t s now x = .ok s') : x.leaf.notBefore ≤ x.notBefore ∧ x.expires ≤ x.leaf.notAfter :=
  let c := (step_ok_parts h).1; ⟨c.2.2.2.1, c.2.2.2.2⟩

theorem step_window {t : Trust} {s s' : DState} {now : Int} {x : Signed}
    (h : step t s now x = .ok s') : x.notBefore ≤ now ∧ now < x.expires :=
  (step_ok_parts h).2

theorem step_body {t : Trust} {s s' : DState} {now : Int} {x : Signed}
    (h : step t s now x = .ok s') :
    (∃ tn dp pf dg ps sq, x.body = .activation tn dp pf dg ps sq ∧ tn = t.tenant ∧ dp = t.dep ∧
        pf = t.profile ∧ s.activationHw < sq ∧ s.profileHw ≤ ps ∧
        s' = { s with activationHw := sq, profileHw := ps, pin := some dg }) ∨
    (∃ tn dp dv rs pfl afl, x.body = .reset tn dp dv rs pfl afl ∧ tn = t.tenant ∧ dp = t.dep ∧
        dv = t.device ∧ s.resetHw < rs ∧
        s' = { s with resetHw := rs, profileHw := pfl, activationHw := afl }) := by
  obtain ⟨c, w⟩ := step_ok_parts h
  unfold step at h
  rw [ite_eq_right (Classical.not_not.2 c), ite_eq_right (Classical.not_not.2 w)] at h
  cases hb : x.body with
  | activation tn dp pf dg ps sq =>
    rw [hb] at h
    dsimp only at h
    by_cases a : tn = t.tenant ∧ dp = t.dep ∧ pf = t.profile
    · by_cases r : s.activationHw < sq ∧ s.profileHw ≤ ps
      · rw [ite_eq_right (Classical.not_not.2 a), ite_eq_right (Classical.not_not.2 r)] at h
        cases h
        exact Or.inl ⟨tn, dp, pf, dg, ps, sq, rfl, a.1, a.2.1, a.2.2, r.1, r.2, rfl⟩
      · rw [ite_eq_right (Classical.not_not.2 a), ite_eq_left r] at h; cases h
    · rw [ite_eq_left a] at h; cases h
  | reset tn dp dv rs pfl afl =>
    rw [hb] at h
    dsimp only at h
    by_cases a : tn = t.tenant ∧ dp = t.dep ∧ dv = t.device
    · by_cases r : s.resetHw < rs
      · rw [ite_eq_right (Classical.not_not.2 a), ite_eq_right (Classical.not_not.2 r)] at h
        cases h
        exact Or.inr ⟨tn, dp, dv, rs, pfl, afl, rfl, a.1, a.2.1, a.2.2, r, rfl⟩
      · rw [ite_eq_right (Classical.not_not.2 a), ite_eq_left r] at h; cases h
    · rw [ite_eq_left a] at h; cases h

/-- An accepted artifact is for this tenant and deployment, and for this profile (activation)
    or this device (reset). A profile for one tenant never activates for another. -/
theorem step_assigned {t : Trust} {s s' : DState} {now : Int} {x : Signed}
    (h : step t s now x = .ok s') :
    (∃ dg ps sq, x.body = .activation t.tenant t.dep t.profile dg ps sq) ∨
    (∃ rs pfl afl, x.body = .reset t.tenant t.dep t.device rs pfl afl) := by
  rcases step_body h with ⟨_, _, _, dg, ps, sq, hb, rfl, rfl, rfl, _⟩ |
    ⟨_, _, _, rs, pfl, afl, hb, rfl, rfl, rfl, _⟩
  · exact Or.inl ⟨dg, ps, sq, hb⟩
  · exact Or.inr ⟨rs, pfl, afl, hb⟩

/-- An activation strictly raises the activation high-water and never lowers the profile one. -/
theorem activation_raises {t : Trust} {s s' : DState} {now : Int} {x : Signed}
    {tn dp pf dg ps sq : Nat} (hb : x.body = .activation tn dp pf dg ps sq)
    (h : step t s now x = .ok s') :
    s.activationHw < s'.activationHw ∧ s.profileHw ≤ s'.profileHw ∧ s'.pin = some dg := by
  rcases step_body h with ⟨_, _, _, dg', ps', sq', hb', _, _, _, r1, r2, rfl⟩ | ⟨_, _, _, _, _, _, hb', _⟩
  · rw [hb] at hb'; cases hb'; exact ⟨r1, r2, rfl⟩
  · rw [hb] at hb'; cases hb'

/-- Only a reset record, signed under this trust for this very device, lowers a high-water. -/
theorem hw_lowered_only_by_reset {t : Trust} {s s' : DState} {now : Int} {x : Signed}
    (h : step t s now x = .ok s')
    (low : s'.activationHw < s.activationHw ∨ s'.profileHw < s.profileHw) :
    ChainOk t x ∧ ∃ rs pfl afl, x.body = .reset t.tenant t.dep t.device rs pfl afl := by
  refine ⟨(step_ok_parts h).1, ?_⟩
  rcases step_body h with ⟨_, _, _, _, ps, sq, _, _, _, _, r1, r2, rfl⟩ |
    ⟨_, _, _, rs, pfl, afl, hb, rfl, rfl, rfl, _⟩
  · rcases low with l | l
    · exact absurd (Nat.lt_trans l r1) (Nat.lt_irrefl _)
    · exact absurd (Nat.lt_of_lt_of_le l r2) (Nat.lt_irrefl _)
  · exact ⟨rs, pfl, afl, hb⟩

theorem refusal_keeps_state {t : Trust} {s : DState} {now : Int} {x : Signed} {r : Refuse}
    (h : step t s now x = .error r) : apply t s now x = s := by
  unfold apply; rw [h]

/-! ## 1. Parametricity: the workstation sees a backend only through its root -/

/-- Two backends with the same root give the workstation the same trust, so every decision it
    makes (`step`, and through the pinned digest every profile admission) is the same. Every
    workstation theorem is stated for an arbitrary trust or assignment (`step_*` here; `admit_*`,
    `admitted_monotone`, `no_write_down`, `result_is_connector` in Proofs), so each holds for
    every backend. The flow and banner checks take no backend or trust argument at all. -/
theorem workstation_parametric (b1 b2 : Backend) (h : b1.root = b2.root) (tn dp pf dv : Nat) :
    trustOf b1 tn dp pf dv = trustOf b2 tn dp pf dv ∧
    ∀ s now x, step (trustOf b1 tn dp pf dv) s now x = step (trustOf b2 tn dp pf dv) s now x := by
  have e : trustOf b1 tn dp pf dv = trustOf b2 tn dp pf dv := by simp [trustOf, h]
  exact ⟨e, fun _ _ _ => by rw [e]⟩

/-- Any conforming backend's activation, inside its leaf and its window and above the device's
    high-water, is admitted by a workstation pinned to that backend's root. -/
theorem conforming_backend_admitted (b : Backend) (hc : Conforms b) {tn dp pf dv dg ps : Nat}
    {last : Option Nat} {nb exp now : Int} (s : DState)
    (hleaf : b.leaf.notBefore ≤ nb ∧ exp ≤ b.leaf.notAfter) (hw : nb ≤ now ∧ now < exp)
    (hseq : s.activationHw < Portal.nextSeq b.floor last) (hps : s.profileHw ≤ ps) :
    outcome (step (trustOf b tn dp pf dv) s now (b.activation tn dp pf dg ps last nb exp)) = none := by
  have c : ChainOk (trustOf b tn dp pf dv) (b.activation tn dp pf dg ps last nb exp) :=
    ⟨rfl, by simp [trustOf, Backend.activation, hc.1], hc.2, hleaf.1, hleaf.2⟩
  have hw' : (b.activation tn dp pf dg ps last nb exp).notBefore ≤ now ∧
      now < (b.activation tn dp pf dg ps last nb exp).expires := hw
  unfold step
  rw [ite_eq_right (Classical.not_not.2 c), ite_eq_right (Classical.not_not.2 hw')]
  simp [Backend.activation, trustOf, hseq, hps, outcome]

/-! ## 2. Substitutability: switching backends is replacing the root -/

theorem chain_iff_pinned (t : Trust) (x : Signed) :
    ChainOk t x ↔ x.leaf.root ∈ t.roots ∧
      (x.sigValid = true ∧ x.leaf.identityOk = true ∧ x.leaf.notBefore ≤ x.notBefore ∧
        x.expires ≤ x.leaf.notAfter) := by
  unfold ChainOk
  constructor
  · rintro ⟨a, b, c, d, e⟩; exact ⟨b, a, c, d, e⟩
  · rintro ⟨b, a, c, d, e⟩; exact ⟨a, b, c, d, e⟩

/-- After a switch to the new backend's root, anything chained to the old root is refused. -/
theorem switch_refuses_old {old new : Backend} (hne : old.root ≠ new.root) (ho : Conforms old)
    {tn dp pf dv : Nat} (s : DState) (now : Int) (x : Signed) (hx : x.leaf = old.leaf) :
    step (trustOf new tn dp pf dv) s now x = .error .chain := by
  have : ¬ ChainOk (trustOf new tn dp pf dv) x := by
    intro c
    have := c.2.1
    simp [trustOf, hx, ho.1] at this
    exact hne this
  unfold step; rw [ite_eq_left this]

/-- And the new backend's activations are admitted (the conforming case above, after a switch). -/
theorem switch_admits_new (new : Backend) (hn : Conforms new) {tn dp pf dv dg ps : Nat}
    {last : Option Nat} {nb exp now : Int} (s : DState)
    (hleaf : new.leaf.notBefore ≤ nb ∧ exp ≤ new.leaf.notAfter) (hw : nb ≤ now ∧ now < exp)
    (hseq : s.activationHw < Portal.nextSeq new.floor last) (hps : s.profileHw ≤ ps) :
    outcome (step (trustOf new tn dp pf dv) s now (new.activation tn dp pf dg ps last nb exp)) = none :=
  conforming_backend_admitted new hn s hleaf hw hseq hps

/-- Mixed trust happens only when both roots are pinned, and then both are admitted. -/
theorem mixed_trust_admits_both (t : Trust) (x : Signed) (r1 r2 : Nat) (h : t.roots = [r1, r2])
    (hx : x.leaf.root = r1 ∨ x.leaf.root = r2) (ok : x.sigValid = true ∧ x.leaf.identityOk = true ∧
      x.leaf.notBefore ≤ x.notBefore ∧ x.expires ≤ x.leaf.notAfter) : ChainOk t x :=
  (chain_iff_pinned t x).2 ⟨by rw [h]; rcases hx with e | e <;> simp [e], ok⟩

/-! ## 3. Migration continuity: the sequence floor must be carried across -/

/-- A new backend that restarts its sequences at or below the device's high-water is refused,
    and the device keeps its pin: no silent rollback. -/
theorem migration_restart_refused (t : Trust) (s : DState) (now : Int) (x : Signed)
    {dg ps sq : Nat} (hb : x.body = .activation t.tenant t.dep t.profile dg ps sq)
    (hlow : sq ≤ s.activationHw) :
    outcome (step t s now x) ≠ none ∧ apply t s now x = s := by
  have h : ∀ s', step t s now x ≠ .ok s' := by
    intro s' h
    have := (activation_raises hb h).1
    rcases step_body h with ⟨_, _, _, _, _, sq', hb', _, _, _, _, _, rfl⟩ | ⟨_, _, _, _, _, _, hb', _⟩
    · rw [hb] at hb'; cases hb'; exact absurd (Nat.lt_of_lt_of_le this hlow) (Nat.lt_irrefl _)
    · rw [hb] at hb'; cases hb'
  cases e : step t s now x with
  | ok s' => exact absurd e (h s')
  | error r => exact ⟨by simp [outcome], refusal_keeps_state e⟩

/-- The operational requirement: start the new backend's activation floor above every device's
    high-water. Then its first activation for the deployment is admitted. -/
theorem migration_carried_admitted (new : Backend) (hn : Conforms new) {tn dp pf dv dg ps : Nat}
    {nb exp now : Int} (s : DState) (hfloor : s.activationHw < new.floor)
    (hleaf : new.leaf.notBefore ≤ nb ∧ exp ≤ new.leaf.notAfter) (hw : nb ≤ now ∧ now < exp)
    (hps : s.profileHw ≤ ps) :
    outcome (step (trustOf new tn dp pf dv) s now (new.activation tn dp pf dg ps none nb exp)) = none :=
  conforming_backend_admitted new hn s hleaf hw hfloor hps

/-! ## 4. Extras and device identity are not load-bearing -/

/-- Adding or removing central evidence or Pushgate changes neither the trust a workstation
    pins nor any artifact the backend signs, so no workstation decision and no theorem changes. -/
theorem extras_not_load_bearing (b : Backend) (e : Extras) (tn dp pf dv dg ps : Nat)
    (last : Option Nat) (nb exp : Int) :
    trustOf { b with extras := e } tn dp pf dv = trustOf b tn dp pf dv ∧
    ({ b with extras := e } : Backend).activation tn dp pf dg ps last nb exp =
      b.activation tn dp pf dg ps last nb exp ∧
    Conforms { b with extras := e } = Conforms b := ⟨rfl, rfl, rfl⟩

/-- Likewise the device-identity kind: it decides how a device enrolls, not what it admits. -/
theorem identity_not_load_bearing (b : Backend) (k : IdentityKind) (tn dp pf dv : Nat) :
    trustOf { b with identity := k } tn dp pf dv = trustOf b tn dp pf dv ∧
    Conforms { b with identity := k } = Conforms b := ⟨rfl, rfl⟩

/-! ## Revocation -/

theorem revoked_gets_nothing (b : Backend) {device : Nat} (h : device ∈ b.revoked) (x : Signed) :
    b.serve device x = none := by
  unfold Backend.serve
  rw [ite_eq_right (fun c => c.2 h)]

/-! ## Two backends and mutants -/

def portal : Backend :=
  { root := 1, identity := .enclavePki, extras := { centralEvidence := false, pushgate := false },
    leaf := { key := 11, root := 1, identityOk := true, notBefore := -86400, notAfter := 518400 },
    floor := 1, enrolled := [7, 8], revoked := [8] }

def platform : Backend :=
  { root := 2, identity := .hardwareKey, extras := { centralEvidence := true, pushgate := true },
    leaf := { key := 22, root := 2, identityOk := true, notBefore := -86400, notAfter := 518400 },
    floor := 41, enrolled := [7, 8], revoked := [8] }

theorem portal_conforms : Conforms portal := ⟨rfl, rfl⟩
theorem platform_conforms : Conforms platform := ⟨rfl, rfl⟩

/-- A device of tenant 1, deployment 1, profile 1, key 7, that has admitted activation 40. -/
def dev40 : DState := { profileHw := 12, activationHw := 40, resetHw := 0, pin := some 100 }

def actFrom (b : Backend) (seq : Nat) : Signed :=
  { body := .activation 1 1 1 200 12 seq, notBefore := -3600, expires := 3600, leaf := b.leaf,
    sigValid := true }

/-- The workstation that accepts any root. -/
def stepAnyRoot (t : Trust) (s : DState) (now : Int) (x : Signed) : Except Refuse DState :=
  step { t with roots := [x.leaf.root] } s now x

theorem trust_any_root :
    outcome (stepAnyRoot (trustOf platform 1 1 1 7) dev40 0 (actFrom portal 41)) = none ∧
    outcome (step (trustOf platform 1 1 1 7) dev40 0 (actFrom portal 41)) = some .chain := by decide

/-- A migration that resets the device's high-water along with the root: the new backend's
    restarted sequence 1 is admitted and the pin moves to whatever it names, silently. -/
def migrateResetting (s : DState) : DState := { s with activationHw := 0, profileHw := 0 }

theorem restart_rolls_back :
    outcome (step (trustOf platform 1 1 1 7) (migrateResetting dev40) 0 (actFrom platform 1)) = none ∧
    outcome (step (trustOf platform 1 1 1 7) dev40 0 (actFrom platform 1)) = some .rollback := by decide

/-- A backend that skips revocation. -/
def serveIgnoringRevoked (b : Backend) (device : Nat) (x : Signed) : Option Signed :=
  if device ∈ b.enrolled then some x else none

theorem serves_revoked :
    serveIgnoringRevoked portal 8 (actFrom portal 41) ≠ none ∧ 8 ∈ portal.revoked := by decide

end Contract.Backends
