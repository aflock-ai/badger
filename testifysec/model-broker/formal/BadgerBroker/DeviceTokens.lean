import BadgerBroker.WorkspaceTokens

/-!
# Device tokens

A person signs in at the edge (with whatever identity provider the edge uses), approves a device
on a consent page the broker serves on its edge listener, and the broker hands that device a
one-time code. The device exchanges the code and its PKCE verifier for a broker token on the
internal listener. The token is a workspace token record marked `device`. Implemented in
`device.go` and `tokens.go`.

Which issuer owns a record is the record's `device` flag, not its name: a provisioned workspace
that happens to be named like a device keeps working, and can still be rotated and revoked.

## Assumptions (accepted, not proved)

* **W4 consenter.** On the edge listener the principal header of a consent request is the
  principal the edge verified for that request (Lean `Edge` assumption B1: the edge strips caller
  copies and is the only client of the edge listener). The broker takes the consenter from it and
  from nothing else.
* **W5 PKCE.** `challenge` is S256 of a verifier only the device that started the sign-in knows,
  and the device's loopback port is not reachable from other machines.

## Proved here

* The provisioner cannot issue over, replace or revoke a device record, and device sign-in cannot
  replace a provisioned record or another person's device record (`provisioner_keeps_device`,
  `device_keeps_provisioned`, `device_keeps_others`).
* A device token is served as the person who consented, never anyone else (`device_served_as_consenter`).
* Logout revokes exactly the presented token (`logout_denies`, `logout_keeps_others`).
* A code is redeemed at most once, and only with its own verifier hash and port, before it
  expires (`code_single_use`, `redeem_binds`).

The Go registry also drops a person's oldest device records beyond a per-person cap; that only
ever removes device records of the same person, which the theorems above do not need.
-/

namespace BadgerBroker

/-- Some record for workspace `w` is a device record. -/
def holdsDevice (reg : List TokenRec) (w : String) : Bool := reg.any (fun r => r.workspace == w && r.device)

/-- The provisioning listener: provisioning, refused for a name a device record holds. -/
def provisionL (humans : List String) (ttl now : Nat) (auth : Bool) (reg : List TokenRec) :
    ProvReq → List TokenRec × Bool
  | .issue w p t => if holdsDevice reg w then (reg, false) else provision humans ttl now auth reg (.issue w p t)
  | .revoke w => if holdsDevice reg w then (reg, false) else provision humans ttl now auth reg (.revoke w)

/-- Device sign-in: issue a device record for name `w` to the consenter `c` (W4). Refused if a
record for `w` exists that is not this person's device record. -/
def deviceIssue (humans : List String) (ttl now : Nat) (c w t : String) (reg : List TokenRec) :
    List TokenRec × Bool :=
  if w != "" && humans.contains c && !ciForm c && reg.all (·.token != t) &&
      reg.all (fun r => r.workspace != w || (r.device && r.principal == c)) then
    ({ workspace := w, token := t, principal := c, exp := now + ttl, device := true } ::
      reg.filter (·.workspace != w), true)
  else (reg, false)

/-- Logout: revoke the record holding the presented token, and only it. -/
def revokeToken (reg : List TokenRec) (t : String) : List TokenRec := reg.filter (·.token != t)

theorem provision_issue_keeps (humans : List String) (ttl now : Nat) (auth : Bool)
    (reg : List TokenRec) (w p t : String) (r : TokenRec) (hr : r ∈ reg) (hw : r.workspace ≠ w) :
    r ∈ (provision humans ttl now auth reg (.issue w p t)).1 := by
  simp only [provision]
  split
  · exact List.mem_cons_of_mem _ (List.mem_filter.mpr ⟨hr, by simpa using hw⟩)
  · exact hr

theorem provision_revoke_keeps (humans : List String) (ttl now : Nat) (auth : Bool)
    (reg : List TokenRec) (w : String) (r : TokenRec) (hr : r ∈ reg) (hw : r.workspace ≠ w) :
    r ∈ (provision humans ttl now auth reg (.revoke w)).1 := by
  simp only [provision]
  split
  · exact List.mem_filter.mpr ⟨hr, by simpa using hw⟩
  · exact hr

theorem holdsDevice_of_mem (reg : List TokenRec) (r : TokenRec) (hr : r ∈ reg) (hd : r.device = true) :
    holdsDevice reg r.workspace = true :=
  List.any_eq_true.mpr ⟨r, hr, by simp [hd]⟩

/-- **The provisioner cannot touch a device record.** -/
theorem provisioner_keeps_device (humans : List String) (ttl now : Nat) (auth : Bool)
    (reg : List TokenRec) (q : ProvReq) (r : TokenRec) (hr : r ∈ reg) (hd : r.device = true) :
    r ∈ (provisionL humans ttl now auth reg q).1 := by
  have hh := holdsDevice_of_mem reg r hr hd
  cases q with
  | issue w p t =>
    simp only [provisionL]
    split
    · exact hr
    · rename_i hw
      exact provision_issue_keeps humans ttl now auth reg w p t r hr (fun h => hw (h ▸ hh))
  | revoke w =>
    simp only [provisionL]
    split
    · exact hr
    · rename_i hw
      exact provision_revoke_keeps humans ttl now auth reg w r hr (fun h => hw (h ▸ hh))

/-- Device sign-in keeps every record that is not this person's device record. -/
theorem device_keeps (humans : List String) (ttl now : Nat) (c w t : String) (reg : List TokenRec)
    (r : TokenRec) (hr : r ∈ reg) (hother : ¬ (r.device = true ∧ r.principal = c)) :
    r ∈ (deviceIssue humans ttl now c w t reg).1 := by
  simp only [deviceIssue]
  split
  · rename_i hcond
    simp only [Bool.and_eq_true, List.all_eq_true] at hcond
    have h := hcond.2 r hr
    refine List.mem_cons_of_mem _ (List.mem_filter.mpr ⟨hr, ?_⟩)
    simp only [Bool.or_eq_true, bne_iff_ne, ne_eq, Bool.and_eq_true, beq_iff_eq] at h
    rcases h with hw | hmine
    · simpa using hw
    · exact absurd hmine hother
  · exact hr

/-- **Device sign-in cannot touch a provisioned record.** -/
theorem device_keeps_provisioned (humans : List String) (ttl now : Nat) (c w t : String)
    (reg : List TokenRec) (r : TokenRec) (hr : r ∈ reg) (hd : r.device = false) :
    r ∈ (deviceIssue humans ttl now c w t reg).1 :=
  device_keeps humans ttl now c w t reg r hr (fun h => by simp [hd] at h)

/-- **Nor another person's device record.** -/
theorem device_keeps_others (humans : List String) (ttl now : Nat) (c w t : String)
    (reg : List TokenRec) (r : TokenRec) (hr : r ∈ reg) (hp : r.principal ≠ c) :
    r ∈ (deviceIssue humans ttl now c w t reg).1 :=
  device_keeps humans ttl now c w t reg r hr (fun h => hp h.2)

theorem provisionL_inv (humans : List String) (ttl now : Nat) (auth : Bool) (reg : List TokenRec)
    (q : ProvReq) (h : Inv reg) : Inv (provisionL humans ttl now auth reg q).1 := by
  cases q with
  | issue w p t =>
    simp only [provisionL]; split
    · exact h
    · exact provision_inv humans ttl now auth reg _ h
  | revoke w =>
    simp only [provisionL]; split
    · exact h
    · exact provision_inv humans ttl now auth reg _ h

theorem deviceIssue_inv (humans : List String) (ttl now : Nat) (c w t : String)
    (reg : List TokenRec) (h : Inv reg) : Inv (deviceIssue humans ttl now c w t reg).1 := by
  obtain ⟨hw, ht, hc⟩ := h
  simp only [deviceIssue]
  split
  · rename_i hcond
    simp only [Bool.and_eq_true, bne_iff_ne, ne_eq, List.contains_iff_mem, Bool.not_eq_true',
      List.all_eq_true] at hcond
    obtain ⟨⟨⟨⟨-, -⟩, hci⟩, hfresh⟩, -⟩ := hcond
    refine ⟨?_, ?_, ?_⟩
    · simp only [List.map_cons, List.nodup_cons, List.mem_map, List.mem_filter, not_exists, not_and]
      exact ⟨fun r hr heq => by simp [heq] at hr, nodup_map_filter _ _ _ hw⟩
    · simp only [List.map_cons, List.nodup_cons, List.mem_map, List.mem_filter, not_exists, not_and]
      exact ⟨fun r hr heq => by have := hfresh r hr.1; simp [heq] at this, nodup_map_filter _ _ _ ht⟩
    · intro r hr
      simp only [List.mem_cons, List.mem_filter] at hr
      rcases hr with rfl | ⟨hr, -⟩
      · exact hci
      · exact hc r hr
  · exact ⟨hw, ht, hc⟩

/-- A successful device sign-in records the new token for the device name, owned by the consenter. -/
theorem deviceIssue_records (humans : List String) (ttl now : Nat) (c w t : String)
    (reg : List TokenRec) (hok : (deviceIssue humans ttl now c w t reg).2 = true) :
    ({ workspace := w, token := t, principal := c, exp := now + ttl, device := true } : TokenRec) ∈
      (deviceIssue humans ttl now c w t reg).1 := by
  simp only [deviceIssue] at hok ⊢
  split at hok
  · rename_i hcond
    rw [if_pos hcond]; exact List.mem_cons_self
  · simp at hok

/-- **A device token is served as the person who consented** (W4 makes that the edge-verified
principal), and as nobody else. -/
theorem device_served_as_consenter (o : OperatorCfg) (pol : Option (List Entry))
    (humans : List String) (ttl now now' : Nat) (c w t : String) (reg : List TokenRec)
    (hi : Inv reg) (hok : (deviceIssue humans ttl now c w t reg).2 = true) (r : BReq)
    (hl : r.listener = .internal) (ht : r.token = some t) (x : String) (m : Option String)
    (h : serve o pol humans (deviceIssue humans ttl now c w t reg).1 now' r = .served x m) :
    x = c :=
  workspace_served_as_owner o pol humans _ (deviceIssue_inv humans ttl now c w t reg hi) now'
    _ (deviceIssue_records humans ttl now c w t reg hok) r hl ht x m h

/-- **Logout denies the presented token.** -/
theorem logout_denies (reg : List TokenRec) (humans : List String) (now : Nat) (t : String) :
    authToken (revokeToken reg t) humans now (some t) = none := by
  apply auth_none_of_absent
  intro r hr heq
  simp only [revokeToken, List.mem_filter, bne_iff_ne, ne_eq] at hr
  exact hr.2 heq

/-- **Logout touches no other token.** -/
theorem logout_keeps_others (reg : List TokenRec) (t : String) (r : TokenRec) (hr : r ∈ reg)
    (hne : r.token ≠ t) : r ∈ revokeToken reg t :=
  List.mem_filter.mpr ⟨hr, by simpa using hne⟩

theorem revokeToken_inv (reg : List TokenRec) (t : String) (h : Inv reg) : Inv (revokeToken reg t) :=
  ⟨nodup_map_filter _ _ _ h.1, nodup_map_filter _ _ _ h.2.1,
    fun r hr => h.2.2 r (List.mem_filter.mp hr).1⟩

/-- An outstanding sign-in code: who consented, for which PKCE challenge, loopback port and
device, until when. -/
structure Code where
  code      : String
  principal : String
  challenge : String
  port      : Nat
  device    : String
  exp       : Nat
  deriving DecidableEq, Repr

/-- Redeem a code with the S256 of the presented verifier. The code is removed on every attempt,
successful or not. -/
def redeem (codes : List Code) (c v : String) (port now : Nat) : Option Code × List Code :=
  let rest := codes.filter (·.code != c)
  match codes.find? (·.code == c) with
  | some k => if k.challenge == v && k.port == port && decide (now < k.exp) then (some k, rest) else (none, rest)
  | none => (none, rest)

theorem redeem_removes (codes : List Code) (c v : String) (port now : Nat) :
    ∀ k ∈ (redeem codes c v port now).2, k.code ≠ c := by
  intro k hk
  have hk' : k ∈ codes.filter (·.code != c) := by
    simp only [redeem] at hk; split at hk
    · split at hk <;> exact hk
    · exact hk
  simpa using (List.mem_filter.mp hk').2

theorem redeem_absent (codes : List Code) (c v : String) (port now : Nat)
    (h : codes.find? (·.code == c) = none) : (redeem codes c v port now).1 = none := by
  simp [redeem, h]

/-- **A code is redeemed at most once.** -/
theorem code_single_use (codes : List Code) (c v v' : String) (port port' now now' : Nat) :
    (redeem (redeem codes c v port now).2 c v' port' now').1 = none := by
  apply redeem_absent
  rw [List.find?_eq_none]
  intro k hk
  simpa using redeem_removes codes c v port now k hk

/-- **A redeemed code was issued, with this verifier hash and port, and had not expired.** -/
theorem redeem_binds (codes : List Code) (c v : String) (port now : Nat) (k : Code)
    (h : (redeem codes c v port now).1 = some k) :
    k ∈ codes ∧ k.code = c ∧ k.challenge = v ∧ k.port = port ∧ now < k.exp := by
  simp only [redeem] at h
  split at h
  · rename_i k' hf
    split at h
    · rename_i hc
      cases h
      simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hc
      exact ⟨List.mem_of_find?_eq_some hf, by simpa using List.find?_some hf, hc.1.1, hc.1.2, hc.2⟩
    · simp at h
  · simp at h

end BadgerBroker
