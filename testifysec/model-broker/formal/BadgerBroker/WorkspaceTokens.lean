import BadgerBroker.BrokerPolicyTheorems

/-!
# Workspace tokens

A workspace calls the broker's internal listener with its own broker token. A provisioner (the
component that creates workspaces for their owners) asks the broker, on a listener only the
provisioner can reach, to issue a token for (workspace, owner); the broker records it and returns
it once; the provisioner stores it in a secret mounted only into that workspace. Issuing again
for the same workspace replaces its token; revoking removes it. Implemented in `tokens.go`.

## Assumptions (accepted, not proved)

* **W1 custody.** A workspace holds only the token issued for it (its own secret, mounted into
  its pod alone), and the provisioner names the workspace's real owner.
* **W2 freshness.** Issued tokens are fresh random values (256 bits); the broker also refuses to
  issue a token equal to one it holds (`issue` checks).
* **W3 provisioner.** Only the provisioner can reach the provisioning listener and it presents
  the provisioning key (`authorized`).
-/

namespace BadgerBroker

inductive ProvReq where
  | issue (workspace principal token : String)
  | revoke (workspace : String)
  deriving Repr

/-- The provisioning API. `ttl` is the operator's token lifetime. -/
def provision (humans : List String) (ttl now : Nat) (authorized : Bool) (reg : List TokenRec) :
    ProvReq → List TokenRec × Bool
  | .issue w p t =>
    if authorized && w != "" && humans.contains p && !ciForm p && reg.all (·.token != t) then
      ({ workspace := w, token := t, principal := p, exp := now + ttl } :: reg.filter (·.workspace != w), true)
    else (reg, false)
  | .revoke w => if authorized then (reg.filter (·.workspace != w), true) else (reg, false)

/-- Registry invariant: one record per workspace, distinct tokens, no pipeline names. -/
def Inv (reg : List TokenRec) : Prop :=
  (reg.map (·.workspace)).Nodup ∧ (reg.map (·.token)).Nodup ∧ ∀ r ∈ reg, ciForm r.principal = false

theorem inv_nil : Inv [] := by simp [Inv]

theorem nodup_map_filter {α β : Type} (f : α → β) (p : α → Bool) (l : List α)
    (h : (l.map f).Nodup) : ((l.filter p).map f).Nodup := by
  induction l with
  | nil => simp
  | cons x xs ih =>
    simp only [List.map_cons, List.nodup_cons, List.mem_map] at h
    obtain ⟨hx, hxs⟩ := h
    simp only [List.filter_cons]
    split
    · simp only [List.map_cons, List.nodup_cons, List.mem_map, List.mem_filter, not_exists, not_and]
      refine ⟨fun a ha hfa => hx ⟨a, ha.1, hfa⟩, ih hxs⟩
    · exact ih hxs

/-- Provisioning keeps the invariant. -/
theorem provision_inv (humans : List String) (ttl now : Nat) (auth : Bool) (reg : List TokenRec)
    (q : ProvReq) (h : Inv reg) : Inv (provision humans ttl now auth reg q).1 := by
  obtain ⟨hw, ht, hc⟩ := h
  cases q with
  | issue w p t =>
    simp only [provision]
    split
    · rename_i hcond
      simp only [Bool.and_eq_true, bne_iff_ne, ne_eq, List.contains_iff_mem, Bool.not_eq_true',
        List.all_eq_true] at hcond
      obtain ⟨⟨⟨⟨-, -⟩, -⟩, hci⟩, hfresh⟩ := hcond
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
  | revoke w =>
    simp only [provision]
    split
    · exact ⟨nodup_map_filter _ _ _ hw, nodup_map_filter _ _ _ ht,
        fun r hr => hc r (List.mem_filter.mp hr).1⟩
    · exact ⟨hw, ht, hc⟩

theorem find_token_unique (reg : List TokenRec) (h : (reg.map (·.token)).Nodup) (r : TokenRec)
    (hr : r ∈ reg) : reg.find? (·.token == r.token) = some r := by
  induction reg with
  | nil => simp at hr
  | cons x xs ih =>
    simp only [List.map_cons, List.nodup_cons, List.mem_map, not_exists, not_and] at h
    simp only [List.find?_cons]
    rcases List.mem_cons.mp hr with rfl | hr'
    · simp
    · have hne : (x.token == r.token) = false := by
        simp only [beq_eq_false_iff_ne, ne_eq]
        intro heq; exact h.1 r hr' heq.symm
      rw [hne]; exact ih h.2 hr'

/-- **A workspace is only ever served as its owner.** In a registry built by provisioning, the
token recorded for workspace `w` (the one W1 says only `w` holds) is served, if at all, as the
principal recorded for `w`, never as anyone else. -/
theorem workspace_served_as_owner (o : OperatorCfg) (pol : Option (List Entry))
    (humans : List String) (reg : List TokenRec) (hi : Inv reg) (now : Nat) (rec : TokenRec)
    (hr : rec ∈ reg) (r : BReq) (hl : r.listener = .internal) (ht : r.token = some rec.token)
    (x : String) (m : Option String) (h : serve o pol humans reg now r = .served x m) :
    x = rec.principal := by
  obtain ⟨-, -, -, t, rec', ht', hf, hpr⟩ := internal_never_pipeline o pol humans reg now r hl x m h
  rw [ht] at ht'
  cases ht'
  rw [find_token_unique reg hi.2.1 rec hr] at hf
  cases hf
  exact hpr.symm

/-- **No workspace can obtain a `ci:` principal**, by any token, header or payload. -/
theorem workspace_never_ci (o : OperatorCfg) (pol : Option (List Entry)) (humans : List String)
    (reg : List TokenRec) (now : Nat) (r : BReq) (hl : r.listener = .internal) (x : String)
    (m : Option String) (h : serve o pol humans reg now r = .served x m) : ciForm x = false :=
  (internal_never_pipeline o pol humans reg now r hl x m h).2.1

/-- And the provisioner cannot even register one. -/
theorem issue_refuses_ci (humans : List String) (ttl now : Nat) (auth : Bool) (reg : List TokenRec)
    (w p t : String) (hp : ciForm p = true) :
    provision humans ttl now auth reg (.issue w p t) = (reg, false) := by
  simp [provision, hp]

theorem auth_none_of_absent (reg : List TokenRec) (humans : List String) (now : Nat) (t : String)
    (h : ∀ r ∈ reg, r.token ≠ t) : authToken reg humans now (some t) = none := by
  have : reg.find? (·.token == t) = none := by
    rw [List.find?_eq_none]; intro r hr; simpa using h r hr
  simp [authToken, this]

/-- **Rotation denies the old token.** After a new token is issued for workspace `w`, the token
`w` held before is refused. -/
theorem rotate_denies_old (humans : List String) (ttl now now' : Nat) (reg : List TokenRec)
    (hi : Inv reg) (old : TokenRec) (hold : old ∈ reg) (p t : String)
    (hok : (provision humans ttl now true reg (.issue old.workspace p t)).2 = true) :
    authToken (provision humans ttl now true reg (.issue old.workspace p t)).1 humans now'
      (some old.token) = none := by
  simp only [provision] at hok ⊢
  split at hok
  · rename_i hcond
    rw [if_pos hcond]
    simp only [Bool.and_eq_true, List.all_eq_true, bne_iff_ne, ne_eq] at hcond
    have hfresh := hcond.2 old hold
    apply auth_none_of_absent
    intro r hr
    simp only [List.mem_cons, List.mem_filter, bne_iff_ne, ne_eq] at hr
    rcases hr with rfl | ⟨hr, hw⟩
    · exact fun h => hfresh h.symm
    · intro heq
      have := eq_of_mem_nodup_map (·.token) reg hi.2.1 r hr old hold heq
      exact hw (this ▸ rfl)
  · simp at hok

/-- **Revocation denies the token.** -/
theorem revoke_denies (humans : List String) (ttl now now' : Nat) (reg : List TokenRec)
    (hi : Inv reg) (old : TokenRec) (hold : old ∈ reg) :
    authToken (provision humans ttl now true reg (.revoke old.workspace)).1 humans now'
      (some old.token) = none := by
  simp only [provision, ite_true]
  apply auth_none_of_absent
  intro r hr heq
  simp only [List.mem_filter, bne_iff_ne, ne_eq] at hr
  have := eq_of_mem_nodup_map (·.token) reg hi.2.1 r hr.1 old hold heq
  exact hr.2 (this ▸ rfl)

/-- An expired token is refused. -/
theorem expired_token_refused (reg : List TokenRec) (humans : List String) (now : Nat)
    (r : TokenRec) (hr : reg.find? (·.token == r.token) = some r) (hx : r.exp ≤ now) :
    authToken reg humans now (some r.token) = none := by
  simp [authToken, hr, Nat.not_lt.mpr hx]

/-- Without the provisioning key nothing changes. -/
theorem unauthorized_provision_noop (humans : List String) (ttl now : Nat) (reg : List TokenRec)
    (q : ProvReq) : provision humans ttl now false reg q = (reg, false) := by
  cases q <;> simp [provision]

end BadgerBroker
