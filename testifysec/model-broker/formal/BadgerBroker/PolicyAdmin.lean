import BadgerBroker.BrokerPolicy

/-!
# Changing the policy

The admin API (`admin.go`) runs on the admin listener only. Every write is a new immutable
version, guarded by optimistic concurrency (`If-Match`), validated, audited with author and diff,
and swapped in without a restart. Operator configuration is not part of the state an admin can
write.

## Assumptions (accepted, not proved)

* **P1 edge identity.** On the edge listener, the identity and role headers were set by the edge
  from a verified human sign-in after it stripped any copy the caller sent, and the edge never
  sets them on a request it forwarded as a pipeline. (`Edge.lean` in the deployment proves the
  second half for its edge.)
* **P2 store.** The version store and audit log are append-only as written (`store.go`); a person
  with write access to the volume can still alter them. The audit log is hash-chained so such an
  edit is detectable, not prevented.
-/

namespace BadgerBroker

/-- Who is calling, as the broker sees it. Any request carrying a pipeline payload is a
`pipeline`, whatever else it carries. -/
inductive Caller where
  | human (id : String) (role : String)
  | pipeline
  | anonymous
  deriving DecidableEq, Repr

def callerOf (payloadPresent : Bool) (id role : Option String) : Caller :=
  if payloadPresent then .pipeline
  else match id, role with
    | some i, some r => .human i r
    | _, _ => .anonymous

structure Version where
  n        : Nat
  entries  : List Entry
  author   : String
  approver : Option String
  created  : Nat
  deriving Repr

inductive AuditKind where
  | write | propose | approve | reject | refused
  deriving DecidableEq, Repr

structure AuditRec where
  kind    : AuditKind
  actor   : String
  version : Nat
  removed : List Entry
  added   : List Entry
  deriving Repr

structure Proposal where
  id      : Nat
  base    : Nat
  entries : List Entry
  author  : String
  isOpen  : Bool
  deriving Repr

structure State where
  operator     : OperatorCfg
  versions     : List Version
  proposals    : List Proposal
  audit        : List AuditRec
  nextProposal : Nat

def State.current (s : State) : Nat :=
  match s.versions with
  | []     => 0
  | v :: _ => v.n

def State.active (s : State) : List Entry :=
  match s.versions with
  | []     => []
  | v :: _ => v.entries

/-- The caller's id if their role is one the operator lists as admin. -/
def adminId (o : OperatorCfg) : Caller → Option String
  | .human id role => if o.adminRoles.contains role && id != "" then some id else none
  | _ => none

/-- With the two-person rule on, a change that adds an enabled named-branch entry (one that
admits an unprotected branch) the active policy does not already hold needs a second admin. -/
def needsSecond (o : OperatorCfg) (old new : List Entry) : Bool :=
  o.twoPerson && new.any (fun e => e.kind == .namedBranch && e.enabled && !old.contains e)

def commit (s : State) (entries : List Entry) (author : String) (approver : Option String)
    (now : Nat) : State :=
  let n := s.current + 1
  { s with
    versions := ⟨n, entries, author, approver, now⟩ :: s.versions
    audit := ⟨.write, author, n, s.active.filter (!entries.contains ·),
              entries.filter (!s.active.contains ·)⟩ :: s.audit }

def close (s : State) (pid : Nat) : State :=
  { s with proposals := s.proposals.map (fun p => if p.id == pid then { p with isOpen := false } else p) }

inductive AdminReq where
  | put (ifMatch : Nat) (entries : List Entry)
  | approve (proposal : Nat)
  | reject (proposal : Nat)
  deriving Repr

inductive Result where
  | created (version : Nat) | pending (proposal : Nat) | approved (version : Nat) | rejected
  | forbidden | stale | invalid | notFound | sameAuthor
  deriving DecidableEq, Repr

def handle (s : State) (caller : Caller) (now : Nat) (req : AdminReq) : State × Result :=
  match adminId s.operator caller with
  | none => ({ s with audit := ⟨.refused, "", s.current, [], []⟩ :: s.audit }, .forbidden)
  | some actor =>
    match req with
    | .put ifMatch entries =>
      if ifMatch != s.current then (s, .stale)
      else if ¬ wellFormed s.operator now entries then (s, .invalid)
      else if needsSecond s.operator s.active entries then
        let pid := s.nextProposal
        ({ s with proposals := ⟨pid, s.current, entries, actor, true⟩ :: s.proposals
                  nextProposal := pid + 1
                  audit := ⟨.propose, actor, s.current, s.active.filter (!entries.contains ·),
                            entries.filter (!s.active.contains ·)⟩ :: s.audit }, .pending pid)
      else (commit s entries actor none now, .created (s.current + 1))
    | .approve pid =>
      match s.proposals.find? (fun p => p.id == pid && p.isOpen) with
      | none => (s, .notFound)
      | some p =>
        if p.author == actor then (s, .sameAuthor)
        else if p.base != s.current then (s, .stale)
        else if ¬ wellFormed s.operator now p.entries then (s, .invalid)
        else (close (commit s p.entries p.author (some actor) now) pid, .approved (s.current + 1))
    | .reject pid =>
      match s.proposals.find? (fun p => p.id == pid && p.isOpen) with
      | none => (s, .notFound)
      | some _ => ({ close s pid with audit := ⟨.reject, actor, s.current, [], []⟩ :: s.audit },
                   .rejected)

/-! ## Properties -/

theorem commit_operator (s : State) (es : List Entry) (a : String) (ap : Option String) (now : Nat) :
    (commit s es a ap now).operator = s.operator := rfl

/-- No admin request, from anyone, changes operator configuration (issuer, audience, routed
models, sources, admin roles, the two-person flag, the TTL cap). -/
theorem operator_immutable (s : State) (c : Caller) (now : Nat) (r : AdminReq) :
    (handle s c now r).1.operator = s.operator := by
  unfold handle
  split
  · rfl
  · split
    · split
      · rfl
      · split
        · rfl
        · split <;> rfl
    · split
      · rfl
      · split
        · rfl
        · split
          · rfl
          · split <;> rfl
    · split <;> rfl

/-- The version list only ever grows by one version at the front: earlier versions are never
edited or removed. -/
theorem versions_append_only (s : State) (c : Caller) (now : Nat) (r : AdminReq) :
    (handle s c now r).1.versions = s.versions ∨
      ∃ v, (handle s c now r).1.versions = v :: s.versions := by
  unfold handle
  split
  · exact Or.inl rfl
  · split
    · split
      · exact Or.inl rfl
      · split
        · exact Or.inl rfl
        · split
          · exact Or.inl rfl
          · exact Or.inr ⟨_, rfl⟩
    · split
      · exact Or.inl rfl
      · split
        · exact Or.inl rfl
        · split
          · exact Or.inl rfl
          · split
            · exact Or.inl rfl
            · exact Or.inr ⟨_, rfl⟩
    · split
      · exact Or.inl rfl
      · exact Or.inl rfl

/-- What every accepted change looks like: one new version numbered after the current one,
well-formed, authored and audited (write record with the author, the new number and the diff),
by a caller holding an admin role. Proposals and approvals carry the same guarantees. -/
theorem change_is_admin_versioned_audited (s : State) (c : Caller) (now : Nat) (r : AdminReq)
    (h : (handle s c now r).1.versions ≠ s.versions) :
    ∃ actor v, adminId s.operator c = some actor ∧
      (handle s c now r).1.versions = v :: s.versions ∧ v.n = s.current + 1 ∧
      wellFormed s.operator now v.entries ∧
      (v.author = actor ∨ v.approver = some actor) ∧
      ∃ rest, (handle s c now r).1.audit = ⟨.write, v.author, v.n,
        s.active.filter (!v.entries.contains ·), v.entries.filter (!s.active.contains ·)⟩ :: rest := by
  cases ha : adminId s.operator c with
  | none => simp [handle, ha] at h
  | some actor =>
    cases r with
    | put ifm es =>
      by_cases h1 : (ifm != s.current) = true
      · simp [handle, ha, h1] at h
      by_cases h2 : wellFormed s.operator now es
      · by_cases h3 : needsSecond s.operator s.active es = true
        · simp [handle, ha, h1, h2, h3] at h
        · simp only [handle, ha, h1, h2, h3, ite_false, not_true_eq_false, Bool.false_eq_true]
          exact ⟨actor, _, rfl, rfl, rfl, h2, Or.inl rfl, _, rfl⟩
      · simp [handle, ha, h1, h2] at h
    | approve pid =>
      cases hp : s.proposals.find? (fun p => p.id == pid && p.isOpen) with
      | none => simp [handle, ha, hp] at h
      | some p =>
        by_cases h1 : (p.author == actor) = true
        · simp [handle, ha, hp, h1] at h
        by_cases h2 : (p.base != s.current) = true
        · simp [handle, ha, hp, h1, h2] at h
        by_cases h3 : wellFormed s.operator now p.entries
        · simp only [handle, ha, hp, h1, h2, h3, ite_false, not_true_eq_false, Bool.false_eq_true]
          exact ⟨actor, _, rfl, rfl, rfl, h3, Or.inr rfl, _, rfl⟩
        · simp [handle, ha, hp, h1, h2, h3] at h
    | reject pid =>
      cases hp : s.proposals.find? (fun p => p.id == pid && p.isOpen) with
      | none => simp [handle, ha, hp] at h
      | some p => simp [handle, ha, hp, close] at h

/-- Only a caller with an admin role changes the policy. -/
theorem only_admin_changes_policy (s : State) (c : Caller) (now : Nat) (r : AdminReq)
    (h : (handle s c now r).1.versions ≠ s.versions) :
    ∃ id role, c = .human id role ∧ role ∈ s.operator.adminRoles := by
  obtain ⟨actor, -, ha, -⟩ := change_is_admin_versioned_audited s c now r h
  cases c with
  | human id role =>
    refine ⟨id, role, rfl, ?_⟩
    simp only [adminId] at ha
    split at ha
    · rename_i hc
      simp only [Bool.and_eq_true, List.contains_iff_mem] at hc
      exact hc.1
    · contradiction
  | pipeline => simp [adminId] at ha
  | anonymous => simp [adminId] at ha

/-- A pipeline can never change the policy, open or approve a proposal; it is refused and the
refusal is audited. -/
theorem pipeline_cannot_administer (s : State) (now : Nat) (r : AdminReq) :
    (handle s .pipeline now r).2 = .forbidden ∧
      (handle s .pipeline now r).1.versions = s.versions ∧
      (handle s .pipeline now r).1.proposals = s.proposals := by
  simp [handle, adminId]

/-- A request carrying a pipeline payload is a pipeline caller whatever identity or role headers
ride along. -/
theorem payload_makes_pipeline (id role : Option String) : callerOf true id role = .pipeline := rfl

/-- A write against a version that is no longer current changes nothing. -/
theorem stale_put_refused (s : State) (c : Caller) (now : Nat) (n : Nat) (es : List Entry)
    (hn : n ≠ s.current) :
    (handle s c now (.put n es)).1.versions = s.versions ∧
      (handle s c now (.put n es)).1.proposals = s.proposals := by
  unfold handle
  split
  · exact ⟨rfl, rfl⟩
  · simp only
    have : (n != s.current) = true := by simpa using hn
    simp [this]

/-- The two-person rule. With it on, every committed version that adds an enabled named-branch
entry was approved by a second admin, distinct from its author. -/
theorem two_person_rule (s : State) (c : Caller) (now : Nat) (r : AdminReq) (v : Version)
    (hv : (handle s c now r).1.versions = v :: s.versions)
    (hn : needsSecond s.operator s.active v.entries = true) :
    ∃ a, adminId s.operator c = some a ∧ v.approver = some a ∧ a ≠ v.author := by
  unfold handle at hv
  split at hv
  · simp at hv
  · rename_i actor ha
    split at hv
    · split at hv
      · simp at hv
      · split at hv
        · simp at hv
        · split at hv
          · simp at hv
          · rename_i hns
            simp only [commit, List.cons.injEq] at hv
            obtain ⟨rfl, -⟩ := hv
            exact absurd hn (by simpa using hns)
    · split at hv
      · simp at hv
      · rename_i p hp
        split at hv
        · simp at hv
        · rename_i hauthor
          split at hv
          · simp at hv
          · split at hv
            · simp at hv
            · simp only [close, commit, List.cons.injEq] at hv
              obtain ⟨rfl, -⟩ := hv
              refine ⟨actor, ha, rfl, ?_⟩
              intro heq
              simp [heq] at hauthor
    · split at hv <;> simp [close] at hv

end BadgerBroker
