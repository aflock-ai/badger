import BadgerBroker.BrokerPolicy

/-!
# Properties of the broker policy

Proofs about `BrokerPolicy.lean` under its assumptions B1-B3. The Go test that checks each one
operationally cites the theorem name.
-/

namespace BadgerBroker

/-! ## Helpers -/

theorem evaluate_allow_cases {o : OperatorCfg} {pol : Option (List Entry)} {now : Nat}
    {pc : Option Claims} {op : Op} {model : Option String} {p : Principal} {id m : String}
    (h : evaluate o pol now pc op model = .allow p id m) :
    ∃ es c e, pol = some es ∧ pc = some c ∧ c.iss = o.issuer ∧ c.aud = .one o.audience ∧
      now < c.exp ∧ op = .chat ∧ es.find? (entryMatches o now c) = some e ∧
      model = some m ∧ e.models.contains m = true ∧ o.routedModels.contains m = true ∧
      p = e.principal ∧ id = e.id := by
  unfold evaluate at h
  split at h
  · contradiction
  · rename_i es
    split at h
    · contradiction
    · rename_i c
      split at h
      · contradiction
      · rename_i hiss
        split at h
        · contradiction
        · rename_i haud
          split at h
          · contradiction
          · rename_i hexp
            split at h
            · contradiction
            · rename_i hop
              split at h
              · contradiction
              · rename_i e hf
                split at h
                · contradiction
                · rename_i m'
                  split at h
                  · rename_i hm
                    simp only [Decision.allow.injEq] at h
                    obtain ⟨rfl, rfl, rfl⟩ := h
                    simp only [Bool.and_eq_true] at hm
                    simp only [bne_iff_ne, ne_eq, Decidable.not_not] at hiss haud hop
                    simp only [Bool.not_eq_true', decide_eq_false_iff_not, Decidable.not_not] at hexp
                    exact ⟨es, c, e, rfl, rfl, hiss, haud, hexp, hop, hf, rfl, hm.1, hm.2, rfl, rfl⟩
                  · contradiction

theorem entryMatches_spec {o : OperatorCfg} {now : Nat} {c : Claims} {e : Entry}
    (h : entryMatches o now c e = true) :
    e.enabled = true ∧ notExpired now e = true ∧ c.projectPath = e.projectPath ∧ c.ref = e.ref ∧
      c.refType = "branch" ∧ protectionOk e c = true ∧
      c.ciConfigRefUri = o.configRef e.projectPath e.ref ∧ c.pipelineSource ∈ e.sources ∧
      (e.triggerUsers = [] ∨ c.userLogin ∈ e.triggerUsers) ∧ mintedOk e c = true := by
  simp only [entryMatches, Bool.and_eq_true, beq_iff_eq, List.contains_iff_mem] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨hen, hne⟩, hpp⟩, href⟩, hrt⟩, hprot⟩, hcfg⟩, hsrc⟩, htr⟩, hmin⟩ := h
  refine ⟨hen, hne, hpp, href, hrt, hprot, hcfg, hsrc, ?_, hmin⟩
  simp only [triggerOk, Bool.or_eq_true, List.isEmpty_iff, List.contains_iff_mem] at htr
  exact htr

/-! ## 1. Soundness, for both kinds of entry -/

/-- An allowed pipeline request carried a verified payload with the configured issuer, a single
audience equal to the configured one, an unexpired `exp`, asked for a chat completion, and
matched an enabled, unexpired entry of the active policy on every claim the entry names. The
principal and entry id are that entry's. -/
theorem allow_sound (o : OperatorCfg) (pol : Option (List Entry)) (now : Nat)
    (pc : Option Claims) (op : Op) (model : Option String) (p : Principal) (id m : String)
    (h : evaluate o pol now pc op model = .allow p id m) :
    ∃ es c e, pol = some es ∧ pc = some c ∧ e ∈ es ∧
      c.iss = o.issuer ∧ c.aud = .one o.audience ∧ now < c.exp ∧ op = .chat ∧
      e.enabled = true ∧ notExpired now e = true ∧
      c.projectPath = e.projectPath ∧ c.ref = e.ref ∧ c.refType = "branch" ∧
      protectionOk e c = true ∧ c.ciConfigRefUri = o.configRef e.projectPath e.ref ∧
      c.pipelineSource ∈ e.sources ∧ (e.triggerUsers = [] ∨ c.userLogin ∈ e.triggerUsers) ∧
      model = some m ∧ m ∈ e.models ∧ m ∈ o.routedModels ∧ p = e.principal ∧ id = e.id ∧
      mintedOk e c = true := by
  obtain ⟨es, c, e, hp, hc, hiss, haud, hexp, hop, hf, hm, hmod, hrt, hpr, hid⟩ :=
    evaluate_allow_cases h
  obtain ⟨hen, hne, hpp, href, hrt', hprot, hcfg, hsrc, htr, hmin⟩ :=
    entryMatches_spec (List.find?_some hf)
  exact ⟨es, c, e, hp, hc, List.mem_of_find?_eq_some hf, hiss, haud, hexp, hop, hen, hne, hpp,
    href, hrt', hprot, hcfg, hsrc, htr, hm, by simpa using hmod, by simpa using hrt, hpr, hid, hmin⟩

/-- A protected-branch entry admits only tokens that say the branch is protected. -/
theorem protected_requires_protected_ref (o : OperatorCfg) (pol : Option (List Entry)) (now : Nat)
    (pc : Option Claims) (op : Op) (model : Option String) (p : Principal) (id m : String)
    (h : evaluate o pol now pc op model = .allow p id m) (proj : String)
    (hp : p = .ci proj none) :
    ∃ c, pc = some c ∧ c.refProtected = "true" := by
  obtain ⟨es, c, e, -, hc, -, -, -, -, -, -, -, -, -, -, hprot, -, -, -, -, -, -, hpr, -, -⟩ :=
    allow_sound o pol now pc op model p id m h
  refine ⟨c, hc, ?_⟩
  cases hk : e.kind with
  | protectedBranch => simpa [protectionOk, hk] using hprot
  | namedBranch => simp [Entry.principal, hk, hp] at hpr

/-- A named-branch entry admits only before its expiry and, in a well-formed policy, only a
listed trigger user (well-formedness makes the list non-empty). -/
theorem named_requires_trigger_user_and_expiry (o : OperatorCfg) (wnow : Nat) (es : List Entry)
    (hw : wellFormed o wnow es) (now : Nat) (pc : Option Claims) (op : Op)
    (model : Option String) (p : Principal) (id m : String)
    (h : evaluate o (some es) now pc op model = .allow p id m) (proj br : String)
    (hp : p = .ci proj (some br)) :
    ∃ c e t, pc = some c ∧ e ∈ es ∧ e.kind = .namedBranch ∧ c.userLogin ∈ e.triggerUsers ∧
      e.expiresAt = some t ∧ now < t ∧ c.ref = br ∧ c.projectPath = proj := by
  obtain ⟨es', c, e, hes, hc, he, -, -, -, -, -, hne, hpp, href, -, -, -, -, htr, -, -, -, hpr, -, -⟩ :=
    allow_sound o _ now pc op model p id m h
  cases hes
  have hok := hw.1 e he
  cases hk : e.kind with
  | protectedBranch => simp [Entry.principal, hk, hp] at hpr
  | namedBranch =>
    simp only [Entry.principal, hk, hp, Principal.ci.injEq, Option.some.injEq] at hpr
    obtain ⟨rfl, rfl⟩ := hpr
    simp only [entryOk, hk, Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff] at hok
    have hnonempty : e.triggerUsers ≠ [] := hok.2.1
    cases hx : e.expiresAt with
    | none => simp [hx] at hok
    | some t =>
      have : now < t := by simpa [notExpired, hx] using hne
      refine ⟨c, e, t, hc, he, hk, ?_, hx, this, href, hpp⟩
      rcases htr with h0 | h1
      · exact absurd h0 hnonempty
      · exact h1

/-! ## 2. Distinct principals, and at most one entry per token -/

theorem eq_of_mem_nodup_map {α β : Type} [DecidableEq β] (f : α → β) :
    ∀ (l : List α), (l.map f).Nodup → ∀ a ∈ l, ∀ b ∈ l, f a = f b → a = b
  | [], _, a, ha, _, _, _ => absurd ha (List.not_mem_nil)
  | x :: xs, hnd, a, ha, b, hb, hab => by
    simp only [List.map_cons, List.nodup_cons, List.mem_map, not_exists, not_and] at hnd
    obtain ⟨hx, hxs⟩ := hnd
    simp only [List.mem_cons] at ha hb
    rcases ha with rfl | ha <;> rcases hb with rfl | hb
    · rfl
    · exact absurd hab.symm (hx b hb)
    · exact absurd hab (hx a ha)
    · exact eq_of_mem_nodup_map f xs hxs a ha b hb hab

/-- Two entries of a well-formed policy that share a principal are the same entry. -/
theorem distinct_principals (o : OperatorCfg) (now : Nat) (es : List Entry)
    (hw : wellFormed o now es) (e₁ e₂ : Entry) (h₁ : e₁ ∈ es) (h₂ : e₂ ∈ es)
    (h : e₁.principal = e₂.principal) : e₁ = e₂ :=
  eq_of_mem_nodup_map (·.principal) es hw.2.2.1 e₁ h₁ e₂ h₂ h

/-- A protected-branch principal never equals a named-branch one. -/
theorem kinds_distinct (e₁ e₂ : Entry) (h₁ : e₁.kind = .protectedBranch)
    (h₂ : e₂.kind = .namedBranch) : e₁.principal ≠ e₂.principal := by
  simp [Entry.principal, h₁, h₂]

/-- In a well-formed policy at most one entry matches any token, so the decision does not depend
on the order of entries. -/
theorem at_most_one_match (o : OperatorCfg) (wnow now : Nat) (es : List Entry)
    (hw : wellFormed o wnow es) (c : Claims) (e₁ e₂ : Entry) (h₁ : e₁ ∈ es) (h₂ : e₂ ∈ es)
    (m₁ : entryMatches o now c e₁ = true) (m₂ : entryMatches o now c e₂ = true) : e₁ = e₂ := by
  obtain ⟨-, -, p₁, r₁, -⟩ := entryMatches_spec m₁
  obtain ⟨-, -, p₂, r₂, -⟩ := entryMatches_spec m₂
  exact eq_of_mem_nodup_map (fun e => (e.projectPath, e.ref)) es hw.2.2.2 e₁ h₁ e₂ h₂
    (by simp only [← p₁, ← p₂, ← r₁, ← r₂])

/-! ## 3. Least privilege -/

/-- A pipeline is served only a chat completion, for a model named in its own entry and routed by
the operator. -/
theorem allow_least_privilege (o : OperatorCfg) (pol : Option (List Entry)) (now : Nat)
    (pc : Option Claims) (op : Op) (model : Option String) (p : Principal) (id m : String)
    (h : evaluate o pol now pc op model = .allow p id m) :
    op = .chat ∧ model = some m ∧ ∃ es e, pol = some es ∧ e ∈ es ∧ p = e.principal ∧
      m ∈ e.models ∧ m ∈ o.routedModels := by
  obtain ⟨es, -, e, hp, -, he, -, -, -, hop, -, -, -, -, -, -, -, -, -, hm, hmm, hmr, hpr, -, -⟩ :=
    allow_sound o pol now pc op model p id m h
  exact ⟨hop, hm, es, e, hp, he, hpr, hmm, hmr⟩

/-! ## 4. Fail closed -/

theorem no_policy_denies (o : OperatorCfg) (now : Nat) (pc : Option Claims) (op : Op)
    (model : Option String) : evaluate o none now pc op model = .deny .noPolicy := rfl

theorem missing_payload_denies (o : OperatorCfg) (pol : Option (List Entry)) (now : Nat) (op : Op)
    (model : Option String) (p : Principal) (id m : String) :
    evaluate o pol now none op model ≠ .allow p id m := by
  intro h
  obtain ⟨es, c, e, hpol, hc, hrest⟩ := evaluate_allow_cases h
  cases hc

theorem expired_token_denies (o : OperatorCfg) (pol : Option (List Entry)) (now : Nat)
    (c : Claims) (op : Op) (model : Option String) (hx : c.exp ≤ now) (p : Principal)
    (id m : String) : evaluate o pol now (some c) op model ≠ .allow p id m := by
  intro h
  obtain ⟨es, c', e, hpol, hc, hiss, haud, hexp, hrest⟩ := evaluate_allow_cases h
  cases hc
  omega

theorem wrong_issuer_denies (o : OperatorCfg) (pol : Option (List Entry)) (now : Nat)
    (c : Claims) (op : Op) (model : Option String) (hx : c.iss ≠ o.issuer) (p : Principal)
    (id m : String) : evaluate o pol now (some c) op model ≠ .allow p id m := by
  intro h
  obtain ⟨es, c', e, hpol, hc, hiss, hrest⟩ := evaluate_allow_cases h
  cases hc
  exact hx hiss

theorem wrong_audience_denies (o : OperatorCfg) (pol : Option (List Entry)) (now : Nat)
    (c : Claims) (op : Op) (model : Option String) (hx : c.aud ≠ .one o.audience) (p : Principal)
    (id m : String) : evaluate o pol now (some c) op model ≠ .allow p id m := by
  intro h
  obtain ⟨es, c', e, hpol, hc, hiss, haud, hrest⟩ := evaluate_allow_cases h
  cases hc
  exact hx haud

theorem not_chat_denies (o : OperatorCfg) (pol : Option (List Entry)) (now : Nat)
    (pc : Option Claims) (model : Option String) (p : Principal) (id m : String) :
    evaluate o pol now pc .other model ≠ .allow p id m := by
  intro h
  obtain ⟨es, c, e, hpol, hc, hiss, haud, hexp, hop, hrest⟩ := evaluate_allow_cases h
  cases hop

/-- No entry matches: deny. In particular an unlisted project is denied. -/
theorem no_match_denies (o : OperatorCfg) (es : List Entry) (now : Nat) (c : Claims) (op : Op)
    (model : Option String) (hn : ∀ e ∈ es, entryMatches o now c e = false) (p : Principal)
    (id m : String) : evaluate o (some es) now (some c) op model ≠ .allow p id m := by
  intro h
  obtain ⟨es', c', e, hes, hc, hiss, haud, hexp, hop, hf, hrest⟩ := evaluate_allow_cases h
  cases hes; cases hc
  have := hn e (List.mem_of_find?_eq_some hf)
  rw [List.find?_some hf] at this
  contradiction

theorem unlisted_project_denies (o : OperatorCfg) (es : List Entry) (now : Nat) (c : Claims)
    (op : Op) (model : Option String) (hn : ∀ e ∈ es, e.projectPath ≠ c.projectPath)
    (p : Principal) (id m : String) : evaluate o (some es) now (some c) op model ≠ .allow p id m := by
  apply no_match_denies
  intro e he
  cases hm : entryMatches o now c e
  · rfl
  · exact absurd (entryMatches_spec hm).2.2.1.symm (hn e he)

theorem disabled_entry_inert (o : OperatorCfg) (now : Nat) (c : Claims) (e : Entry)
    (h : e.enabled = false) : entryMatches o now c e = false := by
  simp [entryMatches, h]

theorem expired_entry_inert (o : OperatorCfg) (now : Nat) (c : Claims) (e : Entry) (t : Nat)
    (hx : e.expiresAt = some t) (hle : t ≤ now) : entryMatches o now c e = false := by
  have : notExpired now e = false := by simp [notExpired, hx]; omega
  simp [entryMatches, this]

theorem unlisted_trigger_user_inert (o : OperatorCfg) (now : Nat) (c : Claims) (e : Entry)
    (hne : e.triggerUsers ≠ []) (hu : c.userLogin ∉ e.triggerUsers) :
    entryMatches o now c e = false := by
  cases hm : entryMatches o now c e
  · rfl
  · rcases (entryMatches_spec hm).2.2.2.2.2.2.2.2.1 with h | h
    · exact absurd h hne
    · exact absurd h hu

theorem unprotected_ref_inert_for_protected (o : OperatorCfg) (now : Nat) (c : Claims) (e : Entry)
    (hk : e.kind = .protectedBranch) (hp : c.refProtected ≠ "true") :
    entryMatches o now c e = false := by
  cases hm : entryMatches o now c e
  · rfl
  · have := (entryMatches_spec hm).2.2.2.2.2.1
    simp [protectionOk, hk, hp] at this

theorem protected_ref_inert_for_named (o : OperatorCfg) (now : Nat) (c : Claims) (e : Entry)
    (hk : e.kind = .namedBranch) (hp : c.refProtected ≠ "false") :
    entryMatches o now c e = false := by
  cases hm : entryMatches o now c e
  · rfl
  · have := (entryMatches_spec hm).2.2.2.2.2.1
    simp [protectionOk, hk, hp] at this

theorem foreign_config_inert (o : OperatorCfg) (now : Nat) (c : Claims) (e : Entry)
    (h : c.ciConfigRefUri ≠ o.configRef e.projectPath e.ref) : entryMatches o now c e = false := by
  cases hm : entryMatches o now c e
  · rfl
  · exact absurd (entryMatches_spec hm).2.2.2.2.2.2.1 h

theorem tag_inert (o : OperatorCfg) (now : Nat) (c : Claims) (e : Entry)
    (h : c.refType ≠ "branch") : entryMatches o now c e = false := by
  cases hm : entryMatches o now c e
  · rfl
  · exact absurd (entryMatches_spec hm).2.2.2.2.1 h

theorem source_not_listed_inert (o : OperatorCfg) (now : Nat) (c : Claims) (e : Entry)
    (h : c.pipelineSource ∉ e.sources) : entryMatches o now c e = false := by
  cases hm : entryMatches o now c e
  · rfl
  · exact absurd (entryMatches_spec hm).2.2.2.2.2.2.2.1 h

/-- `user_login` matters only for entries that name trigger users. -/
theorem user_login_irrelevant_without_triggers (o : OperatorCfg) (now : Nat) (c : Claims)
    (e : Entry) (h : e.triggerUsers = []) (u : String) :
    entryMatches o now { c with userLogin := u } e = entryMatches o now c e := by
  simp [entryMatches, triggerOk, h, protectionOk, mintedOk]

theorem minted_after_bound_inert (o : OperatorCfg) (now : Nat) (c : Claims) (e : Entry) (t : Nat)
    (hx : e.mintedBefore = some t) (hle : t ≤ c.iat) : entryMatches o now c e = false := by
  have : mintedOk e c = false := by simp [mintedOk, hx]; omega
  simp [entryMatches, this]

/-! ## 5. The two listeners: no header principal for pipelines, no default principal -/

/-- On the edge listener a request that carries a payload is decided on the payload alone: the
principal header changes nothing. -/
theorem edge_payload_ignores_principal_header (o : OperatorCfg) (pol : Option (List Entry))
    (humans : List String) (reg : List TokenRec) (now : Nat) (r : BReq) (hs : List String)
    (hl : r.listener = .edge) (pc : Option Claims) (hc : r.claims = some pc) :
    serve o pol humans reg now { r with principals := hs } = serve o pol humans reg now r := by
  cases r; simp only at hl hc; subst hl hc; rfl

/-- The internal listener ignores the principal header entirely. -/
theorem internal_ignores_principal_header (o : OperatorCfg) (pol : Option (List Entry))
    (humans : List String) (reg : List TokenRec) (now : Nat) (r : BReq) (hs : List String)
    (hl : r.listener = .internal) :
    serve o pol humans reg now { r with principals := hs } = serve o pol humans reg now r := by
  cases r; simp only at hl; subst hl; rfl

theorem authToken_spec (reg : List TokenRec) (humans : List String) (now : Nat)
    (tok : Option String) (p : String) (h : authToken reg humans now tok = some p) :
    ∃ t r, tok = some t ∧ reg.find? (·.token == t) = some r ∧ r.principal = p ∧ now < r.exp ∧
      p ∈ humans ∧ ciForm p = false := by
  cases tok with
  | none => simp [authToken] at h
  | some t =>
    simp only [authToken] at h
    split at h
    · rename_i r hr
      split at h
      · rename_i hc
        simp only [Option.some.injEq] at h
        subst h
        simp only [Bool.and_eq_true, decide_eq_true_eq, List.contains_iff_mem, Bool.not_eq_true'] at hc
        exact ⟨t, r, rfl, hr, rfl, hc.1.1, hc.1.2, hc.2⟩
      · contradiction
    · contradiction

/-- The internal listener never serves a pipeline: not a request carrying a payload, and never a
`ci:` principal. What it serves is the principal of the registered token the request presented. -/
theorem internal_never_pipeline (o : OperatorCfg) (pol : Option (List Entry)) (humans : List String)
    (reg : List TokenRec) (now : Nat) (r : BReq) (hl : r.listener = .internal) (x : String)
    (m : Option String) (h : serve o pol humans reg now r = .served x m) :
    r.claims = none ∧ ciForm x = false ∧ x ∈ humans ∧
      ∃ t rec, r.token = some t ∧ reg.find? (·.token == t) = some rec ∧ rec.principal = x := by
  unfold serve at h
  rw [hl] at h
  simp only at h
  split at h
  · contradiction
  · rename_i hc
    split at h
    · rename_i p hp
      simp only [Served.served.injEq] at h
      obtain ⟨rfl, -⟩ := h
      obtain ⟨t, rec, ht, hf, hpr, -, hh, hci⟩ := authToken_spec reg humans now r.token p hp
      exact ⟨hc, hci, hh, t, rec, ht, hf, hpr⟩
    · contradiction

/-- A person served on the edge listener is a listed person, never a `ci:` name. -/
theorem edge_person_listed (o : OperatorCfg) (pol : Option (List Entry)) (humans : List String)
    (reg : List TokenRec) (now : Nat) (r : BReq) (hl : r.listener = .edge) (hc : r.claims = none)
    (x : String) (m : Option String) (h : serve o pol humans reg now r = .served x m) :
    r.principals = [x] ∧ ciForm x = false ∧ x ∈ humans := by
  unfold serve at h
  rw [hl, hc] at h
  simp only at h
  split at h
  · rename_i hh hp
    split at h
    · contradiction
    · rename_i hci
      split at h
      · rename_i hm
        simp only [Served.served.injEq] at h
        obtain ⟨rfl, -⟩ := h
        exact ⟨hp, by simpa using hci, by simpa using hm⟩
      · contradiction
  · contradiction

/-- Whatever the listener, the broker accounts a request only to a listed person or to the
principal of a policy entry. There is no default principal. -/
theorem served_principal_listed (o : OperatorCfg) (es : List Entry) (humans : List String)
    (reg : List TokenRec) (now : Nat) (r : BReq) (x : String) (m : Option String)
    (h : serve o (some es) humans reg now r = .served x m) :
    x ∈ humans ∨ ∃ e ∈ es, x = e.principal.render := by
  cases hl : r.listener with
  | internal => exact Or.inl (internal_never_pipeline o _ humans reg now r hl x m h).2.2.1
  | edge =>
    cases hc : r.claims with
    | some pc =>
      unfold serve at h
      rw [hl, hc] at h
      simp only at h
      split at h
      · rename_i p id m' hd
        simp only [Served.served.injEq] at h
        obtain ⟨rfl, -⟩ := h
        obtain ⟨es', -, e, hes, -, he, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, hpr, -, -⟩ :=
          allow_sound _ _ _ _ _ _ _ _ _ hd
        cases hes
        exact Or.inr ⟨e, he, by rw [hpr]⟩
      · contradiction
    | none => exact Or.inl (edge_person_listed o _ humans reg now r hl hc x m h).2.2

/-- A pipeline principal always has the `ci:` form, so no person is ever served as one. -/
theorem render_ciForm (p : Principal) : ciForm p.render = true := by
  cases p with
  | ci proj b => cases b <;> simp [Principal.render, ciForm, List.take]

/-- On the edge listener a request carrying a payload is served only as a chat completion for a
model on the entry, accounted to a `ci:` principal. -/
theorem edge_served_least_privilege (o : OperatorCfg) (pol : Option (List Entry))
    (humans : List String) (reg : List TokenRec) (now : Nat) (r : BReq) (hl : r.listener = .edge)
    (pc : Option Claims) (hc : r.claims = some pc) (x : String)
    (m : Option String) (h : serve o pol humans reg now r = .served x m) :
    r.path = .chat ∧ r.post = true ∧ ∃ m', m = some m' ∧ r.model = some m' ∧ ciForm x = true := by
  unfold serve at h
  rw [hl, hc] at h
  simp only at h
  split at h
  · rename_i p id m' hd
    simp only [Served.served.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    obtain ⟨hop, hm, -⟩ := allow_least_privilege _ _ _ _ _ _ _ _ _ hd
    simp only [opOf] at hop
    split at hop
    · rename_i hc'
      simp only [Bool.and_eq_true, beq_iff_eq] at hc'
      exact ⟨hc'.1, hc'.2, m', rfl, hm, render_ciForm p⟩
    · contradiction
  · contradiction

end BadgerBroker
