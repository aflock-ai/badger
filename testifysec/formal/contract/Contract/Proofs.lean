/-
  Contract.Proofs: the contract's properties, for every input.

  Markings
    `dom_refl`, `dom_trans`, `dom_antisymm`    dominance is a partial order (up to set equality)
    `lub_upper_left`, `lub_upper_right`        the join dominates both sides
    `lub_least`                                and is dominated by anything that dominates both
    `domGo_iff`                                Go's `Dominates` is exactly `Dom` on the labels
    `joinGo_above_lub`                         Go's `Join` is never below the least upper bound
    `joinGo_upper_left`, `joinGo_upper_right`  so it dominates both sides
    `result_is_connector`                      a result's banner is exactly the connector's marking
  Flow
    `no_write_down`                            a delivered send's sink dominates every label read
                                               before it
    `flowGo_no_write_down`                     the same for the Go primitives composed
    `refused_delivers_nothing`                 a session whose join has no banner sends nothing
    `joinChecked_long_only_refuses`            a banner-length refusal removes a join, never changes it
    `refusedGo_iff`, `joinChecked_bannerable`  Go's Join refuses exactly the joins with no banner
  Admission
    `admit_signed`        an admitted profile was validly signed, only by trust-root keys
    `admit_assigned`      it is the assigned tenant, deployment, profile, payload and manifest
    `admit_tenant`        so a profile for one tenant never activates for another
    `admit_window`        now is inside its window
    `admit_required`      no envelope, no admission (fail closed)
    `admit_unsigned`      an invalid signature is never admitted (fail closed)
    `admit_rollback`      a sequence below the high-water mark is refused
    `admitted_monotone`   the sequences a device admits never decrease
  As built (facts about today's Go, not requirements)
    `asbuilt_pin_blocks_rollback`  with a fixed assignment, the pin alone stops rollback
    `asbuilt_repin_rolls_back`     re-pinning an older profile rolls the device back
    `asbuilt_v1_checks_tenant`     the schema-1 verifier refuses a profile naming another tenant
    `asbuilt_v1_release_needs_profile`  a release build admits no request without a profile
    `asbuilt_v1_uat_no_profile`    only the uatnoprofile build's development flag admits none
    `asbuilt_join_not_least_rel`  where Go's `Join` marks higher than it needs to;
    `asbuilt_join_least_disp`     display, which it now joins exactly
                                   than it needs to
-/
import Contract.Mutants

namespace Contract

/-! ## Token sets -/

theorem sup_refl (a : List Tok) : Sup a a := fun _ h => h

theorem sup_trans {a b c : List Tok} (h1 : Sup a b) (h2 : Sup b c) : Sup a c :=
  fun x hx => h1 x (h2 x hx)

theorem sup_append_left (a b : List Tok) : Sup (a ++ b) a :=
  fun _ hx => List.mem_append.2 (Or.inl hx)

theorem sup_append_right (a b : List Tok) : Sup (a ++ b) b :=
  fun _ hx => List.mem_append.2 (Or.inr hx)

theorem sup_append {c a b : List Tok} (h1 : Sup c a) (h2 : Sup c b) : Sup c (a ++ b) :=
  fun x hx => (List.mem_append.1 hx).elim (h1 x) (h2 x)

theorem sup_nil (a : List Tok) : Sup a [] := fun _ h => nomatch h

theorem mem_filter_in {x : Tok} {a b : List Tok} :
    x ∈ a.filter (fun c => decide (c ∈ b)) ↔ x ∈ a ∧ x ∈ b := by
  simp [List.mem_filter]

theorem sup_filter (a b : List Tok) : Sup a (a.filter (fun c => decide (c ∈ b))) :=
  fun _ hx => (mem_filter_in.1 hx).1

theorem sup_filter' (a b : List Tok) : Sup b (a.filter (fun c => decide (c ∈ b))) :=
  fun _ hx => (mem_filter_in.1 hx).2

/-! ## FGI and release -/

theorem holds_refl (f : Fgi) : f.Holds f := by
  cases f <;> first | exact True.intro | exact sup_refl _

theorem holds_trans {a b c : Fgi} (h1 : a.Holds b) (h2 : b.Holds c) : a.Holds c := by
  cases a <;> cases b <;> cases c <;>
    first | exact True.intro | exact (h1 : False).elim | exact (h2 : False).elim
          | exact sup_trans h1 h2

theorem holds_join_left (a b : Fgi) : (a.join b).Holds a := by
  cases a <;> cases b <;>
    first | exact True.intro | exact sup_refl _ | exact sup_append_left _ _

theorem holds_join_right (a b : Fgi) : (a.join b).Holds b := by
  cases a <;> cases b <;>
    first | exact True.intro | exact sup_refl _ | exact sup_append_right _ _

theorem holds_join_least {a b c : Fgi} (ha : c.Holds a) (hb : c.Holds b) : c.Holds (a.join b) := by
  cases c <;> cases a <;> cases b <;>
    first | exact True.intro | exact (ha : False).elim | exact (hb : False).elim
          | exact sup_append ha hb | exact ha | exact hb

theorem relle_refl (r : Option (List Tok)) : RelLe r r := by
  cases r <;> first | exact True.intro | exact sup_refl _

theorem relle_trans {x y z : Option (List Tok)} (h1 : RelLe x y) (h2 : RelLe y z) : RelLe x z := by
  cases x <;> cases y <;> cases z <;>
    first | exact True.intro | exact (h1 : False).elim | exact (h2 : False).elim
          | exact sup_trans h2 h1

theorem relle_meet_left (x y : Option (List Tok)) : RelLe (relMeet x y) x := by
  cases x <;> cases y <;>
    first | exact True.intro | exact sup_refl _ | exact sup_filter _ _ | exact relle_refl _

theorem relle_meet_right (x y : Option (List Tok)) : RelLe (relMeet x y) y := by
  cases x <;> cases y <;>
    first | exact True.intro | exact sup_refl _ | exact sup_filter' _ _ | exact relle_refl _

theorem relle_meet {r x y : Option (List Tok)} (hx : RelLe r x) (hy : RelLe r y) :
    RelLe r (relMeet x y) := by
  cases r <;> cases x <;> cases y <;>
    first | exact True.intro | exact (hx : False).elim | exact (hy : False).elim | exact hx
          | exact hy
          | exact fun t ht => mem_filter_in.2 ⟨(hx : Sup _ _) t ht, (hy : Sup _ _) t ht⟩

/-! ## Dominance is a partial order -/

theorem dom_refl (a : Label) : Dom a a :=
  ⟨Nat.le_refl _, sup_refl _, sup_refl _, sup_refl _, sup_refl _, sup_refl _, holds_refl _,
   fun _ => sup_refl _, relle_refl _, relle_refl _⟩

theorem dom_trans {a b c : Label} (h1 : Dom a b) (h2 : Dom b c) : Dom a c := by
  obtain ⟨l1, s1, p1, e1, n1, c1, f1, k1, r1, d1⟩ := h1
  obtain ⟨l2, s2, p2, e2, n2, c2, f2, k2, r2, d2⟩ := h2
  exact ⟨Nat.le_trans l2 l1, sup_trans s1 s2, sup_trans p1 p2, sup_trans e1 e2, sup_trans n1 n2,
    sup_trans c1 c2, holds_trans f1 f2,
    fun h => sup_trans (k1 h) (k2 (Nat.lt_of_le_of_lt l1 h)), relle_trans r1 r2, relle_trans d1 d2⟩

theorem dom_antisymm {a b : Label} (h1 : Dom a b) (h2 : Dom b a) : Equiv a b := by
  obtain ⟨l1, s1, p1, e1, n1, c1, f1, k1, r1, d1⟩ := h1
  obtain ⟨l2, s2, p2, e2, n2, c2, f2, k2, r2, d2⟩ := h2
  have hl : a.level = b.level := Nat.le_antisymm l2 l1
  exact ⟨hl, ⟨s1, s2⟩, ⟨p1, p2⟩, ⟨e1, e2⟩, ⟨n1, n2⟩, ⟨c1, c2⟩, f1, f2,
    fun h => ⟨k1 h, k2 (hl ▸ h)⟩, r1, r2, d1, d2⟩

/-! ## The join is the least upper bound -/

theorem lub_upper_left (a b : Label) : Dom (lub a b) a := by
  refine ⟨Nat.le_max_left _ _, sup_append_left _ _, sup_append_left _ _, sup_append_left _ _,
    sup_append_left _ _, sup_append_left _ _, holds_join_left _ _, ?_, relle_meet_left _ _,
    relle_meet_left _ _⟩
  intro h
  have h' : max a.level b.level < confidential := h
  show Sup (if max a.level b.level < confidential then a.cats ++ b.cats else []) a.cats
  rw [ite_eq_left h']; exact sup_append_left _ _

theorem lub_upper_right (a b : Label) : Dom (lub a b) b := by
  refine ⟨Nat.le_max_right _ _, sup_append_right _ _, sup_append_right _ _, sup_append_right _ _,
    sup_append_right _ _, sup_append_right _ _, holds_join_right _ _, ?_, relle_meet_right _ _,
    relle_meet_right _ _⟩
  intro h
  have h' : max a.level b.level < confidential := h
  show Sup (if max a.level b.level < confidential then a.cats ++ b.cats else []) b.cats
  rw [ite_eq_left h']; exact sup_append_right _ _

theorem lub_least {a b c : Label} (ha : Dom c a) (hb : Dom c b) : Dom c (lub a b) := by
  obtain ⟨l1, s1, p1, e1, n1, c1, f1, k1, r1, d1⟩ := ha
  obtain ⟨l2, s2, p2, e2, n2, c2, f2, k2, r2, d2⟩ := hb
  refine ⟨Nat.max_le.2 ⟨l1, l2⟩, sup_append s1 s2, sup_append p1 p2, sup_append e1 e2,
    sup_append n1 n2, sup_append c1 c2, holds_join_least f1 f2, ?_, relle_meet r1 r2, ?_⟩
  · intro h
    show Sup c.cats (if max a.level b.level < confidential then a.cats ++ b.cats else [])
    by_cases hm : max a.level b.level < confidential
    · rw [ite_eq_left hm]; exact sup_append (k1 h) (k2 h)
    · rw [ite_eq_right hm]; exact sup_nil _
  · exact relle_meet d1 d2

/-! ## No write down -/

theorem delivered_sound (tr : List Flow) :
    ∀ (lbl : Option Label) (seen : List Label), (∀ x, lbl = some x → ∀ l ∈ seen, Dom x l) →
      ∀ p ∈ delivered lbl seen tr, ∀ l ∈ p.2, Dom p.1 l := by
  induction tr with
  | nil => intro _ _ _ p hp; exact absurd hp (by simp [delivered])
  | cons e t ih =>
    intro lbl seen hs
    cases e with
    | read l =>
      apply ih
      intro y hy l' hl'
      cases lbl with
      | none => cases hy
      | some x =>
        simp only [readInto] at hy
        split at hy
        · cases hy
          rcases List.mem_cons.1 hl' with rfl | hl'
          · exact lub_upper_right _ _
          · exact dom_trans (lub_upper_left _ _) (hs x rfl l' hl')
        · cases hy
    | send s =>
      intro p hp
      cases lbl with
      | none => exact ih none seen hs p hp
      | some x =>
        by_cases hd : Dom s x
        · simp only [delivered, ite_eq_left hd] at hp
          rcases List.mem_cons.1 hp with rfl | hp
          · exact fun l hl => dom_trans hd (hs x rfl l hl)
          · exact ih _ seen hs p hp
        · simp only [delivered, ite_eq_right hd] at hp
          exact ih _ seen hs p hp

/-- Every send that goes out goes to a sink dominating everything the session read before it. -/
theorem no_write_down (tr : List Flow) :
    ∀ p ∈ delivered (some Label.bot) [] tr, ∀ l ∈ p.2, Dom p.1 l :=
  delivered_sound tr _ _ (fun _ _ _ h => nomatch h)

/-- A session whose join has no banner delivers nothing afterwards. -/
theorem refused_delivers_nothing (seen : List Label) (tr : List Flow) :
    delivered none seen tr = [] := by
  induction tr generalizing seen with
  | nil => rfl
  | cons e t ih => cases e <;> simp [delivered, readInto, ih]

/-- Non-vacuity: a sink at the session's label is reached. -/
theorem flow_delivers :
    delivered (some Label.bot) [] [.read Mutants.secretL, .send Mutants.secretL] =
      [(Mutants.secretL, [Mutants.secretL])] := by decide

end Contract

namespace Contract.AsBuilt

open Contract

/-! ## Go's Dominates is Dom on labels -/

theorem fgi_iff (a b : Mk) :
    ¬ (b.hasFgi = true ∧ (a.hasFgi = false ∨ (a.fgi ≠ [] ∧ (b.fgi = [] ∨ ¬ Sup a.fgi b.fgi)))) ↔
      (sem a).fgi.Holds (sem b).fgi := by
  cases ha : a.hasFgi <;> cases hb : b.hasFgi <;> by_cases ea : a.fgi = [] <;>
    by_cases eb : b.fgi = [] <;> simp [sem, ha, hb, ea, eb, Fgi.Holds]

theorem domGo_iff (a b : Mk) : DomGo a b ↔ Dom (sem a) (sem b) := by
  have hf := fgi_iff a b
  constructor
  · rintro ⟨hn, hr, hd⟩
    simp only [not_or] at hn
    obtain ⟨hl, h1, h2, h3, h4, h5, h6, h7⟩ := hn
    refine ⟨Nat.le_of_not_lt hl, Classical.not_not.1 h1, Classical.not_not.1 h2,
      Classical.not_not.1 h3, Classical.not_not.1 h4, Classical.not_not.1 h5, hf.1 h6, ?_, hr, hd⟩
    intro hlt
    have hlt : a.level < confidential := hlt
    have hb : b.level < confidential := Nat.lt_of_le_of_lt (Nat.le_of_not_lt hl) hlt
    show Sup (if a.level < confidential then a.cats else []) (if b.level < confidential then b.cats else [])
    rw [ite_eq_left hlt, ite_eq_left hb]
    exact Classical.byContradiction fun hc => h7 ⟨hlt, hc⟩
  · rintro ⟨hl, h1, h2, h3, h4, h5, h6, h7, hr, hd⟩
    refine ⟨?_, hr, hd⟩
    simp only [not_or]
    refine ⟨Nat.not_lt.2 hl, fun h => h h1, fun h => h h2, fun h => h h3, fun h => h h4,
      fun h => h h5, hf.2 h6, ?_⟩
    rintro ⟨hlt, hc⟩
    have hb : b.level < confidential := Nat.lt_of_le_of_lt hl hlt
    have hl : b.level ≤ a.level := hl
    have h := h7 hlt
    change Sup (if a.level < confidential then a.cats else [])
      (if b.level < confidential then b.cats else []) at h
    rw [ite_eq_left hlt, ite_eq_left hb] at h
    exact hc h

theorem domGo_trans {a b c : Mk} (h1 : DomGo a b) (h2 : DomGo b c) : DomGo a c :=
  (domGo_iff a c).2 (dom_trans ((domGo_iff a b).1 h1) ((domGo_iff b c).1 h2))

/-! ## Expansion and release -/

theorem mem_expand {x : Tok} {l : List Tok} :
    x ∈ expand l ↔ (x ∈ l ∧ x ≠ fveyTok) ∨ (fveyTok ∈ l ∧ x ∈ fveyMembers) := by
  unfold expand
  rw [List.mem_flatMap]
  constructor
  · rintro ⟨c, hc, hx⟩
    by_cases h : c = fveyTok
    · rw [ite_eq_left h] at hx; exact Or.inr ⟨h ▸ hc, hx⟩
    · rw [ite_eq_right h, List.mem_singleton] at hx; subst hx; exact Or.inl ⟨hc, h⟩
  · rintro (⟨hx, hne⟩ | ⟨hf, hx⟩)
    · exact ⟨x, hx, by rw [ite_eq_right hne]; exact List.mem_singleton.2 rfl⟩
    · exact ⟨fveyTok, hf, by rw [ite_eq_left rfl]; exact hx⟩

theorem fvey_not_expand (l : List Tok) : fveyTok ∉ expand l := by
  intro h
  rcases mem_expand.1 h with ⟨_, h⟩ | ⟨_, h⟩
  · exact h rfl
  · exact absurd h (by decide)

theorem usa_expand {l : List Tok} (h : usa ∈ l) : usa ∈ expand l :=
  mem_expand.2 (Or.inl ⟨h, by decide⟩)

theorem expand_mono {a b : List Tok} (h : Sup b a) : Sup (expand b) (expand a) := by
  intro x hx
  rcases mem_expand.1 hx with ⟨hx, hne⟩ | ⟨hf, hx⟩
  · exact mem_expand.2 (Or.inl ⟨h x hx, hne⟩)
  · exact mem_expand.2 (Or.inr ⟨h _ hf, hx⟩)

theorem release0_some {m : Mk} {r : List Tok} (h : release0 m = some r) :
    (nf ∈ m.controls ∧ r = [usa]) ∨ (nf ∉ m.controls ∧ m.relTo ≠ [] ∧ r = expand m.relTo) ∨
    (nf ∉ m.controls ∧ m.relTo = [] ∧ r = [usa]) := by
  unfold release0 at h
  by_cases c1 : nf ∈ m.controls
  · rw [ite_eq_left c1] at h; cases h; exact Or.inl ⟨c1, rfl⟩
  · rw [ite_eq_right c1] at h
    by_cases c2 : m.relTo ≠ []
    · rw [ite_eq_left c2] at h; cases h; exact Or.inr (Or.inl ⟨c1, c2, rfl⟩)
    · rw [ite_eq_right c2] at h
      by_cases c3 : confidential ≤ m.level
      · rw [ite_eq_left c3] at h; cases h; exact Or.inr (Or.inr ⟨c1, Classical.not_not.1 c2, rfl⟩)
      · rw [ite_eq_right c3] at h; cases h

theorem release0_none {m : Mk} (h : release0 m = none) : nf ∉ m.controls ∧ m.relTo = [] := by
  unfold release0 at h
  by_cases c1 : nf ∈ m.controls
  · rw [ite_eq_left c1] at h; cases h
  · rw [ite_eq_right c1] at h
    by_cases c2 : m.relTo ≠ []
    · rw [ite_eq_left c2] at h; cases h
    · exact ⟨c1, Classical.not_not.1 c2⟩

theorem release_some {m : Mk} {r : List Tok} (h : release m = some r) :
    (nf ∈ m.controls ∧ r = [usa]) ∨ (nf ∉ m.controls ∧ m.relTo ≠ [] ∧ r = expand m.relTo) ∨
    (nf ∉ m.controls ∧ m.relTo = [] ∧ r = [usa]) := by
  unfold release at h
  cases h0 : release0 m with
  | some r' => rw [h0] at h; cases h; exact release0_some h0
  | none =>
    rw [h0] at h
    obtain ⟨c1, c2⟩ := release0_none h0
    by_cases c : m.disp ≠ []
    · simp only [ite_eq_left c] at h; cases h; exact Or.inr (Or.inr ⟨c1, c2, rfl⟩)
    · simp only [ite_eq_right c] at h; cases h

theorem release_usa {m : Mk} (hw : WF m) {r : List Tok} (h : release m = some r) : usa ∈ r := by
  rcases release_some h with ⟨_, rfl⟩ | ⟨_, hne, rfl⟩ | ⟨_, _, rfl⟩
  · exact List.mem_singleton.2 rfl
  · rcases hw with hw | hw
    · exact absurd hw hne
    · exact usa_expand hw
  · exact List.mem_singleton.2 rfl

theorem release_no_fvey {m : Mk} {r : List Tok} (h : release m = some r) : fveyTok ∉ r := by
  rcases release_some h with ⟨_, rfl⟩ | ⟨_, _, rfl⟩ | ⟨_, _, rfl⟩
  · decide
  · exact fvey_not_expand _
  · decide

theorem usa_le {m : Mk} (hw : WF m) : RelLe (some [usa]) (release m) := by
  cases h : release m with
  | none => exact True.intro
  | some r =>
    intro x hx
    rw [List.mem_singleton.1 hx]
    exact release_usa hw h

theorem release_of_relTo {m : Mk} (h1 : nf ∉ m.controls) (h2 : m.relTo ≠ []) :
    release m = some (expand m.relTo) := by
  simp [release, release0, h1, h2]

theorem release_of_nf {m : Mk} (h : nf ∈ m.controls) : release m = some [usa] := by
  simp [release, release0, h]

/-! ## Display -/

theorem release_le_display (m : Mk) : RelLe (release m) (display m) := by
  unfold display
  cases release m with
  | none => exact True.intro
  | some r => exact sup_append_left _ _

theorem usa_le_display {m : Mk} (hw : WF m) : RelLe (some [usa]) (display m) :=
  relle_trans (usa_le hw) (release_le_display m)

theorem display_no_fvey {m : Mk} {d : List Tok} (h : display m = some d) : fveyTok ∉ d := by
  unfold display at h
  cases hr : release m with
  | none => rw [hr] at h; cases h
  | some r =>
    rw [hr] at h; cases h
    intro hf
    rcases List.mem_append.1 hf with hf | hf
    · exact release_no_fvey hr hf
    · exact fvey_not_expand _ hf

theorem display_none {m : Mk} (h : display m = none) : release m = none := by
  unfold display at h
  cases hr : release m with
  | none => rfl
  | some r => rw [hr] at h; cases h

/-! ## Go's Join is never below the least upper bound -/

theorem relle_none_some {r : List Tok} : ¬ RelLe none (some r) := fun h => h

theorem relCtl_controls (a b : Mk) : Sup (relCtl a b).2 (a.controls ++ b.controls) := by
  unfold relCtl
  split
  · exact sup_refl _
  · split
    · exact sup_refl _
    · split
      · exact sup_append_left _ _
      · exact sup_refl _

theorem relCtl_nf {a b : Mk} (h : nf ∉ (relCtl a b).2) :
    nf ∉ a.controls ∧ nf ∉ b.controls := by
  have hs := relCtl_controls a b
  exact ⟨fun h' => h (hs _ (List.mem_append.2 (Or.inl h'))),
         fun h' => h (hs _ (List.mem_append.2 (Or.inr h')))⟩

theorem relCtl_cases (a b : Mk) :
    (RelLe (release a) (release b) ∧ relCtl a b = (a.relTo, a.controls ++ b.controls)) ∨
    (¬ RelLe (release a) (release b) ∧ RelLe (release b) (release a) ∧
      relCtl a b = (b.relTo, a.controls ++ b.controls)) ∨
    (¬ RelLe (release a) (release b) ∧ ¬ RelLe (release b) (release a) ∧ lOf a b = [] ∧
      relCtl a b = ([], a.controls ++ b.controls ++ [nf])) ∨
    (¬ RelLe (release a) (release b) ∧ ¬ RelLe (release b) (release a) ∧ lOf a b ≠ [] ∧
      relCtl a b = (usa :: lOf a b, a.controls ++ b.controls)) := by
  unfold relCtl
  by_cases c1 : RelLe (release a) (release b)
  · exact Or.inl ⟨c1, by rw [ite_eq_left c1]⟩
  · by_cases c2 : RelLe (release b) (release a)
    · exact Or.inr (Or.inl ⟨c1, c2, by rw [ite_eq_right c1, ite_eq_left c2]⟩)
    · by_cases c3 : lOf a b = []
      · exact Or.inr (Or.inr (Or.inl ⟨c1, c2, c3, by rw [ite_eq_right c1, ite_eq_right c2, ite_eq_left c3]⟩))
      · exact Or.inr (Or.inr (Or.inr ⟨c1, c2, c3, by rw [ite_eq_right c1, ite_eq_right c2, ite_eq_right c3]⟩))

/-- Whatever `Join`'s release part restricts to lies inside both sides' releases. -/
theorem release0_joinBase {a b : Mk} (wa : WF a) (wb : WF b) {r : List Tok}
    (h : release0 (joinBase a b) = some r) :
    RelLe (some r) (release a) ∧ RelLe (some r) (release b) := by
  have ua := usa_le wa
  have ub := usa_le wb
  have hctl : (joinBase a b).controls = (relCtl a b).2 := rfl
  have hrel : (joinBase a b).relTo = if nf ∈ (relCtl a b).2 then [] else (relCtl a b).1 := rfl
  rcases release0_some h with ⟨_, rfl⟩ | ⟨hn, hne, rfl⟩ | ⟨_, _, rfl⟩
  · exact ⟨ua, ub⟩
  · have hn' : nf ∉ (relCtl a b).2 := hctl ▸ hn
    have hto : (joinBase a b).relTo = (relCtl a b).1 := by rw [hrel, ite_eq_right hn']
    obtain ⟨na, nb⟩ := relCtl_nf hn'
    rcases relCtl_cases a b with ⟨c, e⟩ | ⟨_, c, e⟩ | ⟨_, _, _, e⟩ | ⟨c1, c2, _, e⟩
    · have hto' : (joinBase a b).relTo = a.relTo := by rw [hto, e]
      have ha : release a = some (expand a.relTo) := release_of_relTo na (hto' ▸ hne)
      rw [hto', ← ha]; exact ⟨relle_refl _, c⟩
    · have hto' : (joinBase a b).relTo = b.relTo := by rw [hto, e]
      have hb : release b = some (expand b.relTo) := release_of_relTo nb (hto' ▸ hne)
      rw [hto', ← hb]; exact ⟨c, relle_refl _⟩
    · rw [e] at hn'; exact absurd (List.mem_append.2 (Or.inr (List.mem_singleton.2 rfl))) hn'
    · rw [e] at hto
      cases hra : release a with
      | none => rw [hra] at c2; exact absurd True.intro c2
      | some x =>
      cases hrb : release b with
      | none => rw [hrb] at c1; exact absurd True.intro c1
      | some y =>
      have hl' : lOf a b = x.filter (fun c => decide (c ∈ y ∧ c ≠ usa)) := by
        unfold lOf; rw [hra, hrb]; rfl
      have key : ∀ z ∈ expand (usa :: lOf a b), z ∈ x ∧ z ∈ y := by
        intro z hz
        rcases mem_expand.1 hz with ⟨hz, _⟩ | ⟨hf, _⟩
        · rcases List.mem_cons.1 hz with rfl | hz
          · exact ⟨release_usa wa hra, release_usa wb hrb⟩
          · rw [hl', List.mem_filter] at hz
            exact ⟨hz.1, (of_decide_eq_true hz.2).1⟩
        · rcases List.mem_cons.1 hf with hf | hf
          · exact absurd hf (by decide)
          · rw [hl', List.mem_filter] at hf
            exact absurd hf.1 (release_no_fvey hra)
      rw [hto]
      exact ⟨fun z hz => (key z hz).1, fun z hz => (key z hz).2⟩
  · exact ⟨ua, ub⟩

theorem release_joinBase (a b : Mk) : release (joinBase a b) = release0 (joinBase a b) := by
  unfold release
  cases release0 (joinBase a b) <;> rfl

theorem joinDisp_nil {a b : Mk} (hd : joinDisp a b = []) (h0 : release0 (joinBase a b) = none) :
    display a = none ∧ display b = none := by
  unfold joinDisp at hd
  cases hm : relMeet (display a) (display b) with
  | none =>
    cases ha : display a <;> cases hb : display b <;> rw [ha, hb] at hm <;> simp [relMeet] at hm
    exact ⟨rfl, rfl⟩
  | some d =>
    rw [hm] at hd
    have : release (joinBase a b) = none := by rw [release_joinBase, h0]
    simp [this] at hd

theorem release_joinGo {a b : Mk} (wa : WF a) (wb : WF b) :
    RelLe (release (joinGo a b)) (release a) ∧ RelLe (release (joinGo a b)) (release b) := by
  have e : release (joinGo a b) =
      match release0 (joinBase a b) with
      | some r => some r
      | none => if joinDisp a b ≠ [] then some [usa] else none := rfl
  rw [e]
  cases h0 : release0 (joinBase a b) with
  | some r => exact release0_joinBase wa wb h0
  | none =>
    by_cases c : joinDisp a b ≠ []
    · simp only [ite_eq_left c]; exact ⟨usa_le wa, usa_le wb⟩
    · simp only [ite_eq_right c]
      obtain ⟨da, db⟩ := joinDisp_nil (Classical.not_not.1 c) h0
      rw [display_none da, display_none db]; exact ⟨True.intro, True.intro⟩

theorem fgi_joinGo (a b : Mk) : (sem (joinGo a b)).fgi.Holds ((sem a).fgi.join (sem b).fgi) := by
  cases ha : a.hasFgi <;> cases hb : b.hasFgi <;> by_cases ea : a.fgi = [] <;>
    by_cases eb : b.fgi = [] <;>
    simp [sem, joinGo, joinBase, ha, hb, ea, eb, Fgi.join, Fgi.Holds] <;>
    first | exact sup_append_right _ _ | exact sup_append_left _ _ | exact sup_refl _

theorem disp_joinGo {a b : Mk} (wa : WF a) (wb : WF b) :
    RelLe (display (joinGo a b)) (relMeet (display a) (display b)) := by
  cases hD : relMeet (display a) (display b) with
  | none => cases display (joinGo a b) <;> exact True.intro
  | some dl =>
    have hr : RelLe (release (joinGo a b)) (some dl) := by
      rw [← hD]
      exact relle_meet (relle_trans (release_joinGo wa wb).1 (release_le_display a))
        (relle_trans (release_joinGo wa wb).2 (release_le_display b))
    have husa : usa ∈ dl := by
      have := relle_meet (usa_le_display wa) (usa_le_display wb)
      rw [hD] at this; exact this usa (List.mem_singleton.2 rfl)
    have hf : fveyTok ∉ dl := by
      intro hf
      cases ha : display a with
      | some x =>
        have := relle_meet_left (display a) (display b)
        rw [hD, ha] at this; exact display_no_fvey ha (this _ hf)
      | none =>
        cases hb : display b with
        | some y =>
          have := relle_meet_right (display a) (display b)
          rw [hD, hb] at this; exact display_no_fvey hb (this _ hf)
        | none => rw [ha, hb] at hD; cases hD
    have hdisp : Sup dl (expand (joinGo a b).disp) := by
      have e : (joinGo a b).disp = joinDisp a b := rfl
      rw [e]
      unfold joinDisp
      rw [hD]
      dsimp only
      split
      · intro z hz
        have sub : ∀ w ∈ usa :: extraOf dl (release (joinBase a b)), w ∈ dl := by
          intro w hw
          rcases List.mem_cons.1 hw with rfl | hw
          · exact husa
          · unfold extraOf at hw; exact (List.mem_filter.1 hw).1
        rcases mem_expand.1 hz with ⟨hz, _⟩ | ⟨hfz, _⟩
        · exact sub z hz
        · exact absurd (sub _ hfz) hf
      · intro z hz; simp [expand] at hz
    unfold display
    cases hrj : release (joinGo a b) with
    | none => rw [hrj] at hr; exact absurd hr relle_none_some
    | some r =>
      rw [hrj] at hr
      exact sup_append hr hdisp

/-- Go's `Join` is at or above the least upper bound of the labels it joins. -/
theorem joinGo_above_lub {a b : Mk} (wa : WF a) (wb : WF b) :
    Dom (sem (joinGo a b)) (lub (sem a) (sem b)) := by
  refine ⟨Nat.le_refl _, sup_refl _, sup_refl _, sup_refl _, sup_refl _,
    relCtl_controls a b, fgi_joinGo a b, ?_,
    relle_meet (release_joinGo wa wb).1 (release_joinGo wa wb).2, disp_joinGo wa wb⟩
  intro h
  have h' : max a.level b.level < confidential := h
  have ha : a.level < confidential := Nat.lt_of_le_of_lt (Nat.le_max_left _ _) h'
  have hb : b.level < confidential := Nat.lt_of_le_of_lt (Nat.le_max_right _ _) h'
  show Sup (if max a.level b.level < confidential then
      (if max a.level b.level < confidential then a.cats ++ b.cats else []) else [])
    (if max a.level b.level < confidential then
      (if a.level < confidential then a.cats else []) ++ (if b.level < confidential then b.cats else [])
      else [])
  rw [ite_eq_left h', ite_eq_left h', ite_eq_left h', ite_eq_left ha, ite_eq_left hb]
  exact sup_refl _

theorem joinGo_upper_left {a b : Mk} (wa : WF a) (wb : WF b) : Dom (sem (joinGo a b)) (sem a) :=
  dom_trans (joinGo_above_lub wa wb) (lub_upper_left _ _)

theorem joinGo_upper_right {a b : Mk} (wa : WF a) (wb : WF b) : Dom (sem (joinGo a b)) (sem b) :=
  dom_trans (joinGo_above_lub wa wb) (lub_upper_right _ _)

theorem wf_joinGo {a b : Mk} (wa : WF a) (wb : WF b) : WF (joinGo a b) := by
  have hrel : (joinGo a b).relTo = if nf ∈ (relCtl a b).2 then [] else (relCtl a b).1 := rfl
  unfold WF; rw [hrel]
  by_cases h : nf ∈ (relCtl a b).2
  · rw [ite_eq_left h]; exact Or.inl rfl
  · rw [ite_eq_right h]
    rcases relCtl_cases a b with ⟨_, e⟩ | ⟨_, _, e⟩ | ⟨_, _, _, e⟩ | ⟨_, _, _, e⟩ <;> rw [e]
    · exact wa
    · exact wb
    · exact Or.inl rfl
    · exact Or.inr (List.mem_cons_self ..)

/-! ## Banners and Go-composed flows -/

/-- One step of the banner fold or the session: keep `m` if it dominates `c`, else join. -/
theorem step_dominates {m c : Mk} (wm : WF m) (wc : WF c) :
    let m' := if DomGo m c then m else joinGo m c
    WF m' ∧ Dom (sem m') (sem m) ∧ Dom (sem m') (sem c) := by
  intro m'
  by_cases h : DomGo m c
  · have e : m' = m := ite_eq_left h
    rw [e]; exact ⟨wm, dom_refl _, (domGo_iff m c).1 h⟩
  · have e : m' = joinGo m c := ite_eq_right h
    rw [e]; exact ⟨wf_joinGo wm wc, joinGo_upper_left wm wc, joinGo_upper_right wm wc⟩

/-- A result's banner is exactly the connector's marking, or there is no result at all. -/
theorem result_is_connector {noCred : Mk → Bool} {conn b : Mk} (h : resultGo noCred conn = some b) :
    b = conn := by
  unfold resultGo at h
  split at h
  · cases h; rfl
  · cases h

/-- `Join` refuses exactly when the least upper bound has no banner. -/
theorem refusedGo_iff (a b : Mk) : refusedGo a b ↔ ¬ Bannerable (lub (sem a) (sem b)) := by
  have hf : ((sem a).fgi.join (sem b).fgi ≠ .absent) ↔ (a.hasFgi = true ∨ b.hasFgi = true) := by
    cases ha : a.hasFgi <;> cases hb : b.hasFgi <;> by_cases ea : a.fgi = [] <;>
      by_cases eb : b.fgi = [] <;> simp [sem, ha, hb, ea, eb, Fgi.join]
  simp only [refusedGo, Bannerable, Classical.not_not]
  show _ ↔ (0 < max a.level b.level ∧ max a.level b.level < confidential ∧
    ((sem a).fgi.join (sem b).fgi ≠ .absent ∨ a.aea ++ b.aea ≠ [] ∨ a.nonic ++ b.nonic ≠ []))
  rw [hf]; simp only [or_assoc]

/-- Every join `Join` returns is a label a banner can print. -/
theorem joinChecked_bannerable {long : Mk → Bool} {a b j : Mk} (h : joinChecked long a b = some j) :
    Bannerable (sem j) := by
  unfold joinChecked at h
  split at h
  · cases h
  · rename_i hr
    split at h
    · cases h
    cases h
    intro ⟨h1, h2, h3⟩
    apply hr
    refine ⟨h1, h2, ?_⟩
    have e1 : (sem (joinGo a b)).aea = a.aea ++ b.aea := rfl
    have e2 : (sem (joinGo a b)).nonic = a.nonic ++ b.nonic := rfl
    rw [e1, e2] at h3
    rcases h3 with h3 | h3 | h3
    · cases ha : a.hasFgi <;> cases hb : b.hasFgi
      · exact absurd (by simp [sem, joinGo, joinBase, ha, hb]) h3
      all_goals simp
    · exact Or.inr (Or.inr (Or.inl h3))
    · exact Or.inr (Or.inr (Or.inr h3))

/-- A banner-length refusal never changes a join; it only removes it. -/
theorem joinChecked_long_only_refuses {long : Mk → Bool} {a b j : Mk}
    (h : joinChecked long a b = some j) : joinChecked noLong a b = some j := by
  unfold joinChecked at h ⊢
  split at h
  · cases h
  · split at h
    · cases h
    · simpa [noLong, *] using h

theorem flowGo_sound (long : Mk → Bool) (tr : List (Bool × Mk)) (htr : ∀ p ∈ tr, WF p.2) :
    ∀ (lbl : Option Mk) (seen : List Mk),
      (∀ m, lbl = some m → WF m ∧ ∀ l ∈ seen, Dom (sem m) (sem l)) →
      ∀ p ∈ flowGo (fun a b => decide (DomGo a b)) long lbl seen tr, ∀ l ∈ p.2, Dom (sem p.1) (sem l) := by
  induction tr with
  | nil => intro _ _ _ p hp; exact absurd hp (by simp [flowGo])
  | cons e t ih =>
    intro lbl seen hs
    have ht : ∀ p ∈ t, WF p.2 := fun p hp => htr p (List.mem_cons_of_mem _ hp)
    have we : WF e.2 := htr e (List.mem_cons_self ..)
    obtain ⟨r, x⟩ := e
    cases r with
    | true =>
      apply ih ht
      intro m hm
      cases lbl with
      | none => cases hm
      | some m0 =>
        obtain ⟨wl, hs0⟩ := hs m0 rfl
        simp only [Option.bind, joinChecked] at hm
        split at hm
        · cases hm
        split at hm
        · cases hm
        · cases hm
          refine ⟨wf_joinGo wl we, fun l hl => ?_⟩
          rcases List.mem_cons.1 hl with rfl | hl
          · exact joinGo_upper_right wl we
          · exact dom_trans (joinGo_upper_left wl we) (hs0 l hl)
    | false =>
      intro p hp
      cases lbl with
      | none => exact ih ht none seen hs p hp
      | some m =>
        obtain ⟨wl, hs0⟩ := hs m rfl
        by_cases hd : DomGo x m
        · simp only [flowGo, decide_eq_true hd, ite_true] at hp
          rcases List.mem_cons.1 hp with rfl | hp
          · exact fun l hl => dom_trans ((domGo_iff _ _).1 hd) (hs0 l hl)
          · exact ih ht _ seen hs p hp
        · simp only [flowGo, decide_eq_false hd] at hp
          exact ih ht _ seen hs p hp

/-- The gateway check composed from Go's `Join` and `Dominates` never writes down. -/
theorem flowGo_no_write_down (long : Mk → Bool) (tr : List (Bool × Mk)) (htr : ∀ p ∈ tr, WF p.2) :
    ∀ p ∈ flowGo (fun a b => decide (DomGo a b)) long (some zero) [] tr, ∀ l ∈ p.2,
      Dom (sem p.1) (sem l) :=
  flowGo_sound long tr htr (some zero) [] (fun m hm => by cases hm; exact ⟨Or.inl rfl, fun _ h => nomatch h⟩)

end Contract.AsBuilt

namespace Contract

/-! ## Admission -/

theorem validate_ok {a : Assignment} {now : Int} {o : Output} (h : validate a now o = .ok ()) :
    bindingOk a o = true ∧ assignedOk a o = true ∧ metadataOk o = true ∧ windowOk now o = true := by
  unfold validate at h
  cases hb : bindingOk a o <;> cases ha : assignedOk a o <;> cases hm : metadataOk o <;>
    cases hw : windowOk now o <;> simp [hb, ha, hm, hw] at h ⊢

theorem admit_ok {a : Assignment} {hw : Nat} {now : Int} {e : Envelope}
    (h : admit a hw now (some e) = .ok ()) :
    validate a now (native a e) = .ok () ∧ hw ≤ e.profile.seq := by
  cases hv : validate a now (native a e) with
  | error r => simp [admit, hv] at h
  | ok u =>
    cases u
    refine ⟨rfl, ?_⟩
    simp [admit, hv] at h
    omega

/-- An admitted profile was validly signed, and only by keys of the trust root. -/
theorem admit_signed {a : Assignment} {hw : Nat} {now : Int} {e : Envelope}
    (h : admit a hw now (some e) = .ok ()) :
    e.sigValid = true ∧ e.signers ≠ [] ∧ ∀ s ∈ e.signers, s ∈ a.trust := by
  have hb := (validate_ok (admit_ok h).1).1
  simp [bindingOk, native] at hb
  obtain ⟨⟨⟨h1, h2⟩, h3⟩, _⟩ := hb
  exact ⟨h1, h2, h3⟩

/-- An admitted profile is the one assigned: tenant, deployment, profile, payload, manifest. -/
theorem admit_assigned {a : Assignment} {hw : Nat} {now : Int} {e : Envelope}
    (h : admit a hw now (some e) = .ok ()) :
    e.profile.tenant = a.tenant ∧ e.profile.deployment = a.deployment ∧
    e.profile.profile = a.profile ∧ e.payload = a.payload ∧ e.profile.manifest = a.manifest := by
  have v := validate_ok (admit_ok h).1
  have hb := v.1
  have ha := v.2.1
  simp [bindingOk, native] at hb
  simp [assignedOk, native] at ha
  obtain ⟨⟨⟨⟨ht, hd⟩, hp⟩, _⟩, hm⟩ := ha
  exact ⟨ht, hd, hp, hb.2, hm⟩

/-- A profile for one tenant never activates on a device assigned to another. -/
theorem admit_tenant {a : Assignment} {hw : Nat} {now : Int} {e : Envelope}
    (hne : e.profile.tenant ≠ a.tenant) : admit a hw now (some e) ≠ .ok () :=
  fun h => hne (admit_assigned h).1

/-- An admitted profile is inside its validity window now. -/
theorem admit_window {a : Assignment} {hw : Nat} {now : Int} {e : Envelope}
    (h : admit a hw now (some e) = .ok ()) :
    e.profile.notBefore ≤ now ∧ now < e.profile.expires := by
  have hw' := (validate_ok (admit_ok h).1).2.2.2
  simp [windowOk, native] at hw'
  obtain ⟨⟨_, h1⟩, h2⟩ := hw'
  exact ⟨h1, h2⟩

/-- No envelope, no admission. -/
theorem admit_required (a : Assignment) (hw : Nat) (now : Int) :
    admit a hw now none = .error .required := rfl

/-- An invalid signature is never admitted. -/
theorem admit_unsigned {a : Assignment} {hw : Nat} {now : Int} {e : Envelope}
    (hs : e.sigValid = false) : admit a hw now (some e) ≠ .ok () :=
  fun h => by have := (admit_signed h).1; rw [hs] at this; cases this

/-- A sequence below the high-water mark is refused. -/
theorem admit_rollback {a : Assignment} {hw : Nat} {now : Int} {e : Envelope}
    (hlt : e.profile.seq < hw) : admit a hw now (some e) ≠ .ok () :=
  fun h => absurd (admit_ok h).2 (Nat.not_le.2 hlt)

/-- The sequences a device admits never decrease, and never go below where it started. -/
theorem admitted_monotone (a : Assignment) (tr : List (Int × Option Envelope)) :
    ∀ hw, (admitted a hw tr).Pairwise (· ≤ ·) ∧ ∀ s ∈ admitted a hw tr, hw ≤ s := by
  induction tr with
  | nil => intro hw; exact ⟨List.Pairwise.nil, fun _ h => nomatch h⟩
  | cons x t ih =>
    intro hw
    obtain ⟨now, e⟩ := x
    cases e with
    | none => simpa [admitted, admit] using ih hw
    | some e =>
      cases h : admit a hw now (some e) with
      | error r => simpa [admitted, h] using ih hw
      | ok u =>
        have hle := (admit_ok h).2
        obtain ⟨p, m⟩ := ih e.profile.seq
        simp only [admitted, h]
        refine ⟨List.pairwise_cons.2 ⟨m, p⟩, ?_⟩
        intro s hs
        rcases List.mem_cons.1 hs with rfl | hs
        · exact hle
        · exact Nat.le_trans hle (m s hs)

end Contract

namespace Contract.AsBuilt

open Contract Contract.Mutants

/-! ## Facts about today's Go -/

/-- With the assignment fixed, two admissions carry the same payload digest; if that digest
    determines the profile, they are the same profile, so the pin alone stops a rollback. -/
theorem asbuilt_pin_blocks_rollback (digest : Profile → Nat)
    (inj : ∀ p q, digest p = digest q → p = q) {a : Assignment} {n1 n2 : Int} {o1 o2 : Output}
    (d1 : o1.payload = digest o1.profile) (d2 : o2.payload = digest o2.profile)
    (v1 : validateGo a n1 o1 = .ok ()) (v2 : validateGo a n2 o2 = .ok ()) :
    o1.profile = o2.profile := by
  have b1 := (validate_ok v1).1
  have b2 := (validate_ok v2).1
  simp [bindingOk] at b1 b2
  exact inj _ _ (d1 ▸ d2 ▸ b1.2.trans b2.2.symm)

/-- But the pin is the administrator's: re-pinning an older profile's digest rolls the device
    back, and nothing on the device notices. -/
theorem asbuilt_repin_rolls_back :
    admitGo asg 0 (some (env 5)) = .ok () ∧
    admitGo { asg with payload := 9 } 0 (some { env 3 with payload := 9 }) = .ok () := by decide

/-- The schema-1 verifier checks the tenant (#160): a profile naming tenant 2 is refused under a
    pin for tenant 1's payload, as the schema-2 verifier refuses it, and tenant 1's is admitted. -/
theorem asbuilt_v1_checks_tenant :
    validateV1 asg 0 (native asg otherTenant) = false ∧
    validateGo asg 0 (native asg otherTenant) = .error .assignment ∧
    validateV1 asg 0 (native asg (env 5)) = true := by decide

/-- Under activation records the schema-1 verifier admits only the sequence the activation names:
    sequence 5 is admitted under an activation naming 5 and refused under one naming 4. -/
theorem asbuilt_v1_activation_binds_sequence :
    validateV1 asg 0 (native asg (env 5)) (some 5) = true ∧
    validateV1 asg 0 (native asg (env 5)) (some 4) = false := by decide

/-- A release build admits no request without a profile, whatever the policy says (#160). -/
theorem asbuilt_v1_release_needs_profile (devSameUid verifierConfigured : Bool) (a : Assignment)
    (now : Int) : admitV1 false devSameUid verifierConfigured a now none = false := by
  simp [admitV1]

/-- Only the `uatnoprofile` build, with the development flag and no verifier, admits no profile. -/
theorem asbuilt_v1_uat_no_profile (a : Assignment) (now : Int) :
    admitV1 true true false a now none = true := rfl

/-- Disjoint REL TO lists: Go's `Join` adds NF where the least upper bound needs only USA. -/
theorem asbuilt_join_not_least_rel :
    ¬ Dom (lub (sem relUsaGbr) (sem relUsaFra)) (sem (joinGo relUsaGbr relUsaFra)) := by decide

/-- DISPLAY ONLY now meets by country: FVEY and GBR share GBR, and Go's `Join` keeps exactly that
    (before this base it met by token and dropped GBR). -/
theorem asbuilt_join_least_disp :
    Dom (lub (sem dispFvey) (sem dispGbr)) (sem (joinGo dispFvey dispGbr)) := by decide

end Contract.AsBuilt
