import JadeCore.Model

/-!
# What jade core guarantees
-/

namespace JadeCore

/-! ## The result contract -/

/-- Exit codes come from the closed set 0..4. -/
theorem exitCode_closed (o : Outcome) : exitCode o ≤ 4 := by
  cases o <;> simp [exitCode]

/-- An agent always has a next action: there is a remedy exactly when the result is not success. -/
theorem remedy_iff_failure (o : Outcome) : remedy o = none ↔ exitCode o = 0 := by
  cases o with
  | refused why => cases why <;> simp [remedy, exitCode]
  | _ => simp [remedy, exitCode]

/-- Only a transient result says retrying unchanged can help, and every transient result is 4. -/
theorem retryable_iff_transient_code (o : Outcome) : retryable o = true ↔ exitCode o = 4 := by
  cases o <;> simp [retryable, exitCode]

/-! ## Preflight -/

/-- Preflight passes exactly when every check holds. -/
theorem preflight_none_iff (r : Repo) :
    preflight r = none ↔ r.atRoot = true ∧ r.clean = true ∧ r.inProgress = false ∧ r.cilock = true := by
  unfold preflight
  cases r.atRoot <;> cases r.clean <;> cases r.inProgress <;> cases r.cilock <;> simp

/-- An invalid manifest runs nothing. -/
theorem invalid_runs_nothing (m : Manifest) (only : List Name) (repo : Repo) (head : Commit)
    (exec : Name → StepRun) (h : valid m = false) : mint m only repo head exec = .invalidManifest := by
  simp [mint, h]

/-- A refused preflight runs nothing, whatever the steps would have done. -/
theorem refusal_runs_nothing (m : Manifest) (only : List Name) (repo : Repo) (head : Commit)
    (exec : Name → StepRun) (why : Refusal) (hv : valid m = true)
    (hk : only.find? (fun n => !(names m).contains n) = none) (hp : preflight repo = some why) :
    mint m only repo head exec = .refused why := by
  unfold mint
  rw [if_neg (by simp [hv]), hk]
  simp [hp]

/-! ## Running the plan -/

def evidenceOf : Outcome → List (Name × Commit)
  | .done ev => ev
  | .stepFailed _ ev => ev
  | .headMoved _ _ _ ev => ev
  | .treeChanged _ ev => ev
  | _ => []

/-- Every piece of evidence a mint records names the commit HEAD was at when it began. -/
theorem evidence_names_head (exec : Name → StepRun) (head : Commit) :
    ∀ (ss : List Step) (ev : List (Name × Commit)), (∀ e ∈ ev, e.2 = head) →
      ∀ e ∈ evidenceOf (runSteps exec head ss ev), e.2 = head := by
  intro ss
  induction ss with
  | nil => intro ev hev e he; simp [runSteps, evidenceOf] at he; exact hev e he
  | cons s ss ih =>
    intro ev hev e he
    unfold runSteps at he
    by_cases hh : ((exec s.name).headAfter != head) = true
    · simp [hh, evidenceOf] at he
      exact hev e he
    · by_cases hc : (exec s.name).cleanAfter = true
      · by_cases hp : (exec s.name).passed = true
        · simp only [hh, hc, hp, Bool.not_true, Bool.false_eq_true, if_false] at he
          refine ih ((s.name, head) :: ev) ?_ e he
          intro x hx
          simp at hx
          rcases hx with rfl | hx
          · rfl
          · exact hev x hx
        · simp [hh, hc, hp, evidenceOf] at he
          exact hev e he
      · simp [hh, hc, evidenceOf] at he
        exact hev e he

/-- Fail fast: when the steps before `s` pass with HEAD unmoved and `s` fails without moving HEAD,
the mint stops at `s` with evidence for exactly the steps before it; nothing after `s` runs. -/
theorem fail_fast (exec : Name → StepRun) (head : Commit) (s : Step) (post : List Step)
    (hs : (exec s.name).passed = false) (hsh : (exec s.name).headAfter = head)
    (hsc : (exec s.name).cleanAfter = true) :
    ∀ (pre : List Step) (ev : List (Name × Commit)),
      (∀ p ∈ pre, (exec p.name).passed = true ∧ (exec p.name).headAfter = head ∧
        (exec p.name).cleanAfter = true) →
      runSteps exec head (pre ++ s :: post) ev =
        .stepFailed s.name (ev.reverse ++ pre.map (fun p => (p.name, head))) := by
  intro pre
  induction pre with
  | nil => intro ev _; simp [runSteps, hs, hsh, hsc]
  | cons p pre ih =>
    intro ev hpre
    obtain ⟨hp, hh, hc⟩ := hpre p (by simp)
    have := ih ((p.name, head) :: ev) (fun q hq => hpre q (by simp [hq]))
    simp [runSteps, hp, hh, hc, this]

/-- A HEAD that moves during a step stops the mint there with exit 3, whether the step passed or
failed. -/
theorem moved_head_stops (exec : Name → StepRun) (head : Commit) (s : Step) (post : List Step)
    (ev : List (Name × Commit)) (hm : (exec s.name).headAfter ≠ head) :
    exitCode (runSteps exec head (s :: post) ev) = 3 := by
  have : ((exec s.name).headAfter != head) = true := by simpa using hm
  simp [runSteps, this, exitCode]

/-- A step that leaves the tree changed stops the mint there with exit 3, whether it passed or
failed, and its evidence is not accepted. -/
theorem changed_tree_stops (exec : Name → StepRun) (head : Commit) (s : Step) (post : List Step)
    (ev : List (Name × Commit)) (hh : (exec s.name).headAfter = head)
    (hc : (exec s.name).cleanAfter = false) :
    exitCode (runSteps exec head (s :: post) ev) = 3 ∧
      evidenceOf (runSteps exec head (s :: post) ev) = ev.reverse := by
  simp [runSteps, hh, hc, exitCode, evidenceOf]

/-! ## The plan -/

/-- The plan keeps steps in file order and never invents one. -/
theorem planAux_sublist (only : List Name) : ∀ m : Manifest, (planAux only m).1.Sublist m := by
  intro m
  induction m with
  | nil => simp [planAux]
  | cons s ss ih =>
    simp only [planAux]
    split <;> simp_all [List.Sublist.cons, List.Sublist.cons₂]

/-- Everything a kept step needs is in the wanted list. -/
theorem needs_wanted (only : List Name) :
    ∀ (m : Manifest) (s : Step), s ∈ (planAux only m).1 → ∀ n ∈ s.needs, n ∈ (planAux only m).2 := by
  intro m
  induction m with
  | nil => intro s hs; simp [planAux] at hs
  | cons x xs ih =>
    intro s hs n hn
    by_cases hc : (only.contains x.name || (planAux only xs).2.contains x.name) = true
    · simp only [planAux, hc, if_true] at hs ⊢
      simp only [List.mem_cons] at hs
      simp only [List.mem_append]
      rcases hs with rfl | hs
      · exact Or.inl hn
      · exact Or.inr (ih s hs n hn)
    · simp only [planAux, hc, Bool.false_eq_true, if_false] at hs ⊢
      exact ih s hs n hn

/-- Keeping is decided by what comes after: a prefix never drops a step kept in the suffix. -/
theorem kept_append (only : List Name) :
    ∀ (pre L : List Step), ∃ K, (planAux only (pre ++ L)).1 = K ++ (planAux only L).1 := by
  intro pre
  induction pre with
  | nil => intro L; exact ⟨[], by simp⟩
  | cons x xs ih =>
    intro L
    obtain ⟨K, hK⟩ := ih L
    simp only [List.cons_append, planAux]
    split
    · exact ⟨x :: K, by simp [hK]⟩
    · exact ⟨K, by simp [hK]⟩

theorem kept_lift (only : List Name) (pre L : List Step) (s : Step)
    (h : s ∈ (planAux only L).1) : s ∈ (planAux only (pre ++ L)).1 := by
  obtain ⟨K, hK⟩ := kept_append only pre L
  rw [hK]
  exact List.mem_append_right K h

/-- Closure: if a kept step `s` needs `t` and `t` comes before it in the file, `t` is kept too. So
`--only` never runs a step without what it needs. -/
theorem plan_closed (only : List Name) (pre mid post : List Step) (t s : Step)
    (hs : s ∈ (planAux only (s :: post)).1) (hn : t.name ∈ s.needs) :
    t ∈ (planAux only (pre ++ t :: (mid ++ s :: post))).1 := by
  apply kept_lift only pre
  have hsL : s ∈ (planAux only (mid ++ s :: post)).1 := kept_lift only mid (s :: post) s hs
  have hw : t.name ∈ (planAux only (mid ++ s :: post)).2 := needs_wanted only _ s hsL t.name hn
  simp only [planAux]
  split
  · simp
  · rename_i hk
    simp only [Bool.or_eq_true, not_or] at hk
    exact absurd (List.contains_iff_mem.mpr hw) (by simpa using hk.2)

/-- In an ordered manifest, every need of a step names a step before it. -/
theorem ordered_needs_before :
    ∀ (pre before : List Step) (s : Step) (post : List Step),
      orderedAux before (pre ++ s :: post) = true → ∀ n ∈ s.needs, n ∈ names (before ++ pre) := by
  intro pre
  induction pre with
  | nil =>
    intro before s post h n hn
    simp only [List.nil_append, orderedAux, Bool.and_eq_true] at h
    have := List.all_eq_true.mp h.1 n hn
    simpa [List.append_nil] using this
  | cons p ps ih =>
    intro before s post h n hn
    simp only [List.cons_append, orderedAux, Bool.and_eq_true] at h
    have := ih (before ++ [p]) s post h.2 n hn
    simpa [List.append_assoc] using this

/-- So in a valid manifest, every need of a step names a step earlier in the file: together with
`plan_closed`, `--only` runs every step it needs. -/
theorem valid_needs_before (m pre post : Manifest) (s : Step) (hm : m = pre ++ s :: post)
    (hv : valid m = true) : ∀ n ∈ s.needs, n ∈ names pre := by
  intro n hn
  simp only [valid, Bool.and_eq_true] at hv
  have := ordered_needs_before pre [] s post (hm ▸ hv.2) n hn
  simpa using this

/-- Every selected step is kept. -/
theorem selected_kept (only : List Name) (pre post : List Step) (s : Step)
    (hsel : s.name ∈ only) : s ∈ (planAux only (pre ++ s :: post)).1 := by
  apply kept_lift only pre
  simp only [planAux]
  split
  · simp
  · rename_i hk
    simp only [Bool.or_eq_true, not_or] at hk
    exact absurd (List.contains_iff_mem.mpr hsel) (by simpa using hk.1)

/-! ## Examples: badger's steps -/

namespace Example

def st (n : Name) (needs : List Name := []) : Step := { name := n, mode := .run, argv := ["sh", n], needs }

def badger : Manifest :=
  [st "build", st "tests" ["build"], st "quality", st "vulns" ["build"],
   { name := "push-metadata", mode := .attest, argv := [], needs := [] }]

example : valid badger = true := by decide

/-- `--only vulns` runs build then vulns, in file order, and nothing else. -/
example : (plan badger ["vulns"]).map Step.name = ["build", "vulns"] := by decide

/-- A step listed before what it needs is rejected at load. -/
example : valid [st "vulns" ["build"], st "build"] = false := by decide

/-- An attest step with a command, or a run step without one, is rejected. -/
example : valid [{ name := "m", mode := .attest, argv := ["x"], needs := [] }] = false := by decide
example : valid [{ name := "m", mode := .run, argv := [], needs := [] }] = false := by decide

/-- A step that both fails and moves HEAD reports the moved HEAD (exit 3), not the failure. -/
example : exitCode (runSteps (fun _ => { passed := false, headAfter := "c2", cleanAfter := true }) "c1" badger []) = 3 := by
  decide

/-- A step that fails without moving HEAD reports the failure (exit 1). -/
example : exitCode (runSteps (fun _ => { passed := false, headAfter := "c1", cleanAfter := true }) "c1" badger []) = 1 := by
  decide

/-- A passing last step that leaves the tree dirty stops the mint with exit 3, not 0. -/
example : exitCode (runSteps (fun n => { passed := true, headAfter := "c1", cleanAfter := n != "push-metadata" })
    "c1" badger []) = 3 := by
  decide

/-- Duplicate names are rejected. -/
example : valid [st "build", st "build"] = false := by decide

end Example

end JadeCore
