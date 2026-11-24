import VexRatchet.Model

/-!
# What the VEX ratchet guarantees, today and with a repository-scoped external

The general theorems are the safety properties. The `Example` section replays the motivating
case under each design.
-/

namespace VexRatchet

/-! ## Which statements exempt -/

/-- Only `not_affected` with a justification, or `fixed`, exempts. -/
theorem exempts_iff (st : Status) :
    st.exempts = true ↔ (∃ j, st = .notAffected (some j)) ∨ st = .fixed := by
  cases st with
  | notAffected j => cases j <;> simp [Status.exempts]
  | fixed => simp [Status.exempts]
  | affected => simp [Status.exempts]
  | underInvestigation => simp [Status.exempts]

theorem affected_never_exempts : Status.affected.exempts = false := rfl
theorem underInvestigation_never_exempts : Status.underInvestigation.exempts = false := rfl
theorem unjustified_never_exempts : (Status.notAffected none).exempts = false := rfl

/-- A statement exempts one vulnerability in one package and nothing else. -/
theorem statement_exempts_iff (a : Advisory) (st : Statement) :
    st.exempts a = true ↔ st.vuln = a.vuln ∧ st.pkg = a.pkg ∧ st.status.exempts = true := by
  simp [Statement.exempts, and_assoc]

/-! ## Discovery and the commit binding -/

theorem mem_discover (s : Store) (seeds : List Subject) (e : Envelope) :
    e ∈ discover s seeds ↔ e ∈ s ∧ ∃ x ∈ e.subjects, x ∈ seeds := by
  simp [discover, List.mem_filter, List.any_eq_true]

/-- Today (no repository scope) a standalone VEX counts for a push only when it is bound to
the pushed commit. -/
theorem admitted_today_is_bound (P : Policy) (now : Nat) (c : Commit) (e : Envelope)
    (hoff : P.repoScoped = false) (h : admitted P now c e = true) : bound c e = true := by
  simp [admitted, hoff] at h
  exact h.2

/-- So a VEX recorded at another commit is refused, however it was found. This is why a VEX
kept in Archivista cannot serve a later push today. -/
theorem other_commit_vex_refused_today (P : Policy) (now : Nat) (c c' : Commit) (e : Envelope)
    (hoff : P.repoScoped = false) (hc : e.commit = some c') (hne : c' ≠ c) :
    admitted P now c e = false := by
  cases h : admitted P now c e
  · rfl
  · have hb := admitted_today_is_bound P now c e hoff h
    simp [bound, hc, hne] at hb

/-- An envelope bound to no commit (a bare predicate without a declared `commitSubject`, such
as a platform VSA whose subjects are `artifact:<digest>`) is never bound, so nested VSA
chaining through the platform verify door cannot serve a bound push. -/
theorem unbound_envelope_never_bound (c : Commit) (e : Envelope) (h : e.commit = none) :
    bound c e = false := by
  simp [bound, h]

/-- With the repository scope, a VEX that is not bound to the commit still needs the
repository subject. -/
theorem repo_scoped_admission (P : Policy) (now : Nat) (c : Commit) (e : Envelope)
    (hnb : bound c e = false) (h : admitted P now c e = true) :
    P.repoScoped = true ∧ P.repoSubject ∈ e.subjects := by
  simp [admitted, hnb] at h
  refine ⟨?_, ?_⟩ <;> simp_all

/-- A stale VEX, or one with no TSA time, is refused, whether or not it is the commit's own. -/
theorem stale_vex_refused (P : Policy) (now : Nat) (c : Commit) (e : Envelope)
    (hstale : fresh P.maxAge now e.tsa = false) : admitted P now c e = false := by
  simp [admitted, hstale]

/-- A VEX signed by another tenant's agent, the platform, or a person is never admitted. -/
theorem foreign_vex_refused (P : Policy) (now : Nat) (c : Commit) (e : Envelope)
    (h : agentOf P.tenant e.signer = false) : admitted P now c e = false := by
  simp [admitted, h]

/-! ## Only the latest VEX document decides -/

/-- Every statement the external contributes comes from an admitted VEX envelope at the
latest admitted TSA time. An older document superseded by a newer one contributes nothing,
which is how an exemption is revoked. -/
theorem external_from_latest (P : Policy) (found : List Envelope) (now : Nat) (c : Commit)
    (st : Statement) (h : st ∈ externalStatements P found now c) :
    ∃ e ∈ found, admitted P now c e = true ∧
      e.tsa = latestTime (found.filter (admitted P now c)) ∧ st ∈ vexStatements e := by
  simp only [externalStatements, List.mem_filter, List.mem_flatMap, Bool.and_eq_true,
    beq_iff_eq] at h
  obtain ⟨⟨e, ⟨⟨hf, hadm⟩, ht, _⟩, hst⟩, _⟩ := h
  exact ⟨e, hf, hadm, ht, hst⟩

/-- At a tie for the latest time, a statement counts only if every latest document carries
it: a revocation signed at the same moment as an exemption revokes it. -/
theorem tie_needs_agreement (P : Policy) (found : List Envelope) (now : Nat) (c : Commit)
    (st : Statement) (e : Envelope) (he : e ∈ found) (hadm : admitted P now c e = true)
    (ht : e.tsa = latestTime (found.filter (admitted P now c)))
    (hsome : (latestTime (found.filter (admitted P now c))).isSome = true)
    (hmiss : st ∉ vexStatements e) : st ∉ externalStatements P found now c := by
  intro h
  simp only [externalStatements, List.mem_filter, List.all_eq_true] at h
  have := h.2 e ⟨⟨he, hadm⟩, by simp [ht, hsome]⟩
  simp at this
  exact hmiss this

/-! ## Steps stay bound, with or without the repository scope -/

/-- A push is accepted only on a scan bound to the pushed commit and recorded by this
tenant's agent, whose every advisory is allowed. The repository scope widens where VEX may
come from; it never lets another commit's scan witness the push. -/
theorem push_needs_own_scan (P : Policy) (s : Store) (c : Commit) (now : Nat)
    (h : pushAccepts P s c now = true) :
    ∃ e ∈ s, e.commit = some c ∧ agentOf P.tenant e.signer = true ∧
      ∃ advs inline, e.body = .scan advs inline ∧
        ∀ a ∈ advs, covered P (externalStatements P (discover s (c :: [P.repoSubject])) now c)
          inline now a = true := by
  simp only [pushAccepts, List.any_eq_true] at h
  obtain ⟨e, he, hp⟩ := h
  have hs := ((mem_discover _ _ e).mp he).1
  unfold scanPasses at hp
  cases hb : e.body with
  | scan advs inline =>
    simp [hb, bound, List.all_eq_true] at hp
    exact ⟨e, hs, hp.1.1, hp.1.2, advs, inline, hb, hp.2⟩
  | vex _ => simp [hb] at hp
  | vsa _ => simp [hb] at hp

/-! ## The ratchet -/

/-- One new advisory that nothing allows fails the scan. -/
theorem new_advisory_fails (P : Policy) (ext : List Statement) (now : Nat) (c : Commit)
    (e : Envelope) (advs : List Advisory) (inline : List Statement) (a : Advisory)
    (hb : e.body = .scan advs inline) (ha : a ∈ advs)
    (hnew : covered P ext inline now a = false) : scanPasses P ext now c e = false := by
  unfold scanPasses
  simp only [hb]
  cases h : advs.all (covered P ext inline now)
  · simp
  · simp only [List.all_eq_true] at h
    rw [h a ha] at hnew
    exact absurd hnew (by decide)

/-- Fixing advisories never turns a pass into a fail. -/
theorem fixing_keeps_pass (P : Policy) (ext inline : List Statement) (now : Nat)
    (advs advs' : List Advisory) (hsub : ∀ a ∈ advs', a ∈ advs)
    (h : advs.all (covered P ext inline now) = true) :
    advs'.all (covered P ext inline now) = true := by
  simp [List.all_eq_true] at h ⊢
  exact fun a ha => h a (hsub a ha)

/-- An inline statement older than `maxAge` by its own timestamp exempts nothing. -/
theorem stale_inline_exempts_nothing (P : Policy) (now : Nat) (a : Advisory) (st : Statement)
    (hold : st.issued + P.maxAge < now) : inlineApplies P now a st = false := by
  have : ¬ now ≤ st.issued + P.maxAge := Nat.not_le.mpr hold
  simp [inlineApplies, within, this]

/-! ## The motivating case under each design -/

namespace Example

def ghsa : Advisory := { vuln := "GHSA-26w7-cxv4-gfx2", pkg := "astro" }

def notAffected (issued : Nat) : Statement :=
  { vuln := ghsa.vuln, pkg := ghsa.pkg,
    status := .notAffected (some .vulnerableCodeNotInExecutePath), issued := issued }

def repo : Subject := "repository:https://github.com/aflock-ai/badger"
def agent : Principal := .agent "testifysec" "claude-badger"

def today (rs : Bool) : Policy :=
  { tenant := "testifysec", baseline := [], maxAge := 365, repoSubject := repo,
    repoScoped := rs }

/-- A VEX document recorded in Archivista on day 0, while main was at c1. -/
def vexDay0 : Envelope :=
  { body := .vex [notAffected 0], commit := some "c1", subjects := ["c1", repo],
    signer := agent, tsa := some 0 }

/-- The push of c2 on day 90 carries the advisory and no VEX of its own. -/
def scanC2 : Envelope :=
  { body := .scan [ghsa] [], commit := some "c2", subjects := ["c2"], signer := agent,
    tsa := some 90 }

/-- The same push when the VEX lives in `.vex/` and is read in the push's own run. -/
def scanC2Inline : Envelope :=
  { body := .scan [ghsa] [notAffected 0], commit := some "c2", subjects := ["c2"],
    signer := agent, tsa := some 90 }

/-- Today, a VEX kept in Archivista does not serve a later commit: the binding refuses it. -/
example : pushAccepts (today false) [vexDay0, scanC2] "c2" 90 = false := by decide

/-- Today, the same VEX read from the repository in the push's own run does. -/
example : pushAccepts (today false) [scanC2Inline] "c2" 90 = true := by decide

/-- With a repository-scoped external, the VEX in Archivista serves the push of c2. -/
example : pushAccepts (today true) [vexDay0, scanC2] "c2" 90 = true := by decide

/-- A year and a day later it no longer does. -/
example : pushAccepts (today true) [vexDay0, scanC2] "c2" 366 = false := by decide

/-- A VEX bound to the pushed commit itself expires too: day 90 accepted, day 366 refused. -/
def vexBoundC2 : Envelope :=
  { body := .vex [notAffected 0], commit := some "c2", subjects := ["c2"], signer := agent,
    tsa := some 0 }

example : pushAccepts (today false) [vexBoundC2, scanC2] "c2" 90 = true := by decide
example : pushAccepts (today false) [vexBoundC2, scanC2] "c2" 366 = false := by decide

/-- A newer, empty VEX document revokes every earlier exemption. -/
def revokeAll : Envelope :=
  { body := .vex [], commit := some "c1c", subjects := [repo], signer := agent, tsa := some 30 }

example : pushAccepts (today true) [vexDay0, revokeAll, scanC2] "c2" 90 = false := by decide

/-- An empty document signed at the same moment as the exemption still revokes it. -/
def revokeSameDay : Envelope := { revokeAll with tsa := some 0 }

example : pushAccepts (today true) [vexDay0, revokeSameDay, scanC2] "c2" 90 = false := by decide

/-- Two documents at the same moment that both carry the statement keep it. -/
def vexDay0Copy : Envelope := { vexDay0 with commit := some "c1d" }

example : pushAccepts (today true) [vexDay0, vexDay0Copy, scanC2] "c2" 90 = true := by decide

/-- A newer VEX document that drops the statement revokes the exemption. -/
def vexDay30 : Envelope :=
  { body := .vex [{ notAffected 30 with vuln := "GHSA-other" }], commit := some "c1b",
    subjects := [repo], signer := agent, tsa := some 30 }

example : pushAccepts (today true) [vexDay0, vexDay30, scanC2] "c2" 90 = false := by decide

/-- Another commit's clean scan never witnesses the push, even with the repository scope. -/
def cleanScanC1 : Envelope :=
  { body := .scan [] [], commit := some "c1", subjects := ["c1", repo], signer := agent,
    tsa := some 90 }

example : pushAccepts (today true) [cleanScanC1] "c2" 90 = false := by decide

end Example

end VexRatchet
