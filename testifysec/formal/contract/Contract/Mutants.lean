/-
  Contract.Mutants: each guard the theorems rest on, switched off, with the concrete case that
  breaks the matching theorem. A theorem that still held with its guard removed would prove
  nothing about the guard. Each mutant names the theorem it kills (Proofs.lean).

  `fgi_old_not_transitive`  `Dominates` before this change let a named FGI list hold concealed
                            FGI. Dominance stops being transitive (kills `domGo_trans`).
  `fgi_old_write_down`      With it, a session sends content to a sink that does not dominate a
                            label it read (kills `flowGo_no_write_down`).
  `last_read_write_down`    The session label is the last read instead of the join of all reads
                            (kills `no_write_down`).
  `meet_ignored`            The join keeps the first release list (kills `lub_upper_right`).
  `cats_dropped`            The join drops categories below confidential (kills `lub_upper_left`).
  `concealed_lost`          Joining concealed FGI with a named list keeps the list (kills
                            `lub_upper_left`).
  `join_ignores_caveats`    `Join` never refuses: controlled-unclassified joined with a non-IC
                            marking yields a label no banner can print (kills
                            `joinChecked_bannerable`).
  `no_high_water`           The device admits whatever validates, as the Go verifier does today:
                            an older profile is admitted after a newer one (kills
                            `admitted_monotone`).
  `no_tenant_check`         Validation skips the assignment check: another tenant's profile is
                            admitted (kills `admit_tenant`).
  `no_window`               Validation skips the window: an expired profile is admitted (kills
                            `admit_window`).
  `any_signer`              The native verifier admits a signer outside the trust root (kills
                            `admit_signed`).
-/
import Contract.AsBuilt

namespace Contract.Mutants

open Contract Contract.AsBuilt

/-! ## Markings -/

def gbr : Tok := 3
def fra : Tok := 5

def sFgiFra : Mk := { level := 3, hasFgi := true, fgi := [fra] }
def sFgiConcealed : Mk := { level := 3, hasFgi := true }
def sFgiGbr : Mk := { level := 3, hasFgi := true, fgi := [gbr] }

theorem fgi_old_not_transitive :
    DomGoOld sFgiFra sFgiConcealed ∧ DomGoOld sFgiConcealed sFgiGbr ∧
    ¬ DomGoOld sFgiFra sFgiGbr := by decide

theorem fgi_fixed_refuses : ¬ DomGo sFgiFra sFgiConcealed := by decide

/-- Read concealed FGI, then FGI GBR, then send to a sink accredited for FGI FRA only. -/
def fgiTrace : List (Bool × Mk) := [(true, sFgiConcealed), (true, sFgiGbr), (false, sFgiFra)]

theorem fgi_old_write_down :
    ∃ p ∈ flowGo (fun a b => decide (DomGoOld a b)) noLong (some {level := 0}) [] fgiTrace,
      ∃ l ∈ p.2, ¬ Dom (sem p.1) (sem l) := by
  refine ⟨(sFgiFra, [sFgiGbr, sFgiConcealed]), by decide, sFgiGbr, by decide, by decide⟩

theorem fgi_fixed_denies : flowGo (fun a b => decide (DomGo a b)) noLong (some {level := 0}) [] fgiTrace = [] := by
  decide

/-- Markings where Go's `Join` is above the least upper bound (AsBuilt facts, not mutants). -/
def relUsaGbr : Mk := { level := 3, relTo := [0, gbr] }
def relUsaFra : Mk := { level := 3, relTo := [0, fra] }
def dispFvey : Mk := { level := 3, disp := [0, 100] }
def dispGbr : Mk := { level := 3, disp := [0, gbr] }

/-! ## Refused joins -/

def cuiL : Mk := { level := 1 }
def uLimdis : Mk := { level := 0, nonic := [500] }

/-- A `Join` that never refuses: controlled-unclassified joined with a non-IC marking gives a
    label no banner can print (kills `joinChecked_bannerable`). -/
def joinNoRefusal (a b : Mk) : Option Mk := some (joinGo a b)

theorem join_ignores_caveats :
    ∃ j, joinNoRefusal cuiL uLimdis = some j ∧ ¬ Bannerable (sem j) :=
  ⟨joinGo cuiL uLimdis, rfl, by decide⟩

theorem join_refuses : joinChecked noLong cuiL uLimdis = none := by decide

/-! ## Join -/

def secretL : Label := { Label.bot with level := 3 }
def unclassL : Label := Label.bot
def ctiL : Label := { Label.bot with level := 1, cats := [400] }

/-- The session label is the last label read. -/
def deliveredLast (lbl : Label) (seen : List Label) : List Flow → List (Label × List Label)
  | [] => []
  | .read l :: t => deliveredLast l (l :: seen) t
  | .send s :: t =>
    if Dom s lbl then (s, seen) :: deliveredLast lbl seen t else deliveredLast lbl seen t

theorem last_read_write_down :
    ∃ p ∈ deliveredLast Label.bot [] [.read secretL, .read unclassL, .send unclassL],
      ∃ l ∈ p.2, ¬ Dom p.1 l :=
  ⟨(unclassL, [unclassL, secretL]), by decide, secretL, by decide, by decide⟩

def lubKeepRel (a b : Label) : Label := { lub a b with rel := a.rel }
def lubNoCats (a b : Label) : Label := { lub a b with cats := [] }

def relGbr : Label := { secretL with rel := some [0, gbr] }

theorem meet_ignored : ¬ Dom (lubKeepRel unclassL relGbr) relGbr := by decide

theorem cats_dropped : ¬ Dom (lubNoCats ctiL unclassL) ctiL := by decide

def fgiJoinKeepsList : Fgi → Fgi → Fgi
  | .concealed, .of l => .of l
  | a, b => a.join b

def lubLosesConcealed (a b : Label) : Label := { lub a b with fgi := fgiJoinKeepsList a.fgi b.fgi }

def concealedL : Label := { secretL with fgi := .concealed }
def gbrFgiL : Label := { secretL with fgi := .of [gbr] }

theorem concealed_lost : ¬ Dom (lubLosesConcealed concealedL gbrFgiL) concealedL := by decide

/-! ## Admission -/

def asg : Assignment :=
  { tenant := 1, deployment := 1, profile := 1, payload := 10, manifest := 7, trust := [42] }

def prof (seq : Nat) : Profile :=
  { tenant := 1, deployment := 1, profile := 1, seq := seq, notBefore := -3600, expires := 3600,
    backendOk := true, manifest := 7 }

def env (seq : Nat) : Envelope := { profile := prof seq, payload := 10, signers := [42], sigValid := true }

/-- The as-built device, run over a trace: no high-water. -/
def admittedGo (a : Assignment) : List (Int × Option Envelope) → List Nat
  | [] => []
  | (now, e) :: t =>
    match admitGo a now e, e with
    | .ok (), some e => e.profile.seq :: admittedGo a t
    | _, _ => admittedGo a t

theorem no_high_water : admittedGo asg [(0, some (env 5)), (0, some (env 3))] = [5, 3] := by decide

theorem high_water_refuses : admitted asg 0 [(0, some (env 5)), (0, some (env 3))] = [5] := by decide

def validateNoTenant (a : Assignment) (now : Int) (o : Output) : Decision :=
  validate { a with tenant := o.profile.tenant, deployment := o.profile.deployment,
                    profile := o.profile.profile } now o

def otherTenant : Envelope := { env 5 with profile := { prof 5 with tenant := 2 } }

theorem no_tenant_check :
    validateNoTenant asg 0 (native asg otherTenant) = .ok () ∧
    otherTenant.profile.tenant ≠ asg.tenant := by decide

def validateNoWindow (a : Assignment) (_now : Int) (o : Output) : Decision :=
  validate a o.profile.notBefore o

theorem no_window :
    validateNoWindow asg 7200 (native asg (env 5)) = .ok () ∧ ¬ (7200 < (env 5).profile.expires) := by
  decide

def nativeAnySigner (a : Assignment) (e : Envelope) : Output :=
  { native a e with admitted := e.sigValid && decide (e.signers ≠ []) }

def strangerSigned : Envelope := { env 5 with signers := [43] }

theorem any_signer :
    validate asg 0 (nativeAnySigner asg strangerSigned) = .ok () ∧ 43 ∉ asg.trust := by decide

end Contract.Mutants
