/-
  Onboarding.Levels: a small concrete marking order for the kernel-decided cases and the
  vectors. A marking is a level (0 UNCLASSIFIED, 1 CONFIDENTIAL, 2 SECRET, 3 TOP SECRET) and a
  set of compartments (1 ALPHA, 2 BRAVO). `a` dominates `b` when a's level is at least b's and a
  holds every compartment b holds. It is a stand-in: the vectors switch to the contract model's
  marking order (Go's `marking.Dominates`) once testifysec/formal/contract merges.
-/
import Onboarding.Model

namespace Onboarding

structure Lv where
  level : Nat
  comps : List Nat
  deriving DecidableEq, Repr

def Lv.dom (a b : Lv) : Bool := decide (b.level ≤ a.level) && b.comps.all (fun c => decide (c ∈ a.comps))

def Lv.join (a b : Lv) : Lv := ⟨max a.level b.level, a.comps ++ b.comps⟩

instance : MarkingOrder Lv where
  dom := Lv.dom
  join := Lv.join
  dom_refl a := by simp [Lv.dom]
  dom_trans {a b c} h1 h2 := by
    simp only [Lv.dom, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at *
    exact ⟨Nat.le_trans h2.1 h1.1, fun x hx => h1.2 x (h2.2 x hx)⟩
  join_left a b := by
    show (decide (a.level ≤ max a.level b.level) &&
      a.comps.all (fun c => decide (c ∈ a.comps ++ b.comps))) = true
    rw [Bool.and_eq_true]
    exact ⟨decide_eq_true (Nat.le_max_left _ _),
      List.all_eq_true.2 fun x hx => decide_eq_true (List.mem_append_left _ hx)⟩
  join_right a b := by
    show (decide (b.level ≤ max a.level b.level) &&
      b.comps.all (fun c => decide (c ∈ a.comps ++ b.comps))) = true
    rw [Bool.and_eq_true]
    exact ⟨decide_eq_true (Nat.le_max_right _ _),
      List.all_eq_true.2 fun x hx => decide_eq_true (List.mem_append_right _ hx)⟩

def U : Lv := ⟨0, []⟩
def C : Lv := ⟨1, []⟩
def S : Lv := ⟨2, []⟩
def TS : Lv := ⟨3, []⟩
def SA : Lv := ⟨2, [1]⟩

def Lv.name (m : Lv) : String :=
  let lvl := match m.level with
    | 0 => "UNCLASSIFIED" | 1 => "CONFIDENTIAL" | 2 => "SECRET" | _ => "TOP SECRET"
  let comp (c : Nat) : String := match c with | 1 => "ALPHA" | 2 => "BRAVO" | n => "C" ++ toString n
  if m.comps.isEmpty then lvl else lvl ++ "//" ++ "/".intercalate (m.comps.map comp)

end Onboarding
