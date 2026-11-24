/-
  Contract.Spec: what the contract requires, as executable definitions.

  Markings: `Dom a b` (a may hold b, no write down) and `lub` (the least label dominating both,
  the session high-water update).
  Flow: a session's label is the `lub` of everything it read; a send is allowed only to a sink
  whose accreditation dominates that label.
  Admission: the device's verifier output is checked in a fixed order, and the device keeps a
  high-water sequence so an older profile is refused after a newer one was admitted.
-/
import Contract.Model

namespace Contract

/-! ## Dominance -/

/-- `a.Holds b`: FGI `a` may hold FGI `b`. Concealed FGI is held only by concealed FGI. -/
def Fgi.Holds : Fgi → Fgi → Prop
  | _, .absent => True
  | .concealed, _ => True
  | .of a, .of b => Sup a b
  | _, _ => False

instance (a b : Fgi) : Decidable (a.Holds b) := by
  cases a <;> cases b <;> unfold Fgi.Holds <;> infer_instance

/-- `RelLe x y`: release `x` is no wider than release `y` (`none` is anyone). -/
def RelLe : Option (List Tok) → Option (List Tok) → Prop
  | _, none => True
  | none, some _ => False
  | some x, some y => Sup y x

instance (x y : Option (List Tok)) : Decidable (RelLe x y) := by
  cases x <;> cases y <;> unfold RelLe <;> infer_instance

/-- `Dom a b`: a system or sink accredited at `a` may hold content labelled `b`. -/
def Dom (a b : Label) : Prop :=
  b.level ≤ a.level ∧ Sup a.sci b.sci ∧ Sup a.sap b.sap ∧ Sup a.aea b.aea ∧
  Sup a.nonic b.nonic ∧ Sup a.controls b.controls ∧ a.fgi.Holds b.fgi ∧
  (a.level < confidential → Sup a.cats b.cats) ∧ RelLe a.rel b.rel ∧ RelLe a.disp b.disp

instance (a b : Label) : Decidable (Dom a b) := by unfold Dom; infer_instance

/-- Equivalent labels: mutual dominance can only relate labels equal in this sense. -/
def Equiv (a b : Label) : Prop :=
  a.level = b.level ∧ SetEq a.sci b.sci ∧ SetEq a.sap b.sap ∧ SetEq a.aea b.aea ∧
  SetEq a.nonic b.nonic ∧ SetEq a.controls b.controls ∧ a.fgi.Holds b.fgi ∧ b.fgi.Holds a.fgi ∧
  (a.level < confidential → SetEq a.cats b.cats) ∧ RelLe a.rel b.rel ∧ RelLe b.rel a.rel ∧
  RelLe a.disp b.disp ∧ RelLe b.disp a.disp

/-! ## Join -/

def Fgi.join : Fgi → Fgi → Fgi
  | .absent, x => x
  | x, .absent => x
  | .concealed, _ => .concealed
  | _, .concealed => .concealed
  | .of a, .of b => .of (a ++ b)

def relMeet : Option (List Tok) → Option (List Tok) → Option (List Tok)
  | none, r => r
  | r, none => r
  | some x, some y => some (x.filter (fun c => decide (c ∈ y)))

/-- The least label dominating both. -/
def lub (a b : Label) : Label :=
  { level := max a.level b.level
    sci := a.sci ++ b.sci, sap := a.sap ++ b.sap, aea := a.aea ++ b.aea
    nonic := a.nonic ++ b.nonic, controls := a.controls ++ b.controls
    fgi := a.fgi.join b.fgi
    cats := if max a.level b.level < confidential then a.cats ++ b.cats else []
    rel := relMeet a.rel b.rel
    disp := relMeet a.disp b.disp }

/-! ## Session flow -/

inductive Flow where
  | read (l : Label)
  | send (sink : Label)
  deriving DecidableEq, Repr

/-- A label a banner can print. A controlled-unclassified banner holds only the control marking,
    categories and limited dissemination controls, so a label at that level carrying FGI,
    atomic-energy or non-IC markings has no banner, and joining into one is refused. -/
def Bannerable (l : Label) : Prop :=
  ¬ (0 < l.level ∧ l.level < confidential ∧ (l.fgi ≠ .absent ∨ l.aea ≠ [] ∨ l.nonic ≠ []))

instance (l : Label) : Decidable (Bannerable l) := by unfold Bannerable; infer_instance

/-- The session label after reading `l`: the join, or `none` when the join has no banner. A
    session with no label delivers nothing again (fail closed). -/
def readInto (lbl : Option Label) (l : Label) : Option Label :=
  match lbl with
  | none => none
  | some x => if Bannerable (lub x l) then some (lub x l) else none

/-- Each send's decision, in order: `true` sent, `false` denied (and recorded). -/
def decisions (lbl : Option Label) : List Flow → List Bool
  | [] => []
  | .read l :: t => decisions (readInto lbl l) t
  | .send s :: t =>
    (match lbl with | none => false | some x => decide (Dom s x)) :: decisions lbl t

/-- Every send that went out, with every label the session had read before it. -/
def delivered (lbl : Option Label) (seen : List Label) : List Flow → List (Label × List Label)
  | [] => []
  | .read l :: t => delivered (readInto lbl l) (l :: seen) t
  | .send s :: t =>
    match lbl with
    | none => delivered lbl seen t
    | some x => if Dom s x then (s, seen) :: delivered lbl seen t else delivered lbl seen t

/-! ## Profile admission -/

/-- What the native verifier reports and the Go layer checks. Booleans stand for "this field
    equals what the assignment pinned" or "is well formed"; numbers are the claims themselves. -/
structure Output where
  schemaOk    : Bool   -- schemaVersion is the one this verifier speaks
  admitted    : Bool
  scopeOk     : Bool   -- scope is profile-admission-only
  envelopeOk  : Bool   -- envelopeSha256 is the digest of the envelope the device sent
  payload     : Nat
  profile     : Profile
  signers     : List Nat
  digestsOk   : Bool   -- trust and native digests are 64-hex
  signerIdsOk : Bool   -- every signer id is a 64-hex digest
  deriving DecidableEq, Repr

def maxSeq : Nat := 9007199254740991

/-- The verifier admitted exactly this envelope, for the pinned payload. -/
def bindingOk (a : Assignment) (o : Output) : Bool :=
  o.schemaOk && o.admitted && o.scopeOk && o.envelopeOk && decide (o.payload = a.payload)

/-- The profile is the one assigned to this device. -/
def assignedOk (a : Assignment) (o : Output) : Bool :=
  decide (o.profile.tenant = a.tenant) && decide (o.profile.deployment = a.deployment) &&
  decide (o.profile.profile = a.profile) && o.profile.backendOk &&
  decide (o.profile.manifest = a.manifest)

/-- The verifier's metadata is in range. -/
def metadataOk (o : Output) : Bool :=
  decide (1 ≤ o.profile.seq) && decide (o.profile.seq ≤ maxSeq) && o.digestsOk &&
  decide (1 ≤ o.signers.length) && decide (o.signers.length ≤ 16) && o.signerIdsOk &&
  decide o.signers.Nodup

/-- Now is inside the profile's window, and the window is not empty. -/
def windowOk (now : Int) (o : Output) : Bool :=
  decide (o.profile.notBefore < o.profile.expires) && decide (o.profile.notBefore ≤ now) &&
  decide (now < o.profile.expires)

/-- The output checks, in the order a refusal must be reported. -/
def validate (a : Assignment) (now : Int) (o : Output) : Decision :=
  if !bindingOk a o then .error .binding
  else if !assignedOk a o then .error .assignment
  else if !metadataOk o then .error .output
  else if !windowOk now o then .error .expired
  else .ok ()

/-- An honest native verifier: it admits only an envelope whose signatures are valid and whose
    every signer is in the trust root, and reports the envelope's own claims. -/
def native (a : Assignment) (e : Envelope) : Output :=
  { schemaOk := true
    admitted := e.sigValid && decide (e.signers ≠ []) && decide (∀ s ∈ e.signers, s ∈ a.trust)
    scopeOk := true, envelopeOk := true, payload := e.payload, profile := e.profile
    signers := e.signers, digestsOk := true, signerIdsOk := true }

/-- The device: refuse a missing envelope, refuse what the verifier refuses, refuse anything
    older than the high-water sequence. -/
def admit (a : Assignment) (hw : Nat) (now : Int) : Option Envelope → Decision
  | none => .error .required
  | some e =>
    match validate a now (native a e) with
    | .error r => .error r
    | .ok () => if e.profile.seq < hw then .error .rollback else .ok ()

/-- Run a device over a trace of deliveries; returns the admitted sequences in order. -/
def admitted (a : Assignment) : Nat → List (Int × Option Envelope) → List Nat
  | _, [] => []
  | hw, (now, e) :: t =>
    match admit a hw now e, e with
    | .ok (), some e => e.profile.seq :: admitted a e.profile.seq t
    | _, _ => admitted a hw t

end Contract
