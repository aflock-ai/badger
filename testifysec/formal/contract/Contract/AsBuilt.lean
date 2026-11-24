/-
  Contract.AsBuilt: what badger's Go does today, transcribed definition by definition, each cited
  by path, line range and the sha256 of those lines (the formal step's `formal-cite.py`
  re-hashes every citation). Proofs about these definitions are in Proofs.lean; the vectors check that
  the Go code computes exactly what these transcriptions compute.

  Markings (testifysec/connectors/internal/marking): `Mk` is the Go `Marking` struct with tokens
  as numbers; `domGo` and `joinGo` follow `Dominates` and `Join` line by line; `sem` is the label
  a banner means. Only one tetragraph is modelled (FVEY); the vectors check its members against
  tokens.json.

  Admission (testifysec/broker): `validateGo` is `vzbackend.validateAdmission`, schema 2, which
  checks the tenant, deployment, profile, backend and manifest. `validateV1` is the top-level
  broker's `verifyAdmission`, schema 1, which binds the pinned payload digest and checks the
  tenant, deployment and profile against its policy. Neither keeps a high-water sequence.
-/
import Contract.Spec

namespace Contract.AsBuilt

open Contract

/-! ## Tokens the Go code names -/

def usa : Tok := 0
def fveyTok : Tok := 100
/-- FVEY's members in tokens.json: AUS, CAN, GBR, NZL, USA. -/
def fveyMembers : List Tok := [1, 2, 3, 4, 0]
/-- The no-foreign-release control (portion NF). -/
def nf : Tok := 200

/-! ## The Go marking -/

/-  The Go engine (engine.go) reads its rules from a scheme; the default, us-gov, is the preset
    below, and every definition in this section transcribes the engine with that preset's values
    (levels by position, the no-foreign-release control, USA as the home country, categories
    absorbed from confidential). -/
-- cite: testifysec/connectors/internal/marking/schemes/us-gov.json:1-21 sha256:28c5b310977bf9b5cd4142ce1da34497b82deee197ce563e1a7f4b5311757eba

/-- `marking.Marking`. A list here is a Go slice; `[]` is nil. The Go struct's `Tags` (another
    scheme's groups) and its scheme are empty for every us-gov marking and are not modelled. -/
-- cite: testifysec/connectors/internal/marking/marking.go:26-43 sha256:4fd28648d7c8bcda86636ce99e02178ec5e79037dd4a1efe2ef2693212e79653
structure Mk where
  level    : Nat
  sci      : List Tok := []
  sap      : List Tok := []
  aea      : List Tok := []
  fgi      : List Tok := []
  hasFgi   : Bool := false
  cats     : List Tok := []
  controls : List Tok := []
  nonic    : List Tok := []
  relTo    : List Tok := []
  disp     : List Tok := []
  deriving DecidableEq, Repr

/-- `expand`: a tetragraph becomes its members, anything else itself. -/
-- cite: testifysec/connectors/internal/marking/engine.go:671-684 sha256:2318a6111603ef65a643d5d904d5fbd7eac16503fcc6519d15470422c3e2c740
def expand (l : List Tok) : List Tok :=
  l.flatMap (fun c => if c = fveyTok then fveyMembers else [c])

/-- `release`'s first three cases: no foreign release, a REL TO list, or classified. -/
def release0 (m : Mk) : Option (List Tok) :=
  if nf ∈ m.controls then some [usa]
  else if m.relTo ≠ [] then some (expand m.relTo)
  else if confidential ≤ m.level then some [usa]
  else none

/-- `release`: none is unrestricted. Below confidential a DISPLAY ONLY list also restricts
    release to USA (display, not release, to the listed countries). -/
-- cite: testifysec/connectors/internal/marking/engine.go:654-669 sha256:902d6e3233d7454b2bcd5ef04842074178b71171191549005642baa638196c56
def release (m : Mk) : Option (List Tok) :=
  match release0 m with
  | some r => some r
  | none => if m.disp ≠ [] then some [usa] else none

/-- `display`: who may see the content, those it may be released to plus DISPLAY ONLY; none is
    anyone. -/
-- cite: testifysec/connectors/internal/marking/engine.go:638-651 sha256:6a4f9a8bfbe13158a2b92e2628df3cbc6e935779a682e717abd4c52b57b680c6
def display (m : Mk) : Option (List Tok) := (release m).map (· ++ expand m.disp)

/-- The label a Go marking means. -/
def sem (m : Mk) : Label :=
  { level := m.level, sci := m.sci, sap := m.sap, aea := m.aea, nonic := m.nonic,
    controls := m.controls
    fgi := if !m.hasFgi then .absent else if m.fgi = [] then .concealed else .of m.fgi
    cats := if m.level < confidential then m.cats else []
    rel := release m, disp := display m }

/-- `Dominates`. The FGI case refuses when `a` names countries and `b` conceals them; display is
    compared like release (a's audience within b's). -/
-- cite: testifysec/connectors/internal/marking/engine.go:501-521 sha256:9e42289d0d5ba3ce176657bc7162d2ff3a54f6817324ff63e0d00fa3ba849500
def DomGo (a b : Mk) : Prop :=
  ¬ (a.level < b.level ∨ ¬ Sup a.sci b.sci ∨ ¬ Sup a.sap b.sap ∨ ¬ Sup a.aea b.aea ∨
     ¬ Sup a.nonic b.nonic ∨ ¬ Sup a.controls b.controls ∨
     (b.hasFgi = true ∧ (a.hasFgi = false ∨ (a.fgi ≠ [] ∧ (b.fgi = [] ∨ ¬ Sup a.fgi b.fgi)))) ∨
     (a.level < confidential ∧ ¬ Sup a.cats b.cats)) ∧
  RelLe (release a) (release b) ∧ RelLe (display a) (display b)

instance (a b : Mk) : Decidable (DomGo a b) := by unfold DomGo; infer_instance

/-- The `Dominates` FGI case before this change: a named list held concealed FGI. -/
def DomGoOld (a b : Mk) : Prop :=
  ¬ (a.level < b.level ∨ ¬ Sup a.sci b.sci ∨ ¬ Sup a.sap b.sap ∨ ¬ Sup a.aea b.aea ∨
     ¬ Sup a.nonic b.nonic ∨ ¬ Sup a.controls b.controls ∨
     (b.hasFgi = true ∧ (a.hasFgi = false ∨ (a.fgi ≠ [] ∧ ¬ Sup a.fgi b.fgi))) ∨
     (a.level < confidential ∧ ¬ Sup a.cats b.cats)) ∧
  RelLe (release a) (release b) ∧ RelLe (display a) (display b)

instance (a b : Mk) : Decidable (DomGoOld a b) := by unfold DomGoOld; infer_instance

/-- `Join`'s release case: the REL TO list and the controls. Where neither release contains the
    other, the countries both share (USA aside) become the list, or NF when there are none. -/
def lOf (a b : Mk) : List Tok :=
  ((release a).getD []).filter (fun c => decide (c ∈ (release b).getD [] ∧ c ≠ usa))

def relCtl (a b : Mk) : List Tok × List Tok :=
  if RelLe (release a) (release b) then (a.relTo, a.controls ++ b.controls)
  else if RelLe (release b) (release a) then (b.relTo, a.controls ++ b.controls)
  else if lOf a b = [] then ([], a.controls ++ b.controls ++ [nf])
  else (usa :: lOf a b, a.controls ++ b.controls)

/-- `Join` without its display part. -/
def joinBase (a b : Mk) : Mk :=
  let concealed := (a.hasFgi && decide (a.fgi = [])) || (b.hasFgi && decide (b.fgi = []))
  { level := max a.level b.level, sci := a.sci ++ b.sci, sap := a.sap ++ b.sap,
    aea := a.aea ++ b.aea, nonic := a.nonic ++ b.nonic, controls := (relCtl a b).2
    hasFgi := a.hasFgi || b.hasFgi
    fgi := if (a.hasFgi || b.hasFgi) && !concealed then a.fgi ++ b.fgi else []
    cats := if max a.level b.level < confidential then a.cats ++ b.cats else []
    relTo := if nf ∈ (relCtl a b).2 then [] else (relCtl a b).1
    disp := [] }

/-- `Join`'s display part: the join may be shown only where both may. Countries in that audience
    the join's release does not already reach (USA aside) become DISPLAY ONLY; an unrestricted
    release is restricted to the list. -/
def extraOf (d : List Tok) (rj : Option (List Tok)) : List Tok :=
  d.filter (fun c => decide (c ≠ usa) && (match rj with | none => true | some r => decide (c ∉ r)))

def joinDisp (a b : Mk) : List Tok :=
  match relMeet (display a) (display b) with
  | none => []
  | some d =>
    if extraOf d (release (joinBase a b)) ≠ [] ∨ release (joinBase a b) = none
    then usa :: extraOf d (release (joinBase a b)) else []

/-- `Join`'s marking when it does not refuse (see `joinChecked`). -/
-- cite: testifysec/connectors/internal/marking/engine.go:529-573 sha256:db4032f9c7a97f429e99a8832f7cd8f74dc2e052c91879e3a2206c941c4e0b06
-- cite: testifysec/connectors/internal/marking/engine.go:575-624 sha256:a675341278bb509e0e768338ae2d3820c0047ce4fcfc2c9245a5abd9dc2f04db
def joinGo (a b : Mk) : Mk := { joinBase a b with disp := joinDisp a b }

/-- A REL TO list the parser accepts starts with USA. Every proof about `joinGo` assumes it. -/
def WF (m : Mk) : Prop := m.relTo = [] ∨ usa ∈ m.relTo

/-! ## Result banners -/

/-- `Server.result`: a connector carries one classification, its administrator-set marking, and
    every result carries it as the banner. Nothing in the result changes it. `noCred` stands for
    the check that neither the rendered banner nor the administrator's notice line holds a
    credential the client sent (for one connector's configuration the notice is fixed, so the
    check is a predicate on the marking); when it fails the result carries no banner and no
    content (`none`), which a consumer denies. The notice is its own line, never part of the
    banner, so it does not change the marking a result carries. -/
-- cite: testifysec/connectors/internal/connector/output.go:23-34 sha256:6196030b9e7dd9ad2895180409b8da003e09380975afb8fc6e7a98a0a21bdaef
def resultGo (noCred : Mk → Bool) (conn : Mk) : Option Mk :=
  if noCred conn then some conn else none

/-! ## Session flow, composed from the Go primitives

  The gateway's flow check is specified (testifysec/CONNECTORS.md) but not built yet. `flowGo`
  is the composition it must make: `Join` on every read, `Dominates` on every send, and a session
  whose `Join` is refused delivers nothing again. -/

/-- `Join`'s refusal: a joined level above UNCLASSIFIED and below CONFIDENTIAL carrying FGI,
    atomic-energy or non-IC markings has no banner. -/
def refusedGo (a b : Mk) : Prop :=
  0 < max a.level b.level ∧ max a.level b.level < confidential ∧
  (a.hasFgi = true ∨ b.hasFgi = true ∨ a.aea ++ b.aea ≠ [] ∨ a.nonic ++ b.nonic ≠ [])

instance (a b : Mk) : Decidable (refusedGo a b) := by unfold refusedGo; infer_instance

/-- `Join` with its errors: `none` is `ErrNoBanner`, or `ErrBannerTooLong` when `long` holds of
    the joined marking. `long` stands for `len(j.String()) > maxBanner`; the model does not render
    banners, so it is a parameter and every theorem about `joinChecked` holds for all of them. -/
-- cite: testifysec/connectors/internal/marking/engine.go:529-573 sha256:db4032f9c7a97f429e99a8832f7cd8f74dc2e052c91879e3a2206c941c4e0b06
-- cite: testifysec/connectors/internal/marking/engine.go:575-624 sha256:a675341278bb509e0e768338ae2d3820c0047ce4fcfc2c9245a5abd9dc2f04db
def joinChecked (long : Mk → Bool) (a b : Mk) : Option Mk :=
  if refusedGo a b then none else if long (joinGo a b) then none else some (joinGo a b)

/-- No banner too long: the vectors' joins all render under the cap, and the harness fails on any
    refusal the vectors do not predict. -/
def noLong : Mk → Bool := fun _ => false

/-- `(true, l)` reads `l`; `(false, s)` sends to sink `s`. Returns each delivered send with the
    labels read before it. -/
def flowGo (dom : Mk → Mk → Bool) (long : Mk → Bool) (lbl : Option Mk) (seen : List Mk) :
    List (Bool × Mk) → List (Mk × List Mk)
  | [] => []
  | (true, l) :: t => flowGo dom long (lbl.bind (joinChecked long · l)) (l :: seen) t
  | (false, s) :: t =>
    match lbl with
    | none => flowGo dom long lbl seen t
    | some m => if dom s m then (s, seen) :: flowGo dom long lbl seen t else flowGo dom long lbl seen t

/-- The zero `Marking`, a session's label before it reads anything. -/
def zero : Mk := { level := 0 }

/-! ## Profile admission -/

/-- `vzbackend.validateAdmission` with `admissionValidity` and `validAdmissionMetadata`: the
    same four checks in the same order as the contract's `validate`. -/
-- cite: testifysec/broker/vzbackend/admission.go:42-57 sha256:815d77922ae5f6f3db0c658f4429e74eee7475b5da0b585592b40a10e2b30ed1
-- cite: testifysec/broker/vzbackend/admission.go:58-66 sha256:cda316e7feabae06c4ff3440ca41731fdfe622ee22bce6dd184e843335b32485
-- cite: testifysec/broker/vzbackend/admission.go:68-80 sha256:979cfb9eeaf405e8cb9826935bff1eefc2195d7b367609929b6c71f42e655d14
def validateGo (a : Assignment) (now : Int) (o : Output) : Decision := validate a now o

/-- The vzbackend device as built: no high-water, every validated profile runs. -/
def admitGo (a : Assignment) (now : Int) : Option Envelope → Decision
  | none => .error .required
  | some e => validateGo a now (native a e)

/-- The top-level broker's `verifyAdmission`, schema 1. It binds the payload digest and the
    window, and (since #160) checks the admitted tenant, deployment and profile against its own
    policy and the sequence's range. It keeps no high-water sequence. With no verifier configured
    it admits a request with no envelope only in a build tagged `uatnoprofile` with the
    development flag set; `developmentNoProfile` is the constant false in every other build.
    Under activation records (`act = some s`) the admitted profile's sequence must be exactly the
    one the activation names; without them (`none`, the default) any sequence in range. -/
-- cite: testifysec/broker/admission.go:48-57 sha256:f737b85d2300d4540c123f55dbcf60963c6ce3f9300b706b20562ab2e83b4d4c
-- cite: testifysec/broker/admission.go:120-129 sha256:b3260105f2c76129a44b878666b6e8834871ceb5d6bfd176399b4b85175c1b07
-- cite: testifysec/broker/admission.go:135-137 sha256:dad6a6d6190b0d43e635fd089665944ade1692dfc3d053bfd0e87eabd48261a3
-- cite: testifysec/broker/admission_release.go:1-7 sha256:b132e96dbae19d5796e0501e1897f427c87bfc2ecee91de8a844cc4204501302
def validateV1 (a : Assignment) (now : Int) (o : Output) (act : Option Nat := none) : Bool :=
  o.schemaOk && o.admitted && o.scopeOk && o.envelopeOk && decide (o.payload = a.payload) &&
  decide (o.signers ≠ []) && decide (o.profile.notBefore ≤ now) &&
  decide (now < o.profile.expires) && decide (o.profile.notBefore < o.profile.expires) &&
  decide (o.profile.tenant = a.tenant) && decide (o.profile.deployment = a.deployment) &&
  decide (o.profile.profile = a.profile) && decide (1 ≤ o.profile.seq) && decide (o.profile.seq ≤ maxSeq) &&
  (match act with | none => true | some s => decide (o.profile.seq = s))

/-- `uatBuild` is `developmentNoProfile`: true only under the `uatnoprofile` build tag. -/
def admitV1 (uatBuild devSameUid verifierConfigured : Bool) (a : Assignment) (now : Int) :
    Option Output → Bool
  | none => !verifierConfigured && uatBuild && devSameUid
  | some o => verifierConfigured && validateV1 a now o

end Contract.AsBuilt
