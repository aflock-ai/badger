/-
  Contract.Model: the vocabulary of the badger platform contract.

  The contract is what any platform (the TestifySec platform, badger's own lightweight portal,
  or a third party) must honour to hand a device a profile and to label what a session reads and
  sends. Three surfaces are pinned today:

    * classification labels and their dominance order (testifysec/connectors/internal/marking);
    * the session high-water mark and the no-write-down flow rule (testifysec/CONNECTORS.md);
    * signed profile admission on the device (testifysec/broker).

  Every token (a country, a control, a compartment, a key id) is a `Nat`. Only equality matters
  to the contract, and `Nat` keeps every concrete check decidable by the kernel. `Names.lean`
  maps the numbers back to the strings the Go code uses when the vectors are written.
-/
namespace Contract

abbrev Tok := Nat

/-! ## Token sets -/

/-- `Sup a b`: `a` carries every token `b` carries (lists read as sets). -/
def Sup (a b : List Tok) : Prop := ∀ x ∈ b, x ∈ a

instance (a b : List Tok) : Decidable (Sup a b) :=
  inferInstanceAs (Decidable (∀ x ∈ b, x ∈ a))

/-- Equal as sets. -/
def SetEq (a b : List Tok) : Prop := Sup a b ∧ Sup b a

/-! ## Labels: the semantic marking

  A label is what a banner means for dominance, after the parser's syntax is gone: release is an
  explicit country set (tetragraphs expanded), display likewise, retired-marking flags
  dropped. Levels: 0 unclassified, 1 controlled unclassified, 2 confidential, 3 secret,
  4 top secret. -/

def confidential : Nat := 2

/-- Foreign government information. `concealed` is FGI whose source countries are not named:
    it may come from anyone, so it sits above every named list. -/
inductive Fgi where
  | absent
  | concealed
  | of (countries : List Tok)
  deriving DecidableEq, Repr

structure Label where
  level    : Nat
  sci      : List Tok
  sap      : List Tok
  aea      : List Tok
  nonic    : List Tok
  /-- every dissemination control, classified and controlled-unclassified ones alike -/
  controls : List Tok
  fgi      : Fgi
  /-- controlled-unclassified categories; they only order labels below confidential -/
  cats     : List Tok
  /-- countries the content may be released to; `none` is anyone -/
  rel      : Option (List Tok)
  /-- who may see the content (those it may be released to, plus a DISPLAY ONLY list), expanded;
      `none` is anyone -/
  disp     : Option (List Tok)
  deriving DecidableEq, Repr

/-- The label a session starts with, before it has read anything. -/
def Label.bot : Label :=
  { level := 0, sci := [], sap := [], aea := [], nonic := [], controls := [], fgi := .absent,
    cats := [], rel := none, disp := none }

/-! ## Profile admission

  A profile is the signed, assigned configuration a device runs under. The platform publishes it;
  the device admits it or refuses it. Digests and key ids are numbers: only equality matters. -/

/-- What the device's administrator pinned: which tenant, deployment and profile this device
    belongs to, the digest of the one payload it may run, and the trust root's key ids. -/
structure Assignment where
  tenant     : Nat
  deployment : Nat
  profile    : Nat
  payload    : Nat
  manifest   : Nat
  trust      : List Nat
  deriving DecidableEq, Repr

/-- The signed profile's claims. -/
structure Profile where
  tenant     : Nat
  deployment : Nat
  profile    : Nat
  seq        : Nat
  notBefore  : Int
  expires    : Int
  /-- the profile names the backend kind this device runs -/
  backendOk  : Bool
  manifest   : Nat
  deriving DecidableEq, Repr

/-- A signed envelope as the device receives it. `sigValid` is the cryptographic fact that every
    listed signer really signed this payload; the crypto itself is abstracted (NotCovered). -/
structure Envelope where
  profile  : Profile
  payload  : Nat
  signers  : List Nat
  sigValid : Bool
  deriving DecidableEq, Repr

/-- Why a profile is refused. The first four are the Go verifier's own codes. -/
inductive Refusal where
  | output          -- malformed or out-of-range verifier output (`admission_output`)
  | binding         -- not admitted, wrong schema or scope, or not this envelope/payload
  | assignment      -- another tenant, deployment, profile, backend or manifest
  | expired         -- outside its validity window (`profile_expired`)
  | required        -- no envelope at all (`profile_required`)
  | rollback        -- older than a profile this device already admitted
  deriving DecidableEq, Repr

abbrev Decision := Except Refusal Unit

instance : DecidableEq Decision := fun a b =>
  match a, b with
  | .ok (), .ok () => isTrue rfl
  | .error x, .error y =>
    if h : x = y then isTrue (h ▸ rfl) else isFalse (fun e => h (by cases e; rfl))
  | .ok _, .error _ => isFalse (fun e => nomatch e)
  | .error _, .ok _ => isFalse (fun e => nomatch e)

end Contract
