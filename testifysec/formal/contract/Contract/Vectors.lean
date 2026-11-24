/-
  Contract.Vectors: the conformance vectors, written by `lake exe contract-vectors`.

  Every expected value here is computed by the definitions the theorems are about, so a vector is
  a theorem's instance, not a hand-written guess. The Go harnesses replay them:
    marking.dominates   Dom on the labels (= Go's Dominates, `domGo_iff`)
    marking.join        Go's Join as transcribed (`joinGo`), plus whether it is the least bound
    flow                the Go-composed session (`flowGo`) and the contract's (`decisions`)
    admission           the verifier-output checks and the refusal each must report
    admissionSequence   the device high-water rule; no Go implementation consumes these yet
    backends            backend swap, mixed trust and migration (Backends.lean): each case is
                        run against the portal and against a platform, which must agree
  Tokens are written as the Go code holds them, except dissemination controls, which are written
  as portion marks (NF, OC); a harness maps them through tokens.json.
-/
import Contract.Backends

namespace Contract.Vectors

open Contract Contract.AsBuilt

/-! ## Names -/

def tokName (t : Tok) : String :=
  match t with
  | 0 => "USA" | 1 => "AUS" | 2 => "CAN" | 3 => "GBR" | 4 => "NZL" | 5 => "FRA"
  | 100 => "FVEY"
  | 200 => "NF" | 201 => "OC"
  | 300 => "SI" | 301 => "TK"
  | 400 => "SP-CTI" | 401 => "PRVCY"
  | 500 => "LIMDIS"
  | 600 => "DOD UCNI"
  | n => "T" ++ toString n

/-! ## JSON -/

def jstr (s : String) : String := "\"" ++ s ++ "\""
def jarr (l : List String) : String := "[" ++ ", ".intercalate l ++ "]"
def jobj (kv : List (String × String)) : String :=
  "{" ++ ", ".intercalate (kv.map fun (k, v) => jstr k ++ ": " ++ v) ++ "}"
def jbool (b : Bool) : String := if b then "true" else "false"
def jtoks (l : List Tok) : String := jarr (l.eraseDups.map (jstr ∘ tokName))
def jlines (l : List String) : String := "[\n  " ++ ",\n  ".intercalate l ++ "\n ]"

def mkJson (m : Mk) : String :=
  jobj [("level", toString m.level), ("sci", jtoks m.sci), ("sap", jtoks m.sap),
    ("aea", jtoks m.aea), ("hasFgi", jbool m.hasFgi), ("fgi", jtoks m.fgi),
    ("categories", jtoks m.cats), ("controls", jtoks m.controls), ("nonic", jtoks m.nonic),
    ("relTo", jtoks m.relTo), ("displayOnly", jtoks m.disp)]

/-! ## Markings -/

def markings : List (String × Mk) :=
  [ ("u", { level := 0 }), ("cui", { level := 1 }), ("cui-cti", { level := 1, cats := [400] }),
    ("cui-prvcy", { level := 1, cats := [401] }), ("cui-nf", { level := 1, controls := [200] }),
    ("cui-rel-gbr", { level := 1, relTo := [0, 3] }), ("c", { level := 2 }), ("s", { level := 3 }),
    ("s-nf", { level := 3, controls := [200] }), ("s-oc", { level := 3, controls := [201] }),
    ("s-rel-gbr", { level := 3, relTo := [0, 3] }), ("s-rel-fra", { level := 3, relTo := [0, 5] }),
    ("s-rel-fvey", { level := 3, relTo := [0, 100] }),
    ("s-fgi-gbr", { level := 3, hasFgi := true, fgi := [3] }),
    ("s-fgi-fra", { level := 3, hasFgi := true, fgi := [5] }),
    ("s-fgi-concealed", { level := 3, hasFgi := true }),
    ("s-disp-fvey", { level := 3, disp := [0, 100] }), ("s-disp-gbr", { level := 3, disp := [0, 3] }),
    ("s-limdis", { level := 3, nonic := [500] }), ("ts-si", { level := 4, sci := [300] }),
    ("ts-si-tk", { level := 4, sci := [300, 301] }),
    ("u-limdis", { level := 0, nonic := [500] }), ("u-fgi-gbr", { level := 0, hasFgi := true, fgi := [3] }),
    ("u-ucni", { level := 0, aea := [600] }) ]

def mk (i : Nat) : Mk := (markings.getD i ("", { level := 0 })).2

def indexed : List (Nat × String × Mk) := (List.range markings.length).zip markings

def pairs : List (Nat × Nat) :=
  (List.range markings.length).flatMap fun i => (List.range markings.length).map fun j => (i, j)

def dominatesVec (p : Nat × Nat) : String :=
  jobj [("a", toString p.1), ("b", toString p.2),
    ("dominates", jbool (decide (Dom (sem (mk p.1)) (sem (mk p.2)))))]

def joinVec (p : Nat × Nat) : String :=
  let l := lub (sem (mk p.1)) (sem (mk p.2))
  match joinChecked noLong (mk p.1) (mk p.2) with
  | none => jobj [("a", toString p.1), ("b", toString p.2), ("refused", "true")]
  | some j =>
    jobj [("a", toString p.1), ("b", toString p.2), ("refused", "false"), ("join", mkJson j),
      ("least", jbool (decide (Dom l (sem j))))]

/-! ## Flow -/

/-- `decisions` for the Go composition. -/
def decisionsGo (lbl : Option Mk) : List (Bool × Mk) → List Bool
  | [] => []
  | (true, l) :: t => decisionsGo (lbl.bind (joinChecked noLong · l)) t
  | (false, s) :: t =>
    (match lbl with | none => false | some m => decide (DomGo s m)) :: decisionsGo lbl t

def toFlow (e : Bool × Nat) : Flow := if e.1 then .read (sem (mk e.2)) else .send (sem (mk e.2))

def idx (n : String) : Nat := (markings.findIdx? (·.1 == n)).getD 0

def r (n : String) : Bool × Nat := (true, idx n)
def s (n : String) : Bool × Nat := (false, idx n)

def traces : List (String × List (Bool × Nat)) :=
  [ ("no write down to a lower level", [r "s", s "u", s "s", s "ts-si"]),
    ("a classified sink holds categories", [r "cui-cti", s "cui", s "cui-cti", s "s"]),
    ("concealed FGI is held only by concealed FGI",
      [r "s-fgi-concealed", r "s-fgi-gbr", s "s-fgi-fra", s "s-fgi-concealed"]),
    ("disjoint release lists", [r "s-rel-gbr", r "s-rel-fra", s "s-rel-gbr", s "s", s "s-nf"]),
    ("no foreign release stays home", [r "cui-nf", s "s-rel-gbr", s "s-nf"]),
    ("display only meets", [r "s-disp-fvey", r "s-disp-gbr", s "s", s "s-disp-gbr"]),
    ("compartments accumulate", [r "ts-si", r "s-oc", s "ts-si", s "ts-si-tk"]),
    ("a join with no banner stops the session", [r "cui-cti", r "u-limdis", s "s", s "ts-si"]),
    ("caveats above the controlled-unclassified level join", [r "u-fgi-gbr", r "s", s "s-fgi-gbr"]) ]

def flowVec (t : String × List (Bool × Nat)) : String :=
  let go := decisionsGo (some { level := 0 }) (t.2.map fun e => (e.1, mk e.2))
  let spec := decisions Label.bot (t.2.map toFlow)
  jobj [("name", jstr t.1),
    ("events", jarr (t.2.map fun e => jobj [(if e.1 then "read" else "send", toString e.2)])),
    ("expect", jarr (go.map jbool)), ("contract", jarr (spec.map jbool))]

/-- The Go composition never allows a send the contract denies. Checked when writing. -/
def flowSound : Bool :=
  traces.all fun t =>
    let go := decisionsGo (some { level := 0 }) (t.2.map fun e => (e.1, mk e.2))
    let spec := decisions Label.bot (t.2.map toFlow)
    (go.zip spec).all fun (g, c) => !g || c

/-! ## Admission -/

def refusalCode : Refusal → String
  | .output => "admission_output" | .binding => "admission_binding"
  | .assignment => "admission_assignment" | .expired => "profile_expired"
  | .required => "profile_required" | .rollback => "profile_rollback"

def decisionCode : Decision → String
  | .ok () => "ok"
  | .error r => refusalCode r

def asg : Assignment := Mutants.asg

def base : Output := native asg (Mutants.env 5)

def withProfile (f : Profile → Profile) : Output := { base with profile := f base.profile }

def admissionCases : List (String × Output) :=
  [ ("admitted", base),
    ("wrong schema", { base with schemaOk := false }),
    ("verifier refused", { base with admitted := false }),
    ("wrong scope", { base with scopeOk := false }),
    ("another envelope", { base with envelopeOk := false }),
    ("another payload", { base with payload := 11 }),
    ("another tenant", withProfile ({ · with tenant := 2 })),
    ("another deployment", withProfile ({ · with deployment := 2 })),
    ("another profile", withProfile ({ · with profile := 2 })),
    ("another backend", withProfile ({ · with backendOk := false })),
    ("another manifest", withProfile ({ · with manifest := 8 })),
    ("sequence zero", withProfile ({ · with seq := 0 })),
    ("sequence one", withProfile ({ · with seq := 1 })),
    ("sequence at the JSON limit", withProfile ({ · with seq := maxSeq })),
    ("sequence past the JSON limit", withProfile ({ · with seq := maxSeq + 1 })),
    ("no signer", { base with signers := [] }),
    ("sixteen signers", { base with signers := List.range 16 }),
    ("seventeen signers", { base with signers := List.range 17 }),
    ("a signer twice", { base with signers := [42, 42] }),
    ("malformed signer id", { base with signerIdsOk := false }),
    ("malformed digest", { base with digestsOk := false }),
    ("not yet valid", withProfile ({ · with notBefore := 3600, expires := 7200 })),
    ("expired", withProfile ({ · with notBefore := -7200, expires := -3600 })),
    ("empty window", withProfile ({ · with notBefore := -3600, expires := -3600 })),
    ("binding before assignment", { withProfile ({ · with tenant := 2 }) with payload := 11 }),
    ("assignment before metadata", withProfile ({ · with tenant := 2, seq := 0 })),
    ("metadata before window", withProfile ({ · with seq := 0, notBefore := 3600, expires := 7200 })) ]

def admissionVec (c : String × Output) : String :=
  let o := c.2
  let same (b : Bool) := jstr (if b then "assigned" else "other")
  jobj [("name", jstr c.1), ("schemaVersion", if o.schemaOk then "2" else "1"),
    ("admitted", jbool o.admitted),
    ("scope", jstr (if o.scopeOk then "profile-admission-only" else "profile-admission")),
    ("envelope", jstr (if o.envelopeOk then "match" else "other")),
    ("payload", same (o.payload == asg.payload)),
    ("tenant", same (o.profile.tenant == asg.tenant)),
    ("deployment", same (o.profile.deployment == asg.deployment)),
    ("profile", same (o.profile.profile == asg.profile)),
    ("backend", same o.profile.backendOk),
    ("manifest", same (o.profile.manifest == asg.manifest)),
    ("sequence", toString o.profile.seq),
    ("notBefore", toString o.profile.notBefore), ("expires", toString o.profile.expires),
    ("signers", toString o.signers.length),
    ("duplicateSigner", jbool (!decide o.signers.Nodup)),
    ("signerIdsValid", jbool o.signerIdsOk), ("digestsValid", jbool o.digestsOk),
    ("expect", jstr (decisionCode (validate asg 0 o)))]

def sequenceTraces : List (Nat × List Nat) :=
  [ (0, [5, 3, 5, 6, 1]), (4, [3, 4, 9]), (0, [1, 2, 3]), (7, [6, 5]) ]

def sequenceVec (t : Nat × List Nat) : String :=
  let tr := t.2.map fun n => ((0 : Int), some (Mutants.env n))
  jobj [("highWater", toString t.1), ("sequences", jarr (t.2.map toString)),
    ("admitted", jarr ((admitted asg t.1 tr).map toString))]

/-! ## Backends: swap, mixed trust, migration -/

section
open Contract.Backends

def own (b : Backend) (seq ps : Nat) : Signed :=
  { body := .activation 1 1 1 200 ps seq, notBefore := -3600, expires := 3600, leaf := b.leaf,
    sigValid := true }

def resetFor (b : Backend) (device rseq : Nat) : Signed :=
  { body := .reset 1 1 device rseq 0 0, notBefore := -3600, expires := 3600, leaf := b.leaf,
    sigValid := true }

/-- Each case for backend `b`, whose peer is `o`: name, which roots are pinned, device state,
    artifact. The expected outcome is `step`'s. -/
def backendCases (b o : Backend) : List (String × String × DState × Signed) :=
  [ ("own root, above the high-water", "own", dev40, own b 41 12),
    ("old root after a switch", "own", dev40, own o 41 12),
    ("both roots pinned", "both", dev40, own o 41 12),
    ("migration restarted the sequence", "own", dev40, own b 1 12),
    ("migration carried the floor", "own", dev40, own b 41 13),
    ("replay at the high-water", "own", dev40, own b 40 12),
    ("profile sequence below its high-water", "own", dev40, own b 41 11),
    ("signed window outside the leaf", "own", dev40, { own b 41 12 with expires := 518401 }),
    ("another deployment", "own", dev40,
      { own b 41 12 with body := .activation 1 2 1 200 12 41 }),
    ("expired", "own", dev40, { own b 41 12 with notBefore := -7200, expires := -3600 }),
    ("bad signature", "own", dev40, { own b 41 12 with sigValid := false }),
    ("leaf without the signer identity", "own", dev40,
      { own b 41 12 with leaf := { b.leaf with identityOk := false } }),
    ("reset for this device", "own", dev40, resetFor b 7 1),
    ("reset for another device", "own", dev40, resetFor b 9 1),
    ("reset replayed", "own", { dev40 with resetHw := 1 }, resetFor b 7 1),
    ("reset under the old root", "own", dev40, resetFor o 7 1) ]

def trustFor (b o : Backend) (kind : String) : Trust :=
  if kind == "both" then { trustOf b 1 1 1 7 with roots := [b.root, o.root] } else trustOf b 1 1 1 7

def refuseCode : Option Refuse → String
  | none => "ok" | some .chain => "chain" | some .expired => "expired"
  | some .assignment => "assignment" | some .rollback => "rollback"

def backendOutcomes (b o : Backend) : List String :=
  (backendCases b o).map fun (_, k, s, x) => refuseCode (outcome (step (trustFor b o k) s 0 x))

def signedJson (b : Backend) (x : Signed) : String :=
  let who := jstr (if x.leaf.root == b.root then "own" else "other")
  let same (v : Nat) (w : Nat) := jstr (if v == w then "assigned" else "other")
  let body := match x.body with
    | .activation tn dp pf dg ps sq =>
      [("kind", jstr "activation"), ("tenant", same tn 1), ("deployment", same dp 1),
       ("profile", same pf 1), ("profileDigest", toString dg), ("profileSequence", toString ps),
       ("sequence", toString sq)]
    | .reset tn dp dv rs pfl afl =>
      [("kind", jstr "reset"), ("tenant", same tn 1), ("deployment", same dp 1),
       ("device", same dv 7), ("resetSequence", toString rs), ("profileFloor", toString pfl),
       ("activationFloor", toString afl)]
  jobj (body ++ [("notBefore", toString x.notBefore), ("expires", toString x.expires),
    ("signedUnder", who), ("leafNotBefore", toString x.leaf.notBefore),
    ("leafNotAfter", toString x.leaf.notAfter), ("signerIdentity", jbool x.leaf.identityOk),
    ("signatureValid", jbool x.sigValid)])

def stateJson (s : DState) : String :=
  jobj [("activation", toString s.activationHw), ("profile", toString s.profileHw),
    ("reset", toString s.resetHw)]

/-- The vector, written from the portal's side; the platform's outcome must be the same. -/
def backendVec (c : (String × String × DState × Signed) × String × String) : String :=
  let ((name, kind, st, x), po, pl) := c
  jobj [("name", jstr name), ("pinned", jstr kind), ("highWater", stateJson st),
    ("artifact", signedJson portal x), ("expect", jstr po), ("portal", jstr po), ("platform", jstr pl)]

/-- Both backends give every case the same outcome. Checked when writing. -/
def backendsAgree : Bool := backendOutcomes portal platform == backendOutcomes platform portal

/-- The same as the check in Main, proved: the portal and a platform agree on every case. -/
theorem backends_agree : backendsAgree = true := by decide

def serveVec (d : Nat × String) : String :=
  let served (b : Backend) := (b.serve d.1 (own b 41 12)).isSome
  jobj [("device", jstr d.2), ("portal", jbool (served portal)), ("platform", jbool (served platform))]

def serveCases : List (Nat × String) := [(7, "enrolled"), (8, "revoked"), (9, "unknown")]

end

/-! ## The document -/

def document : String :=
  "{\n" ++
  " \"schema\": \"badger.contract.vectors/v1\",\n" ++
  " \"generator\": \"testifysec/formal/contract: lake exe contract-vectors\",\n" ++
  " \"tetragraphs\": " ++ jobj [("FVEY", jtoks fveyMembers)] ++ ",\n" ++
  " \"timeUnit\": \"seconds relative to the verifier's now\",\n" ++
  " \"markings\": " ++ jlines (indexed.map fun (i, n, m) =>
      jobj [("index", toString i), ("name", jstr n), ("marking", mkJson m)]) ++ ",\n" ++
  " \"dominates\": " ++ jlines (pairs.map dominatesVec) ++ ",\n" ++
  " \"join\": " ++ jlines (pairs.map joinVec) ++ ",\n" ++
  " \"flow\": " ++ jlines (traces.map flowVec) ++ ",\n" ++
  " \"admission\": " ++ jlines (admissionCases.map admissionVec) ++ ",\n" ++
  " \"admissionSequence\": " ++ jlines (sequenceTraces.map sequenceVec) ++ ",\n" ++
  " \"backends\": " ++ jlines (((backendCases Backends.portal Backends.platform).zip
      ((backendOutcomes Backends.portal Backends.platform).zip
        (backendOutcomes Backends.platform Backends.portal))).map backendVec) ++ ",\n" ++
  " \"serve\": " ++ jlines (serveCases.map serveVec) ++ "\n" ++
  "}\n"

end Contract.Vectors
