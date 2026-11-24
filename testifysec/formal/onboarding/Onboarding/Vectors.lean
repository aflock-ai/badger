/-
  Onboarding.Vectors: conformance vectors, written by `lake exe onboarding-vectors`.

  Every expected value is computed by `step`, the definition the theorems are about, so each
  vector is an instance of a theorem, not a hand-written guess. The document lists the bootstrap
  config (`install`), the setup steps that staff the portal from it (each with its expected
  outcome), and the people that leaves (`initial`). Every trace starts from that state, applies
  its events in order, and records for each event the outcome, the error code on refusal, and how
  many audit records it appended (1 for a successful write, 0 otherwise). The final state lists
  every person and device and the roles whose bootstrap has ended.

  Markings use the stand-in order in Levels.lean (level and compartments). An implementation
  that uses Go's `marking.Dominates` replays them by mapping each marking to its banner
  (`banner`), which that order ranks the same way for these markings.
-/
import Onboarding.Mutants

set_option maxRecDepth 100000

namespace Onboarding.Vectors

open Onboarding Onboarding.Mutants

/-! ## JSON -/

def jstr (s : String) : String := "\"" ++ s ++ "\""
def jarr (l : List String) : String := "[" ++ ", ".intercalate l ++ "]"
def jobj (kv : List (String × String)) : String :=
  "{" ++ ", ".intercalate (kv.map fun (k, v) => jstr k ++ ": " ++ v) ++ "}"
def jbool (b : Bool) : String := if b then "true" else "false"
def jnat (n : Nat) : String := toString n
def jlines (l : List String) : String := "[\n  " ++ ",\n  ".intercalate l ++ "\n ]"

def mkJson (m : Lv) : String :=
  jobj [("level", jnat m.level), ("compartments", jarr (m.comps.map jnat)), ("banner", jstr m.name)]

def roleName : Role → String
  | .admin => "admin" | .approver => "approver" | .auditor => "auditor"

def optRole : Option Role → String
  | some r => jstr (roleName r)
  | none => "null"

def ustatus : UStatus → String
  | .pending => "pending" | .active => "active" | .offboarded => "offboarded"

def dstatus : DStatus → String
  | .pending => "pending" | .approved => "approved" | .revoked => "revoked"

def principal : Principal → String
  | .user u => jobj [("user", jnat u)]
  | .idp => jstr "idp"
  | .device d => jobj [("device", jnat d)]

def reqJson : Req → String
  | .activate u => jobj [("kind", jstr "activate"), ("user", jnat u)]
  | .grant u r => jobj [("kind", jstr "grant"), ("user", jnat u), ("role", jstr (roleName r))]
  | .publish dep => jobj [("kind", jstr "publish"), ("deployment", jnat dep)]

def evJson : Ev Lv → String
  | .invite u => jobj [("kind", jstr "invite"), ("user", jnat u)]
  | .request r => jobj [("kind", jstr "request"), ("request", reqJson r)]
  | .approve p => jobj [("kind", jstr "approve"), ("pending", jnat p)]
  | .reject p => jobj [("kind", jstr "reject"), ("pending", jnat p)]
  | .assign u d => jobj [("kind", jstr "assign"), ("user", jnat u), ("deployment", jnat d)]
  | .unassign u d => jobj [("kind", jstr "unassign"), ("user", jnat u), ("deployment", jnat d)]
  | .dropRole u => jobj [("kind", jstr "drop-role"), ("user", jnat u)]
  | .setDeployment d cs gw =>
    jobj [("kind", jstr "set-deployment"), ("deployment", jnat d),
      ("connectors", jarr (cs.map mkJson)), ("gateway", mkJson gw)]
  | .enroll k o d p =>
    jobj [("kind", jstr "enroll"), ("device", jnat k), ("owner", jnat o), ("deployment", jnat d),
      ("proof", jbool p)]
  | .approveDevice d => jobj [("kind", jstr "approve-device"), ("device", jnat d)]
  | .revokeDevice d => jobj [("kind", jstr "revoke-device"), ("device", jnat d)]
  | .offboard u => jobj [("kind", jstr "offboard"), ("user", jnat u)]
  | .pull p => jobj [("kind", jstr "pull"), ("proof", jbool p)]
  | .list => jobj [("kind", jstr "list")]
  | .readAudit => jobj [("kind", jstr "read-audit")]

def outJson : Out → List (String × String)
  | .ok => [("outcome", jstr "ok")]
  | .served => [("outcome", jstr "served")]
  | .refused r => [("outcome", jstr "refused"), ("error", jstr r.code)]

/-! ## Traces -/

theorem seed_is_setup : seed = run (install boot) setup := rfl

def traces : List (String × List (Event Lv)) :=
  [ ("onboard a person and a device; the device pulls", onboard ++ [dev 100 (.pull true)]),
    ("an unknown principal is unauthenticated", [by_ 9 (.invite 5), by_ 9 .list]),
    ("an auditor reads and changes nothing",
      onboard ++ [by_ 3 .list, by_ 3 .readAudit, by_ 3 (.invite 6), by_ 3 (.request (.publish 10)),
        by_ 3 (.revokeDevice 100), by_ 3 (.setDeployment 10 [] U), by_ 3 (.offboard 5),
        by_ 3 (.approve (P 0))]),
    ("an approver only decides",
      [by_ 2 .list, by_ 2 .readAudit, by_ 2 (.request (.publish 10)), by_ 2 (.invite 6),
        by_ 2 (.approve (P 7)), by_ 2 (.reject (P 7))]),
    ("an admin cannot approve", [by_ 1 (.invite 5), by_ 1 (.approve (P 0)), by_ 4 (.approve (P 0)),
        by_ 1 (.reject (P 0))]),
    ("publish takes an admin request and an approver's approval",
      [by_ 1 (.setDeployment 10 [S] S), by_ 1 (.request (.publish 10)), by_ 2 (.approve (P 0)),
        by_ 2 (.approve (P 0))]),
    ("an approval of a request publishing a missing deployment fails",
      [by_ 1 (.request (.publish 11)), by_ 2 (.approve (P 0))]),
    ("an approver who was the requester cannot approve", ownRequest),
    ("an approver cannot approve their own elevation", ownElevation),
    ("a lone admin cannot grant itself a role", selfGrant),
    ("a deployment's gateway must be accredited for every connector",
      [by_ 1 (.setDeployment 11 [C, TS] S), by_ 1 (.setDeployment 11 [C, S] S),
        by_ 1 (.setDeployment 12 [SA] S), by_ 1 (.setDeployment 12 [SA] SA),
        by_ 1 (.setDeployment 11 [TS] S)]),
    ("leaving the deployment stops the device pulling",
      leaveDep ++ [dev 100 (.pull true), by_ 1 (.assign 5 10), dev 100 (.pull true)]),
    ("the bootstrap principals are out once people hold their roles",
      [by_ 90 .list, by_ 91 .list, by_ 90 (.invite 6), by_ 91 (.approve (P 0))]),
    ("offboarding every admin does not bring the bootstrap admin back",
      noAdmins ++ [by_ 90 .list, by_ 90 (.invite 6), by_ 2 .list]),
    ("offboarding by the IdP revokes devices and is final",
      leave ++ [dev 100 (.pull true), by_ 1 (.approveDevice 100), by_ 1 (.invite 5),
        by_ 1 (.assign 5 10), by_ 5 (.enroll 101 5 10 true)]),
    ("an offboarded admin is unauthenticated",
      [by_ 1 (.offboard 4), by_ 4 (.invite 6), by_ 4 .list]),
    ("enrollment needs proof of possession", noPop ++ [dev 101 (.pull true)]),
    ("a pull needs a valid proof, from a known device",
      onboard ++ [dev 100 (.pull false), dev 999 (.pull true)]),
    ("an admin cannot approve their own device", ownDevice ++ [by_ 1 (.approveDevice 102)]),
    ("a revoked device is refused and stays revoked",
      onboard ++ [by_ 1 (.revokeDevice 100), dev 100 (.pull true), by_ 1 (.approveDevice 100)]),
    ("enrollment needs an active member and a new key",
      onboard ++ [by_ 5 (.enroll 101 5 11 true), by_ 5 (.enroll 100 5 10 true),
        by_ 3 (.enroll 102 3 10 true), by_ 7 (.enroll 103 7 10 true)]),
    ("a person enrolls only their own key", proxyEnroll ++ [dev 105 (.pull true)]),
    ("a pending person cannot be assigned or enroll",
      [by_ 1 (.setDeployment 10 [S] S), by_ 1 (.invite 5), by_ 1 (.assign 5 10),
        by_ 5 (.enroll 100 5 10 true), by_ 1 (.invite 5)]),
    ("a rejected activation is gone",
      [by_ 1 (.invite 5), by_ 2 (.reject (P 0)), by_ 2 (.approve (P 0)), by_ 1 (.assign 5 10)]),
    ("requesting a role the person already holds is refused",
      [by_ 1 (.request (.grant 2 .approver)), by_ 1 (.request (.grant 2 .admin))]),
    ("after hand-over a bootstrap subject is an ordinary identity",
      [by_ 1 (.invite 90), by_ 1 (.offboard 91), by_ 90 .list]),
    ("a dropped role is gone", [by_ 4 (.dropRole 1), by_ 1 .list, by_ 4 (.dropRole 4), by_ 4 .list]),
    ("publish and list, by role",
      [by_ 1 (.request (.publish 10)), by_ 2 (.request (.publish 10)),
        by_ 3 (.request (.publish 10)), by_ 9 (.request (.publish 10)), by_ 1 .list, by_ 2 .list,
        by_ 3 .list, by_ 9 .list, by_ 4 (.request (.publish 10))]) ]

def stepJson (s : State Lv) (e : Event Lv) : String :=
  let r := step s e
  jobj ([("actor", principal e.actor), ("event", evJson e.ev)] ++ outJson r.1 ++
    [("audit", jnat (r.2.audit.length - s.audit.length))])

def stepsJson : State Lv → List (Event Lv) → List String
  | _, [] => []
  | s, e :: es => stepJson s e :: stepsJson (step s e).2 es

def userJson (u : User) : String :=
  jobj [("id", jnat u.id), ("status", jstr (ustatus u.status)), ("role", optRole u.role),
    ("deployments", jarr (u.deps.map jnat))]

def deviceJson (d : Device) : String :=
  jobj [("id", jnat d.id), ("owner", jnat d.owner), ("deployment", jnat d.dep),
    ("status", jstr (dstatus d.status)), ("enrolledBy", jnat d.enrolledBy),
    ("approvedBy", match d.approvedBy with | some a => jnat a | none => "null")]

/-- Traces that start from the bootstrap config itself, before the setup. -/
def installTraces : List (String × List (Event Lv)) :=
  [ ("an offboarded bootstrap principal loses its role before handing over",
      bootLeave ++ [by_ 91 .list, by_ 91 (.invite 2)]),
    ("a live bootstrap principal cannot be invited, nor removed by an admin",
      [by_ 90 (.invite 91), by_ 90 (.offboard 91), fromIdp (.offboard 91), by_ 91 .list]) ]

def deploymentJson (D : Deployment Lv) : String :=
  jobj [("id", jnat D.id), ("connectors", jarr (D.connectors.map mkJson)), ("gateway", mkJson D.gateway),
    ("activation", jnat D.activation)]

def traceJson (start : String) (s0 : State Lv) (t : String × List (Event Lv)) : String :=
  let f := run s0 t.2
  jobj [("name", jstr t.1), ("from", jstr start), ("steps", jarr (stepsJson s0 t.2)),
    ("final", jobj [("users", jarr (f.users.map userJson)),
      ("devices", jarr (f.devices.map deviceJson)),
      ("deployments", jarr (f.deployments.map deploymentJson)),
      ("bootstrapEnded", jarr (f.ended.eraseDups.map (jstr ∘ roleName)))])]

def installJson : String :=
  jarr (boot.map fun p => jobj [("id", jnat p.1), ("role", jstr (roleName p.2))])

def document : String :=
  "{\n \"schema\": \"badger.onboarding.vectors/v1\",\n" ++
  " \"generator\": \"testifysec/formal/onboarding (lake exe onboarding-vectors)\",\n" ++
  " \"install\": " ++ installJson ++ ",\n" ++
  " \"setup\": " ++ jlines (stepsJson (install boot) setup) ++ ",\n" ++
  " \"initial\": " ++ jarr (seed.users.map userJson) ++ ",\n" ++
  " \"traces\": " ++ jlines (traces.map (traceJson "initial" seed) ++
    installTraces.map (traceJson "install" (install boot))) ++ "\n}\n"

/-! ## Self-checks run when writing -/

/-- Every final state satisfies the proved invariants (the theorems, evaluated). -/
def finalStatesSound : Bool :=
  (traces.map (fun t => run seed t.2) ++ installTraces.map (fun t => run (install boot) t.2)).all
    fun f =>
    decide (Members f) && decide (OffboardedInert f) && decide (Bound f) && decide (Accredited f) &&
      decide (HeldEnded f)

/-- Every step appends at most one record, and exactly one on a successful write. -/
def auditSound : Bool :=
  check (install boot) setup && traces.all (fun t => check seed t.2) &&
    installTraces.all (fun t => check (install boot) t.2)
where
  check : State Lv → List (Event Lv) → Bool
    | _, [] => true
    | s, e :: es =>
      let r := step s e
      let n := r.2.audit.length - s.audit.length
      (if r.1 = .ok && !isRead e.ev then n == 1 else n == 0) && check r.2 es

def stepCount : Nat := (traces.map (·.2.length)).foldl (· + ·) 0

end Onboarding.Vectors
