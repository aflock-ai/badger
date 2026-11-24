/-
  The formal step's own audit of the commit's built model. It is the runner's, never the commit's.

    lean --run .pushgate/steps/formal-audit.lean <the model's .lake/build/lib/lean> <module>...

  It never imports the commit's modules, so none of the commit's code (an `initialize`, an
  attribute, an `#eval` at import) runs here. The step names every module the commit has (from
  its git objects); each must have a built .olean, and every module one of them imports must be
  `Init` or another of them, so deleting or hiding a module's .olean fails. It reads them as data,
  starts from Lean's own `Init` (the image's), and sends every declaration in them to the kernel
  (`Kernel.Environment.replay`): a declaration that does not typecheck, a forged or tampered
  .olean, or a reference to anything outside `Init` and the model fails the replay. Then:

  * every declaration the model's modules make, in any namespace and private ones included, may
    depend only on `propext`, `Quot.sound` and `Classical.choice`. A `sorry` however written is
    `sorryAx`, `native_decide` is `Lean.ofReduceBool`, and a new `axiom` names itself; each fails;
  * every headline theorem must be there, so deleting or renaming one fails too.

  What it cannot see is a theorem whose statement was weakened; that is a diff of the model.
-/
import Lean

open Lean

def allowedAxioms : List Name := [``propext, ``Quot.sound, ``Classical.choice]

def requiredTheorems : List Name :=
  [ `Contract.dom_trans, `Contract.dom_antisymm, `Contract.lub_least, `Contract.no_write_down,
    `Contract.AsBuilt.domGo_iff, `Contract.AsBuilt.joinGo_above_lub,
    `Contract.AsBuilt.result_is_connector,
    `Contract.AsBuilt.flowGo_no_write_down, `Contract.AsBuilt.refusedGo_iff,
    `Contract.AsBuilt.joinChecked_bannerable, `Contract.AsBuilt.joinChecked_long_only_refuses, `Contract.refused_delivers_nothing, `Contract.admit_signed, `Contract.admit_assigned,
    `Contract.admit_tenant, `Contract.admit_window, `Contract.admit_unsigned,
    `Contract.admit_rollback, `Contract.admitted_monotone,
    `Contract.Backends.workstation_parametric, `Contract.Backends.switch_refuses_old,
    `Contract.Backends.migration_restart_refused, `Contract.Backends.migration_carried_admitted,
    `Contract.Backends.hw_lowered_only_by_reset, `Contract.Backends.revoked_gets_nothing,
    `Contract.Vectors.backends_agree ]

/-- The axioms `n` depends on, through the model's constants and `Init`'s. -/
partial def axiomsOf (base : Environment) (model : Std.HashMap Name ConstantInfo)
    (n : Name) : StateT (NameSet × NameSet) IO Unit := do
  let (seen, _) ← get
  if seen.contains n then return
  modify fun (s, a) => (s.insert n, a)
  let some ci := model.get? n <|> base.find? n
    | throw <| .userError s!"audit: {n} is in neither the model nor Init"
  if ci matches .axiomInfo _ then modify fun (s, a) => (s, a.insert n)
  -- allowOpaque: a theorem's (and an opaque's) proof is its value too; without it the walk
  -- would see only statements.
  let used := ci.type.getUsedConstants ++
    ((ci.value? (allowOpaque := true)).map (·.getUsedConstants)).getD #[]
  for m in used do axiomsOf base model m

def main (args : List String) : IO UInt32 := do
  let lib :: mods := args | throw <| .userError "usage: lean --run formal-audit.lean <lib dir> <module>..."
  if mods.isEmpty then throw <| .userError "audit: no modules named"
  let names := mods.map String.toName
  initSearchPath (← findSysroot)
  let base ← importModules #[{ module := `Init }] {}
  let mut model : Std.HashMap Name ConstantInfo := {}
  for (m, n) in mods.zip names do
    let f : System.FilePath := lib / (m.replace "." "/" ++ ".olean")
    unless ← f.pathExists do throw <| .userError s!"audit: module {m} has no built .olean"
    let (data, _) ← readModuleData f
    for i in data.imports do
      unless base.header.moduleNames.contains i.module || names.contains i.module do
        throw <| .userError s!"audit: {n} imports {i.module}, which is neither the toolchain's Init nor the model"
    for ci in data.constants do
      -- An .olean holds only its own module's declarations, so a name Init has is a module (a
      -- `prelude` one, importing nothing) declaring Init's names afresh: refuse it rather than skip it.
      if base.contains ci.name then
        throw <| .userError s!"audit: {ci.name} is also declared by Init"
      -- Two modules declaring one name never import each other, so each compiles alone; the map
      -- would keep only the later one and the audit would never see the first.
      if model.contains ci.name then
        throw <| .userError s!"audit: {ci.name} is declared by more than one module"
      model := model.insert ci.name ci
  -- The kernel checks every declaration of the model against Init.
  discard <| Kernel.Environment.replay model base.toKernelEnv
  for n in requiredTheorems do
    unless model.get? n matches some (.thmInfo _) do
      throw <| .userError s!"audit: required theorem {n} is missing"
  let mut checked := 0
  let mut bad : Array (Name × Name) := #[]
  for (n, _) in model.toList do
    -- Every declaration the model's modules make, whatever its namespace.
    checked := checked + 1
    let ((), (_, axs)) ← (axiomsOf base model n).run ({}, {})
    for a in axs.toList do
      unless allowedAxioms.contains a do bad := bad.push (n, a)
  unless bad.isEmpty do
    throw <| .userError s!"audit: {bad.size} constants depend on disallowed axioms: {bad.toList.take 20}"
  IO.println s!"audit: ok {checked} constants, kernel-checked, only {allowedAxioms}"
  return 0
