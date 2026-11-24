/-
  Contract.Audit: the axioms each headline result rests on. Allowed: `propext`, `Quot.sound`,
  `Classical.choice`. A `sorryAx` here means a proof hole.
-/
import Contract.Proofs
import Contract.Portal
import Contract.Backends

#print axioms Contract.dom_trans
#print axioms Contract.lub_least
#print axioms Contract.no_write_down
#print axioms Contract.AsBuilt.domGo_iff
#print axioms Contract.AsBuilt.joinGo_above_lub
#print axioms Contract.AsBuilt.result_is_connector
#print axioms Contract.AsBuilt.flowGo_no_write_down
#print axioms Contract.admit_signed
#print axioms Contract.admit_tenant
#print axioms Contract.admitted_monotone
#print axioms Contract.Portal.publish_increasing
#print axioms Contract.Backends.workstation_parametric
#print axioms Contract.Backends.switch_refuses_old
#print axioms Contract.Backends.migration_restart_refused
#print axioms Contract.Backends.migration_carried_admitted
#print axioms Contract.Backends.hw_lowered_only_by_reset
