/-
  Onboarding.Audit: the axioms each headline result rests on. Allowed: `propext`, `Quot.sound`,
  `Classical.choice`. A `sorryAx` means a proof hole; `Lean.ofReduceBool` means a decision the
  kernel did not check. check.sh fails on either.
-/
import Onboarding.AsBuilt
import Onboarding.Vectors

#print axioms Onboarding.accredited_run
#print axioms Onboarding.members_run
#print axioms Onboarding.ceiling_accredited
#print axioms Onboarding.ended_run
#print axioms Onboarding.grant_ends_bootstrap
#print axioms Onboarding.held_ended_run
#print axioms Onboarding.bootstrap_never_revives
#print axioms Onboarding.bootstrap_two_people
#print axioms Onboarding.offboard_bootstrap
#print axioms Onboarding.offboarded_bootstrap_never_acts
#print axioms Onboarding.ending_requires_holder
#print axioms Onboarding.redecide_conflict
#print axioms Onboarding.pull_served_iff
#print axioms Onboarding.served_requires
#print axioms Onboarding.served_possession
#print axioms Onboarding.served_separated
#print axioms Onboarding.bound_run
#print axioms Onboarding.offboard_complete
#print axioms Onboarding.offboarded_inert_run
#print axioms Onboarding.offboarded_never_served
#print axioms Onboarding.approve_separated
#print axioms Onboarding.device_approve_separated
#print axioms Onboarding.single_actor_no_elevation
#print axioms Onboarding.audit_one_record
#print axioms Onboarding.audit_frame
#print axioms Onboarding.audit_prefix_run
#print axioms Onboarding.unauthorized_unchanged
#print axioms Onboarding.auditor_read_only
#print axioms Onboarding.approver_only_decides
#print axioms Onboarding.admin_cannot_approve
#print axioms Onboarding.AsBuilt.asbuilt_roles_agree
#print axioms Onboarding.AsBuilt.request_does_not_publish
#print axioms Onboarding.AsBuilt.asbuilt_role_change_unaudited
#print axioms Onboarding.AsBuilt.asbuilt_self_elevation
#print axioms Onboarding.AsBuilt.asbuilt_offboard_unaudited
#print axioms Onboarding.Mutants.gateway_unchecked
#print axioms Onboarding.Mutants.bootstrap_revives
#print axioms Onboarding.Mutants.grant_skips_marker
#print axioms Onboarding.Mutants.bootstrap_survives_offboard
#print axioms Onboarding.Mutants.grant_strands_role
#print axioms Onboarding.Mutants.pull_ignores_owner
#print axioms Onboarding.Mutants.pull_no_proof
#print axioms Onboarding.Mutants.enroll_no_possession
#print axioms Onboarding.Mutants.enroll_for_another
#print axioms Onboarding.Mutants.offboard_keeps_devices
#print axioms Onboarding.Mutants.portal_as_specified
#print axioms Onboarding.Mutants.offboard_keeps_role
#print axioms Onboarding.Mutants.approve_own_request
#print axioms Onboarding.Mutants.approve_own_elevation
#print axioms Onboarding.Mutants.device_owner_approves
#print axioms Onboarding.Mutants.admin_self_grant
#print axioms Onboarding.Mutants.offboard_unaudited
#print axioms Onboarding.Mutants.audit_prepends
#print axioms Onboarding.Mutants.offboard_revokes_all
#print axioms Onboarding.Mutants.auditor_can_revoke
#print axioms Onboarding.Mutants.approver_can_request
