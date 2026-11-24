# Onboarding and offboarding (Lean 4)

The management portal (testifysec/PORTAL.md) decides who may administer it, which people belong to
which deployment, and which devices may pull a deployment's signed profile. This directory is the
machine-checked model of that lifecycle: the configured bootstrap principals bring in the first
people and then step aside for good; a person known to the enclave's IdP is invited, approved by
a second person, given a role or a deployment membership, enrolls a cilock device key under their
own authenticated identity, and is eventually offboarded. It also writes conformance vectors so
the portal, and later a platform, can be tested against the same traces.

No person carries a classification level here. The data classification level a person is
authorized for is an external service's decision, which the model trusts (`NotCovered.lean`);
classification levels sit only on connectors, gateways and deployments.

```sh
sh testifysec/formal/onboarding/check.sh           # build, hole check, axiom audit, vectors current
sh testifysec/formal/onboarding/check.sh --write   # regenerate vectors/onboarding-vectors.json
```

Lean 4.34.1, core only (no Mathlib, no dependencies). It is its own Lake package and does not
depend on the contract model (testifysec/formal/contract, PR #169), so neither waits on the other.
The marking order is a parameter (`MarkingOrder`: a preorder with an upper-bound join). Every
theorem holds for any such order. `Levels.lean` is a stand-in order (level plus compartments) for
the kernel-decided cases and the vectors; once #169 merges, the vectors switch to its order (Go's
`marking.Dominates` and `Join`, whose laws that model proves). Go's `Join` is sometimes above the
least bound; nothing here needs it to be least (`ceiling_accredited`).

## Files

| File | What it is |
|---|---|
| `Model.lean` | People, devices, deployments, pending requests, events, audit records, refusal codes |
| `Spec.lean` | The lifecycle as one transition function `stepG g`, with every guard named in `Guards`; `step` is the specification |
| `Levels.lean` | The stand-in marking order |
| `Proofs.lean` | The invariant and every property, for every reachable state and every marking order |
| `Mutants.lean` | Each guard switched off, with the kernel-decided trace that breaks its theorem |
| `AsBuilt.lean` | Today's portal slice (PR #173), transcribed and cited |
| `NotCovered.lean` | What the model abstracts away |
| `Vectors.lean`, `Main.lean` | `lake exe onboarding-vectors`, which writes `vectors/onboarding-vectors.json` |
| `Audit.lean` | `#print axioms` for every headline result and mutant |
| `check.sh` | Build, refuse `sorry`/`native_decide`/`admit`, audit axioms, check the vectors are current |

## The model in one paragraph

Every step authorizes the actor first (PORTAL.md's role table: admin authors and manages people,
deployments and devices; approver approves or rejects; auditor reads; the IdP disables people; a
person enrolls their own device key; a device key pulls). A configured bootstrap principal holds
its role only until the first person is granted that role; the grant writes a marker that nothing
clears (portal #204, #205). A refused step changes nothing. Reads
change nothing. A successful write appends exactly one audit record carrying the actor, the
action, the subject, and the subject's slice of the state before and after. Lookups never assume
identifiers are unique: a check on "user u" holds for every entry named u. A pull is served only
to an approved device whose owner is an active member of the device's deployment. A deployment
is refused unless its gateway is accredited for every connector marking in it.

## What is proved

The theorems quantify over every installed starting state (`install`, any bootstrap config),
every trace and every marking order.

| # | Property | Theorem |
|---|---|---|
| 1 | Every deployment's gateway is accredited for all its connectors; every membership is held by an active person | `accredited_run`, `members_run` |
| 1 | A gateway accredited for the ceiling (the join of the markings) is accredited for each connector | `ceiling_accredited` |
| 1 | Approving a role grant ends that role's bootstrap in the same step; an ended bootstrap stays ended; any role a person holds has ended its bootstrap | `grant_ends_bootstrap`, `ended_run`, `held_ended_run` |
| 1 | The bootstrap never revives: once ended, no later state (every holder offboarded included) gives the role to a principal that is not a person | `bootstrap_never_revives` |
| 1 | Under the config rule (one subject per role, one role per subject) the admin and approver bootstraps are two people | `bootstrap_two_people` |
| 1 | The IdP can always offboard a bootstrap principal, even before it has handed over and has no person entry, and it never holds a bootstrap role again | `offboard_bootstrap`, `offboarded_bootstrap_never_acts` |
| 1 | A bootstrap ends only in a step that leaves an active person holding the role, so ending it never strands the role | `ending_requires_holder` |
| 4 | Deciding an already-decided request is a conflict, not a missing request | `redecide_conflict` |
| 2 | A pull is answered exactly when `serve` holds, and changes nothing | `pull_served_iff`, `pull_unchanged` |
| 2 | A served device is approved (enrolled, not revoked), the pull carried a valid proof, its owner exists and every entry for the owner is an active member of its deployment | `served_requires` |
| 2 | ...and enrollment proved possession of the key | `served_possession` |
| 2 | ...it was enrolled by its owner, authenticated as themselves, and approved by someone other than its owner; this holds for every device in every reachable state | `served_separated`, `bound_run` |
| 3 | After `offboard u`: u is offboarded with no role and no membership, every device u owns is revoked and refused, and one record about u shows all of it | `offboard_complete` |
| 3 | In every reachable state an offboarded person holds no role or membership and owns only revoked devices; none of their devices is ever served | `offboarded_inert_run`, `offboarded_never_served` |
| 4 | An approval succeeds only when an approver clicks, for a pending request someone else made, not about the approver | `approve_separated` |
| 4 | An admin never approves a device they own | `device_approve_separated` |
| 4 | A principal acting alone, over any trace, never gains a role (bootstrap principals included) | `single_actor_no_elevation` |
| 5 | A successful write appends exactly one record (actor, action, subject, before, after); a refusal or a read changes nothing | `audit_one_record`, `record_fields` |
| 5 | A write changes nothing outside its record's subject, so every change is in the record | `audit_frame` |
| 5 | The log only grows at the end: no reachable state removes or reorders a record | `audit_prefix_run` |
| 6 | An event the actor's role does not permit changes nothing | `unauthorized_unchanged`, `write_permitted` |
| 6 | An auditor never changes state; an approver changes state only by approving, rejecting or enrolling its own device; an admin cannot approve | `auditor_read_only`, `approver_only_decides`, `admin_cannot_approve` |
| as built | The slice's route table agrees with the specification on publish and list; today one admin request signs | `AsBuilt.asbuilt_roles_agree`, `asbuilt_signs_alone`, `request_does_not_publish` |
| as built | Today's config-file registry: a role change and a removal append no record; one principal with config write access makes itself admin and signs, and only the signature is logged | `AsBuilt.asbuilt_role_change_unaudited`, `asbuilt_offboard_unaudited`, `asbuilt_self_elevation` |

The invariant behind 1 to 3 is `Inv` (memberships held by active people, inert offboarded people, possession
proved, devices bound to their enrolling owner and approved by someone else, accredited
deployments, held roles past their bootstrap), shown to hold at install (`inv_install`) and preserved by every step (`inv_step`).

## Mutants

Each mutant flips one field of `Guards` (or two, where two independent defences guard one
property) and is a concrete trace the kernel decides, beside the same trace under the
specification.

| Mutant | Guard | Kills |
|---|---|---|
| `gateway_unchecked` | a deployment whose gateway is below a connector is accepted | `accredited_run` |
| `bootstrap_revives` | the bootstrap comes back when no active person holds the role (the portal's rule before #204) | `bootstrap_never_revives` |
| `grant_skips_marker` | a role grant leaves the bootstrap running beside the new holder | `held_ended_run`, `grant_ends_bootstrap` |
| `bootstrap_survives_offboard` | offboarding a bootstrap principal that is not a person is refused as not found, so it keeps inviting | `offboard_bootstrap` |
| `grant_strands_role` | a grant ends the bootstrap without giving the person the role, leaving nobody admin | `ending_requires_holder` |
| `pull_ignores_owner` | pull checks only the device | `served_requires` |
| `pull_no_proof` | pull ignores the proof | `served_requires` |
| `enroll_no_possession` | enrollment without proof of possession | `served_possession` |
| `offboard_keeps_devices` | offboarding leaves devices approved | `offboard_complete` |
| `portal_as_specified` | both of the above: PORTAL.md's pull plus an offboarding that does not revoke | `offboarded_never_served` |
| `offboard_keeps_role` | offboarding keeps the role | `offboarded_inert_run`, `offboard_complete` |
| `approve_own_request` | no requester check: an admin later made approver approves its own publish | `approve_separated` |
| `approve_own_elevation` | no subject check: an approver approves its own promotion | `approve_separated` |
| `device_owner_approves` | an admin approves its own device | `device_approve_separated`, `served_separated` |
| `enroll_for_another` | a person enrolls a key in someone else's name: an admin enrolls its own key as a member's, approves it (the owner is not the admin), and the key pulls with the member's membership | `served_separated` |
| `admin_self_grant` | an admin may approve, with both checks off | `single_actor_no_elevation` |
| `offboard_unaudited` | offboarding writes no record | `audit_one_record` |
| `audit_prepends` | records go in front of the log | `audit_prefix_run` |
| `offboard_revokes_all` | offboarding revokes everyone's devices | `audit_frame` |
| `auditor_can_revoke` | an auditor may revoke a device | `auditor_read_only` |
| `approver_can_request` | an approver may request a publish | `approver_only_decides` |

## The vectors

`vectors/onboarding-vectors.json` (schema `badger.onboarding.vectors/v1`) is generated, never
edited. `install` is the bootstrap config (90 admin, 91 approver); `setup` is 16 steps from it,
with expected outcomes, that bring in admin 1 and approver 2 (ending both bootstraps), then
auditor 3 and admin 4; `initial` is the people that leaves. Then 30 traces, 177 steps: 28 start
from `initial` (`"from": "initial"`) and two from the bootstrap config (`"from": "install"`), each
listing, per step, the actor, the event, the outcome, the error code
on refusal, and how many audit records it appended. The final state lists every person, device,
deployment (with its activation counter) and ended bootstrap. Before writing, the generator checks every final state against the proved invariants and
every step against the one-record rule, and exits non-zero if either fails.

Error codes: `unauthenticated` and `forbidden` (the portal's existing codes, 401 and 403),
`not-found`, `conflict`, `invalid-state`, `separation-of-duties`, `not-accredited`, `no-proof`,
`invalid-request`. A refused pull is `forbidden`: PORTAL.md answers a revoked or unknown device
with 403 and nothing else. `conflict` also covers inviting a bootstrap principal that has not
handed over, an admin removing one, and deciding a request twice; `invalid-state` covers
requesting a role the person already holds (portal #204, #205, #210).

**Replay in the portal.** `TestOnboardingVectors` (testifysec/portal/internal/web) replays every
trace made only of what the portal implements today (a user publishing a version, a user listing
profiles) and skips every other trace with a log line naming the events it waits for. It fails if
no trace is replayable, so it cannot pass without checking anything. Against #173 it replays 1 of
30 traces (9 steps: publish and list by each role and by an unknown principal, with the audit line
count), taking roles from `initial`; the portal's users work (#204, #205) replays more. It waits for PR #173 (the portal module) and lands right after it. Making `POST
.../versions` accept an approver, or changing a vector's audit count, fails it.

One known difference: in the model a publish is a request an approver must approve; today's
portal signs on the admin's request (PORTAL.md, PR 10). Both answer 201 and append one record, so
the replayed trace agrees; the approval traces are skipped until PR 10.

## What the model found

1. **PORTAL.md has no person lifecycle.** Principals are a static map from certificate subject DN
   to role in the config file (`AsBuilt.Slice`). Adding, removing or re-roling an administrator
   is a config edit and a restart: no request, no second person, no audit record, and no actor.
   An auditor with write access to the config makes itself admin and signs a version, and the log
   shows only the signature (`asbuilt_self_elevation`); a removal leaves no trace
   (`asbuilt_offboard_unaudited`). This model specifies the intended design: people provisioned
   from the IdP, role changes approved by a second person, no self-approval.
2. **PORTAL.md's pull checks only the device.** "The portal checks the device is enrolled and not
   revoked, finds its deployment." A device has no owner in the spec, so offboarding a person
   leaves their devices served until an admin revokes each one (`portal_as_specified`). The model
   gives each device an owner, revokes the owner's devices on offboarding, and also refuses a pull
   whose owner is not an active member; either defence alone keeps `offboarded_never_served`.
3. **Bootstrap revival.** The portal's first users design gave a config subject admin or approver
   whenever no active person held the role, so one admin could offboard every other admin and
   approver and come back through config alone (`bootstrap_revives`). Portal #204 and #205 end a
   bootstrap for good the first time a person is granted the role; the model now specifies that.
4. **Enrollment is by the device alone.** `POST /api/v1/devices` is called by the device with a
   proof of possession of its key. Nothing authenticates the person the device is for, so whoever
   enrolls a key decides whose membership it pulls with. The model makes the
   enrolling person the actor (their own CAC or OIDC credential) and refuses an owner other than
   the actor (`enroll_for_another`).
5. **The two-person rule covers versions, activations and resets only.** Device approval is
   admin-only in the API table, so an admin can approve their own device
   (`device_owner_approves`), and role grants have no approval at all.

## Spec gaps (open questions)

1. How does an IdP disable reach the portal: SCIM push, the OIDC token at next login, a periodic
   sync, or certificate revocation? Until it arrives the person keeps their role. Does the portal
   check revocation (CRL or OCSP) on CAC client certificates, or only the chain to `clientCa`?
2. A person's authorized classification level is the external service's decision. Where does the portal ask it, and what does a
   "no" do: refuse an assignment, refuse a device approval, refuse a pull, or only gate the
   session at the gateway? Until that is fixed, nothing in the portal ties a person to a
   deployment's classification.
3. Is a refused deployment configuration the intent? The model refuses a deployment whose
   gateway is not accredited for every connector marking, instead of letting sessions fail at
   runtime.
4. Is a person a member of a deployment, or is the device the only subject? PORTAL.md binds
   devices to deployments and never names the device's user. Should `POST /api/v1/devices`
   (enrollment) carry the owner?
5. Should pull refuse a device whose owner is offboarded or no longer a member, in addition to
   offboarding revoking the devices? The model does both.
6. Should device approval go through the approver queue (PR 10) like versions and role grants?
   The model keeps it with admins, but never by the device's owner.
7. Should removing an admin's or approver's role, or offboarding one, need a second person? As
   modelled, one admin can drop every other admin's role and offboard every approver, which
   locks out publishing until the offline recovery step (vector "a dropped role is gone").
8. What happens to a rejected invitation (the model leaves the person pending, and a re-invite
   conflicts), and can an offboarded identity ever be onboarded again (the model says no)?
9. Are reads and refusals audited? PR 11 says denied requests will be. If an auditor's read
   appends a record, the auditor changes state; the model keeps reads and refusals out of the
   log. A separate access log would keep both properties.
10. One record per action or one per object? Offboarding revokes every device the person owns;
    the model writes one record whose before and after images include those devices
    (`audit_frame`). PORTAL.md's record has one object and one before/after digest.
11. Enrollment: how does `POST /api/v1/devices` carry the owner's own authentication beside the
    device key's proof? May an auditor own a device? The model says no, so an auditor never
    changes state.
12. Bootstrap recovery is an offline operator step. Is it audited when the portal next starts,
    and does it re-arm one bootstrap role or both?
