/-
  Onboarding.NotCovered: what this model abstracts away or leaves out. Each item is a place a bug
  could hide that no theorem here would catch.

  Authorized classification level (external assumption)
    * The data classification level a person is authorized for is decided by an external
      service, not by the portal, and the model trusts that decision. No person carries a marking
      here; classification levels sit only on connectors, gateways and deployments. Whether an
      authorized person may hold a membership, use a device or read a deployment's content is
      the external service's check. If it answers wrongly, or the portal does not ask it, no
      theorem here notices.
  Identity
    * The identity provider and the PKI. A person is a number. That the certificate subject or
      OIDC subject behind it is the right person, and that a disabled account is reported
      promptly, are the IdP's and PKI's job. `offboard` from `.idp` is an event the portal must
      act on when it arrives; how it arrives (SCIM, a group claim at next login, a CRL, a cron) is
      not modelled, and neither is the delay. A person disabled in the IdP keeps every portal role
      until that event arrives.
    * Mapping a certificate to a principal (PORTAL.md: subject DN) and an OIDC token to one
      (PR 11). Two DNs for one person, or one DN reused, are outside the model.
    * Bootstrap recovery. When every admin is gone, the portal's recovery is an offline operator
      step (portal #204); the model has no event for it, so `bootstrap_never_revives` says
      nothing about what that step may do.
  Devices
    * cilock enrollment internals: TPM endorsement-key or Secure Enclave attestation, the proof
      of possession's JWS, nonce freshness and audience. `possession` and the pull's `proof` are
      booleans.
    * Key custody. A device key copied off its TPM is still that device.
    * How one enrollment request carries both credentials: the device key's proof of possession
      and the owner's own authentication (the actor of the `enroll` event). The model assumes
      the actor is authenticated, as for every event, and requires the owner to be the actor.
  Cryptography and transport
    * Signatures on profiles, activations and resets, certificate chains, short-lived leaves:
      the contract model (testifysec/formal/contract, Backends.lean) covers the workstation
      side. TLS and the network are not modelled.
  Time
    * There are no clocks. Pending requests do not expire, invitations do not time out, and the
      7-day activation that bounds an offline revoked device (PORTAL.md) is not modelled.
  Markings
    * The order is a parameter. `Levels.lean` is a stand-in; Go's `marking.Dominates` and its
      laws are the contract model's. The model needs only a preorder with an upper-bound join,
      so Go's join (sometimes above the least bound) satisfies it.
    * Parsing banners, and where a deployment's markings come from (an admin entering a
      connector's marking too low under-reports; no theorem sees that).
    * The runtime flow check (a session's content reaches only a gateway accredited for it) is
      the contract model's; here only the configured deployment is checked (`accredited_run`).
  Bootstrap marker ordering
    * The portal writes a role's bootstrap marker (naming the holder) before the holder's record,
      and the marker takes effect only once that record exists (portal #204, #205). Here the
      marker and the grant are one atomic step (`ending_requires_holder`). A marker whose holder
      record is never written, then a later invite of that same subject without a grant, would
      end the bootstrap with nobody holding the role in a portal that checks only that the
      record exists; the model cannot express that interleaving.
  Storage and concurrency
    * A storage fault between an approval's user write and its request write leaves a partly
      applied request, which the portal lets an approver finish but not reject (#205). Steps
      here are atomic, so no state is partly applied.
    * Steps are atomic and totally ordered. The portal serializes writes with one process and a
      locked append-only log (PORTAL.md); a crash between the audit append and the store write
      leaves a record of an attempt (issue.go), which the model does not represent.
    * The hash chain, the exported anchors and `verify-audit` (PR 9): the model's log is a list,
      and append-only is a theorem about the list, not about the file.
  Reads
    * Reads (`list`, `readAudit`, `pull`) are not audited. PORTAL.md PR 11 says denied requests
      will be audited; refusals here change nothing.
  Not in scope
    * Profile content, sequences, admission and high-water: the contract model.
    * Who may see which audit records (an auditor reads everything).
-/
