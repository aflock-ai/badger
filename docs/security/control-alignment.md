---
title: NIST SP 800-53 control alignment
description: Which NIST SP 800-53 Rev. 5 controls Badger's mechanisms support, with the source and tests behind each and the status of every row.
sidebarLabel: Control alignment
sidebarPosition: 10
---

# NIST SP 800-53 control alignment

> [!IMPORTANT]
> Control alignment, not an authorization or compliance claim. Implementation and assessment are
> deployment-specific. Badger source does not carry an authorization; a deployment's authorizing
> official, its authorization boundary and its environment do.

This page maps Badger mechanisms to NIST SP 800-53 Revision 5 controls, so an assessor can find
the code and tests behind each one. It covers the Badger repository: the managed build, the model
gateway, the admission verifier, the connectors, the management portal and the Pushgate steps
that gate this repository. Who is responsible for the rest of each control is on the
[shared responsibility](shared-responsibility.md) page.

Status values:

- **Available**: merged on `main`, with the tests named.
- **In review (#n)**: in an open pull request; not on `main`.
- **Planned**: designed, not built.
- **Not addressed**: the repository does nothing for this control; the deployment provides it.

## Access control

| Control | Badger mechanism | Evidence | Status |
|---|---|---|---|
| AC-2 Account Management | Portal user directory: an administrator provisions identities the enclave PKI issued; roles are granted only when an approver who is neither requester nor subject approves; drop-role is immediate; offboarding is final and clears role, memberships and pending requests. A bootstrap entry works only until the first real holder of its role exists. Issuing and revoking the identities stays with the enclave. | `testifysec/portal/internal/users/`, `testifysec/formal/onboarding/` | Available |
| AC-3 Access Enforcement | Compiled permissions: deny all, then allow read, edit, shell. HTTP routes for credentials, MCP, shells, terminals, worktrees and `git init` refused. Portal checks the role per endpoint. | `packages/server/src/managed.ts`, `packages/server/test/managed-routes.test.ts` | Available |
| AC-4 Information Flow Enforcement | Every HTTP request from the process goes to the gateway socket or is refused. Each connector is locked to one HTTPS base URL. The marking flow check is specified. | `packages/server/test/managed-egress.test.ts`, `packages/cli/test/managed-egress-binary.test.ts`, `testifysec/connectors/internal/egress/` | Available for the process and connector library; flow check planned |
| AC-6 Least Privilege | Kept-command set, refused auto-approve and server options, no credentials in the process, connector write tools off unless enabled. | `packages/cli/src/managed.ts`, `packages/cli/test/managed-refusal.test.ts` | Available; connector writes in review (#181, #180, #186) |
| AC-16 Security and Privacy Attributes | A data marking compiled into the build that can only be raised at run time and is stamped on every session record; each connector's one administrator-set marking on every result it returns. | `packages/util/src/security-marking.ts`, `packages/cli/test/managed-marking-binary.test.ts` | Session marking available for unclassified levels; connector marking available |

## Identification and authentication

| Control | Badger mechanism | Evidence | Status |
|---|---|---|---|
| IA-2 Identification and Authentication (Organizational Users) | Portal accepts only TLS client certificates that chain to the enclave CA. The command line authenticates nobody; the operating system login does. | `testifysec/portal/main.go` | Available; enclave OIDC planned |
| IA-3 Device Identification and Authentication | Hardware-held device keys with a nonce-bound proof on every pull. | [Enroll a device](../admin/enroll-device.md) | Planned |
| IA-5 Authenticator Management | Portal signing key sealed as an encrypted system credential. Badger holds no provider credential; the gateway does, read from a file or an inherited pipe. | `testifysec/portal/internal/sign/`, `testifysec/gateway/credential.go` | Available; hardware security module planned |

## Audit and accountability

| Control | Badger mechanism | Evidence | Status |
|---|---|---|---|
| AU-2 Event Logging | Gateway records every model request, including denied ones. Portal records every profile signature, assignment and user change. | `testifysec/gateway/`, `testifysec/portal/internal/` | Available; command-line security events planned |
| AU-3 Content of Audit Records | Gateway: IDs, time, tenant, session, agent, profile, model, outcome, byte counts; never prompts or bodies. Portal: time, actor, role, action, object, digests, previous record hash. | `testifysec/gateway/README.md`, `testifysec/portal/internal/store/` | Available |
| AU-5 Response to Audit Logging Process Failures | Gateway writes the start record before the provider call; a full or undeliverable spool stops new requests with 503. | `testifysec/gateway/` UAT | Available |
| AU-9 Protection of Audit Information | Portal audit log is append-only, hash-chained, synced, and locked to one process. Truncating the tail is not detectable until signed anchors exist. | `testifysec/portal/internal/store/` | Available; anchors planned |
| AU-12 Audit Record Generation | Records are written on the request path, before the action completes. | as above | Available |

## Configuration management

| Control | Badger mechanism | Evidence | Status |
|---|---|---|---|
| CM-2 Baseline Configuration | One compiled configuration; upstream pinned to an exact commit. | `packages/server/src/managed.ts`, `testifysec/upstream.commit` | Available |
| CM-5 Access Restrictions for Change | The managed policy is a compile-time constant; no flag, variable or file changes it. | `packages/cli/src/managed.ts` | Available |
| CM-7 Least Functionality | Built-in providers, model catalog, MCP, plugins, web tools, updates, sharing, LSP and terminals removed or refused. | `packages/server/test/managed.test.ts`, `packages/cli/test/managed.test.ts` | Available |
| CM-14 Signed Components | Profiles are DSSE envelopes; admission checks signature, assignment, window and sequence. The trust input is a prototype. | `testifysec/managed/`, its `uat.py` | Available (prototype trust input); portal signing available; release signing planned |

## System and communications protection

| Control | Badger mechanism | Evidence | Status |
|---|---|---|---|
| SC-7 Boundary Protection | The process reaches only the gateway socket. Tool commands' egress is not Badger's. | as AC-4 | Available for the process; the rest not addressed |
| SC-8 Transmission Confidentiality and Integrity | Portal serves TLS 1.2 or later only. Connectors use HTTPS only. Gateway uses TLS to the provider, with an optional key pin. | `testifysec/gateway/config.go`, `testifysec/connectors/internal/egress/` | Available |
| SC-13 Cryptographic Protection | No FIPS 140-3 claim. A FIPS-mode gateway build and a cryptographic inventory are planned. | `testifysec/HARDENING.md`, `testifysec/native/FIPS.md` | Planned |
| SC-28 Protection of Information at Rest | Owner-only file modes; no encryption at rest in Badger. | | Not addressed |

## System and information integrity

| Control | Badger mechanism | Evidence | Status |
|---|---|---|---|
| SI-7 Software, Firmware, and Information Integrity | Admission checks the runtime's digest before starting it and verifies the signed profile. In TestifySec's development repository, push evidence is bound to the exact commit and a clean tree. | `testifysec/managed/` | Available |
| SI-10 Information Input Validation | Strict JSON with unknown fields refused in admission, gateway and portal; the marking parser refuses unknown tokens. | `testifysec/managed/strict-json.ts`, `testifysec/gateway/config.go` | Available |
| SI-15 Information Output Filtering | Credential redaction on tool and shell output, best effort and not a security boundary. Connector output wrapped as untrusted and capped. | `packages/core/src/tool-output-redaction.ts`, `testifysec/TOOL-OUTPUT-REDACTION.md` | Available |

## Supply chain and development

| Control | Badger mechanism | Evidence | Status |
|---|---|---|---|
| SA-11 Developer Testing and Evaluation | Negative tests run each case against the managed build and the upstream control build. Lean models of the broker policy, the contract and onboarding. | `packages/*/test/managed*.test.ts`, `testifysec/model-broker/formal/` | Available; contract model in review (#182) |
| SR-3 Supply Chain Controls and Processes | Every push to TestifySec's development repository must carry signed evidence of build, tests, secret scan, leak check and a vulnerability ratchet, run by a trusted runner on a worker. That gate's configuration is not published. | Development repository | Available |
| SR-4 Provenance | Command attestations bound to the commit. The signing identity comes from the TestifySec platform as the development repository is configured; a deployment that builds Badger supplies its own signer. | Development repository | Available for the development repository; release provenance planned |
| SR-11 Component Authenticity | The runner signs only with a cilock binary whose digest is listed; step commands and images are pinned. Connector digests in the profile are planned. | Development repository | Available; connector digests planned |

## Not mapped

These families are outside the repository and belong to the deployment: AT, CA, IR, MP, PE, PL,
PM, PS, RA. AU-10 (non-repudiation) is not claimed, because profile signatures are by a key, not
an authenticated person.

## Known gaps an assessor should test

- No signed binary release, SBOM or release provenance exists.
- The admission sequence floor does not persist across runs (issue #160).
- No operating-system egress-deny acceptance run has been recorded for tool commands.
- Credential redaction misses unprefixed secrets (such as cloud secret access keys), secrets split
  across lines, and more than two layers of encoding. It is listed in
  `testifysec/TOOL-OUTPUT-REDACTION.md`.
- The model gateway's production configuration depends on the TestifySec platform for the
  per-request identity check. See [the open API and the platform](../concepts/platform.md).
