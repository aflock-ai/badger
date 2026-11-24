---
title: Signed profiles and activation
description: What a Badger profile contains, how admission verifies it, who signs it, and which parts of activation are still being built.
sidebarLabel: Signed profiles and activation
sidebarPosition: 30
---

# Signed profiles and activation

A profile is the administrator's signed statement of what a deployment may run. Components that
hold something worth protecting (the model gateway and the session broker) refuse to act without
a profile they can verify.

| Piece | Status |
|---|---|
| Profile format and admission verifier | Available on `main` |
| Trust input compiled into the build | Available on `main` (prototype) |
| Profile signing, history and assignment in the management portal | Available on `main` |
| Activation records, persisted sequence floor, certificate-chain trust | Designed, not built |

## The profile

A profile is a [DSSE](https://github.com/secure-systems-lab/dsse) envelope whose payload type is
`application/vnd.testifysec.hardened-opencode.profile.v1+json`. The payload has exactly these
fields:

| Field | Meaning |
|---|---|
| `schemaVersion` | Payload schema version |
| `profileId` | The profile this version belongs to |
| `tenantId` | The customer tenant |
| `deploymentId` | The deployment (group of workstations) the profile is assigned to |
| `sequence` | Version number; a higher sequence replaces a lower one |
| `notBefore` | Start of the validity window, inclusive |
| `expiresAt` | End of the validity window, exclusive |
| `controls` | `runtimePackageDownloads: false`, `execution: "broker-only"`, `audit: "required"` |

Parsing is strict: an unknown field, a duplicate key or a number that is not a canonical
unsigned decimal integer is a refusal, not a warning. The full schema, with an example, is in
[the admission README](https://github.com/aflock-ai/badger/blob/main/testifysec/managed/README.md).

A second payload type, `...profile.v2+json`, adds a `backend` object that names a VM backend and
the SHA-256 of its manifest. A build accepts one version and never falls back to the other. A v2
profile approves a manifest reference only; it does not read the manifest or authorize a VM boot.
The broker and the managed host read v1.

## Admission

The admission launcher, `hardened-admission`, reads one envelope on standard input and returns a
result only if all of these pass:

1. The signature verifies against the trusted public keys, with at least the threshold number of
   distinct signers.
2. The payload matches the schema exactly.
3. The tenant, deployment and profile match the build's assignment.
4. The current time is inside `notBefore` and `expiresAt`.
5. The sequence is at least the build's minimum sequence.

The launcher checks the digest of the runtime it starts, refuses command-line arguments, and
replaces its environment before the runtime starts, so an inherited preload hook cannot run. Its
acceptance harness covers tampered, wrong-key, expired, not-yet-valid, wrong-assignment,
rollback, unknown-field, duplicate-key and trust-injection cases. Source:
`testifysec/managed/`.

**Who calls it.** The model gateway runs admission before every provider request and records a
failure as `profile-refused` in its audit spool. The session broker runs it on every request.
The managed terminal UI does not verify a profile itself: it runs its one compiled
configuration, and the profile takes effect at the gateway and the broker.

## Who signs, and what the build trusts

The trusted keys and the assignment are compiled into the admission executable from a build
administrator's trust input:

```json
{
  "schemaVersion": 1,
  "publicKeys": ["-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"],
  "threshold": 1,
  "tenantId": "tenant-example",
  "deploymentId": "managed-linux-example",
  "profileId": "managed-engineering",
  "minimumSequence": 10
}
```

Nothing at run time (a request, an environment variable, a local file) can add or replace a key.
To change keys or assignment, the administrator builds again. This is a bounded trust prototype:
the signer is a key, not an authenticated person, and there is no timestamp authority or
certificate chain behind it.

## Known gaps

These are recorded so that nobody relies on them:

- **The sequence floor does not persist.** Admission compares against the compiled minimum only.
  After it accepts sequence 12, it would still accept 11 if the compiled minimum is 10. A
  persisted per-device high-water mark is tracked in
  issue #160.
- **The clock is trusted.** The validity window is checked against the operating system clock.
- **Two findings from the Lean contract model** (PR #182),
  also tracked in issue #160: the schema-1 verifier does not compare the tenant, and a development
  flag admits a request that carries no profile.

## Signing in the portal (available)

The management portal is where profiles are signed. An administrator asks the portal for the next
version of a profile; the portal assigns the sequence (the client cannot choose one), signs a DSSE
envelope with an ECDSA P-256 key held as an encrypted system credential, and writes the version
once. A signed version is never changed. The portal serves each profile's version history and
each version's envelope byte for byte, records which profile version a deployment is assigned to
(an assignment only moves forward), and exports the admission trust input for a profile, so the
build that verifies it and the service that signs it agree.

## Activation (designed, not built)

The design adds:

- **Two-person publish.** An approver approves a draft before the administrator signs it. Today
  one administrator signs alone.
- **Activation records.** A signed record, one per deployment, that says which profile version is
  live. Devices keep a persisted counter so an older activation is refused.
- **Pull, not push.** Enrolled workstations pull their profile and activation from the portal
  every 15 minutes and at session start, proving possession of a device key. A workstation that
  cannot reach the portal keeps its last admitted profile until the activation expires, at most
  seven days.
- **Short-lived certificates.** Signing with seven-day leaf certificates instead of a bare key.

Rollback is done by signing a new, higher version with the old content. An old version is never
re-activated.
