---
title: Enroll a device
description: How a workstation will enroll with the management portal and pull its signed profile, and what exists today.
sidebarLabel: Enroll a device
sidebarPosition: 40
---

# Enroll a device

> [!WARNING]
> **Not built.** Device enrollment and pull are specified in the portal's OpenAPI document (the
> two device endpoints) and modelled in Lean in `testifysec/formal/onboarding/`. No portal or
> workstation code for them exists yet. This page describes the design so that
> administrators and assessors can review it.

Today a workstation gets its profile the way the gateway does: the administrator places the signed
envelope and the admission executable on it (see [publish a profile](publish-profile.md)). The
`enroll` command in `testifysec/enrollment/` is parked and cannot be built from this repository.

## The planned flow

A device is identified by a key whose private half stays in hardware (a TPM, or the Secure
Enclave on a Mac), enrolled through cilock. The portal keys each device by the SHA-256 of that
key's SubjectPublicKeyInfo.

1. **Request.** The workstation submits an enrollment request with its device key and a proof of
   possession. The device is **pending**.
2. **Approve.** An administrator approves the device into a deployment, the group of devices that
   share a profile. The device is **enrolled**.
3. **Pull.** The workstation asks for a one-use nonce (`GET /api/v1/device/nonce`, valid for 60
   seconds), signs it with the device key together with the key's thumbprint and the portal's
   audience, and sends the proof (`POST /api/v1/device/profile`). The portal returns the profile
   envelope and the deployment's current activation record, byte for byte as signed.
4. **Admit.** The workstation verifies both with its admission executable. If the portal is
   unreachable, or the new pair is refused, it keeps the last pair it admitted.
5. **Repeat.** The workstation pulls every 15 minutes and at session start.
6. **Revoke.** An administrator revokes the device. It gets 403 and nothing else on its next
   pull. A revoked device that stays offline keeps working until its activation expires, at most
   seven days.

The portal never connects to a workstation and holds no workstation address; pull is the only
path. An unknown device gets the same 403 as a revoked one.

## What the Lean model proves

The data classification level a person is authorized for is not Badger's to hold or decide. It is
asserted by an external service, the enclave's identity provider or PKI, and Badger only consumes
that assertion; the onboarding model in `testifysec/formal/onboarding/` leaves it out of scope for
that reason (`NotCovered.lean`). For the flow it does model, it proves that a device is served only
if it is approved, every entry for its owner is an active member of its deployment and the pull
carried a valid proof (`served_requires`), that its enrollment proved possession of the device key
(`served_possession`), and that an offboarded person's devices are never served again
(`offboarded_never_served`). Comparing that model with the portal's written design found gaps the
code must close:

- The portal design's pull checks the device and not the person who owns it.
- The portal design does not yet consume the identity service's assertion of a person's
  authorized classification level.
- Device approval is an administrator action with no second person.
- A role map in a configuration file lets role changes go unaudited.

These are open questions on the design, not properties of shipped code.
