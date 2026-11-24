---
title: The open API and the optional platform
description: Which Badger functions depend on the TestifySec platform today, and how the offline portal and its open API are meant to replace that dependency.
sidebarLabel: Open API and the platform
sidebarPosition: 50
---

# The open API and the optional platform

Badger is meant to run in a network that cannot reach TestifySec. The design puts one contract
between the workstation and whatever manages it, with two implementations: the management portal,
which runs offline inside the enclave, and the TestifySec platform. A workstation should behave
the same against either. This page says how far that is true today.

| Piece | Status |
|---|---|
| Gateway identity check against the TestifySec platform | Available on `main` |
| Management portal and its OpenAPI specification | Available on `main`; device endpoints specified, not built |
| HTTP conformance suite for any portal implementation | Available on `main` |
| Lean model of onboarding and offboarding | Available on `main` |
| Lean model of the contract and its backends | In development, PR #182 |

## What depends on the platform today

**The model gateway's production configuration.** A production gateway is configured with a
private `platformConfigFile`. Before every model request it makes a fresh, nonce-bound check
against the platform that the agent is enrolled, active and assigned to the expected tenant and
repository. If the platform refuses, or cannot be reached, the provider call does not happen. The
check returns identity only, never authorization: the signed profile still decides what the
session may do. Without `platformConfigFile` the gateway refuses to start ("live platform identity required") unless it is in development loopback mode.
Source: `testifysec/gateway/README.md`, `testifysec/platform/`.

**The Requirements panel.** A developer who opts a directory in with `--requirements` signs in
to the platform with a device code and reads the repository's Pushgate requirements. The server
side of that API is not deployed yet; the client is tested against fixtures. A directory that was
never opted in makes no network request, polls nothing and runs no Git command.

**Enrollment and attestation commands.** `badger enroll` and `badger attest` talk to the
platform, but the managed build does not keep them, so a managed workstation refuses them.

A managed session with a gateway in development loopback mode, no Requirements opt-in and no
connectors runs with no platform at all. That is a development configuration, not a production
one.

## The portal and its open API

The portal is one static Go binary with no third-party modules, run as a system service on one
Linux VM inside the enclave. It makes no outbound connection, holds no workstation address and
never pushes to a workstation: workstations pull. It does not run sessions, hold model or service
credentials, or evaluate evidence. Its only output is signed configuration that the existing
admission verifier accepts.

Its HTTP API is described by an OpenAPI 3.1 document, `testifysec/portal/api/openapi.yaml`, so
that another implementation, including the TestifySec platform, can serve the same contract.
The [portal API reference](../reference/portal-api.md) is generated from that file. It
serves profile signing, version history and envelope reads, deployment assignment, a discovery
document, and a user directory: invitations, role requests that an approver decides, deployment
membership and offboarding. The
device endpoints are specified and not built.

### Conformance

The portal carries an HTTP conformance suite that any implementation can be run against
by URL. It checks authentication, role enforcement, server-assigned sequences, listing and the
trust document. The suite signs test profiles, so run it against a test deployment only. See
[run the conformance suites](../developer/run-conformance.md).

### The contract model

The Lean model in PR #182 states the workstation's behaviour as a function of the backend and
proves, among other things, that a backend that conforms to the contract gets its profiles
admitted (`conforming_backend_admitted`), that switching backends refuses the old trust and
admits the new (`switch_refuses_old`, `switch_admits_new`), and that a revoked device is served
nothing (`revoked_gets_nothing`). The onboarding model on `main` (`testifysec/formal/onboarding/`) covers onboarding and offboarding: people,
roles, device enrollment and the audit log. Both export JSON test vectors for the Go code to
replay; some vector sets have no Go consumer yet.

## Pushgate

Pushgate is separate from both. It decides whether a push reaches a repository, on signed
evidence that the push's checks passed. Badger connectors deliberately cannot push or merge, so
code the agent writes reaches a repository only through the gate. See
[testifysec.com/docs/pushgate](https://www.testifysec.com/docs/pushgate).
