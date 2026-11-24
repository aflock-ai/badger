---
title: Shared responsibility
description: Which parts of each control TestifySec, the customer program, the enclave and the model operator own, and what Badger does and does not bring to a deployment's authorization.
sidebarLabel: Shared responsibility
sidebarPosition: 20
---

# Shared responsibility

> [!IMPORTANT]
> Control alignment, not an authorization or compliance claim. The responsibilities below are a
> starting point for a program's system security plan and customer responsibility matrix; the
> authorizing official decides the final allocation.

## The parties

| Party | Who | Owns |
|---|---|---|
| TestifySec | The Badger code in this repository | What the managed build, gateway, admission verifier, connectors and portal enforce, and the tests that show it |
| Customer program | The build administrator, enclave administrators and portal operators | Build inputs, signing keys, profiles, which connectors and writes are on, operation and review |
| Enclave | The hosting environment | Facility, network boundary, operating systems, identity provider and PKI, storage |
| Model operator | Whoever runs the model and the gateway's provider endpoint | Provider credentials, TLS to the provider, the model's own accreditation |

## By control area

| Area | TestifySec | Customer program | Enclave | Model operator |
|---|---|---|---|---|
| Access control (AC-3, AC-6) | Compiled permissions, refused routes and commands, writes off by default | File permissions on the workspace; whether to enable connector writes | Operating system accounts | |
| Information flow (AC-4, SC-7) | The process reaches only the gateway; connectors reach one service each | Denying network access to tool commands with a VM, container or host firewall | The enclave boundary | |
| Markings (AC-16) | Stamping, parsing and comparing markings; refusing a connector call below the workspace's label | Choosing the build's data marking and each connector's marking; keeping content that reaches a workspace other than through a connector (repository files, user input) within what its lowest admitted connector may receive | Accrediting the system high | Accrediting the model |
| A person's authorized classification level (PS-3, AC-2) | None: Badger neither stores nor decides the data classification level a person is authorized for | Operating the identity service that asserts it; deciding which classification level each person is authorized for | The identity provider or PKI that carries the assertion | |
| Identity (IA-2, IA-5) | Portal certificate checks; no credentials in the agent process | Key custody and rotation for the portal and admission trust | Smart cards, the enclave CA, operating system login | Provider credentials |
| Device identity (IA-3) | Planned device-key protocol | Approving devices | TPM or Secure Enclave hardware, device inventory | |
| Audit (AU-2 to AU-12) | Gateway and portal records, hash chain; the worker's connector decision record | Collecting, retaining and reviewing records; the collector's queue and access controls; protecting the Badger state directory and its connector decision record from change or removal by the workspace user (AU-9), since changing or removing them resets the worker's connector label | Operating system audit | |
| Configuration (CM-2, CM-5, CM-7, CM-14) | Compiled configuration, signed profiles, admission | Who may build, sign and install; the trust input | | |
| Cryptography (SC-8, SC-13) | TLS in the portal and connectors; a future FIPS-mode gateway | Choosing approved modules with the authorizing official | Network encryption required for the data's classification | TLS to the provider |
| Data at rest (SC-28) | Owner-only file modes | Retention | Disk and storage encryption | |
| Output filtering (SI-15) | Best-effort credential redaction | Keeping secrets out of paths the agent can read | | |
| Supply chain (SR-3, SR-4, SR-11) | Gated pushes with signed evidence; pinned runner | A deployment-owned signer and roots, and verifying digests on install | | |

Families with no Badger mechanism (awareness and training, assessment, incident response, media
protection, physical protection, personnel security, planning, risk assessment) belong to the
customer program and the enclave. The portal's audit log is an input to incident response, not a
mechanism for it.

## Classification levels: data and people

Badger handles the classification level of data and deployments: the marking compiled into a
deployment, the marking each connector carries, and the marking a model gateway is accredited to.
It does not decide the data classification level a person is authorized for. That is decided by an
external service (the enclave's identity provider or PKI) and the program that runs it. Badger
neither stores a person's authorized classification level nor decides it; where a Badger component
needs to know, it consumes that service's assertion. Assessors should place it with the customer
program and its identity service, not with Badger.

## Where Badger depends on TestifySec

- **This repository's push gate** signs its evidence with an identity from the TestifySec platform.
  A program that builds Badger itself runs its own gate and signer.
- **The model gateway's production configuration** checks every request against the TestifySec
  platform. Removing that dependency is what the offline portal and its open contract are for;
  see [the open API and the platform](../concepts/platform.md).

## Badger and a deployment's authorization

A deployment's accreditation and impact level belong to its operator and the operator's authorizing
official. Badger brings no authorization of its own: the application does not acquire one from its
source code, and an authorized hosting service does not authorize this application, or every model
service inside it, by being authorized itself.

What Badger can contribute to an authorization is evidence: the mechanisms on the
[control alignment](control-alignment.md) page, the tests that exercise them, and signed records
of what was built and pushed. What a program still has to establish, for its own deployment:

- the mission sponsor and authorizing official, the system boundary and its categorization;
- the applicable security requirements, configuration guides and control baseline, and which
  controls are inherited;
- an approved model host and model, the identity and network architecture, and the cryptographic
  modules (FIPS 140-3 validation is about modules, and is not by itself the protection decision
  for the data's classification level);
- the security plan, test evidence, remediation record and continuous monitoring.

These are deployment deliverables, not a property of the repository.
