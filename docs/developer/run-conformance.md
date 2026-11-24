---
title: Run the conformance suites
description: Check a portal or platform implementation against the Badger contract, and rerun the acceptance harnesses and formal models.
sidebarLabel: Run the conformance suites
sidebarPosition: 60
---

# Run the conformance suites

Badger is meant to work with any management backend that serves its contract: its own portal or
the TestifySec platform. These suites let you check an implementation yourself instead of taking
our word for it.

| Suite | What it checks | Status |
|---|---|---|
| Portal HTTP contract | Any portal implementation, by URL | Available on `main` |
| Contract model vectors | Markings, dominance, join, flow, admission, backends | In development, PR #182 |
| Onboarding model vectors | People, roles, devices, audit | Available on `main` |
| Admission acceptance harness | The compiled admission executable | Available on `main` |
| Gateway acceptance harness | The compiled gateway | Available on `main` |
| Portal admission harness | Portal-signed profiles through the compiled admission executable | Available on `main` |

## Portal HTTP contract

`testifysec/portal/contract` holds the suite; Badger's own portal runs it in-process (`internal/web`). It checks:

- an anonymous request to sign a version gets 401 `unauthenticated`;
- an auditor's request to sign gets 403 `forbidden`;
- a request that names its own sequence gets 400;
- an administrator's request gets 201, and the next one gets the next sequence;
- an auditor's list shows the latest version;
- the trust document is well formed and its minimum sequence is the latest sequence;
- the history lists both versions, newest first, and an envelope comes back as the signed bytes;
- a deployment assignment succeeds, and re-pinning an older version is refused;
- the discovery document is served.

The suite runs against a portal started inside the test, with its own throwaway signing key and
store, so it touches no deployment. From the repository root:

```sh
(cd testifysec/portal && go test -run TestContractInProcess ./internal/web)
```

`go test` reports `ok` or names the failing check. Another implementation runs the same suite
by calling `contract.Run` with an HTTP client per role.

## Formal model vectors

The onboarding model is on `main`; the contract model is in PR #182.

The Lean models export JSON vectors that the Go code replays. Each model has a check script that
builds the model, refuses `sorry`, `admit` and `native_decide`, audits the axioms (only `propext`,
`Quot.sound` and `Classical.choice` are allowed), and fails if the committed vectors are stale:

```sh
sh testifysec/formal/onboarding/check.sh
sh testifysec/formal/contract/check.sh   # PR #182, not on main yet
```

Each needs the Lean toolchain named in its `lean-toolchain` file (v4.34.1, core only, no
Mathlib). The contract vectors cover 21 markings, 441 dominance and 441 join cases, 7 flows and 27
admission cases, which the Go connector and admission code replay. The onboarding vectors cover 27
traces of 168 steps; the Go replay test for them is not written yet.

## Acceptance harnesses (available)

These compile the real executables and drive them against synthetic services on loopback. Each
writes a JSON report that binds the source and executable hashes. Reports are unsigned local
observations, not release evidence.

From the repository root:

```sh
# Admission: valid, tampered, wrong-key, expired, rollback, unknown-field and injection cases
(cd testifysec/managed && python3 uat.py --go "$(command -v go)" --bun "$(command -v bun)" --report /tmp/admission-uat.json)

# Gateway: streaming, credential isolation, denied-request audit, offline bounds, restart recovery
(cd testifysec/gateway && python3 uat.py --go "$(command -v go)" --report /tmp/gateway-uat.json)

# Portal: portal-signed profiles through the compiled hardened-admission
(cd testifysec/portal && python3 uat.py --go "$(command -v go)" --bun "$(command -v bun)" --report /tmp/portal-uat.json)
```

## Run your platform against the contract

A backend conforms when it passes the portal HTTP contract and the workstation admits what it
serves. The contract model in PR #182 states that a conforming backend's profiles are admitted
whichever backend it is (`conforming_backend_admitted`); the backend vectors that would check
this against running code have no Go consumer yet.
