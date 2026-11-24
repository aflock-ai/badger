# Badger: TestifySec components

This directory holds the components TestifySec added to OpenCode. They are licensed under
Apache-2.0 (see `../LICENSE-APACHE` and `../NOTICE`). OpenCode's own code lives in `../packages`
and stays MIT.

Badger is a maintained fork: a small patch series on a pinned upstream commit
(`upstream.commit`). Changes to upstream files are kept narrow and reviewable against that
commit. See [upstream provenance and build notes](STANDALONE.md).

Source publication does not establish runtime isolation or compliance qualification.

## Components

| Directory | What |
|---|---|
| `gateway` | Model gateway: the session's only network path |
| `managed` | Admission launcher and signed-profile verification |
| `broker` | Session broker for hosted workers |
| `model-broker`, `portal` | Model broker and management portal (`badger-broker`) |
| `connectors` | MCP connectors (Jira, Confluence, GitLab) and the connector gateway |
| `platform` | Checks an enrolled agent against TestifySec platform state |
| `commands` | `badger enroll` and `badger attest` |
| `runtime`, `sandbox`, `vm` | Managed Linux runtime path, local execution boundary, macOS VM fixture |
| `native`, `packaging`, `distribution`, `execution` | Native verification diagnostic, single-executable packaging, offline bundle verification, execution probe |
| `requirements` | Optional reader for Pushgate requirements |
| `jade` | Build-and-gate CLI |
| `formal` | Lean models and cross-language test vectors |
| `enrollment` | Parked: not buildable from this repository |

## Architecture

Use the same policy and agent core in both profiles. The application, worker, model gateway, storage, identity, and audit paths must all remain within the deployment's approved boundary.

| Concern | Managed workstation | Hosted service |
| --- | --- | --- |
| Initial platform | Managed Linux reference image; additional OSes require their own evidence | Managed Linux service and isolated workers |
| User interface | CLI/TUI first; desktop/IDE integration reviewed separately | Authenticated UI/API with explicit session and workspace authorization |
| Execution | Agent and descendants inside a constrained VM or equivalent enforced boundary; narrowly mounted workspace | Isolated worker per user/workspace; no shared writable home, credentials, or cross-user execution identity |
| Identity | Existing enclave identity and managed credential broker | Existing enclave identity provider, short-lived session credentials, per-request authorization |
| Network | Deny-by-default egress enforced outside the agent; approved internal model gateway | Same egress policy for service and workers; ingress through authenticated boundary |
| Storage | Managed protected storage for repository, history, cache, credentials, temporary files, and swap | User/workspace-scoped storage, retention and backup policies, protected audit destination |
| Administration | Policy installed through privileged management outside the agent's writable paths | Centrally managed policy and deployment identity outside worker control |

Do not treat prompt approval as isolation. Repository content, tool output, model responses, plugins, and MCP servers are untrusted inputs or executable components. The threat model includes malicious repositories, prompt injection, compromised dependencies, stolen user tokens, and cross-user access. Local administrators and enclave operators require separate privileged-access controls; application policy cannot contain a compromised host administrator.

## Findings at the pinned baseline

These are architectural observations, not a complete security audit:

| Evidence | Consequence for the patch series |
| --- | --- |
| `SECURITY.md` explicitly excludes sandboxing and treats permission prompts as a UX feature | Add enforced execution isolation and test descendants, filesystem boundaries, and egress |
| `packages/server/src/auth.ts`: a listening server requires a password, but the in-process (embedded) routes run with none | Hosted profile must fail closed and enforce identity and resource authorization throughout API, event streams, and terminal paths |
| `packages/core/src/config.ts` loads user and repository configuration; global policy takes priority over repository policy | Reuse upstream policy machinery but add a distinct administrator-controlled policy authority that user settings cannot relax |
| `packages/core/src/permission.ts` checks deny rules first, then the last matching rule; `packages/core/src/managed-policy.ts` can only deny and otherwise allows | Inventory every enforcement call site and make managed capability admission default-deny |
| `packages/core/src/config/plugin/source.ts` discovers plugin directories, installs configured packages, and imports executable code | Check managed policy before discovery/install/import side effects; filesystem and network containment remain necessary |
| `packages/cli/src/updater.ts` checks public release endpoints and can download and run an installer | Disable unattended public update paths and support reviewed internal distribution |
| `packages/core/src/credential.ts` keeps provider credentials in the local database | Local storage does not replace managed secret storage and lifecycle controls |
| `packages/cli/script/build.ts` compiles using Bun | Establish the exact shipped runtime's crypto inventory and validation evidence before selecting the FIPS architecture |

OpenCode 2.0 splits entrypoints across `packages/cli`, `packages/server` and the SDK's embedded host. Test all supported CLI, server, SDK, and integration entrypoints; a control in one configuration loader does not establish coverage of every entrypoint.

## Ordered patch backlog

All entries below are planned, not implemented.

| Series | Change | Acceptance evidence |
| --- | --- | --- |
| 01 managed policy | Administrator-owned policy source; strict schema; fail closed on absent/invalid required policy; policy version in diagnostics | User config, repository config, environment, CLI flags, and config API cannot relax restrictions; validation occurs before executable plugin loading or network side effects |
| 02 offline capabilities | Explicitly admit model endpoints, providers, plugins, MCP, LSP, formatters, custom tools and download paths; disable public sharing, telemetry export, catalog refresh and public updates in managed profiles | A complete workflow runs with external networking blocked; denied actions fail before connection/install; approved operation works without public DNS or package registries |
| 03 authenticated service | Require secure hosted startup, trusted identity integration, resource ownership checks, bounded sessions and streams | Missing/expired credentials, forged proxy headers, foreign session IDs, WebSocket/event-stream access, and terminal access are denied; direct backend bypass is prevented |
| 04 execution boundary | Integrate external sandbox launch and scoped workspace/credential access; isolate subprocesses and MCP/LSP processes | Attempts to read host secrets, escape via symlinks, reach host sockets/metadata services, persist outside workspace, or bypass egress through children fail |
| 05 audit and data lifecycle | Structured security events, actor/workspace identity, policy revision, tool decision/outcome; secret redaction, retention and protected export | Audit output excludes credentials and prompt bodies by default; loss-of-audit behavior is explicit and tested; caches, traces, backups and crash artifacts follow the same data classification |
| 06 crypto integration | Implement the selected documented crypto boundary and approved-mode startup checks | Every security-relevant crypto operation maps to an exact module/version, certificate and operational environment; negative tests prove failure on unsupported configuration |
| 07 release profiles | Workstation and hosted reference deployment manifests, mirrored dependencies, SBOM, signed artifacts and provenance, vulnerability triage | Clean rebuild and patch replay; signature verification; offline deployment; isolation and authorization regression suite on each supported profile |

Network enforcement must constrain destinations, redirects, proxies and resolution, not merely provider display names. A user-selectable custom base URL must not bypass the approved endpoint restriction. Shell networking is a separate path from SDK networking.

## FIPS and classified-system gate

FIPS 140-3 validation concerns cryptographic modules, their approved mode, and the allowed operating configuration. A FIPS-capable OS or TLS proxy does not automatically cover crypto performed inside Bun, native dependencies, SDKs, Git/SSH, or child tools. Inventory transport encryption, credential handling, signing/verification, random generation, and storage encryption separately; distinguish non-security checksums from security uses.

Evaluate these options before a runtime rewrite:

1. Retain the upstream runtime if the exact shipped crypto implementation can be supported by the required validation evidence and approved-mode configuration.
2. Keep UI and orchestration largely upstream and move security-relevant transport/credential operations into a narrowly scoped broker using a validated module. Review local IPC protection, residual application crypto, and all alternate routes; a sidecar alone is insufficient.
3. If neither approach closes the inventory, scope a runtime adapter or replacement and measure its long-term patch maintenance cost.

For Secret information, obtain the program's requirements for NSA-approved protection in transit and at rest, including applicable CSfC or other approved architecture. FIPS alone is not the classified-data protection decision. Do not choose cryptographic products or claim compliance before the deployment boundary and authorizing authority's requirements are established.

## Authorization and release gates

IL6 describes the cloud environment's handling of information up to Secret. The workstation application is part of the mission system; it does not acquire an IL6 authorization from its source code. An authorized cloud service also does not automatically authorize this application or every model service within it.

Before a production release, establish the mission sponsor and authorizing official, system boundary and categorization, applicable current DoD SRGs/STIGs and control baseline, inherited versus implemented controls, approved model hosting, identity and network architecture, crypto evidence, and assessment/ATO path. Produce the system security plan inputs, test evidence, vulnerability remediation record and ongoing monitoring responsibilities. These are deployment-specific deliverables, not a generic certification badge on the repository.

Initial engineering gates:

- Demonstrate one end-to-end coding task on each reference profile using synthetic data, an internal model endpoint, no public egress, and enforced worker isolation.
- Demonstrate policy bypass, authentication/authorization, plugin admission, and subprocess isolation negative tests.
- Resolve the crypto inventory and module evidence before making a FIPS claim.
- Release only a pinned, signed, traceable build whose patch series replays against the recorded upstream revision.

Open decisions: supported workstation OSes beyond the Linux reference; target classified hosting environment and model endpoint; mission sponsor/AO; required crypto architecture and approved modules. None of these should be inferred from a commercial provider's general government marketing.

## References

Reviewed 2026-09-08; file references updated for the OpenCode 2.0 base on 2026-10-19. Recheck authoritative guidance when establishing the assessment baseline.

- [Upstream security model](https://github.com/anomalyco/opencode/blob/843a6c514e606b436a7fe713422ace0a93ad3d61/SECURITY.md)
- [Upstream policies](https://opencode.ai/docs/policies/): useful resource controls; not a substitute for the managed boundary.
- [NIST CMVP validated modules](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/validated-modules): verify exact modules and operating conditions.
- [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final)
- [DoD Cloud Security Playbook, Volume 1](https://dodcio.defense.gov/Portals/0/Documents/Library/CloudSecurityPlaybookVol1.pdf): IL6 and mission-owner responsibilities.
- [DISA DoD Cloud Computing Security](https://www.cyber.mil/dccs/): obtain current applicable SRGs for the target authorization.
- [NSA CSfC overview](https://www.nsa.gov/Resources/Commercial-Solutions-for-Classified-Program/Overview/): classified-system protection architecture.
