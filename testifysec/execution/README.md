# Native execution preflight

This is a native prerequisite probe for the [one-executable product contract](../PRODUCT-CONTRACT.md),
not a VM backend or a launchable hardened coding session. It contains no Go module
dependencies. Linux and Windows use Go's standard library; the macOS native build
also links a small Objective-C bridge against Apple's installed system frameworks.
Customers do not install Go, Python, Node, npm, Bun, Docker or a separate helper to
run this probe. Go/Python and the macOS SDK are development build/UAT tools.

The five **proposed** targets are macOS arm64/amd64, Linux arm64/amd64 and Windows
amd64. Cross-compilation is not a supported-release or isolation qualification.
Windows arm64 has an additional compile-only check but is deliberately outside
the proposed product matrix and refuses without probing WHP. No backend here is
implemented, VM-runtime-tested or qualified. Every `preflight` returns exit 3 and
`executionAllowed: false`, including when every observed OS prerequisite succeeds.

## What the binary actually observes

| Host | Native observations | What remains unproven |
| --- | --- | --- |
| Linux | Opens fixed `/dev/kvm` with no final symlink, verifies a character device, calls `KVM_GET_API_VERSION` and requires version 12, then closes the descriptor. | No VM/vCPU is created; guest CPU/device capabilities, resource controls, guest payload integrity and lifecycle isolation are untested. Device access is scoped to this process's credentials and namespace. |
| macOS, CGO enabled | Calls `sysctl(kern.hv_support)`, `VZVirtualMachine.isSupported`, and Security's `SecTaskCreateFromSelf` / `SecTaskCopyValueForEntitlement` for the current task's Boolean `com.apple.security.virtualization`. | A returned entitlement is only the named task entitlement observation. No VM configuration is validated, guest booted, publisher identity authenticated or runtime memory measured. Release signing, notarization and the final VM configuration remain separate requirements. |
| macOS, CGO disabled | Calls the same native sysctl; the framework and entitlement checks explicitly return `unknown` because their native bridge is absent. | A pure Go cross-build cannot establish Virtualization framework or entitlement readiness. |
| Windows amd64 | Loads `WinHvPlatform.dll` with `LoadLibraryExW` and `LOAD_LIBRARY_SEARCH_SYSTEM32`, resolves `WHvGetCapability`, and queries `WHvCapabilityCodeHypervisorPresent`; requires `S_OK` and the expected BOOL result size. | No partition/vCPU is created. Optional features, installed OS support, workload operation and Windows custody/IPC isolation remain to be qualified on a real Windows host. |

An API error, inaccessible prerequisite or unrecognized value cannot grant
execution. The JSON separates observed prerequisites from backend implementation
and qualification. A missing backend never changes a successful OS observation
into a claim that hardware is absent. Reports are **unsigned local observations**,
not authorization input, hardware attestation, ALPS, FIPS or IL6 evidence. Time is
the local clock. A caller can modify JSON but cannot modify the compiled execution
guard by doing so. Future authorization must recheck live state at actual launch;
it must never accept this diagnostic JSON as a security credential.

The host OS, kernel, system DLL/framework loader and process environment remain
trusted for these observations. Running under a restricted process can change
the answers; an unknown/false result is not a diagnosis that physical hardware
lacks virtualization. The future product launcher must enforce its own secure
loading/custody rules before invoking the integrated probe.

## CLI and local UAT

This engineering command is intended to become an internal product startup
check, not another customer-installed component:

```text
hardened-execution inspect     # JSON diagnostic, exit 0 if output succeeds
hardened-execution preflight   # JSON plus execution refusal, exit 3
hardened-execution matrix      # proposed target metadata only, exit 0
```

All other arguments return exit 2. There is no command-execution operation,
backend override, Docker/unconfined fallback, remote fallback, package discovery,
download or privilege escalation. `inspect` exit 0 means only that the diagnostic
was emitted; it never means the backend is runnable.

From this directory, using an explicitly selected installed Go toolchain:

```sh
GOCACHE=/private/tmp/hardened-opencode-gocache python3 uat.py \
  --go /absolute/path/to/go \
  --output-directory /private/tmp/hardened-execution-uat
```

The output directory must be new. The harness builds from a private source
snapshot, checks source hashes before/after, runs real current-host native probes
and refusal tests with an empty helper PATH, and cross-compiles the five proposed
targets plus unsupported Windows arm64. macOS also runs CGO-disabled tests to
prove the bridge's absence remains unknown. Each cross-build is explicitly marked
unrun. Source, compiler executable, binary and log hashes accompany the report.
These are pathname byte hashes for attribution, not a runtime measurement. The
Go toolchain, compiler/SDK and external cache are development inputs; this is not
a reproducible release or verified dependency-supply-chain claim. The harness
does not sign the macOS executable or add an entitlement to make a test pass.

## Integration seam and next phase

The existing `jade/internal/sandbox` deliberately falls back without restrictions
when Landlock is unavailable or on other operating systems. Its contract cannot
be used as this product's execution backend. `agentflow/tools/coding` provides
read-only filesystem tools, not containment for arbitrary OpenCode commands.
The existing hardened broker's Docker Engine lifecycle remains unchanged; neither
this probe nor a Docker-less client removes its current daemon requirement.

Next, separate broker `Preflight / Create / Run / Freeze / Capture / Destroy`
operations from its Docker implementation, preserve native admission and the
regular-file artifact contract, and implement the chosen local Linux VM backend.
An approved embedded guest kernel/rootfs/toolpack, bounded host-to-guest channel,
gateway transport, stable artifact export and complete owned-process cleanup must
be tested before enabling execution. A managed remote worker remains an explicit
separate deployment mode with its own residency/trust contract. It is never a
silent fallback. Windows/macOS-native SDK toolchains remain a separate feature;
a Linux guest cannot run them merely because the launcher is cross-platform.

## Primary API references

- [Linux KVM API](https://docs.kernel.org/virt/kvm/api.html): device API version and capability calls; positive device API access is narrower than working VM execution.
- [Apple Hypervisor framework](https://developer.apple.com/documentation/hypervisor): hardware support via `kern.hv_support`.
- [Apple VZVirtualMachine](https://developer.apple.com/documentation/virtualization/vzvirtualmachine): framework support and same-architecture guest lifecycle.
- [Apple virtualization entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.virtualization): required entitlement and VM configuration validation.
- [Apple Code Signing Services](https://developer.apple.com/documentation/security/code-signing-services): supported current-task entitlement query APIs. The local SDK's `Security/SecTask.h` distinguishes absent entitlement from API error.
- [Microsoft WHvGetCapability](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvgetcapability): hypervisor-present capability, result layout and architecture-specific prerequisites. Future Windows arm64 support must additionally check its `Arm64Support` feature.
- [Microsoft LoadLibraryExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw): System32-only DLL dependency search.

Documentation reviewed 2026-09-08. Qualify pinned OS/toolchain releases before
claiming a supported product target; current vendor documentation can change.
