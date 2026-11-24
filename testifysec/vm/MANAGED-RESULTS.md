# Managed-shaped VM jobs and results, version 3

This development prerequisite adds complete, bounded regular-file observations
for a pinned OpenCode worker. It does **not** admit a signed VM profile, authenticate
a platform agent, register a finalized signing record, or qualify a production
deployment. A developer still chooses the configuration, image and paths.
Linux broker, native admission, signing and producer consumers remain unchanged
and must not accept this as their existing Docker execution receipt.

Version 2 fixture behavior remains unchanged, including its result-file and
`HARNESS_TEST_PASSED` checks. V3 succeeds on an observed zero worker exit plus
completed reaping, output EOF and capture. It makes no claim that a model's tools
or requested tests passed merely because OpenCode exited zero.

## Explicit version boundary

Use `build.py --protocol 3 --mode worker --worker-root PREPARED_ROOT` to build a
development job. The default remains protocol 2. V3 configuration, job and
envelope schemas are `testifysec.vm-{config,job,envelope}/v3`. Host dispatch uses
the explicit config schema; guest dispatch uses the host's `hc.protocol=3` boot
argument. The job frame is `HCJOB3\r\n`, a four-byte big-endian envelope size,
the exact envelope and EOF. V2 and V3 are not interchangeable or fallback modes.
The model relay remains HCMDL2; its existing assignment and transport checks apply.

The V3 job retains the existing binding tuple. `requestSha256` and
`materialsSha256` hash the **exact nested JSON bytes**, not a reserialization.
`backendSha256` retains its kernel-digest/newline/root-digest/newline definition;
it is not a hardware measurement or a new signed backend-manifest digest.

The request has exactly `prompt` and `timeoutSeconds`; only the fixed
`/toolpack/opencode-worker` executable runs. Material entries have exactly
`path`, `sha256`, `size`, `executable`, `contentBase64`. Input files must be
strictly path-sorted. Canonical base64, exact sizes/digests and all portable
path rules are checked before installation or worker execution.

## Fixed V3 limits

| Resource | Limit |
| --- | --- |
| Config | 4 KiB |
| Exact job JSON | 512 KiB |
| Encoded job envelope | 768 KiB |
| Prompt | 4,096 UTF-8 bytes |
| Worker duration | 1–45 seconds |
| Host duration | At least worker duration + 10 seconds, at most 70 seconds |
| Worker memory / workspace tmpfs | 1 GiB / 64 MiB |
| Material or final regular-file content | 256 KiB total, 64 KiB per file |
| Material or final files | 128 |
| Material prefixes / final filesystem entries | 256, including directories |
| Portable path | 1,024 ASCII bytes, 32 components, 255 bytes/component |
| Combined stdout/stderr | 64 KiB |
| Result JSON | 768 KiB |
| Total serial data | Result limit + 256 KiB |

Enumeration is bounded before sorting. Capture walks the whole workspace after
all workload processes are killed and reaped; it rejects incomplete reads,
links, special files, privileged modes, ambiguous case/prefix collisions,
`.git` and `git~` aliases, Windows device names, and unsafe portable paths.
Empty directories and full filesystem modes are not exported. A single
`executable` flag preserves executable intent. No files are applied on the host.

## Result and completion

PID1 emits `testifysec.vm-result/v3` inside one `HCVM3` serial frame. It binds
the exact job, nonce and tuple, then reports `workerStarted`, `exitObserved`,
nullable `exitCode`, `reaped`, `outputDrained`, `outputComplete` and
`captureComplete`. A missing or unknown exit is never converted to zero.
One shared kernel pipe supplies exact combined stdout/stderr bytes in
`outputBase64` with `outputSha256`. EOF is independently observed; `os/exec.Wait`
returning an exit error cannot hide a forced pipe close behind a drain claim.

Successful capture contains all regular files with their exact content and
`removed` initial paths. Initial and final manifest digests hash compact
descriptor arrays in this field order:

```json
[{"path":"file","sha256":"...","size":1,"executable":false}]
```

Descriptors are bytewise path-sorted and use Go JSON string escaping, including
`&` as `\u0026`. Content transport bytes are excluded from the descriptor hash.
Failure before complete capture returns empty file/removal arrays and no final
manifest. A partial traversal can never be mistaken for file deletion.

The host independently checks the typed result, exact output and file hashes,
manifest hashes and removals against its validated initial job. Host success
also requires actual VM running/stopped observations and drained serial, job
and model relay channels. The host observation is separately versioned
`testifysec.vm-observation/v3` and still reports `admissionIntegrated:false` and
`qualification:developer-only-unqualified`.

## Local UAT

From the OpenCode subtree, using trusted cached build tools and retained inputs:

```sh
python3 testifysec/vm/uat-managed.py \
  --go /absolute/path/to/go \
  --worker /absolute/path/to/gateway-mode-opencode-worker \
  --worker-inputs /absolute/path/to/retained-vm-worker-inputs \
  --output /private/tmp/aflock-managed-uat-NEW
```

The harness builds native fault fixtures, runs guest Go capture/parser tests in
Linux VZ, mutates real results against the exact Swift validator, and runs the
actual compiled OpenCode worker through the native gateway and a synthetic local
provider. A test-only static utility invoked by OpenCode's ordinary Bash tool
performs filesystem operations in the VM. There are no customer credentials,
live model calls, public pulls or Docker invocations. Gateway profile bypass is
explicit local-fixture mode; this is not signed V3 VM admission evidence.
Source, tool, binary, input, output and report digests are retained. Existing
`uat.py`, `uat-relay.py` and `uat-relay-io.py` cover V2 regression separately.
