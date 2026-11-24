# HC-03: local execution boundary foundation

This is a **local development adapter**, not the finished hardened product. It
demonstrates a real, constrained Linux worker behind a typed execution request.
Python is required for this prototype and its UAT; the shipping native service,
installer and every upstream OpenCode tool integration remain outstanding. No
ALPS, hardware-attestation, FIPS or IL6 qualification is claimed.

The controller starts repository code only inside a non-root container from an
administrator-selected **already cached image ID**. Runtime image pulls and host
execution fallback are absent. The image filesystem is read-only; networking,
capabilities, device mappings and credential/socket mounts are unavailable. CPU,
memory, workspace storage, process count, file descriptors, execution time and
captured output have fixed limits. The controller inspects the concrete container configuration before
starting it and removes that container after completion or refusal.
The Docker logging driver is disabled and verified before start, so discarded
worker output cannot grow an unbounded daemon log. Output is captured only from
the bounded live attachment.

The policy is a broker-owned private file outside the workspace. Requests may
select only that policy's workspace ID, a command, and a lower timeout. They
cannot add images, mounts, environment variables or engine endpoints. This is
**not authenticated admission**: same-uid host processes can modify the policy.
A separate-user daemon and platform-issued caller capabilities are subsequent
phases. Run this scaffold only as a local developer harness.

Before execution the adapter copies a bounded workspace through no-follow
directory descriptors into a private disposable directory. It rejects symlinks,
hardlinks and special files; it excludes every `.git` entry. It never invokes
host Git on the copied content, exports edits or executes repository metadata.
Directory enumeration stops at the global entry budget before sorting; excluded
entries count toward that budget. A hostile wide directory cannot force an
unbounded host-side list allocation.
The snapshot is mounted read-only at `/inputs` and copied into a 64 MiB tmpfs
workspace under the unprivileged worker identity. There are no writable host
mounts. A separate 16 MiB temporary filesystem blocks direct file execution.
The result binds the actual copied file bytes, request, output, policy, runtime
image and normalized container arguments by digest. It records the command's
exit code, **not a semantic assertion that tests passed**. Results are unsigned.

## Run the local UAT

Use an existing Linux Alpine/busybox image. No public pulls, package installs,
cloud services, production credentials or published host ports are required.
The harness provisions only synthetic source, secrets and a private Docker
bridge TCP echo endpoint. It cleans only containers it created.

```sh
cd testifysec/sandbox
python3 uat.py \
  --engine-socket /absolute/path/to/local/docker.sock \
  --image sha256:YOUR_ALREADY_CACHED_IMAGE_ID \
  --out .cache/local-uat.json
```

Use `docker image inspect YOUR_EXISTING_IMAGE --format '{{.Id}}'` to read an
existing image's immutable local ID. On this development machine the exercised
fixture is Docker Desktop's Linux VM with Alpine 3.20 arm64. Do not generalize
those results to native Linux, other kernels, other Docker settings or macOS
process isolation.

The report retains source hashes, the current commit and dirty paths, runtime
version/image, per-check results and full successful execution receipts. A
failed runtime setup is a failed UAT, never a passing sandbox denial. Negative
checks include actual root-write and network refusals, host-secret exclusion,
unassigned workspaces, unknown request fields, mutable/missing images, missing
engine, symlinks, hardlinks, timeout, storage quota and output exhaustion. Positive controls
establish that files, commands and the synthetic network endpoint actually work.

## Direct request format

Provision the policy in a private directory outside the source workspace, with
mode `0600` and directory mode `0700`. These paths are developer inputs, not
worker-supplied values:

```json
{
  "schema": "testifysec.hardened-opencode.sandbox-policy/v1",
  "dockerBinary": "/absolute/path/to/docker",
  "engineSocket": "/absolute/path/to/local/docker.sock",
  "image": "sha256:64_LOWERCASE_HEX_DIGITS",
  "workspace": { "id": "demo", "source": "/absolute/path/to/source" },
  "limits": {
    "timeoutSeconds": 5,
    "outputBytes": 8192,
    "workspaceBytes": 1048576,
    "workspaceFiles": 100
  }
}
```

```json
{
  "schema": "testifysec.hardened-opencode.exec/v1",
  "workspace": "demo",
  "command": "printf 'hello from the worker\\n'",
  "timeoutSeconds": 3
}
```

```sh
python3 broker.py --policy /absolute/admin/policy.json --request /absolute/request.json
```

Only `completed` means the controller observed a terminated worker; inspect
`exitCode` separately. `rejected` includes both admission refusal and interrupted
execution such as an output limit. Neither implies successful test evidence.

## Native integration work that follows

The first production adapter must route shell execution through the broker: on Badger
1.x, `packages/opencode/src/tool/shell.ts` and `packages/core/src/tool/bash.ts`; on the
OpenCode 2.0 base, `packages/core/src/tool/plugin/shell.ts` and `packages/core/src/shell.ts`. Bash-only wrapping does
not complete HC-03. PTYs, local MCP subprocesses, LSP servers, formatters,
repository/custom plugin imports, Git helpers, web tools and built-in file
operations are additional authority-bearing paths. Unsupported capabilities
must fail closed before initialization until routed or removed. Read tools can
start LSP servers, so permission-filtering the advertised shell tool is
insufficient.

Do not reuse `jade/internal/sandbox` unchanged: it intentionally runs without
restrictions when Landlock is unavailable and on non-Linux hosts. The existing
ALPS sandbox controls also document writable Git hooks/config escaping through
later host-side Git use; this adapter avoids that path by never exporting or
running host Git on the worker snapshot.

Next product work is authenticated native service IPC, separate controller and
runner identities, safe reviewed edit export, approved tool packs, complete
upstream routing, independently observed execution evidence, protected signing,
and production Linux qualification. Hardware protection strengthens signing
custody; it does not make an in-process observer or an unsigned local UAT report
authoritative.
