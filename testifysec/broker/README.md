# Native Hardened OpenCode execution broker

This phase replaces the Python sandbox scaffold with a compiled Go service using
the Docker Engine HTTP API over an administrator-selected Unix socket. There are
no third-party Go dependencies, Python runtime, Docker CLI calls, image pulls or
repository-code host execution fallback.

Production startup requires Linux, an explicit allowed caller UID distinct from
the broker UID, and a pinned native profile-admission executable. Each connection
is authenticated with kernel `SO_PEERCRED`; request JSON cannot assert identity.
The broker independently re-verifies the signed DSSE profile on **every request**,
including time validity, and requires its payload digest to match the exact
administrator-selected `profileSha256`. That immutable selection binds the
profile to this policy's workspace, runtime image and optional toolpack/gateway.
UID attribution is local process authentication, not SPIFFE or tenant identity.

The sole host child is the hash-pinned `hardened-admission` launcher, with bounded
input/output/time and a clean environment. That launcher pins its compiled
runtime, which verifies the profile with native Rookery. Repository code executes
only inside the worker. Deployment must protect the broker and complete admission
bundle from the untrusted caller; binary hashes alone do not establish custody.

Workers run as UID/GID 65534 with read-only root, no network, dropped capabilities,
built-in seccomp, no-new-privileges, private IPC/PID domains, bounded process/CPU/
memory/file-descriptor limits, bounded workspace/tmp tmpfs, and logging driver
`none`. Input snapshots are read-only mounts. No host path is writable by the
worker. The broker inspects concrete engine settings before starting code. A
fixed sleeping keeper retains the workspace while the requested command runs
through Docker's attached exec API. Its authoritative exec exit status is checked
before the whole container is paused for artifact capture. It removes the worker
and temporary workspace volume after completion, cancellation or refusal.

The workspace is a broker-created, uniquely named `local` driver volume backed
by tmpfs with the administrative size limit, `nosuid,nodev`, UID/GID 65534 and
mode 0700. Docker archive does **not** expose `HostConfig.Tmpfs` contents; using
that form would yield an incorrect empty artifact. The inspected local-driver
volume is visible to both the worker and Docker's archive implementation. The
ordinary `/tmp` mount retains its separate 16 MiB `noexec` tmpfs limit.

Cleanup ownership is registered before either Docker create operation. Lost or
malformed responses are reconciled through unpredictable operation names and
exact policy/operation labels; unrelated objects are never deleted. Container
force-removal is attempted before volume removal, with absence verified through
the API. A cleanup failure refuses further executions and is never represented
as `cleanup: true`. SIGTERM/SIGINT closes admission, cancels active requests, and
waits up to 35 seconds for handlers and their independent bounded cleanup before
the process exits. Allow at least 45 seconds in a service-manager stop timeout.

SIGKILL, host failure, a stalled daemon, or a create that remains unresolved
beyond the bounded API/cleanup deadline still require administrative orphan
reconciliation. No persistent ownership journal or startup recovery is
implemented; the broker does not claim crash-safe resource reclamation.

Snapshot traversal holds directory handles, refuses links and special files,
bounds enumeration before sorting, excludes `.git`, detects observed changes and
binds copied regular-file bytes. Results bind the broker binary, request, policy,
profile, inputs, runtime image, normalized boundary and raw output. `output` is a
display string; **`outputBase64` is the exact byte representation bound by
`outputSha256`**, including non-UTF8 data. Results are unsigned observations and
do not assert that a test suite is meaningful or assign an ALPS level.

## Retained workspace artifacts

Successful execution returns `artifact` with schema
`testifysec.hardened-opencode.workspace-artifact/v1` and scope
`regular-files-only`. Decode `payloadBase64` and verify `sha256` against those
**exact bytes before parsing**. The inner `workspace-bundle/v1` contains:

- `materialsSha256`, matching the initial regular-file manifest in the result.
- `files`, the sorted final regular-file manifest, and `finalManifestSha256`.
- `changes`, sorted added or changed files with exact `contentBase64` bytes.
- `removed`, sorted initial regular-file paths absent from the final export.

Manifest records use fields in the order `path`, `sha256`, `size`, `executable`;
the digest covers their compact Go JSON array encoding, with an empty array
represented as `[]`. Content hashes cover decoded file bytes; mode records only
whether a file is executable. The result also binds the exact request/profile/
policy and a normalized fixed exec invocation. Consumers must verify these
against independently retained expectations, including the initial snapshot;
an unsigned caller-provided receipt is not an authenticated broker statement.

Capture streams the daemon archive while all worker processes remain paused.
It never extracts into the host checkout. It rejects emitted links, devices,
FIFOs, privileged modes, unexpected metadata, duplicate paths, file/directory
collisions, `.git` variants and traversal. Version 1 conservatively permits
ASCII paths only, with at most 32 components and 1024 bytes, and rejects names
ambiguous on common filesystems. Final entries/content obey the workspace
budgets; changed content is capped at 256 KiB, decoded payload at 768 KiB and
the complete response at 2 MiB. Exceeding any limit refuses the whole artifact.

Docker silently omits Unix sockets from archives. The artifact therefore proves
the exported regular-file contents, **not absence of every special entry in the
worker filesystem**. All emitted special/link records are refused. Empty
directories, ownership, timestamps and extended attributes are not exported.
No artifact is automatically applied to the host; the worker and volume are
removed after capture, and exact retained bytes remain in the response.

## Build

```sh
cd testifysec/broker
GOWORK=off CGO_ENABLED=0 go build -trimpath -o dist/hardened-broker .
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -o dist/hardened-broker-linux-arm64 .
GOWORK=off go test ./...
```

## Administrative policy and IPC

Provision a private policy file outside the workspace. Its directory and file
must be owned by the broker, with no other-user write access (file mode `0600`).
The listener directory is also broker-owned and not writable by callers; Linux
socket mode permits connecting, while kernel UID authorization gates every
request. Only one execution is admitted at a time; connection and body sizes are
bounded.

```json
{
  "schema": "testifysec.hardened-opencode.broker-policy/v1",
  "listenSocket": "/run/hardened-code/broker.sock",
  "dockerSocket": "/run/docker.sock",
  "image": "sha256:EXACT_ALREADY_CACHED_IMAGE_ID",
  "workspace": { "id": "demo", "source": "/srv/workspaces/demo" },
  "limits": {
    "timeoutSeconds": 60,
    "outputBytes": 1048576,
    "workspaceBytes": 1048576,
    "workspaceFiles": 1000,
    "memoryMiB": 1024,
    "workspaceMiB": 256
  },
  "allowedUIDs": [2001],
  "developmentAllowSameUID": false,
  "admissionExecutable": "/opt/testifysec/admission/hardened-admission",
  "admissionSha256": "EXACT_LAUNCHER_SHA256",
  "profileSha256": "EXACT_PROFILE_PAYLOAD_SHA256",
  "tenantId": "tenant-example",
  "deploymentId": "deploy-a",
  "profileId": "engineering",
  "toolpack": "/opt/testifysec/toolpack"
}
```

`tenantId`, `deploymentId` and `profileId` are required with an admission executable. The
native verifier checks the profile's assignment against the trust compiled into it, and the
broker checks the admitted profile against these three again, so a verifier built for another
assignment cannot admit a profile here even when its payload digest is pinned.

### The worker's /run/badger mount

Every execution gets a fresh, broker-written directory mounted read-only at `/run/badger`:
`profile/profile.dsse.json` is the exact envelope the broker admitted, and `tokens/<name>.token`
are the caller's connector tokens, copied from `<connectorTokenDir>/<caller uid>/<name>.token`
when the policy names `connectorTokenDir` (a broker-owned directory outside the workspace; each
token a private, broker-owned, singly linked file of at most 64 KiB named `[a-z0-9-]{1,32}.token`,
at most 16 per caller; anything else refuses the execution). The tokens are removed when the
execution ends, also from a retained run. The admission verifier and the connector binaries come
from the toolpack, at `/toolpack/badger/admission/hardened-admission` and
`/toolpack/badger/connectors/<name>`. Anything running as the worker's user can read the tokens
(CONNECTORS.md, "Stolen token"), so give the broker the narrowest, shortest-lived ones.

### Activation records instead of a pinned digest

With an `activation` block the policy names no `profileSha256`; the pin is the digest named by
the latest activation record the device admitted (testifysec/PORTAL.md):

```json
"activation": {
  "stateDir": "/var/lib/badger/device",
  "rootCas": ["-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"],
  "signerSan": "spiffe://enclave.example/badger/portal",
  "deviceKeySpkiSha256": "<64 hex: SHA-256 of this device key's SPKI>",
  "activationFloor": 0,
  "profileFloor": 0
}
```

A request may carry `activationEnvelope` and `resetEnvelope`, the signed records from the
management backend's pull. The broker verifies them (`activation/`), commits the new high-waters
to `stateDir` durably, and only then admits the profile under the activated digest, refusing a
profile sequence below the profile high-water. The installer creates `stateDir` (broker-owned, not
group- or world-writable) and its first-install marker with `activation.Install`; deleting the
state after the first activation fails closed until a reset record for this device is admitted.
Protected finalization still needs a policy-pinned digest and is not available with activation.

The optional read-only `toolpack` mounts at `/toolpack`. One optional
administrator-fixed `gatewaySocket` mounts at
`/run/hardened-gateway/gateway.sock`; alternatively, `gatewayVolume` selects an
**existing** dedicated Docker volume mounted read-only at
`/run/hardened-gateway`. These are never request-controlled mounts. The volume
must contain only the session's constrained model-gateway socket. A macOS Unix
socket should not be assumed to communicate through Docker Desktop bind mounts;
use a Linux socket/volume for that deployment.

```sh
dist/hardened-broker serve --config /absolute/admin/policy.json
dist/hardened-broker execute --socket /run/hardened-code/broker.sock \
  --request /absolute/request.json
```

Clients use HTTP `POST /v1/execute` over the Unix socket:

```json
{
  "schema": "testifysec.hardened-opencode.exec/v1",
  "workspace": "demo",
  "command": "/toolpack/opencode-worker",
  "stdin": "BOUNDED_WORKER_INPUT_JSON",
  "profileEnvelope": "RAW_SIGNED_DSSE_JSON",
  "timeoutSeconds": 60
}
```

The worker reads stdin from a private read-only input mount and executes in
`/workspace`. The image's inherited environment entries are explicitly cleared;
only fixed runtime variables are assigned. No provider or signing credential is
forwarded. The approved gateway must independently authenticate and limit the
session; mounting a socket is not that authorization protocol.

## macOS sessions: device sign-in

A macOS VZ session (`vzsession`) gets its model provider token by device sign-in
to the model broker (`testifysec/model-broker`, `device.go`), not from a file. The
gateway template's `brokerSignIn` names where the edge serves the broker
(`edgeUrl`, for example `https://edge.example.test/broker`), the edge certificate's
key pin (`edgeCertSha256`, SHA-256 of its SubjectPublicKeyInfo; empty if a system
root signs it) and optionally `deviceIdFile` (default: the user's config directory,
`badger/device-id`, a non-secret random id). `providerURL` must be
`<edgeUrl>/v1/chat/completions`; a template that names `providerTokenFile` is
refused.

At session start this host process opens the person's browser at the edge's
approval page, receives the one-time code on a `127.0.0.1` listener (state
checked), and redeems it with its PKCE verifier. The broker token stays in this
process's memory and reaches the gateway only on descriptor 3 (`providerTokenFd`):
never in a file, argv, the environment, `gateway.json` or anything the VM receives.
At the end the session closes the pipe (the gateway drops the token) and signs the
token out at the broker (`signedOut` in the result).

## Local UAT

The compiled broker includes an explicit `uat` command. It launches its own actual
service binary, uses the Docker HTTP API directly, creates only disposable
fixtures and never fetches an image. Use a cached Alpine/busybox Linux image:

The `uat` command runs unsigned sandbox fixtures, which only a broker built with
`-tags uatnoprofile` can do; a release build refuses to start it:

```sh
GOWORK=off CGO_ENABLED=0 go build -trimpath -tags uatnoprofile -o dist/hardened-broker-uat .
dist/hardened-broker-uat uat \
  --docker-socket /absolute/local/docker.sock \
  --image sha256:EXACT_CACHED_ALPINE_IMAGE_ID \
  --linux-binary dist/hardened-broker-linux-arm64 \
  --report .cache/native-uat.json
```

Add `--admission-executable`, `--profile`, `--profile-sha256`, `--tenant-id`,
`--deployment-id`, `--profile-id`, `--expired-profile` and `--wrong-key-profile` to exercise the actual built Rookery
admission bundle. The report records the binary/source digests, successful and
refused requests, boundary settings and limitations. Native peer-credential UAT
uses a separate disposable Linux container with only `SETUID`/`SETGID` added so a
broker UID 0 can test caller UID 65534; no Docker socket is mounted there. Those
two capabilities are never added to repository workers. It proves credential
separation and required profile admission, not a qualified deployment.

Setting `developmentAllowSameUID: true` is an explicit local fixture mode and is
reported as such. It permits macOS UAT and, only in a broker built with
`-tags uatnoprofile` and only when no verifier/profile is configured, unsigned
sandbox-only fixtures. A release build has no such path: its policy must name a
verifier whatever the flag says. A supplied profile is never silently ignored. This mode provides no protection from a hostile same-UID host process.

## Remaining scope

ALPS qualification, SPIFFE/tenant delegation, signed independent trace evidence,
central audit, production installation permissions, hardware custody, safe host
application, exact Pushgate delivery and complete upstream runtime qualification
are separate phases. Bounded regular-file edits are retained for independent
review; automatic checkout modification is not performed. The Docker daemon and kernel
remain trusted. No container-escape or native-host qualification is implied by
Docker Desktop UAT.

The adapter targets the [Docker Engine API v1.47](https://docs.docker.com/reference/api/engine/version/v1.47/).
