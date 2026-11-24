# Managed upstream OpenCode runtime

This is the managed Linux reference headless runtime path: a native host verifies a
signed profile, then requests a fixed compiled OpenCode worker from the native
broker. The complete upstream `opencode run` implementation runs inside the
broker's nonroot, network-disabled Linux container. No upstream application
module is imported by the host admission process.

The maintained upstream patch changes both configuration pipelines: the legacy
application loader and the newer core loader. Both bypass repository and user
configuration in the compiled managed build. External plugins, custom tools,
LSP, formatters, MCP, updates, sharing and npm installation are disabled.
The compiled entrypoint exposes only headless `run`; it does not expose the
server, PTY, auth, attach, upgrade or interactive command families. Shell and
file tools run inside the same worker boundary, with no host mounts or provider
credentials. Repository instructions and model output remain untrusted.

Provider requests use the bundled OpenAI-compatible adapter and exactly
`POST /v1/chat/completions` on the administrator-mounted Unix socket at
`/run/hardened-gateway/gateway.sock`. The worker receives no provider credential and
cannot choose another provider URL or SDK package. The gateway service owns
provider access, request limits and audit. A separate compile-time fixture mode
uses a deterministic local scripted provider for UAT; it is not a live model.

## Build

Install upstream's locked build dependencies with scripts disabled. Do this
only in the build environment; customer bundles need no npm, Node or Bun install.
Linux optional native artifacts and Bun's matching Linux runtime must be cached
before an offline build. The supplied worker builder embeds a fixed empty model
catalog and does not fetch models.dev.

```sh
bun install --frozen-lockfile --ignore-scripts --filter opencode
bun testifysec/runtime/build-worker.ts /tmp/opencode-worker bun-linux-arm64
bun testifysec/runtime/build-worker.ts /tmp/opencode-worker-fixture bun-linux-arm64 fixture
python3 testifysec/runtime/build-host.py --go /path/to/go --bun /path/to/bun --trust /protected/trust.json --broker-socket /protected/broker.sock --workspace example --output /tmp/hardened-host
```

`build-host.py` emits the environment-sanitizing native `hardened-code` launcher,
the host runtime, native Rookery library, and matching independent admission
bundle. Install the latter under the broker's protected ownership and pin its
launcher digest in broker policy. Broker policy also selects an exact profile
payload digest, workspace, image and tool pack. The broker re-verifies the signed
profile before each execution; a caller's assertion that admission passed is
never accepted as authority.

This host and its broker protocol require profile/trust version 1. The builder
refuses version 2 before building artifacts. The separate version 2 admission
component verifies approval of a pinned VZ backend manifest; it does not enable
VM execution through this host. A VZ host, broker and gateway must consume that
approval explicitly before the managed VM path can run.

The host accepts this stdin request (the `profile` value is an actual DSSE
envelope, not a filename):

```json
{"schema":"testifysec.hardened-opencode.run/v1","profile":{"payloadType":"...","payload":"...","signatures":[]},"prompt":"Make the change and run its tests."}
```

The host cannot select a command or mount. It submits
`/toolpack/opencode-worker` and a bounded prompt to the broker. Any admission,
gateway or broker failure remains a failure; there is no host execution fallback.

## Local UAT

```sh
python3 testifysec/runtime/uat-worker.py --worker /tmp/opencode-worker-fixture --image sha256:EXACT_LOCAL_IMAGE_ID --report /tmp/hc-worker-uat.json
python3 testifysec/runtime/uat.py --go /path/to/go --bun /path/to/bun --worker /tmp/opencode-worker-fixture --image sha256:EXACT_LOCAL_IMAGE_ID --engine-socket /path/to/docker.sock --report /tmp/hc-native-runtime-uat.json
```

The fixture exercises the actual upstream model protocol, tool dispatch, file
write, shell test, and follow-up model turn. It also attempts repository plugin,
custom-tool, bunfig and environment injection, rejects alternate CLI commands
and ambiguous prompt JSON, and fails if forbidden tools reach the provider's
tool list. It never calls a paid or external model. Reports retain executable,
input and output digests plus real upstream events.

The second harness builds the native host, admission verifier and broker, then
executes the same upstream workflow through the broker with an independently
re-verified exact profile. Expired, wrong-key and ambiguous profiles fail. These
local development harnesses exercise the named paths; full external gateway
integration, separate-UID Linux deployment, signing authority, platform identity,
audit delivery and release distribution require their own evidence. Docker
Desktop does not reproduce every native Linux host boundary, and macOS host Unix
sockets cannot be assumed to work through container bind mounts; use a Linux
gateway or administrator-provisioned shared Docker volume.

The broker now captures a bounded regular-file artifact before cleanup. With
the optional administrator-pinned finalized-session producer (a parked component, not part of this repository),
it retains the admitted input/base, validates the completed candidate and
publishes the protected record consumed by `aflock attest`. This does not
automatically apply changes to the user's checkout or push them. Complete
platform evaluation, signed delivery and independent receipt readback remain
integration work. The interactive preview and VZ fixture do not produce this
Linux reference record. There is no ALPS, FIPS or IL6 qualification claim.

Worker stdout and individual tool events remain untrusted observations. The
broker proves the bounded whole-worker execution it observed; it does not turn
a worker's statement that an individual test passed into independently produced
test evidence. That stronger evidence still requires the protected execution
and evidence service in the remaining epic.
