# Local macOS VM fixture

This development slice uses Apple's Virtualization framework to boot a Linux
ARM64 VM with one vCPU, 512 MiB RAM, a reusable private read-only ext4 root disk and a
64 MiB tmpfs workspace. It attaches no network device, directory share or writable
host disk. A static Go PID1 starts a synthetic worker as UID/GID 65534, reaps the
workload, accepts only bounded regular-file results, and powers off. The native
Swift host requires an observed stopped state; a guest success message alone
does not complete a run. The guest's statements remain unsigned observations,
not authenticated evidence about an adversarial or compromised guest kernel.

An optional fixed relay now connects a guest model request to a native gateway
running on the host. The gateway retains its own signed profile checks and can
use its existing platform identity checks. **VM job admission, Pushgate, product
packaging and the production execution backend remain unintegrated**. The existing
execution preflight continues to refuse production execution. Ad-hoc signing
enables a developer entitlement only; it does not establish publisher identity,
notarization, release qualification, hardware attestation, ALPS, FIPS or IL6.

The session job travels over one fixed virtio socket channel. The root
image is built once and reused unchanged across jobs; the native host needs no
filesystem-image builder or other executable at runtime. See [protocol.md](protocol.md)
for exact bounds, digest/freshness binding and the separate fault-test binary.
The job binding remains a developer fixture, not a signed profile grant. Shutdown
closes new socket admission on the VM queue before taking its connection snapshot,
then interrupts and drains the registered sender before releasing the VM. The UAT
also refuses an actual connection delivered after this admission fence.

The initial local kernel is a development input copied from the installed
Docker application. Its embedded configuration disables `CONFIG_BLK_DEV_INITRD`
but includes virtio block/console and ext4, so an external initramfs cannot boot
with it. This fixture instead creates its own root disk and never boots Docker's
userspace or starts Docker during build/run. A distributable kernel/rootfs needs
separate source, license, build and release review. Kernel, selected source,
tool executables and output bytes are hashed in the local manifest; these are
pathname readbacks, not runtime measurements or authenticated provenance.

Build and run on this macOS arm64 development host:

```sh
GOCACHE=/private/tmp/hardened-opencode-gocache python3 -B build.py \
  --go /absolute/path/to/installed/go --output /private/tmp/new-vm-build
/private/tmp/new-vm-build/hc-vm /private/tmp/new-vm-build/config.json
```

Go, Swift, the macOS SDK, `codesign` and native `mke2fs` are development tools;
no guest runtime package installation or network access occurs. `mke2fs` is used
only to prepare a new immutable image. `--reuse /path/to/build` writes a fresh
job/configuration and reuses the existing disk; it does not require `mke2fs`. The default
`mke2fs` path is `/opt/homebrew/opt/e2fsprogs/sbin/mke2fs`. Output must be a new
directory. The generated host and guest source are copied before compilation.
The generated config is a developer input, **not a signed execution grant**.
Only trusted developer-owned directories and inputs may be used for this fixture;
it does not implement the production install/ancestor custody contract.

Run actual local VM UAT:

```sh
GOCACHE=/private/tmp/hardened-opencode-gocache python3 -B uat.py \
  --go /absolute/path/to/installed/go --output /private/tmp/new-vm-uat
```

The harness performs real same-image multi-session edit/test/capture, bounded
material transfer, exact prior-frame replay refusal, assignment/schema/length/EOF
refusals, guest timeout, host deadline,
SIGTERM, a descendant retaining output pipes in a new process group, output
overflow, symlink-artifact refusal and assignment/digest/resource
negatives. Each VM must start and stop; negative cases must fail at the expected
stage. It keeps the base build/report, removes owned per-case scratch, proves reused
jobs require no image builder, and checks
read-only disk/source/binary readbacks. A missing macOS entitlement or unavailable
Virtualization service is a failure, never a fallback to host execution.

The compiled fixture-model OpenCode worker also runs in a component UAT. Supply
`--worker /absolute/path/to/opencode-worker --image sha256:EXACT_CACHED_DEBIAN_ID`
to `uat.py`. The helper copies only selected regular library/shell bytes from a
never-started temporary container and removes that container; image pulling and
registry credentials are disabled. Docker is used only to extract already cached
development inputs. All VM executions use native Virtualization.framework with
an empty helper PATH. The worker VM uses 1 GiB RAM and a 512 MiB read-only disk.
The harness verifies actual upstream write and shell-test events and the exact
captured file. That fixture-model worker test does not use the host relay and must not be described as
the complete hardened product journey. `build.py --mode worker --worker-root DIR`
can reuse independently prepared regular input files without Docker extraction.

Run the separate native model relay UAT:

```sh
GOCACHE=/private/tmp/hardened-opencode-gocache python3 -B uat-relay.py \
  --go /absolute/path/to/installed/go --output /private/tmp/new-vm-relay-uat \
  --admission-bundle /private/path/to/retained-native-admission-bundle \
  --valid-profile /private/path/to/valid-fixture.json \
  --expired-profile /private/path/to/expired-fixture.json
```

It builds the actual native gateway and uses only a synthetic local HTTP provider
and OTLP collector. A fixed synthetic worker running as UID65534 calls the guest
Unix socket; PID1 frames its body/path over VSOCK17002. The host validates the
complete frame, nonce, job and assignment before connecting to one private,
configured gateway socket. Provider credentials stay on the host. Valid/expired
profile fixtures exercise the actual native admission bundle; omitting all three
profile arguments instead selects the explicit gateway development fixture and
does not establish signature enforcement. The UAT retains exact source, binary,
configuration, audit and effect bindings. It tests Chat Completions and Responses,
stream truncation, audit-before-effect, collector acknowledgment, frame replay,
malformed/oversized input, socket custody, concurrency and cancellation.

The relay is not an OAuth implementation. It preserves the gateway's configured
credential and protocol choices. That relay UAT uses a small synthetic native
HTTP client; the separate integration below executes the actual compiled worker.

## Compiled OpenCode through the VM relay

`uat-worker-relay.py` combines the existing `worker` job mode with the model
relay's version 2 receipt/acceptance transport and bounded duplex HTTP exchange
described in [protocol.md](protocol.md). It requires a compiled Linux ARM64
gateway-mode OpenCode worker (`fixtureModel:false`), its manifest, and a retained
`extract-worker.py` directory. The harness verifies the original manifest and
every regular shell/library/worker byte, retains that manifest, and replaces only
the copied worker with the separately pinned gateway-mode executable. It then
builds the VM and native host gateway from staged sources. This harness invokes
no Docker command and starts no container. Its retained development kernel and
library inputs still need release provenance and licensing qualification.

```sh
GOCACHE=/private/tmp/hardened-opencode-gocache python3 -B uat-worker-relay.py \
  --go /absolute/path/to/installed/go --output /private/tmp/new-worker-relay-uat \
  --worker /private/path/to/compiled-gateway-worker \
  --worker-inputs /private/path/to/retained-vm-worker-inputs \
  --admission-bundle /private/path/to/native-admission-bundle \
  --valid-profile /private/path/to/valid-fixture.json \
  --expired-profile /private/path/to/expired-fixture.json
```

The actual upstream tool loop receives controlled Chat Completions SSE from a
local synthetic provider, writes `result.txt`, and runs a shell test. Each fresh
VM uses the same read-only disk, a distinct session/job/boot binding and a bounded
material file. The harness matches emitted tool call IDs and arguments, completed
states, shell exit codes and output lines, as well as captured bytes and observed
VM start/stop and drained channels, gateway credential absence from outputs,
durable start records before each provider effect, matching terminal audit and
collector acknowledgment. Expired gateway profile, wrong model/protocol, absent
writable audit storage, failed shell test and truncated stream must not produce
a successful VM result. No live model or customer credential is used.
Tool states and exit codes are worker-reported fixture observations, not
independently attested per-tool process facts. The guest's legacy artifact/marker
success heuristic remains a fixture check. A host refusal of truncated HTTP can
stop the VM before a guest result exists; that negative case requires the exact
host refusal and drained lifecycle, and does not claim guest completion.

This is a component integration, not the production broker or an enrolled-agent
session. The gateway independently validates the signed profile for model access;
the VM job itself remains developer-authorized, and no Docker execution receipt
or finalized-session record is manufactured. Matching configured session/profile
values correlate the VM and gateway observations; they do not authenticate a
platform agent, operator or hardware state. Interactive OAuth/API-key custody,
Pushgate handoff and product execution qualification remain separate work.
The current worker uses the `approved` Chat Completions alias, not Responses or
Astra. Fast synthetic responses fit the existing two-second guest/three-second
host idle timeouts; this UAT does not establish compatibility with long live-model
response delays. Existing 45-second worker, 60-second host, 32 KiB output and flat
16-file/16 KiB capture limits remain in force.

Local developer processes and the host kernel/framework loader are trusted.
Virtualization.framework, the guest kernel and its built-in device drivers remain
part of the VM boundary. Dormant kernel-created virtual interfaces can exist;
PID1 rejects hardware interfaces and any active interface, while the host never
attaches a NIC. Guest `/tmp` is a separate bounded 256 MiB tmpfs. The host observes
fixed CPU/RAM allocation and overall deadline; this slice does not yet qualify
per-process cgroups, all guest resource exhaustion paths or hardware attestation.
