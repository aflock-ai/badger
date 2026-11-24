# Native Linux build and local UAT

`uat-linux.py` compiles the Rookery C shared library, Bun host and admission
runtimes, environment-sanitizing Go launchers, broker and gateway inside a
cached Linux build image. It then runs the actual signed-profile → broker →
compiled upstream worker → separate gateway edit/test journey on Linux.
The supplied worker must be a production gateway-mode Linux build with a
matching source and binary manifest; fixture-model workers are refused.

The orchestrator uses Python and the Docker CLI on the development machine.
The build image needs Python 3, Git, a C compiler, libc development files and
Go meeting the modules' minimum version. Supply a cached Linux Bun executable
matching the worker builder and a populated Go module download cache, including
the published `github.com/aflock-ai/rookery/attestation` the native modules
require (`cd testifysec/native && go mod download`). Images
must already exist locally and are selected by immutable SHA-256 ID. Containers
run with `--pull never` and `--network none`; Go resolves dependencies only from
the read-only local module cache. Missing dependencies fail the build and are
reported. No package manager or runtime installer is invoked.

```sh
python3 -B testifysec/runtime/uat-linux.py \
  --engine-socket /absolute/docker.sock \
  --build-image sha256:EXACT_CACHED_GOLANG_GLIBC_IMAGE \
  --image sha256:EXACT_CACHED_GLIBC_WORKER_IMAGE \
  --bun /absolute/cached-linux-bun \
  --module-cache /absolute/go/pkg/mod \
  --worker /absolute/opencode-worker \
  --worker-manifest /absolute/opencode-worker.manifest.json \
  --report /absolute/new-linux-uat.json
```

The report's sibling `.artifacts` directory must not exist before invocation.
It retains the native binaries, nested manifests, isolated source snapshot and
detailed Linux report for review. Its synthetic fixture profiles are generated
locally for each run. The source snapshot has its own unsigned local commit;
the report separately records the original monorepo revision, dirty state and
the exact copied source hashes. None of these is a release signature.

The root broker uses the production Linux peer gate with UID 65533 as its only
allowed caller. The host runs as that UID. The gateway runs as UID 65534 with a
private provider credential and audit spool; the worker runs as UID 65534 in a
separate container. The caller must be unable to read the provider credential
or Docker socket, and unassigned UID 0 must be refused by the broker. Controller
root still controls Docker and is part of the trusted fixture. UID numbers in
different containers do not imply distinct hardware identities.

The controller's Linux state volume holds the protected policy and native
bundle. Task-owned scratch and tool-pack directories are mounted at identical
absolute host-visible paths. Docker rejects `rprivate` bind sources beneath its
own data directory; this layout preserves the broker's required propagation
control. Docker Desktop maps ownership on those host-shared directories, so this
fixture does not establish native-host custody against the desktop user. The
gateway socket has its own volume; its credentials and spool are never mounted
in the worker. The fixture removes only its uniquely named, label-checked resources.
Cleanup failures make the report fail and preserve the resource names for
inspection.

The acceptance checks include real upstream write and shell-test events,
independent broker profile verification, expired/wrong-key/ambiguous profile
refusal before additional provider traffic, exact retained artifact bytes,
unchanged host input files, launcher preload isolation, and correlated start
and terminal audit records for each model request. The provider and collector
are local scripted fixtures. The gateway explicitly enables its development
loopback mode and labels attribution as administrator-provisioned. Its separate
per-request profile-admission and platform checks are omitted in this fixture;
the broker still independently requires signed admission. This harness does
not claim platform-authenticated identity. The real platform handler and
gateway integration have a separate `platform/uat.py --gateway` harness.

This proves the observed Linux component journey inside a disposable controller
container. It does not install system services, establish release authenticity,
exercise production credentials, or qualify a native Linux host, hardware
attestation, AAL, FIPS, IL6 or an ALPS level. Python, Go and Bun are build/UAT
dependencies; the resulting native runtime bundle needs no such installations.
