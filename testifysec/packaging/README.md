# Single-executable payload packaging

This layer embeds an already built native bundle in one `hardened-code`
executable for an explicit OS and architecture. End users do not assemble the
embedded component files or install Go, Python, Bun, Node or npm to launch it.
The maintained TestifySec fork can use this as its customer entrypoint.

This is the **packaging slice**, not completion of the portable product. The
current embedded managed host still expects its protected broker and gateway;
its worker backend still needs the administrator's Linux engine. This layer does
not install that engine, launch untrusted tools on the host, or claim that the
complete product already works without Docker. Automatic backend provisioning
and native macOS/Windows/Linux sandbox implementations remain separate work.

## Build

Build the native host bundle first with the existing runtime builder. Its
`manifest.json` names exact files and SHA256 digests. Then, from the monorepo root:

```sh
python3 testifysec/packaging/build.py --go /path/to/go --input /path/to/built-host --entry hardened-code --target darwin-arm64 --output /tmp/hardened-code
/tmp/hardened-code --version
/tmp/hardened-code < request.json
```

`--target` accepts `darwin`, `linux` or `windows`, each with `amd64` or `arm64`.
Every target needs matching native payloads; a cross-compiled launcher does not
make a macOS Rookery library run on Windows. The existing native library/host
builders currently cover native macOS/Linux, and the upstream worker is Linux.
Windows builds should use an `.exe` output and entrypoint.

The builder reads bounded, single-link regular files from the input manifest,
verifies the exact bytes being embedded, and refuses aliases, unsafe names,
changed digests and an existing output executable. It records the target,
payload/file digests, product and upstream versions, source hashes and build
revision. The report starts with `runtimeVerified: false` and
`releaseQualified: false`. A sidecar report is build evidence; the executable
contains everything it needs to unpack its selected payload.

Declared regular plugin assets may retain scoped-package and dot-directory
paths, such as `approved-plugins/@scope/plugin/index.js` or `.opencode/plugins`.
Packaging does not implement an OAuth protocol or replace OpenCode's plugin
APIs. The current UAT exercises the stdin-only managed host, not a normal
interactive OpenCode session or Codex OAuth; approved plugin lifecycle and
interactive compatibility require their own integration tests.

## Startup and custody

The launcher validates its embedded manifest and target, then creates a fresh
private directory. It never reuses a writable extraction cache or searches for
external component executables. Only declared regular files are written through
Go's `os.Root` APIs. File names, count, depth, size, permissions and hashes are
bounded, and the native entry's actual executable format must match the target.
All extracted bytes are checked again before execution. The selected entry runs
with no forwarded arguments, in the private payload directory, with a fixed
environment and private scratch directory. Only exact `--help`/`--version` flags
return embedded information without unpacking or starting the runtime.

On macOS/Linux, the system temporary parent must be root-owned and either
non-writable by other users or sticky; the new child is mode0700. Signals are
forwarded to the selected process group, followed by bounded termination and
an observed group disappearance before cleanup. A successful signal request
alone does not authorize deleting the payload. Unconfirmed entry exit, group
drain or Go pipe drain closes the launcher's directory handles but retains the
private files and returns a cleanup-incomplete error. A trusted entry must not
deliberately escape that group with `setsid`.
The temporary filesystem must permit execution. A `noexec` mount is refused;
the launcher does not bypass it or fall back to another host executable.

On Windows, the launcher uses the OS token's local profile directory, checks
every ancestor's owner and DACL for unsafe mutation/deletion rights, rejects
reparse paths and holds directory handles through cleanup. The new directory is
created with a protected current-user/SYSTEM DACL on an ACL-capable volume.
The child is created suspended, assigned to a kill-on-close Job Object, and only
then resumed. Termination is checked and active job processes must drain before
cleanup. Failed Job assignment also requires the still-suspended process to
reach `WAIT_OBJECT_0`; a timeout with no API error is not termination. Unresolved
termination/drain retains the payload after closing the launcher's handles.
Conservative ACL checks may reject a host configuration that needs
explicit qualification. **Cross-compilation alone does not validate any of
these Windows runtime controls.**

Private extraction protects payload custody from other unprivileged accounts.
It is not a boundary against the launching account, administrator or kernel,
and it must not be used to pretend that same-user helpers are protected signing
or execution services. It conveys no human presence or hardware attestation.
Executable authenticity, platform signing/notarization, protected service
installation, backend lifecycle and qualification remain release requirements.
Abrupt host/process death can leave a private directory; this layer does not
claim crash recovery or a persistent cache garbage collector.

## Local verification

The module tests exercise materialization, native format checks, exact non-UTF8
data retention, post-extraction changes and malformed manifest/archive refusal:

```sh
cd testifysec/packaging
GOWORK=off /path/to/go test -count=1 ./...
```

The local UAT builds disposable native fixtures, embeds an actual managed host,
executes macOS and a cached Linux-container fixture, and records all six target
compilations separately from runtime results. It uses Docker only as the current
development Linux test runner. It never pulls an image or calls a model.

```sh
python3 testifysec/packaging/uat.py --go /path/to/go --native-bundle /path/to/built-host --image sha256:EXACT_CACHED_IMAGE_ID --report /tmp/hardened-packaging-uat.json
```

Windows runtime UAT must still cover actual ACL/deletion attacks, reparse points,
immediate child-helper creation, signal/Job Object cleanup and DLL loading on a
real supported Windows host before making a Windows execution claim.

The Go suite also executes native POSIX entry/descendant/cancellation fixtures
through the real materialization and supervisor path. Test-only dependencies
suppress exit observation, refuse the final kill, keep group-drain observation
alive or permission-denied, or report incomplete pipe drain. Each fault must retain the exact
private payload; the harness independently observes native exit before removing
its own retained fixture. These are injected observation failures, not a claim
that a userspace test can reproduce every kernel-stuck process. Packaging UAT
records these cases separately; no customer input enables the fault hooks.

References: [Go traversal-resistant APIs](https://go.dev/blog/osroot),
[Windows CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw),
[Job Object assignment](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject).
