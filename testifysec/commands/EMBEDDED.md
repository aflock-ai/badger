# Embedded native command runner

`runNative(role, request, onEvent, {signal?})` selects only `enroll` or `attest`
from a build-pinned asset table. It never discovers a helper through PATH, npm,
an environment override or a workspace. The native program receives exactly one
fixed argument (the selected role) and at most 16 KiB of strict JSON on stdin.
`EnrollmentRequest` and `AttestationRequest` come from the ordinary CLI request
builders. The native backend independently validates its request and authority.

The interactive builder's optional **sixth** positional argument is the native
asset manifest, after the existing plugin manifest argument. Pass an empty fifth
argument when no external plugin manifest is needed. An asset manifest must
contain both roles; duplicate/missing roles, wrong digests, wrong executable
formats and mismatched OS/architecture are refused. For example:

```json
{
  "schema": "testifysec.hardened-code.native-assets/v1",
  "assets": [
    {"role":"enroll","file":"/private/build/aflock-native","os":"darwin","arch":"arm64","sha256":"EXACT_SHA256","size":123456,"timeoutSeconds":600},
    {"role":"attest","file":"/private/build/aflock-native","os":"darwin","arch":"arm64","sha256":"EXACT_SHA256","size":123456,"timeoutSeconds":120}
  ]
}
```

The builder reads each regular single-link input through a nofollow descriptor,
hashes those exact bytes, and privately stages them for Bun's embedded file
loader. Original input files are not needed afterward. The output manifest
records role, target, digest, size and timeout, plus the input manifest digest.
The maximum helper size is 128 MiB per role. Legacy preview builds can omit the
manifest and explicitly report native commands unavailable; this does not make
them a fully working command release. A release with enrollment and attestation
must supply and test both native roles.

On macOS/Linux the runner ignores caller TMPDIR/HOME, checks the canonical
system temporary parent, creates a fresh 0700 directory and writes the selected
helper with mode0500. It reopens and verifies the materialized bytes before an
absolute-path launch. Fixed child environment contains only system PATH, private
HOME/TMPDIR and LANG; platform mode also receives CILOCK_STATE_DIR bound to the
request's platform state child. No provider token, proxy, preload or Node/Bun
options are inherited. This is custody against other unprivileged accounts,
**not isolation from the launching user, administrator or kernel**.

Only valid UTF-8 JSONL command events are delivered to the synchronous callback:
16 KiB per line, 128 KiB total stdout, at most128 events. The common wire schema
remains `testifysec.hardened-code.command-event/v1`; the expected final event is
`enrolled` or `attested`, matching the role. Unknown roles/events, duplicate JSON
keys, output after a terminal event, missing terminal success and truncated
lines fail closed. The frontend renders its public-field allowlist; the runner
never prints raw stdout or stderr. Stderr is discarded with a16 KiB cap. Callback
exceptions, deadline and cancellation stop the helper. Initial TERM is only a
request; observed child exit, final group termination and bounded pipe drain are
required before normal completion. Native nonzero exit codes are retained.
These conditions also gate payload deletion on exceptional paths. If a bounded
post-KILL wait cannot confirm exit, group termination and pipe drain, the runner
closes its own handles, retains the private payload and reports
`cleanup-incomplete`. A failed directory creation never removes its target;
cleanup requires successful creation and the original opened directory identity.

The native helpers are trusted programs, not arbitrary worker executables.
Unix process-group cleanup does not contain deliberately escaping `setsid`
descendants. SIGKILL/host failure can leave private scratch; this component has
no persistent orphan recovery. A process stuck in the kernel cannot be promised
terminated by a userspace deadline; timeout/cleanup failure is an error.

Windows target metadata and PE format are supported by the build checks, but
the runner **refuses Windows execution** until the native ACL, ancestor-handle
and suspended Job Object custody implemented in `packaging/` is integrated.
Node/Bun chmod is not substituted for that contract. Linux runtime qualification
also needs its own actual runner evidence; the supplied harness executes macOS.

```sh
python3 -B uat-embedded.py --go /absolute/installed/go \
  --bun /absolute/installed/bun --output /private/tmp/new-aflock-command-uat
```

The harness compiles a real Go fixture and a Bun artifact, deletes the original
native files, and runs under a local network-deny guard. It tests both roles,
poisoned PATH/environment, exact argv, tampered pins, duplicate assets, request
and JSONL bounds, callback failure, nonzero exit, deadlines/signals and owned
descendant/private-file cleanup. It performs no real enrollment, provider call
or attestation signing and does not touch user credentials.
Additional explicitly instrumented compiled fixtures suppress exit observation,
fail group termination, stall pipe-drain observation, collide with an existing
directory and fail the first directory open. These prove retained-payload/error
behavior without creating a kernel-stuck process or exposing fault controls in
the shipping runner.
