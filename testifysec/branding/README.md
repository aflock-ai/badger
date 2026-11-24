# Badger branding

`product.json` is the customer naming source. The product version comes from
the Badger root `VERSION`; the upstream OpenCode package version remains separate.
The managed host and worker manifests include the product metadata and its
source digest.

Badger replaces the owned Aflock product name and help command. Existing storage
paths, environment/configuration keys, service identities and protocol names
remain unchanged. Resume commands use the actual executable path, not the display
command. The [standalone repository](../STANDALONE.md) preserves the upstream
ancestry.

The worker builder and the normal fork builder (Badger 1.x: `packages/opencode/script/build.ts`;
OpenCode 2.0 base: `packages/cli/script/build.ts`, once branding is ported)
define `HARDENED_BUILD=true`. That compile-time switch
changes customer CLI/TUI wordmarks, window titles, help/provider login text,
session exit summaries and OAuth callback pages. Managed provider/model display
labels retain their existing contracts. The preview additionally defines
`HARDENED_PREVIEW=true` for its visible development status. Without the switch, upstream CLI branding remains unchanged.
The TUI home/footer and both session-sidebar implementations use the product display
version, while diagnostics retain the upstream version. The normal build keeps its
`OPENCODE_VERSION` and channel for database compatibility; do not change those to the
product version when rebuilding an installed client. The switch is display metadata;
it does not enable managed execution or confer
trust. Environment variables cannot change it after compilation.

Only the customer native launcher is built with `wrap.py --brand-product`.
Its exact `--help` and `--version` flags print embedded information before any
runtime discovery, digest check, import or execution. They require no profile,
broker or provider connection. All other argument combinations are refused.
Internal verification launchers and the managed worker retain their stdin-only
protocols. Runtime execution still verifies the pinned sibling digest and clears
the inherited environment before starting Bun.

OpenCode remains identified in the attribution and version output. This patch
does not change upstream licenses, copyright notices, package/import identifiers,
protocol schema IDs, configuration keys, model IDs, internal artifact names or
upstream website links. The full upstream interactive CLI/TUI is also branded in the separate development
preview. This does not enable its protected worker, gateway or signing authority.
Third-party OpenCode Zen/Go service names, OAuth identifiers and endpoints remain
unchanged. The embedded web app uses the product name, a plain monogram
(`badger-mark.svg`) and no vendor mark, and rebrands owned translation strings
before interpolation, leaving provider service names intact. A managed web UI
links to no outside site and makes no request outside the deployment:
upstream docs, forum, issue and feedback links are dropped at compile time,
the error page says "Contact your administrator.", and
`packages/app/src/runtime/shipped.test.ts` builds the managed UI and fails on
any outside address or TestifySec/Discord mark it ships.
The packaged native desktop application and upstream website are outside this phase.

`about` embeds and displays the exact original OpenCode MIT license. The callback
page shows the same monogram and the product name, without external resources. The normal OAuth protocol and callback state/PKCE lifecycle
remain the existing integration. `packages/core/test/oauth-page-brand.test.ts` checks the
page's exact strings in managed and upstream builds. (1.x also kept browser screenshots from
`plugins/browser/uat.py`, which retired with the bring-your-own-provider path.)

The preview session summary emits the quoted actual binary path, workspace and
only HOME/XDG storage locations, so a privately launched session can be resumed
from a fresh terminal. It never includes provider keys or arbitrary environment
values. POSIX shell quoting is exercised on macOS; the PowerShell rendering has
not been runtime-tested. The separate mini-mode splash still uses the upstream
one-line scrollback renderer and can clip long resume commands; the full TUI
epilogue is the tested complete command. Branding and these paths are not
security boundaries.

## Local UAT

Use the already provisioned locked build dependencies and cached Bun target;
these commands do not install dependencies or pull images. Run from the
repository root, with an already cached immutable glibc Linux image. On macOS,
Docker's VM sees only the home directory, so keep the worker and `TMPDIR` there:

```sh
export TMPDIR=$HOME/badger-uat-tmp && mkdir -p $TMPDIR
/path/to/bun testifysec/runtime/build-worker.ts $TMPDIR/worker bun-linux-arm64 fixture
python3 testifysec/branding/uat.py --go /path/to/go --bun /path/to/bun --worker $TMPDIR/worker --image sha256:EXACT_CACHED_IMAGE_ID --report /tmp/badger-branding.json
```

The harness builds actual native launchers and compiled display probes. It
removes the runtime before testing help/version, checks argument and preload
refusals, verifies environment clearing and changed-runtime rejection, and
compares hardened, false and absent build-switch output. The probe
(`probe.ts`) compiles the 2.0 CLI brand and the managed profile: in a hardened
build it must show the `badger` command, the product version with the upstream
one, `about` with the exact upstream license, and the product's gateway and
model names on the fixed `managed/approved` IDs; with the switch false or
absent it must match OpenCode exactly. It then runs the actual compiled worker
write/test loop with the local scripted provider and verifies the product label
without changing protocol identifiers. The report records source and executable
digests, upstream version and dirty-worktree status.

This verifies branding and the stated local execution paths. It is not release
qualification, live-model testing or an ALPS, FIPS or IL6 compliance claim.

## Interactive UAT

```sh
python3 testifysec/interactive/uat-branding.py --binary /tmp/badger-dist/cli-darwin-arm64/bin/badger --output-directory /tmp/badger-branding-uat
```

This macOS harness runs the managed binary under a local test network guard
with private synthetic state, and checks help, version, `about` with the
unchanged upstream license, and the real TUI home screen. See
`testifysec/interactive/README.md`.
