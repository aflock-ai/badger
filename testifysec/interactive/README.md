# Interactive UAT for the managed binary

These harnesses run the 2.0 managed binary, `badger`, the way a person at a terminal would, and
check what it shows, what it refuses and what it leaves behind. They do not build anything. Build
the binary first, then pass it as `--binary`:

```sh
cd packages/cli
bun run script/build.ts --managed --skip-web-ui --target=opencode-darwin-arm64 --outdir=/tmp/badger-release
bun run script/build.ts --managed --fixture-model --skip-web-ui --target=opencode-darwin-arm64 --outdir=/tmp/badger-fixture
# the binaries are /tmp/badger-{release,fixture}/cli-darwin-arm64/bin/badger
```

The release binary reaches models only through the administrator's gateway, and refuses to start a session or the
TUI without it. The `--fixture-model` build is the same binary pointed at the UAT fixture model's socket
(`/tmp/hardened-fixture-model.sock`); each harness serves that fixture model itself while it needs a session or the
TUI, and checks that only the fixture build contains the socket path. It is never a release artifact.

Each harness is macOS only. It runs the binary under `sandbox-exec` with external network denied
(loopback and Unix sockets stay open) and with fresh HOME, XDG and workspace directories. The
sandbox is a test guard, not the product's isolation. No harness uses a real credential, makes a
model request or downloads a package.

| Harness | Checks |
| --- | --- |
| `uat.py --binary B --fixture-binary F --report R.json` | `--help` names `badger`; `--version` is the product version; every non-work command and the auto-approve flags are refused with one line and exit 1, leaving at most the CLI log; `models` lists only `managed/approved`; plugins named in config (a local file and an npm package) are neither loaded nor installed; the real TUI renders on the managed gateway and exits on Ctrl+C; no `node_modules`, lock file or `auth.json` appears. |
| `uat-branding.py --binary B --fixture-binary F --output-directory D` | help, version and `about` name Badger, and `about` carries OpenCode's license byte for byte; the TUI home screen has the window title `Badger`, the welcome art, the product version in its footer, and never says OpenCode. Paths contain a space and a quote. |
| `uat-api-key.py --binary B --fixture-binary F --report R.json` | login is refused; an OpenAI provider, key and base URL set in config and `OPENAI_API_KEY` are not listed, not offered in the TUI, and never contacted (a loopback fixture records zero requests while a prompt names that model); neither synthetic key appears in any file or output. |

`managed_harness.py` holds the pieces they share: the guard, the private environment, the PTY
driver and the report.

Each report records both binaries' and the harness's SHA-256 and every check. With the fixture model,
`uat.py` also checks that the release TUI refuses to start without its gateway, `uat-branding.py` runs a
real session and checks the exit text's `Continue '<binary>' -s '<session>'` line and that running it from
another directory reopens the session, and `uat-api-key.py` checks that a session's requests go to the one
`approved` model carrying neither configured key while the configured provider still hears nothing.

These replace the 1.x interactive preview harnesses. The 1.x preview was a separate, unmanaged
build (`interactive/build.ts`) that loaded approved plugins, kept Codex OAuth and API-key login,
and refused only release management. 2.0 ships one managed binary, which refuses all of those, so
the checks that proved them now prove the refusals instead.
