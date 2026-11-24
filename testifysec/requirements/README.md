# Optional Requirements Reader

A read-only client for `pushgate.requirements.v1` in the managed Badger build
(OpenCode 2.0, `port/v2`). It shows which Pushgate requirements apply to the
current worktree, in the TUI sidebar and through one model tool. The server API is
not yet deployed; the tests run against local fixtures, not a live platform.
Nothing here builds, publishes, evaluates, enrolls, signs or changes assignments.

The code is in `packages/core/src/requirements`. The managed launch wires it in
(`packages/server/src/requirements.ts`, `packages/cli/src/requirements.ts`); a
build that is not managed contains none of it.

## Use

Opt a directory in once, from an interactive terminal in that directory:

```sh
badger --requirements          # TUI
badger run --requirements ...  # one non-interactive run
```

The launch prints a sign-in URL and a code. Open the URL, confirm the browser
shows the same code, and approve. Then choose the repository from the platform's
authorized catalog. If the Git remotes match exactly one catalog entry, it is
offered as the default; that is a name hint, not identity or authorization. The
selected entry supplies the immutable repository ID.

Only that choice is saved, in a file of this directory's own: `requirements/<hash
of the directory's real path>.json`, beside Badger's user settings
(`~/Library/Application Support/TestifySec/Aflock/` on macOS,
`$XDG_CONFIG_HOME/aflock/` or `~/.config/aflock/` on Linux). It holds no
credential. No launch reads or writes another directory's choice.

Every later launch in that directory signs in again, the same way, because the
bearer is never stored. It reuses the saved repository without asking. If the
catalog no longer authorizes it, the launch says so and starts without
Requirements; run with `--requirements` to choose again.

A launch anywhere else, or in a directory that never opted in, starts without
Requirements after one local file check: no network, no polling, no Git.

To stop, launch once with `--no-requirements` in that directory. It removes this
directory's choice file and starts without Requirements; later launches there do
not sign in. Other directories' choices are separate files and are never touched.

## Custody

- The read bearer lives in one `CredentialHolder` in the launch's own process.
  The managed build runs its server in-process: no listener, no background
  service, no `service.json`. The bearer ends with the launch, and a second
  launch has to sign in for itself.
- Nothing writes the bearer to disk. A Badger 1.x on-disk credential
  (`pushgate-read.json`) is deleted without being read.
- Built-in heap snapshots are disabled in a process that holds a bearer, before
  the bearer exists. This does not stop a debugger, a profiling flag, an OS dump
  or another process of the same user from reading memory.
- Device consent requests exactly `pushgate:repo-read pushgate:policy-read` from
  `https://platform.testifysec.com`. Missing or broader returned scopes refuse.
  No other session, token or credential is reused. No refresh token, no scope
  upgrade.
- The only requirements endpoint is `https://pushgate.dev/api/requirements`.
  Requests refuse redirects, time out after ten seconds through the whole body,
  and stop at 2 MiB before strict JSON parsing (duplicate keys and unsafe numbers
  refuse). The closed response schema, immutable authority URL, status/code pairs
  and exact target must match. A response that echoes the bearer anywhere is
  unavailable.
- Neither endpoint can be changed at runtime: no config, flag or environment
  variable reads one. Only a test build (`build.ts --fixture-requirements=
  https://localhost:<port>`) points them at a local fixture, and the build refuses
  any other managed binary that contains `https://localhost`.

## Sidebar

A **Requirements** section in the session sidebar, in managed TUI launches that
signed in. It shows the state and a summary for the session's directory. Every
second the monitor checks the local selection, credential, HEAD and ref; every
thirty seconds it reads again. A change of credential (sign-out, new sign-in,
expiry) stops the current read at once and nothing is shown under the old one.
A change of scope clears the display. No previous success is kept through a
failure. Detached HEAD, an unborn branch, a non-Git directory, a SHA-256
repository or another directory's selection shows unavailable.

## Model Tool

`pushgate_requirements` exists only in a launch that signed in. It accepts only
`{}`: no credential, URL, directory, repository, commit, ref or policy argument.
The managed policy allows it without asking: it is read-only, takes no arguments
and exists only after the human signed in.

Each call runs a one-shot instance of the same monitor for the session's own
location instead of returning a cached result, and rechecks credential, HEAD and
ref after the response. Cancellation stops its request. The output labels all
display text as untrusted data, never instructions: current status is always
unavailable, applicability incomplete, and any recorded decision historical.

Both the sidebar and the tool run every line through the tool-output redactor in
display mode (`ToolOutputRedaction.text(…, { display: true })`, see
`testifysec/TOOL-OUTPUT-REDACTION.md`): terminal controls are removed, recognizable
authorization, token, password, private-key and URL credential forms are redacted,
and URL queries and fragments are withheld. The launch's own bearer is removed before and after
every normalization. A credential split by control or invisible characters is
withheld whole. This is bounded display sanitation, not a claim that every secret
hidden or encoded in prose is detected.

## Display Meaning

Availability is not satisfaction. Step and attestation names, Rego/AI counts,
modes and requirement counts are a non-authoritative summary of the connection
snapshot. Applicability remains incomplete. The full immutable policy is
authoritative; this client does not verify it.

Current status is always unknown. A recorded accepted or refused push is
historical, not permission to push now or proof of delivery. No row is not a
passing result. No remediation command is generated from remote text.

## Verification

```sh
cd packages/core && bun test test/requirements
cd packages/tui && bun test test/feature-plugins/sidebar-requirements.test.tsx
cd packages/cli && bun test test/managed-requirements.test.ts test/fixture-requirements-flag.test.ts test/requirements-unmanaged.test.ts
```

`managed-requirements.test.ts` builds the real managed binary against a fixture
Requirements server and model: sign-in at launch, the tool's answer, no bearer
on disk, opting out, a second launch that cannot use the first one's bearer, sign-in before
the TUI starts, and the sidebar in a TUI session (the last two on Linux). None of
it proves the undeployed platform route accepts a real device credential.
