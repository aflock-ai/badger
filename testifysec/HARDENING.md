# Badger managed-build hardening

Scope: the interactive `badger` CLI and TUI on OpenCode 2.0, built with
`packages/cli/script/build.ts --managed`. This replaces the 1.x hardening design,
which was written against the pre-2.0 tree. Each surface below says what the
managed build does now, which test shows it, and what is still to do.

## How the build selects hardening

- **Compile time only.** `--managed` defines `TESTIFYSEC_MANAGED_WORKER` and
  `HARDENED_BUILD` (`packages/cli/script/build.ts`). `Managed.enabled`
  (`packages/cli/src/managed.ts`) is a compiled literal: no environment variable,
  flag, user config or project config turns it off.
- **One profile.** The managed CLI runs the server in-process with
  `ManagedProfile.replacements()` (`packages/server/src/managed.ts`). Each
  replacement swaps an upstream service for one that cannot reach the
  filesystem, the network or the environment beyond what the profile allows.
- **Upstream code is unreachable, not deleted.** Upstream paths stay in the
  source. The managed build replaces the services, switches off the built-in
  plugins, refuses the HTTP routes and gates the commands that would reach them.
  This keeps the TestifySec delta small for the next upstream port. Deleting
  instead is an open question below.
- **Only a managed build is the product.** A build without `--managed` behaves
  like upstream OpenCode 2.0. It is the development build and the control in
  every managed test.

## 1. Updates

**Now.** The managed updater never checks, downloads or installs anything
(`Managed.updaterLayer`); the compiled config sets `update: "disable"`. Commands
outside the kept set (`about`, `run`, `mini`, `models`, `stats`, `session`,
`serve`) refuse, so `upgrade` and `uninstall` are not available.

**To do.** A notify-only check against a TestifySec signed channel: a
DSSE-signed manifest of version and per-target digest, verified against the
release trust root with the `testifysec/distribution` verifier. It never
downloads or runs anything. Whether to build it at all is open question 3.

## 2. Share

**Now.** The compiled config sets `share: "disabled"`. Project and global config
are never read, so nothing can turn sharing back on.

## 3. Model catalog

**Now.** The models.dev catalog is empty in the managed build and is never
fetched or read from the on-disk cache. The models are the ones the gateway's
unsigned profile lists, read once at start (`GET /v1/models`), or else the one
in the compiled config (`managed/approved` on the `managed` provider).

**To do.** The upstream source still bundles a models.dev snapshot for the
development build. A managed build does not use it.

## 4. Plugins and MCP

**Now.**
- Plugin configuration is a fixed list of trusted removals
  (`ManagedProfile.removed`). There is no plugin-directory scan, npm install or
  import from disk, and the built-ins that reach the network or load code are
  off: every model provider except the compiled one, web search and fetch, the
  OpenCode Console provider, MCP config, wellknown remote config, model warming
  and the browser. Repository config cannot remove a guarded built-in; only
  these trusted removals can.
- MCP servers come only from the compiled config, which has none. The routes that
  add or connect an MCP server are refused (`RoutePolicy`, below).

**Tests.** `packages/server/test/managed.test.ts` (plugins on disk never load;
control shows they do upstream) and `packages/core/test/plugin/supervisor.test.ts`.

**To do.** Open question 1: compiled-in plugins only, or also a signed loadable
format verified by cilock/Rookery against a policy trust root.

## 5. Phone-home and egress from the process

**Now.** Every HTTP request in the service graph goes to the model gateway over
its unix socket, or is refused (`ManagedProfile.gatewayHttpClient`). The fetch
accepts only `http://hardened-gateway/...`, uses the socket fixed at build time
(`/run/hardened-gateway/gateway.sock`) and refuses redirects. LSP and formatters
are off in the compiled config.

Badger exports no telemetry of its own: its exporter is not configured from
`OTEL_*` (`Observability.ignoreEnvironment`), so the environment cannot point
it at a collector. The variables still reach the processes the agent starts,
which belong to the user's project (`packages/cli/test/managed-otel-binary.test.ts`).

**Tests.** `packages/server/test/managed-egress.test.ts`,
`packages/server/test/managed-gateway.test.ts` and
`packages/cli/test/managed-egress-binary.test.ts`. The last runs a session on
the fixture-model binary with a counting HTTP proxy in the environment, which
Bun's fetch honours: nothing but the gateway socket is reached, and code mode,
web fetch and web search are never offered to the model. The direct `fetch`
calls in the source are unreachable from the managed build: their provider
plugins are removed, the `api` command and the updater are replaced, a remote
`--server` and `session import` from a URL are refused, and code mode is off
because the compiled rules deny `execute`.

**To do.**
- Editor `$schema` hints still name upstream URLs. Badger never fetches them;
  re-point them at a published Badger schema.
- Acceptance run: the managed binary under an OS-level egress deny (a network
  namespace on Linux CI) makes no connection except to the gateway socket.

## 6. Model endpoints and the network boundary

**Now.** The managed process has one model route: the gateway. The gateway holds
the provider credentials and is configured by the administrator
(`testifysec/gateway/README.md`). A managed build fails at once, in one line,
when the gateway socket is not reachable (`Managed.requireGateway`), and refuses
any `--model` other than the compiled one.

The process cannot police its own children. Shell commands the agent runs, and
anything they start, are bounded by OS or VM egress control
(`testifysec/vm/README.md`, `testifysec/sandbox/`), not by the app.

**To do.** The 1.x design proposed a runtime admin policy file. On 2.0 the whole
config is compiled in, and deployment-specific values (the gateway socket, the
data marking) are build inputs. Open question 2 asks whether a deployment needs
a runtime policy file at all.

## 7. Server surface and terminals

**Now.** In the managed build:
- The routes that read or store credentials, add or connect MCP servers, or
  start a process (shell, terminals, persistent terminals, worktrees,
  `git init`) are refused before routing (`ManagedProfile.refused`, enforced by
  `RoutePolicy` in `packages/server/src/route-policy.ts`). The in-process client
  cannot reach their handlers either.
- Terminals cannot be opened. Persistent terminals are unavailable: their daemon
  binary is never resolved, so `OPENCODE_PTY_BIN` is never read.
- `--auto`, `--yolo` and `--dangerously-skip-permissions` are refused; what a
  session may do comes from the compiled permission rules (deny by default,
  then read, edit and shell).
- `--server` and `--standalone` are refused on every command that takes them:
  the CLI reaches only its in-process server. `session import` reads a local
  file and refuses a URL.
- `serve` is the one listening port, for a hosted workspace behind an edge; it
  puts a listener in front of the same in-process server (section 11).

**Tests.** `packages/server/test/managed-routes.test.ts` (each refused route
reaches its handler and spawns a process upstream; managed answers 404 and
spawns nothing), `packages/cli/test/managed-refusal.test.ts` and
`packages/cli/test/managed-session-binary.test.ts` (upstream connects to
`--server` and fetches the URL; managed refuses each in one line and connects
to nothing).

## 8. Secrets at rest

**Now.** The managed process holds no provider credentials: they live in the
gateway. The credential and integration-connect routes are refused and the
`auth` commands are not kept.

**To do.** Credential redaction of tool output on 2.0, at the tool execution
chokepoint and in the shell's streamed output file, is in review; the boundaries
are in `testifysec/TOOL-OUTPUT-REDACTION.md`. If a future build keeps local
credentials, store them in the OS keychain (macOS Keychain, Windows Credential Manager,
Linux Secret Service) rather than in `auth.json`.

## 9. Release, SBOM and signing

**Now.** There is no release workflow. `testifysec/distribution` verifies a
DSSE-signed bundle manifest offline, but nothing mints a production signature.

**To do.** A release workflow on a `v*` tag, never on `pull_request`:
1. `bun install --frozen-lockfile`.
2. `cilock run` wraps each per-target `build.ts --managed`, attesting the
   binaries and `bun.lock` as products and materials.
3. A CycloneDX SBOM from `bun.lock` and the Go modules, attested as its own step.
4. Keyless signing through the platform's Fulcio; release assets are the
   binaries, the SBOM, the DSSE envelopes and the update manifest from §1.
5. A reproducibility check: build twice from one commit on separate runners
   and compare digests; list and fix differences, never waive them.

Local builds stay unsigned and say so in `--version`.

## 10. FIPS boundary

**Now.** The managed process sends model traffic as plain HTTP over the gateway's
unix socket; it does no TLS of its own for that traffic. TLS to the provider is
the gateway's. This is the sidecar shape: the security-relevant crypto sits in
the Go gateway, not in Bun. The gateway does not yet claim FIPS validation
(`testifysec/gateway/README.md`). `testifysec/native/FIPS.md` documents the
frozen `GOFIPS140` module build for the Go native library.

**To do.**
- Build the gateway with `GOFIPS140` and have it report
  `crypto/fips140.Enabled()` and the exact module version.
- A managed build in FIPS mode refuses to start unless the gateway reports that.
- An inventory of Bun's remaining hashing (content digests, git object ids),
  each entry saying why it is not security-relevant.
- Open question 4.

## 11. Hosted workspace: `serve` behind an edge

A hosted workspace runs the managed build in a container and opens its web UI
through an authenticating edge. `serve` is kept for that
(`packages/cli/src/managed-serve.ts`); every other section still holds.

**Now.**
- The listener binds only the `--hostname` and `--port` given; there is no
  default address. `--service`, `--stdio` and `--cors` are refused.
- It forwards `/api`, `/auth` and `/openapi.json` to the in-process server the
  managed CLI already runs, so the managed profile, `RoutePolicy` refusals and
  the gateway-socket-only HTTP client hold unchanged. It serves the web UI
  assets, with the upstream web UI's content security policy, and nothing
  else. There is no CORS, pairing, tunnel, service
  registration or terminal.
- Every request, `/healthz` and the event stream included, needs
  `Authorization: Bearer <JWT>`: the identity provider's token for the signed-in
  user, which the edge forwards. The listener checks it against public keys
  only, the JWKS file named by `BADGER_SERVE_JWKS_FILE` (a file holding private
  key material is refused), with the key's own algorithm (ES256, ES384, RS256
  or PS256). `iss` must be `BADGER_SERVE_ISSUER`, `aud` must include
  `BADGER_SERVE_AUDIENCE`, `sub` must be `BADGER_SERVE_SUBJECT` (the workspace's
  owner), `exp` must be in the future and `nbf`, if present, in the past (30
  seconds of skew). The listener strips the header before forwarding. A
  long answer, such as the event stream, is cut when the token that opened
  it expires (exp plus the skew), so the client must reconnect with a
  current token. There is no WebSocket route: terminals are refused.
  Nothing the workspace's own account can read mints a token, and the agent's
  shell never sees the browser's requests, so it holds none.
  `OPENCODE_SERVER_PASSWORD` and `OPENCODE_PASSWORD` are removed from the
  environment before the server starts.

**Tests.** `packages/cli/test/managed-serve.test.ts`: a token signed by
another key, for another audience, issuer or user, expired, not yet valid,
unsigned, with another algorithm or with tampered claims is refused; a key file
with private material, or a missing setting, refuses to start; the listener
refuses everything without a token; the event stream streams through with one;
and a credential, shell and terminal route answer 404 through the listener as
they do in-process.
`packages/cli/test/managed.test.ts` shows `serve` is kept.

**Trade-offs.** Each is accepted for a hosted deployment and named here so an
accreditor sees it.

| Surface | Before | With `serve` | Risk | Real fix |
|---|---|---|---|---|
| Listening port | None; the server is in-process | One TCP listener on the given address | Network policy is what keeps everyone but the edge off the port | Bind a unix socket the edge's sidecar reaches, or mTLS from the edge |
| Listener credential | None | The identity provider's token, forwarded by the edge, checked against public keys | A token is good until it expires, so a stolen browser token reaches the API until then, and a stream it opened is cut at that expiry; there is no revocation check, and the keys are read once at start, so a key the provider removes is accepted until the listener restarts | Short token lifetimes at the identity provider; a revocation or session check against it |
| Web UI | Not served | The embedded web UI assets, behind the same credential | A browser bug in the UI is reachable by a signed-in user | Same as the upstream UI; no extra code path |

A deployment that uses `serve` also owns these, which the build cannot check:
- The edge: it signs users in with the identity provider and forwards that
  provider's token as `Authorization: Bearer` on every request to the
  listener, the event stream included, and only for the workspace's owner.
- The JWKS file: the provider's public keys, mounted read-only and not
  writable by the workspace's account. The listener reads it once at start, so
  a later change has no effect until a restart; a key the workspace could add
  before a restart would let it mint tokens.
- Network policy: only the edge reaches the listener; the workspace reaches the
  model broker, the audit collector and the connector pod, nothing else.
- The gateway socket at `/run/hardened-gateway/gateway.sock`, mounted for the
  workspace alone. A relay that re-exposes it in a shared volume is extra code
  on the capability path.
- TLS from the gateway to the model provider or broker with a pinned key; plain
  HTTP inside the cluster leaves model traffic readable on the node network.
- An audit collector with its own credential that the workspace network cannot
  reach directly, or a shell command can post forged audit records.
- The workspace container: non-root, read-only root, all capabilities dropped,
  RuntimeDefault seccomp at least; `hostUsers: false`, the restricted Pod
  Security profile, or a VM runtime for the worker are stronger.

## Open questions

1. Plugins: compiled-in only, or also a signed, runtime-loadable format (§4)?
2. Runtime policy: does a deployment need an admin policy file, or are build
   inputs enough (§6)?
3. Updates: notify-only against a signed channel, or never check (§1)?
4. FIPS: will accreditors accept the validated module in the gateway, with the
   Bun process doing no security-relevant crypto (§10)? If they require a
   validated runtime, that is a runtime swap.
5. Upstream code: keep it unreachable in the source, as now, or delete the
   paths the managed build never uses?
