# Badger

Badger is TestifySec's distribution of [OpenCode](https://github.com/anomalyco/opencode), an open
source AI coding agent, for networks that keep their code, tickets and models inside a boundary:
classified enclaves, air-gapped labs and regulated programs. A managed Badger build keeps the
OpenCode terminal UI and agent loop and removes or replaces what would let a session reach outside
that boundary.

Badger is not OpenCode. It is not affiliated with, endorsed by or supported by the OpenCode
project or its maintainers. "OpenCode" names the upstream project and appears here only to say
where the code comes from.

> [!WARNING]
> Badger is a development preview. There is no binary release and no signed release artifact.
> Publishing the source does not establish runtime isolation, a compliance qualification or an
> authorization. See [Security model](#security-model) for what is and is not claimed.

## What a managed build changes

Build with `--managed` and the policy is compiled in. No flag, environment variable, user setting
or repository file turns it off or widens it.

- **One model route.** Every model request goes to a gateway the administrator runs, over a Unix
  socket. The gateway holds the provider credential. The workstation holds none.
- **A smaller surface.** Only the commands `about`, `run`, `mini`, `models`, `stats`, `session`
  and `serve` remain. Built-in providers, web search and fetch, plugin install, sharing, the
  updater, LSP servers, formatters and terminals are off.
- **Signed configuration.** What a workstation may run is described by a profile an administrator
  signs. The gateway and session broker refuse a profile that is unsigned, expired, assigned to
  another deployment or below the minimum sequence the build trusts.
- **Labelled data.** Each connector carries one classification set by the administrator. A session
  refuses to send data to a connector or model accredited below what it has already read.

A build without `--managed` is plain OpenCode and is the control build in the test suites.

## Architecture

```
developer workstation                       administrator-run services
+---------------------------+               +--------------------------------+
| badger (managed build)    |  unix socket  | model gateway (Go)             |
| CLI/TUI + server in one   +-------------->| checks the signed profile,     |
| process, no listening port|               | writes an audit record, calls  |
+------------+--------------+               | the provider with its own key  |
             | MCP over stdio               +---------------+----------------+
             v                                              |
+---------------------------+               +---------------v----------------+
| connectors (Go): Jira,    |               | badger-broker (Go)             |
| Confluence, GitLab, one   |               | model broker + management      |
| base URL each, marked     |               | portal: policy, quotas, tokens,|
+---------------------------+               | profile signing and assignment |
                                            +--------------------------------+
```

| Component | Path | Role |
|---|---|---|
| Managed build | `packages/cli`, `packages/server`, `packages/core` | OpenCode's agent and TUI with the managed policy compiled in |
| Model gateway | `testifysec/gateway` | The only network path from a session; holds the provider credential |
| Admission launcher | `testifysec/managed` | Verifies a signed profile before anything starts |
| Session broker | `testifysec/broker` | Starts constrained worker containers for hosted sessions |
| Model broker and portal | `testifysec/model-broker`, `testifysec/portal` | Policy API, usage and quotas, workspace and pipeline tokens, profile signing. The broker's decision logic has Lean proofs in `testifysec/model-broker/formal` |
| Connectors | `testifysec/connectors` | One MCP server per enclave service, with data markings |
| Jade | `testifysec/jade` | A small build-and-gate CLI that records evidence of the checks a push must pass |

[`docs/`](docs/index.md) has the concepts, administrator guides, walkthroughs and reference.
[`testifysec/README.md`](testifysec/README.md) describes the TestifySec components.

## Build and test

Requirements: Bun 1.4.2 (pinned in `package.json`) and Go 1.26.4 or newer.

```sh
bun install --frozen-lockfile
bun turbo typecheck
bun turbo test --continue          # run from the root with turbo; not `bun test`

# Go modules under testifysec/ build and test on their own
cd testifysec/gateway && GOWORK=off go test ./...
```

To build the managed binary and start a session, see
[Run Badger as a developer](docs/developer/run-badger.md). The installation instructions in
OpenCode's documentation install OpenCode, not Badger.

## Security model

Badger treats repository content, tool output, model responses, plugins and MCP servers as
untrusted. Prompt approval is a usability feature, not isolation. The managed build restricts
what Badger's own tools and commands do. It does not confine a shell command; that depends on the
VM or container the deployment puts around it. The threat model, the controls and the boundaries
the deployment must supply are in
[Architecture and trust boundaries](docs/concepts/architecture.md) and
[Shared responsibility](docs/security/shared-responsibility.md).

To report a vulnerability, follow [SECURITY.md](SECURITY.md). Do not open a public issue.

## License

Badger combines two bodies of work under two licenses. [NOTICE](NOTICE) describes the split.

- OpenCode code is MIT licensed, copyright 2025 opencode: [LICENSE](LICENSE).
- TestifySec's components under `testifysec/` are Apache-2.0: [LICENSE-APACHE](LICENSE-APACHE).

Some packages carry their own license files; those apply to their directories.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
