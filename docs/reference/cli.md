---
title: Command-line reference
description: Commands, build flags and environment variables for the managed Badger binary, the model gateway and the management portal.
sidebarLabel: Command line
sidebarPosition: 10
---

# Command-line reference

## badger

The managed binary is OpenCode's command line with the policy compiled in. Upstream options that
the managed build keeps behave as upstream documents them; this section lists only what Badger
changes.

### Commands

<!-- BEGIN GENERATED: managed-commands -->
The managed build keeps these commands and refuses every other one (`kept` in `packages/cli/src/managed.ts`):

- `badger about`
- `badger run`
- `badger mini`
- `badger models`
- `badger stats`
- `badger session`
- `badger serve`
<!-- END GENERATED: managed-commands -->

A refused command prints one line and exits 1.

### Refused options

| Option | Why |
|---|---|
| `--auto`, `--yolo`, and the option that skips permission prompts | Permissions are compiled in; nothing auto-approves |
| `--server`, `--standalone` | The build talks only to the server in its own process |
| `--model` outside `managed/` | The models are the gateway profile's, all under `managed/` |

`badger session import` accepts a local file and refuses a URL.

### Badger options

| Option | Effect |
|---|---|
| `--requirements` | Sign in to the TestifySec platform and show this directory's Pushgate requirements; the choice is saved per directory |
| `--no-requirements` | Turn requirements off for this directory and delete the saved choice |

### Environment

| Variable | Effect |
|---|---|
| `BADGER_DATA_MARKING` | Raises the session's data marking above the compiled one. A marking outside the compiled set stops the process. |
| `BADGER_ALLOWED_MARKINGS` | JSON array that narrows the markings a connector may carry. It can only remove markings from the compiled set. |
| `BADGER_TRUSTED_ROLE_HEADER` | Name of a request header carrying the caller's role, for a hosted deployment. Set it only behind a proxy that strips callers' copies of that header. |
| `BADGER_MARKING_ADMIN_ROLES` | Roles allowed to lower a connector's marking. With no role header configured, nobody can. |

Variables that upstream OpenCode reads for providers, telemetry (`OTEL_*`), proxies or updates have
no effect on a managed build.

## Build flags

`bun run script/build.ts` in `packages/cli`:

| Flag | Effect |
|---|---|
| `--managed` | Build Badger: compile in the managed policy. Without it the build is upstream OpenCode. |
| `--target=<name>` | One platform, for example `opencode-linux-x64`, `opencode-linux-arm64`, `opencode-darwin-arm64` |
| `--single` | Only the host's platform |
| `--outdir=<dir>` | Output directory; the binary is `<dir>/cli-<os>-<arch>/bin/badger` |
| `--skip-web-ui` | Do not build the bundled web UI |
| `--data-marking=<marking>` | Compile in the deployment's data marking. Requires `--managed`. |
| `--allowed-markings=<a,b>` | Markings a connector may carry; must include the data marking. Defaults to the data marking alone. |
| `--fixture-model`, `--worker` | Test builds only: a fixture model for the acceptance harnesses, and the Linux worker entry. Both require `--managed`; neither is a release artifact. |

Today the marking flags accept only the two unclassified levels.

## hardened-gateway

```text
hardened-gateway -config <file>
```

Takes no other arguments. See [configure the model gateway](../admin/install-gateway.md) for
every configuration key.

## hardened-admission

```text
hardened-admission < envelope.dsse.json
```

Takes no arguments and ignores its environment. Reads one DSSE envelope on standard input and
prints the admission result, or refuses. Trust is compiled in by `testifysec/managed/build.py`;
see [publish a profile](../admin/publish-profile.md).

## portal

```text
portal -config <file>      run the portal
portal -generate-key       write a new P-256 signing key to standard output and exit
```

`-generate-key` output is meant to be piped straight into `systemd-creds encrypt`. See
run the portal, which is part of the model broker (testifysec/model-broker/README.md).

## Connectors

Each connector binary takes `--base-url`, `--token-file`, `--ca-file`, `--enable-writes` and,
once PR #179 lands, `--classification`, plus its own flags. See
[configure a connector](../admin/connectors.md) and the
[connector tool reference](connector-tools.md).
