---
title: Run Badger as a developer
description: Build or receive the managed Badger binary, start a session against your administrator's gateway, and understand what it refuses.
sidebarLabel: Run Badger as a developer
sidebarPosition: 10
---

# Run Badger as a developer

Badger looks and works like OpenCode's terminal UI. What differs is what it will not do: it has
one model, it reaches the network only through your administrator's gateway, and its policy is
compiled in.

## Before you start

- **A managed binary.** There is no published release. Your administrator gives you a `badger`
  binary built with `--managed`, or you build one from source (below).
- **A running gateway.** Your administrator runs the model gateway for your session and makes its
  socket available at `/run/hardened-gateway/gateway.sock`. Without it, starting a session or the
  terminal UI stops with a one-line error. See [configure the model gateway](../admin/install-gateway.md).

## Build the managed binary from source

From a checkout of this repository, with Bun installed:

```sh
cd packages/cli
bun run script/build.ts --managed --skip-web-ui --target=opencode-linux-x64 --outdir=/tmp/badger-release
/tmp/badger-release/cli-linux-x64/bin/badger --version
```

Use `--target=opencode-darwin-arm64` on Apple silicon. To compile in a data marking, add
`--data-marking=UNCLASSIFIED --allowed-markings=UNCLASSIFIED`; see
[classification markings](../concepts/classification.md). A build without `--managed` is plain
OpenCode and enforces none of this.

## Start a session

Run it from the repository you want to work in:

```sh
cd my-service
badger                  # the terminal UI
badger run "explain the retry logic in client.go"
```

The models are the ones the gateway's profile lists, under `managed/`; without such a list the only
model is `managed/approved`. `badger models` lists them; `--model` outside `managed/` stops the
command before anything runs, and one the profile does not list is refused when it is used.

The agent can read and edit files in the project and run shell commands, subject to the
permission prompts. Its own file tools are refused outside the project. A shell command is not
confined that way: what it can read or reach depends on the VM or container around Badger, not on
Badger (see the last section).

## What the managed build refuses

| You try | What happens |
|---|---|
| A command other than `about`, `run`, `mini`, `models`, `stats`, `session` or `serve` | Refused with one line, exit 1 |
| `--auto`, `--yolo`, or the option that skips permission prompts | Refused |
| `--server` or `--standalone` | Refused; the build talks only to the server inside its own process |
| `badger session import` from a URL | Refused; a local file works |
| Logging in to a provider, or setting a provider and API key in config | Not offered, not listed, never contacted |
| Adding an MCP server, installing a plugin, opening a terminal | Not available |
| Updating itself | Never checks, downloads or installs |

These come from the build, not from a setting, so no environment variable or config file changes
them. If something your work needs is refused, ask your administrator; it has to change in the
build or the signed profile.

## Repository requirements panel (optional)

If your repository is gated by Pushgate, you can show its requirements in the sidebar:

```sh
badger --requirements
```

This signs you in to the TestifySec platform with a device code and records the choice for this
directory. `--no-requirements` turns it off again and deletes the saved choice. A directory that
was never opted in makes no network request for this feature.

> [!NOTE]
> The platform API that serves requirements is not deployed yet, so this works only against a
> test fixture today.

## What the agent's commands can reach

The managed build controls the network requests it makes itself. A shell command the agent runs
is a separate process: whether it can reach the network or files outside your project depends on
the VM or container your administrator runs Badger in, not on Badger. On a workstation without
such a boundary, tool commands run as your own account. See
[architecture and trust boundaries](../concepts/architecture.md).
