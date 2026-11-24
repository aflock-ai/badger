# Contributing to Badger

Thanks for looking. Badger is TestifySec's distribution of OpenCode. Two kinds of change land here,
and they go to different places.

- **A change to OpenCode itself** (the agent loop, the TUI, providers, tools) belongs upstream at
  [anomalyco/opencode](https://github.com/anomalyco/opencode). Badger is based on a pinned upstream
  commit (`testifysec/upstream.commit`), and upstream fixes reach it by updating that pin.
- **A change to Badger** (the managed build, or anything under `testifysec/`) belongs here.

## Before you start

- Open an issue first for anything bigger than a bug fix, so we can say early whether it fits.
  Badger's scope is narrow on purpose: it removes capabilities rather than adding them.
- Report vulnerabilities through [SECURITY.md](SECURITY.md), not an issue.
- You must be able to license your contribution under the license of the files you change:
  Apache-2.0 under `testifysec/`, MIT elsewhere (see [NOTICE](NOTICE)). By opening a pull request
  you confirm that you have the right to submit it under that license. There is no CLA.

## Set up

Requirements: Bun 1.4.2 (pinned in `package.json`) and Go 1.26.4 or newer.

```sh
bun install --frozen-lockfile
```

## Check your change

CI runs these on every pull request, on GitHub-hosted runners, with no secrets. Run the ones that
cover your change.

```sh
bun turbo typecheck
bun turbo test --continue            # from the repository root; do not run `bun test` there
cd testifysec/<module> && GOWORK=off go test ./...
```

`AGENTS.md` has more detail on the TypeScript workspaces. Its notes on branches and the default
branch describe upstream's repository; here, branch from `main` and open the pull request
against `main`.

## Pull requests

- Keep a pull request to one change. Say what it does, why it works and how you checked it.
- Add or update a test. A change to the managed build's behaviour needs a test that runs the same
  case against the managed build and the unmanaged control build.
- Do not weaken a refusal to make a test pass. If a refusal looks wrong, say so in the issue.
- Write the description yourself. Text you did not read and cannot explain will slow the review.

## Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
