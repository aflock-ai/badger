# Upstream provenance and build notes

Badger is built on OpenCode. This file records which upstream commit the tree is based on and
which parts of the TestifySec components do not build on their own.

## Upstream pin

- `upstream.commit` holds the upstream OpenCode commit Badger is based on, and `upstream.tree`
  its tree.
- The public repository is a single snapshot and carries none of the original commit history, so
  `git blame` and `git log` here start at the snapshot. The upstream history is at
  <https://github.com/anomalyco/opencode>.
- Upstream files keep their MIT license and copyright notice (`LICENSE`). See `NOTICE` for the
  license split.

## Building

`python3 -I testifysec/standalone-check.py --go "$(command -v go)"` builds and tests every Go
module and fixture on its own, with the dependencies each `go.mod` declares. It lists the
components it skips and why.

Bun package tests need the dependencies in `bun.lock`. Run TUI tests from `packages/tui` and
web tests from `packages/app`, or run `bun turbo test --continue` from the root.

## Known gaps

- Full native builds of the desktop launcher need Rookery dependencies that are not part of this
  repository.
- Full preview, VM, Docker, cross-platform and signed-release verification are separate work.
  No binary release exists.

## GitHub Actions

`.github/workflows/ci.yml` is the only workflow. It runs on GitHub-hosted runners, reads the
repository and uses no secrets, so pull requests from forks run it unchanged. Upstream's
deployment, publishing and triage workflows are not part of this repository.
