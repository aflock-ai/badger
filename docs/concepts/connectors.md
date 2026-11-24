---
title: Connectors
description: How Badger connectors give the agent read and write access to an enclave's Jira, Confluence and GitLab, and what each one is locked to.
sidebarLabel: Connectors
sidebarPosition: 40
---

# Connectors

An enclave already runs its own source host, issue tracker and wiki. A connector lets the agent
read those services, and write to them where the administrator allows, as the signed-in
developer.

| Piece | Status |
|---|---|
| Shared connector library and reference connector | Available on `main` |
| One administrator-set marking on every result | Available on `main` |
| Jira Data Center connector | Available on `main` |
| Confluence Data Center connector | Available on `main` |
| GitLab self-managed connector, read tools | Available on `main` |
| GitLab write tools | Available on `main` |
| Admission through the signed profile (v3), pinned by digest | Available on `main` |
| Connector gateway (`conngw`) for hosted workspaces | Available on `main` |
| Connector plugins built outside this repository, per-workspace grants, one gateway for many namespaces | Available on `main` |

## How a connector runs

Each connector is one static Go binary with no third-party dependencies, built with
`CGO_ENABLED=0`. It speaks MCP over standard input and output and never opens a listening socket.
It runs in one of two places: started by the managed build as a local MCP server, or, for a hosted
workspace, as a plugin behind the connector gateway (`conngw`), a separate pod that holds the
service tokens so the workspace never does. See [connectors](../admin/connectors.md) for both. The
MCP implementation is about a hundred lines in `testifysec/connectors/internal/connector/stdio.go`
instead of the official SDK, which would have added nine third-party modules to a process that
holds a user's credential.

## Plugins

A plugin is a connector built and shipped outside this repository with the same interface (the
public `testifysec/connectors/sdk` package), or one of the in-repo connectors packed the same way.
It is a static executable in a vendor's image plus a bundle: a manifest naming the executable's
sha256 and its tools, signed by the vendor's ed25519 key. The gateway's administrator-signed
profile trusts the signer, pins the digest and decides the marking and who may call which tool;
nothing in the manifest changes either.

The vendor's image never runs. Each plugin's container runs the platform's `plughost` image, built
from this repository, with the vendor's image mounted read-only. `plughost` copies the executable
into a memory-backed directory while hashing it, runs the copy only if the digest matches, and
sandboxes it per stream:

- **No filesystem writes, little to read.** Landlock limits it to executing its verified copy and
  reading the platform image and its own stream's token copy, nothing else vendor-supplied.
- **No network of its own.** Its seccomp filter kills every socket call. To reach its service it
  asks `plughost` over one descriptor, and `plughost` dials the host and port of the profile's
  `baseUrl`, never one the plugin names. The plugin runs TLS itself, end to end.
- **Static executables only.** A script's interpreter or a dynamic executable's libraries would be
  files no signature covers, so they are refused.
- **Its token, per stream.** Each stream gets its own copy of the service token; `plughost` ends the
  stream if the plugin's output carries it. A hostile plugin can still encode its token, so the
  boundary is the vendor's signature, the administrator's review before pinning the digest, and a
  narrowly scoped token.

See [connectors](../admin/connectors.md) for running them, [ship a connector
plugin](../walkthroughs/ship-a-plugin.md) for building one, and the full threat model in
[CONNECTORS.md, "Plugins"](https://github.com/aflock-ai/badger/blob/main/testifysec/CONNECTORS.md#plugins).

## What a connector is locked to

These limits are in the shared library on `main` (`testifysec/connectors/internal/`) and apply to
every connector:

- **One service.** The HTTP client is bound to one base URL. It refuses any other host, any path
  outside the base, any redirect that leaves the base, and plain HTTP (except to loopback in tests). It ignores proxy
  environment variables. Responses are capped at 8 MiB.
- **The developer's own credential.** The connector reads a short-lived token from a file on
  every request and sends it as the developer. There is no shared service account. In the design
  the session broker provisions that file per user.
- **Configuration from the administrator only.** A connector takes its settings from flags or
  `BADGER_CONNECTOR_*` environment variables. In a managed session the model, user settings and
  repository files have no way to set them, and `mcp add`, plugin install and the connect routes
  stay refused. A managed build starts a connector with only the flags its signed profile entry
  admits and an empty environment.
- **Untrusted output.** Every result is wrapped in an `untrusted-external-content` block naming
  the source and tool and capped at 48 KiB. Any credential the connector itself sent is replaced
  with `[redacted]` before the result leaves it.
- **Fixed error text.** Authentication, permission, not-found, rate-limit and server errors become
  short fixed messages. Validation errors keep at most 300 bytes of the service's message, with
  credentials removed.

## Read and write tools

Every tool is registered as read or write. Without `--enable-writes`, write tools are not
registered at all: they are absent from `tools/list`, and calling one by name returns "unknown
tool". Read tools carry the MCP annotation `readOnlyHint: true`, write tools `false`.

The connectors provide:

| Connector | Read | Write (with `--enable-writes`) |
|---|---|---|
| Jira | search with JQL, get an issue, list comments | add a comment, create an issue, transition an issue |
| Confluence | search with CQL, get a page as Markdown, list child pages, list spaces | create a page, update a page at its current version |
| GitLab | get a project, search issues, get an issue, list and get merge requests, get a merge request diff, get a file, list pipelines, get a job log | create an issue, add a note to an issue or merge request |

GitLab write tools refuse any line starting with `/`, because GitLab runs it as a quick action,
and refuse labels that carry the marking prefix. Push, merge, approve, branch and tag creation,
pipeline retry and settings changes are deliberately absent: code reaches a repository through
Pushgate, not through a connector.

## Classification

Each connector has one classification, the marking the administrator sets for the service it
reads, and every result it returns carries that marking. The marking belongs to the connector,
not to individual items. See [classification markings](classification.md) for the rule and its
status.

## Admission

Only the administrator's signed profile turns a connector on. A profile v3 entry names the binary's
SHA-256, the base URL, the token and CA paths, whether writes are on, the service's marking,
connector-specific flags from a fixed list, and per-tool permissions such as
`"jira_add_comment": "ask"`. A managed build compiled with the verifier's pin checks the envelope
before its server starts and refuses to start on any failure; a binary whose digest differs never
runs. A profile cannot admit a connector above the model gateway's marking. The steps are in
[connectors](../admin/connectors.md).
