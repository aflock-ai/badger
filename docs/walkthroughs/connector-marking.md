---
title: Turn on a connector with a marking
description: Admit the GitLab and Jira connectors at two different markings, watch every result carry its banner, and see the session refuse to write down.
sidebarLabel: Connector with a marking
sidebarPosition: 20
---

# Turn on a connector with a marking

This walkthrough admits two connectors at different markings into one managed build and then
shows the no-write-down rule refusing a flow. It assumes a working deployment from
[your first deployment](first-deploy.md). The procedures it uses are in
[connectors](../admin/connectors.md) and [publish a profile](../admin/publish-profile.md); the
rule itself is in [classification markings](../concepts/classification.md).

The example markings:

| Sink | Marking |
|---|---|
| Model gateway | `CONFIDENTIAL` |
| GitLab connector | `CONFIDENTIAL` |
| Jira connector | `UNCLASSIFIED` |

Use your own, from the levels your build accepts (`tokens.json`, listed in the
[marking grammar](../reference/marking-grammar.md)). The one constraint admission enforces is that the gateway's marking dominates every
connector's, because whatever a connector returns may go to the model.

## 1. Build the connectors and record their digests

```sh
cd testifysec/connectors
mkdir -p bin
for c in jira gitlab; do CGO_ENABLED=0 go build -trimpath -o bin/$c ./$c; done
sha256sum bin/jira bin/gitlab
```

Copy both binaries into the release's `connectors/` directory, beside the `badger` executable.

## 2. Check what each one exposes, before any profile

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
| ./bin/gitlab --base-url https://gitlab.example.invalid/api/v4 --token-file /dev/null \
    --classification "CONFIDENTIAL"
```

Only read tools are listed. Write tools exist only with `--enable-writes`, which the profile entry's
`writes` sets. Every tool is in the [connector tool reference](../reference/connector-tools.md).

## 3. Write the v3 profile payload

Add `gateway` and two entries to the payload, as described in
[admit connectors in the managed build](../admin/connectors.md#admit-connectors-in-the-managed-build):

```json
{
  "gateway": { "classification": "CONFIDENTIAL" },
  "connectors": [
    { "name": "gitlab", "binarySha256": "<gitlab digest>", "baseUrl": "https://gitlab.example.invalid/api/v4",
      "tokenPath": "/run/badger/tokens/gitlab.token", "caPath": "/etc/badger/enclave-ca.pem", "writes": false,
      "classification": "CONFIDENTIAL", "flags": {}, "permissions": {} },
    { "name": "jira", "binarySha256": "<jira digest>", "baseUrl": "https://jira.example.invalid/rest/api/2",
      "tokenPath": "/run/badger/tokens/jira.token", "caPath": "/etc/badger/enclave-ca.pem", "writes": false,
      "classification": "UNCLASSIFIED", "flags": {}, "permissions": {} }
  ]
}
```

Have the portal sign it: create the profile with `"schemaVersion": 3` and these two fields, as in
[publish a profile](../admin/publish-profile.md). The portal refuses, before signing, anything
admission would refuse. Put the envelope at `/run/badger/profile.dsse.json` in the workspace.

Admission refuses a payload whose gateway marking does not dominate every connector's, so a
mistake here stops the build at start instead of letting CONFIDENTIAL results reach an UNCLASSIFIED
model.

## 4. Build the managed binary with connector admission

From `testifysec/connectors`, where step 1 left the shell:

```sh
cd ../../packages/cli
bun run script/build.ts --managed --connector-admission-sha256=<sha256 of the verifier> \
  --skip-web-ui --target=opencode-linux-x64 --outdir=<dir>
```

A build without `--connector-admission-sha256` admits no connector at all. The build verifies the
envelope before its server starts and refuses to start if it fails, if a binary's digest differs
from its pin, or if a binary is missing.

## 5. Read at the higher marking, then try the lower one

In a new session:

```sh
badger run "list the open merge requests in platform/release-bot"
```

Every GitLab result carries `CONFIDENTIAL` banners, whatever the merge request's own
labels say. The session's label has now risen to that marking.

The label belongs to the state directory, not the session, so a new session there starts at it:

```sh
badger run "search Jira for tickets that mention release-bot"
```

The Jira call is refused before the connector runs: Jira's `UNCLASSIFIED` does not dominate the
session's label, and a search query carries content too. The decision is a line in
`connector-flow.jsonl` in the session's state directory.

**Check.** Start with a fresh state directory and call Jira first: it is allowed, and a GitLab call
after it is allowed too, since the label only has to rise.

## 6. Move the connectors into conngw (hosted workspaces)

For a workspace that must not hold service tokens, run the connectors as plugins behind `conngw`
and pin `mcp-bridge` in the profile instead. The in-repo connectors print their own manifest, so
they are packed and signed like any plugin ([ship a connector plugin](ship-a-plugin.md), steps 2 to
4), each with the same classification as above. The gateway's profile and pod are in
[run connectors in the connector gateway](../admin/connectors.md#run-connectors-in-the-connector-gateway).
`conngw` keeps the authoritative label per workspace in its labels file, so replacing the
workspace's state directory no longer resets it.

**Check.** A stream whose declared classification differs from `conngw`'s own entry is refused
with 409, and a workspace no grant names with 403.

## 7. Grant tools per workspace

In `conngw`'s profile, each connector's `grants` decide which workspaces may use it and which tools.
Let every workspace in `team-a` read GitLab, and only the release bot comment:

```json
"grants": [
  { "workspaces": ["team-a/*"] },
  { "workspaces": ["team-a/release-bot"], "tools": [], "writeTools": ["gitlab_add_note"] }
]
```

Left out, `tools` is every read tool in the signed manifest; an exact workspace wins over its
namespace, so the release bot's grant replaces the namespace's (here: no reads, one write). Write
tools need `writes: true` on the connector, and the plugin starts with writes only for a workspace
whose grant has one. Sign the profile and restart the pod.

**Check.** From `team-a/release-bot`, `tools/list` on GitLab returns only the granted write tool; from
another `team-a` workspace it returns the read tools and no write tool, and calling the write tool
by name is answered by `conngw` without reaching the plugin. A workspace in another namespace is
refused with 403.

## Resetting a label

Only an administrator lowers a label, by replacing the workspace's state directory (managed build)
or, in `conngw`, replacing the labels file with a fresh one (`conngw --init-labels`), which resets
every workspace the pod serves. Reset only after the content of every workspace it resets has been
reviewed, never to get past a refusal.
