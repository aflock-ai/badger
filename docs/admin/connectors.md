---
title: Connectors
description: Turn on the Jira, Confluence and GitLab connectors for a deployment, set each one's marking and credential, and choose where they run.
sidebarLabel: Connectors
sidebarPosition: 50
---

# Connectors

A connector gives the agent one enclave service (Jira, Confluence or GitLab) as the signed-in
developer, with the administrator's marking on every result. Read
[connectors](../concepts/connectors.md) first for what a connector is locked to.

A connector runs in one of two places:

| Where | For | Configured by |
|---|---|---|
| Inside the managed build, as a local MCP server | A workstation, or a hosted workspace that may hold the service token itself | The signed profile (v3) |
| In the connector gateway, `conngw`, a separate pod | Hosted workspaces that must never hold the service token or reach the service | `conngw`'s own signed profile, checked against each workspace's signed profile |

## Build the connectors

Each connector is a static Go binary from the `testifysec/connectors` module, which has no
third-party dependencies:

```sh
cd testifysec/connectors
mkdir -p bin
for c in jira confluence gitlab; do CGO_ENABLED=0 go build -trimpath -o bin/$c ./$c; done
sha256sum bin/*
```

Keep the digests. The profile pins each binary by its SHA-256, and a binary with any other digest
does not run.

## Choose the marking

Set each connector's classification to the highest marking the service is accredited to hold, in
banner form, for example `CONFIDENTIAL`; the levels a build accepts are those in `tokens.json`,
listed in the [marking grammar](../reference/marking-grammar.md). Every result the connector returns carries
that marking; nothing in an issue, page, label or file changes it. If parts of a service hold data
at different levels, use the highest. The grammar is in the
[marking grammar reference](../reference/marking-grammar.md).

The profile also names the model gateway's marking. Admission refuses a connector whose marking the
gateway's marking does not dominate, because whatever the connector returns may reach the model.
See [classification markings](../concepts/classification.md).

## Admit connectors in the managed build

A managed build admits connectors only if it was compiled with the pin of the profile v3 verifier:

```sh
cd packages/cli
bun run script/build.ts --managed --connector-admission-sha256=<sha256 of the verifier> \
  --skip-web-ui --target=opencode-linux-x64 --outdir=<dir>
```

Without `--connector-admission-sha256` a managed build admits no connector. With it, the build runs
the verifier on the signed envelope (`/run/badger/profile.dsse.json` unless built with
`--connector-envelope=<path>`) before the server starts, and refuses to start on any failure. The
connector binaries are read from the release's `connectors/` directory beside the executable
(`--connector-release=<path>` to change it), each checked against its pin. The checked copy is what
runs, from a private directory under Badger's state directory, with only the flags the entry
admits and an empty environment, so no `BADGER_CONNECTOR_*` variable reaches it.

The profile payload (`...profile.v3+json`) carries the v1 fields, `gateway: {"classification": ...}`,
and up to 16 entries in `connectors`. Every key except `notice` is required:

```json
{
  "name": "jira",
  "binarySha256": "<64 hex digits>",
  "baseUrl": "https://jira.example.invalid/rest/api/2",
  "tokenPath": "/run/badger/tokens/jira.token",
  "caPath": "/etc/badger/enclave-ca.pem",
  "writes": false,
  "classification": "CONFIDENTIAL",
  "flags": {},
  "permissions": { "jira_add_comment": "ask" },
  "notice": "Test data only"
}
```

| Key | Meaning |
|---|---|
| `name` | `jira`, `confluence` or `gitlab`, or a plugin behind the connector pod under any name the pod accepts (a lowercase letter, then up to 31 lowercase letters, digits or hyphens); each name once. For a plugin the pinned binary is the bridge, read from the release's `connectors/` directory under that name |
| `binarySha256` | The digest of the binary in the release's `connectors/` directory |
| `baseUrl` | The one service the connector may reach; HTTPS only |
| `tokenPath`, `caPath` | Absolute paths of the developer's token file and the enclave CA bundle (`caPath` may be `null`) |
| `writes` | Registers the write tools; without it they do not exist |
| `classification` | The connector's one marking |
| `flags` | Only the settings the release lists for that connector: Jira `marking-field`, `marking-label-prefix`; Confluence `label-prefix`; GitLab `auth` (`private-token` or `bearer`), `marking-prefix`. For a plugin, any flag the pod would pass it (the same name rule; not a shared flag or `notice`) |
| `permissions` | `allow`, `ask` or `deny` per tool, keys starting with the connector's own prefix |
| `notice` | Optional line printed inside the banners of every result, such as the content's real status; at most 160 letters, digits, spaces and `. , ; : ( ) ' / -` |

Any invalid entry fails the whole profile. The management portal signs it: a create request with
`"schemaVersion": 3` adds `gateway` and `connectors`, and the portal refuses before signing anything
admission would refuse later, including a connector the gateway's marking does not dominate
(`testifysec/PORTAL.md`, "Profile v3"). Publish it the same way as any profile:
[publish a profile](publish-profile.md).

## Run connectors in the connector gateway

For hosted workspaces, `conngw` runs in a connector pod and every connector there is a plugin:
an executable in its own container, as its own user, with only its own service token. The
workspace's signed profile pins a bridge binary (`mcp-bridge`) under each connector name; the bridge
carries the MCP stream over TLS to `conngw`, which carries it, checked, to the plugin. The in-repo
connectors run this way too, packed and signed like any vendor's plugin. Building and signing a
plugin is in [ship a connector plugin](../walkthroughs/ship-a-plugin.md).

The workspace profile that pins the bridge is a v3 profile, which the portal signs (see above). The
gateway's own profile is signed with `plugintool`, below.

### The gateway's profile

`conngw`'s configuration is a profile signed by the administrator. Every key is in the
[configuration reference](../reference/config.md#connector-gateway-conngw). The parts that decide
what runs:

| Key | Meaning |
|---|---|
| `signers` | The plugin signers this profile trusts: name to base64 ed25519 public key |
| `hostDigest` | The `plughost` image every plugin container must run (built from this repository) |
| `namespaces` | The namespaces whose workspaces this gateway serves; a workspace is `<namespace>/<account>` |
| `connectors[].bundle`, `digest`, `signer` | The plugin's signed manifest, the executable's sha256 it must name, and which signer signed it |
| `connectors[].socket`, `uid`, `gid` | The plugin host's socket and the plugin container's own user and group: not root, not another connector's, not the gateway's |
| `connectors[].grants` | Who may use the connector and which tools (below) |
| `connectors[].classification`, `writes`, `flags`, `baseUrl`, `tokenPath`, `caPath` | As for the managed build; the paths are inside the plugin's container |

Sign it with the key whose public half the gateway is started with. That key is pinned on the
command line, outside the profile, so an unsigned profile, one signed by another key or one edited
after signing refuses start:

```sh
plugintool sign -key admin.key -passphrase-file admin.pass -in conngw.json   # writes conngw.json.sig
conngw --init-labels /var/lib/conngw/labels.jsonl                            # first install only
conngw --config conngw.json --admin-key "$(cat admin.pub)"                    # signature read from conngw.json.sig
```

On start every connector's manifest must verify against its signer and name the digest the profile
pins; any failure refuses start.

### Grants

Each connector's `grants` say which workspaces may use it and which tools:

```json
"grants": [
  { "workspaces": ["team-a/*"], "tools": ["jira_get_issue", "jira_search"] },
  { "workspaces": ["team-a/release-bot"], "writeTools": ["jira_add_comment"] }
]
```

A subject is one workspace (`<namespace>/<account>`) or a whole namespace (`<namespace>/*`); an
exact workspace wins over its namespace. `tools` is the read allowlist: left out, every read tool
in the signed manifest; empty, none. `writeTools` are opt-in and need `writes: true` on the
connector, and the plugin starts with writes only for a workspace whose grant has write tools. Any
other workspace is refused (403). A call to a tool outside the grant is answered by `conngw` and
never reaches the plugin, and `tools/list` returns the grant. Whether a tool writes is the signer's
statement; the service token's scope stays the hard control for read-only.

### What each stream gets

1. The workspace's projected service-account token is checked with a TokenReview for the configured
   audience; the account must be in one of `namespaces`.
2. A workspace without a grant is refused (403); a declaration (classification, writes, flags) that
   differs from this profile is refused (409).
3. The plugin's container must be running the pinned `plughost` image, and the socket must be
   answered by the plugin's own uid and gid from inside that container.
4. A durable per-workspace label refuses any call to a connector the label is above, before it
   reaches the plugin.

### The pod

- **One container per plugin**, named as the connector, running the `plughost` image (never the
  vendor's) as the connector's `uid` and `gid`, with only its own token and a socket volume shared
  with the gateway alone:
  `plughost -socket /run/conngw/<name>/plugin.sock -vendor /vendor -plugin /vendor/plugin -gateway-uid <gateway uid>`.
- **The vendor image as a volume.** Mount the vendor's image read-only as a Kubernetes image volume
  at the `-vendor` path, which must be a mount point holding `-plugin`. The plugin cannot read
  anything beneath it; it runs from `plughost`'s verified copy.
- **A memory-backed staging directory.** `TMPDIR` in each plugin container must be an `emptyDir`
  with `medium: Memory`; `plughost` refuses to start on a disk. On the first stream for a digest it
  copies the executable there while hashing it and keeps the copy only if the sha256 is the pinned
  digest. The mounted file must be a regular file of at most 256 MiB.
- **Static executables only.** `plughost` refuses scripts, dynamically linked executables and ELF
  files for another architecture, with the reason in its log.
- **The gateway** runs as neither root nor a plugin's user, adds no capabilities and mounts no
  connector token. The pod sets `shareProcessNamespace: true`, passes `POD_NAME` and
  `POD_NAMESPACE` from the Downward API, and its account needs `get` on its own pod and
  `system:auth-delegator`. Run one replica with the Recreate strategy, with the labels file on a
  persistent volume.
- **The node.** Set `debug.exception-trace=0`. `plughost` refuses to start where Landlock is
  missing or where `kernel.core_pattern` could carry a core dump off the node. Where the node's
  audit rules match the plugins' uids, exclude those uids first; that is a documented deviation.

### Service tokens and the CA bundle

Each stream takes its own copy of the connector's token when it starts. The plugin gets that copy
(`--token-file`) and `plughost` scrubs the plugin's output for the same bytes, ending the stream if
the token appears raw, base64, hex or URL-escaped. A Secret rotated during a stream changes nothing
for that stream; the next stream takes the new token. To cut a token off at once, revoke it at the
issuing service or restart the connector pod. A plugin reads only its own stream's copy, never a
later stream's. Tokens shorter than 16 bytes are refused. Give each connector its own read-only
token, scoped to what its grants serve: the scrub catches accidents, not a hostile plugin.

A `caPath` must sit beside the token (a projected service-account volume puts `token` and `ca.crt`
together), be a regular file of at most 1 MiB, and hold only PEM `CERTIFICATE` blocks that parse.
The plugin gets a per-stream copy as `--ca-file`, never the original; otherwise the stream is
refused with the reason.

The full behaviour, including stream bounds, durable labels and what is logged, is in
[CONNECTORS.md](https://github.com/aflock-ai/badger/blob/main/testifysec/CONNECTORS.md).

## Credentials

In the managed build each connector reads the developer's token from `tokenPath` on every request
and sends it as that developer: a bearer token, or for GitLab a private token unless `auth` is
`bearer`. Use a personal access token with the narrowest scope the service allows. In `conngw` the
token is the connector's service token, copied per stream as above. Whether a tool is a write is
the connector's own statement; the token's scope is your hard control for read-only access.

## Check what a connector exposes

A connector speaks MCP on standard input and output. List its tools without a session:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
| ./bin/jira --base-url https://jira.example.invalid/rest/api/2 --token-file /dev/null \
    --classification "CONFIDENTIAL"
```

Without `--enable-writes` no write tool is listed, and calling one by name returns "unknown tool".
Every tool is in the [connector tool reference](../reference/connector-tools.md).
