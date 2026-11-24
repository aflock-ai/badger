# Enclave service connectors

Issue: #159. Status: the shared library, a reference connector, classification markings and the
Jira and Confluence connectors are in; GitLab and the profile admission land in later changes
listed at the end.

## Purpose

A customer enclave already runs its own source host, issue tracker and wiki. A connector lets
the agent read those services, and with the administrator's permission write to them, as the
signed-in developer. The rules:

- Every connector is a plugin: an executable in a vendor image plus a manifest signed by its
  signer, admitted by the executable's digest. The vendor's image is never run; the platform's
  `plughost` image runs it, sandboxed. GitLab, Jira and Confluence are built and signed from this repository; any other
  connector is a plugin built elsewhere against the public `sdk` package and admitted the same
  way. There is no runtime download.
- The customer administrator turns a connector on per signed profile and gives it the service's
  enclave address. Developers cannot add, remove or reconfigure a connector: `mcp add`, plugin
  install and the connect routes stay refused, and user or repository config cannot name one.
- A connector acts with the developer's own short-lived credential, which the broker provisions.
  There is no shared service account, and Badger holds no long-lived credential.
- A connector reaches exactly one service, the one its profile entry names.

## Layout

`testifysec/connectors/` is one Go module with no third-party dependencies.

| Path | What it is |
|---|---|
| `internal/connector` | MCP stdio server, tool registration (read or write), output wrapping and capping, flags |
| `internal/egress` | HTTP client locked to one base URL, token source, status-to-message mapping |
| `internal/marking` | classification banner parser, token tables (`tokens.json`), `Dominates`, `Join` |
| `internal/fakeserver` | httptest fake built from recorded JSON fixtures, for connector tests |
| `sdk/` | public plugin interface (re-exports the runtime); every connector, here or elsewhere, builds on it |
| `internal/bundle` | plugin bundle format: manifest naming the executable digest, signature; ed25519 helpers |
| `internal/launch` | the gateway-to-plugin-container protocol (one hello line, then MCP) |
| `cmd/plughost/` | runs in each plugin's container: listens on the plugin's socket, starts the plugin per stream |
| `cmd/plugintool/` | `keygen`, `pack` (manifest + executable digest + signature), `verify`, `sign` (profiles) |
| `example/` | reference connector (one read tool, one write tool); not shipped |
| `jira/`, `confluence/`, `gitlab/` | the connectors, one static binary each (later changes) |
| `cmd/conngw/` | connector gateway for hosted workspaces: runs the connectors in a separate pod (below) |

Each connector is `CGO_ENABLED=0` and speaks MCP over stdio. The OpenCode worker starts it as a
local MCP server inside the worker boundary, so it never needs a listening socket.

## Decisions

**MCP implementation: hand-rolled, not the official SDK.** We evaluated
`github.com/modelcontextprotocol/go-sdk` v1.8.0. A minimal stdio server built with it compiles in
nine third-party modules (the SDK, `google/jsonschema-go`, `golang.org/x/oauth2`, `x/sync`,
`x/sys`, `x/time`, `segmentio/encoding`, `segmentio/asm`, `yosida95/uritemplate`), with 14 modules
in the graph and 24 `go.sum` lines. That includes an assembly JSON decoder and OAuth and HTTP
transport code a stdio tools server never runs. A connector holds a user's credential, so every
module in it is review and govulncheck surface. A tools-only stdio server needs four methods
(`initialize`, `ping`, `tools/list`, `tools/call`) over newline-delimited JSON-RPC; that is about
100 lines in `internal/connector/stdio.go`, with zero dependencies. It answers protocol revisions
2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05. The API connectors code against is ours, so
moving to the SDK later would not touch a connector. Revisit if we need resources, prompts,
sampling or the streamable HTTP transport.

**Targets.** Self-managed first: Jira Data Center/Server REST API v2, Confluence Data Center REST
API (content API and CQL), GitLab self-managed REST v4. Cloud variants later.

**Configuration** comes only from flags or `BADGER_CONNECTOR_*` environment variables that the
administrator's profile sets: `--base-url`, `--token-file`, `--ca-file` (enclave CA roots) and
`--enable-writes` and `--classification`, plus any connector-specific settings it registers through `Spec.Flags`
(each with a `BADGER_CONNECTOR_<NAME>_*` environment fallback). The model, user config and repository config have no way to set them.
`--insecure-loopback-http` exists for tests against a loopback fake and is never set by a profile.

**Credential.** The broker writes a per-user token to a file. The connector reads it on every
request so the broker can rotate it, and never logs it, echoes it in errors or returns it in tool
output. The header is the connector's choice: `Authorization: Bearer` (Atlassian DC personal
access tokens, GitLab OAuth) or `PRIVATE-TOKEN` (GitLab personal or project tokens). The token
source is an interface (`egress.TokenSource`) so the broker's later OIDC token exchange slots in.
As a second line of defence the server replaces every credential the client has recently sent
with `[redacted]` in all tool output and logs.

**Egress lock.** One base URL per connector. The client refuses any other scheme, host or port,
any path outside the base path (including `..`, encoded dot segments, and segments holding `;`
or `\`, which Tomcat-style servers normalize away), and any redirect that
leaves the base. It requires https unless the loopback test flag is set, ignores proxy
environment variables, sets dial, header and whole-request timeouts, and refuses response bodies
over 8 MiB (`Tail` reads the end of a longer one, such as a job log, and scrubs a credential it cuts
through). Only paging headers
(`PagingHeaders`) are returned to connector code. Network egress control around the worker is still the real boundary; this lock is what
stops a confused or injected tool call from pointing the credential somewhere else.

**Read and write tools.** Tools are read-only by default. A write is a separate, clearly named
tool (`jira_add_comment`) with `Write: true`, so profile permission rules can deny it by name. A
connector started without `--enable-writes` does not register write tools at all; `tools/list`
does not show them and calling one returns "unknown tool". Write tools also carry
`readOnlyHint: false` in their MCP annotations.

**Tool output** is plain text or markdown, capped at 48 KiB on a UTF-8 boundary with a note
giving the full size, and wrapped in an `<untrusted-external-content source=... tool=...>` block
that tells the model the content is data, not instructions. Content that tries to close the block
early has the tag defused. OpenCode runs ToolOutputRedaction
(`packages/core/src/tool-output-redaction.ts`) over MCP output again on the client side.

**Errors** become short messages without headers or tokens: 401/403 "the connector's credential
was rejected or lacks permission", 404 "not found, or not visible to you", 429 with the
Retry-After seconds, 5xx "the service failed". For 400, 409 and 422 a one-line, 300-byte,
credential-scrubbed excerpt of the body is kept, because it usually says what the model got wrong
(a JQL syntax error, a missing field). `HTTPError.Body` gives the connector the whole scrubbed body, capped at 16
KiB, to parse the service's own error format. Errors go through the same wrapper as results.

## Shared library API

Connector code needs only this:

```go
// package connector
type Spec struct {
	Name    string            // "jira"; tool names start with it
	Version string
	Scheme  egress.AuthScheme // egress.Bearer or egress.PrivateToken
	Tools   func(c *egress.Client) []Tool
	// Connector-only admin settings; the returned func validates them and may set Scheme.
	Flags   func(fs *flag.FlagSet) func(*Spec) error
}
type Tool struct {
	Name        string          // ^[a-z][a-z0-9_]{0,63}$
	Description string
	Write       bool            // changes the service; hidden unless writes are enabled
	InputSchema json.RawMessage // JSON Schema object
	Handler     func(ctx context.Context, args json.RawMessage) (Result, error)
}
type Result struct {
	Text string // plain text or markdown; the server wraps, caps, scrubs and banners it
}
func Main(spec Spec)                                       // a connector's whole main()
func Parse(spec Spec, args []string) (Spec, Config, error) // what Main does with os.Args, for tests
func Env(name, def string) string                          // flag default from the environment
func New(spec Spec, cfg Config) (*Server, error)           // tests build a server directly
func (s *Server) Call(ctx context.Context, name string, args json.RawMessage) CallResult
func (s *Server) ToolNames() []string
func Decode(args json.RawMessage, v any) error             // strict: unknown fields are errors
func ObjectSchema(props map[string]string, required ...string) json.RawMessage

// package egress
func (c *Client) Get(ctx context.Context, path string, query url.Values) ([]byte, error)
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, contentType string, body []byte) ([]byte, error)
func (c *Client) GetWithHeaders(ctx context.Context, path string, query url.Values) ([]byte, http.Header, error)
func (c *Client) DoWithHeaders(ctx context.Context, method, path string, query url.Values, contentType string, body []byte) ([]byte, http.Header, error)
var PagingHeaders = []string{"Link", "X-Next-Page", "X-Page", "X-Per-Page", "X-Prev-Page", "X-Total", "X-Total-Pages"} // the only headers returned
func (c *Client) Tail(ctx context.Context, path string, query url.Values, n int64) (tail []byte, dropped bool, err error) // last n bytes (n <= the 8 MiB cap) via a suffix Range, or streamed
type HTTPError struct{ Status int; RetryAfter, Detail, Body string } // errors.As; Body is the scrubbed body, capped at 16 KiB, for parsing

// package marking (used by the server and other modules; a connector only configures a banner)
func Parse(banner string) (Marking, error)       // configured banner, strict
func Dominates(a, b Marking) bool                // a may hold b (no write down)
func Join(a, b Marking) (Marking, error)         // high-water update; ErrNoBanner or ErrBannerTooLong when no banner prints it
func (m Marking) String() string                 // canonical banner

// package fakeserver
func New(t testing.TB, fixturesDir string, routes ...Route) *Server // Route{Method, Path, Query, Status, Fixture, Body, EchoAuth, Header, Responses}
type Response struct{ Status int; Fixture, Body string; Header map[string]string } // Route.Responses: nth match gets nth, last repeats
func (s *Server) Requests() []Request
```

`path` is relative to the base URL, starts with `/`, and has its segments already escaped
(`url.PathEscape`), so GitLab's `projects/group%2Fproject` survives. `example/` shows the whole
pattern, including its test.

## Threat model

1. **Prompt injection through service content.** Ticket descriptions, comments, page bodies,
   merge request descriptions, diffs and job logs are written by people the developer does not
   control. Treat all of it as hostile. Controls: the untrusted-content wrapper, the output cap,
   writes off unless the profile turns them on, write tools named so permission rules can require
   approval or deny them, and the egress lock so an injected instruction cannot send the
   credential or data to another host through the connector. The wrapper is a label, not a
   boundary; the model can still be talked into misusing an allowed write tool, which is why
   writes are separately gated.
2. **Stolen token.** The token in the file is the user's, scoped by the service, short-lived and
   rotated by the broker. The connector never writes it anywhere. Anything that can read the
   token file (the worker's own user) can use it directly, so the file permissions and the worker
   boundary protect it, not the connector. The broker should mint the narrowest scope the service
   offers (read-only scopes when writes are off).
3. **Egress.** A connector process can open sockets like any process in the worker. The library
   lock covers the connector's own requests; the worker's network policy must also limit the
   connector to the service address. The later admission change derives that allowance from the
   same profile entry.
4. **The connector itself.** Signed and pinned by digest in the release; the profile names the
   digest; no runtime download.

## Tools

Draft lists; each connector's change finalizes names and arguments. Lists are paged with a
service-native cursor or page argument and a small default page size.

**Jira (DC REST v2, Bearer).** Read: `jira_search` (JQL, fields subset, paging),
`jira_get_issue` (key; summary, status, assignee, description as text, links),
`jira_list_comments` (key, paging). Write: `jira_add_comment`, `jira_create_issue` (project,
type, summary, description), `jira_transition_issue` (key, transition name or id; list the
available transitions in the error when the name does not match).

**Confluence (DC REST content API, Bearer).** Read: `confluence_search` (CQL, paging),
`confluence_get_page` (id; storage format converted to markdown: headings, lists, tables, links,
code macros kept, other macros named but not expanded), `confluence_list_children` (id).
Write: `confluence_create_page` (space, parent, title, markdown body converted to storage
format), `confluence_update_page` (id, expected version, new body; refuse on version conflict).

**GitLab (self-managed REST v4, PRIVATE-TOKEN or Bearer).** Implemented in `gitlab/`; see
[GitLab connector](#gitlab-connector).

## Classification markings

Implemented in `internal/marking` and stamped on every result by `internal/connector`. A
connector has no part in it beyond the administrator's `--classification` setting.

**What is guaranteed.** A service holds one classification. Every result carries the
connector's administrator-set marking (the service's system high), and nothing a service returns
changes it. Connectors make no assumption about how an application records classification and
read none from it: no fields, labels, page or file banners, panels or tables.

**Profile field.** Each connector entry carries `classification`: the system-high marking of the
service, as a banner string (`SECRET//NOFORN`, `CUI//SP-CTI`, `UNCLASSIFIED`). The administrator
sets it; the model, user config and repository config cannot. The connector parses it at startup
and refuses to start on any token it does not know. It does not guess.

**Parser.** Structure, not all of CAPCO. A banner is `//`-separated groups in the order
CLASSIFICATION//SCI//SAP//AEA//FGI//DISSEM//NONIC (DoDM 5200.01 Vol 2, Encl 3; the IC structure
under ICD 710). Within a group, `/` separates values (`SI/TK`). Level is one of UNCLASSIFIED,
CONFIDENTIAL, SECRET, TOP SECRET, or the CUI control marking `CUI` with its own groups
CUI//categories//limited-dissemination (32 CFR 2002.20(b); NARA CUI Registry and Marking
Handbook), categories prefixed `SP-` when Specified, Specified first. Within a group the parser
accepts any order and prints a canonical one (table order for controls, alphabetical otherwise).
Banners must use full words; portion marks are not accepted. SCI and SAP control systems are kept as
opaque tokens but must appear in the allowlist; dissemination controls (NOFORN, ORCON, RELIDO,
FEDCON, NOCON, DL ONLY, FED ONLY, ...) come from the allowlist; `REL TO` and `DISPLAY ONLY` take
a comma list that must start with USA, then trigraphs in alphabetical order, then tetragraphs
(CUI Registry, Limited Dissemination Controls). Country codes are ISO 3166-1 alpha-3; the IC
uses GENC, which differs for a few entities (XKS), and those are refused until added. Tetragraphs
(ACGU, FVEY, NATO) expand to their members for dominance. A classified banner may also carry CUI
limited dissemination controls (NOCON, FEDCON, ...) so that a joined high-water mark can be
printed; that is a Badger extension, not a CAPCO form. The token tables are a versioned JSON file
embedded in the binary, each table citing its source, so updating them is a data change.
Out of scope: AEA and FGI detail beyond recognizing the group, the full CAPCO register (it is not
public), declassification blocks, and validating that a combination is legal beyond structure
and allowlist.

**FOUO.** Retired by DoDI 5200.48 (2020), which replaced DoDM 5200.01 Vol 4; under 32 CFR
2002.20(a) legacy markings no longer indicate protection. A connector's configured marking may
not be a retired legacy marking: startup fails and names the current markings to use.

**Every result carries the banner** as its first and last line, outside the untrusted-content
block, including errors and truncated output, and in the MCP result's `_meta` under the key
`com.testifysec/classification` as `{"schema": 1, "banner": "..."}`. A marking holds only
letters, digits, spaces, commas, hyphens and slashes (it is printed outside the untrusted-content
block), and a REL TO or DISPLAY ONLY list may appear once.

**Test and sample data: a notice, never a banner token.** Marking guidance says not to put TEST
or SAMPLE inside a banner: the banner stays as the content would be marked, and a separate line
states its real status (DoDM 5200.01 Vol 2, Encl 3, para 22; 32 CFR 2002.20(a)(2) and (l)(4)).
A connector takes an optional `--notice` from the administrator, for example `TEST DATA - Not
controlled. Markings are for test purposes only.`, and prints it as its own line directly under the top
banner and over the bottom one. It is never part of the banner or of `_meta`, never parsed as a
marking, and the token tables carry no TEST or SAMPLE token. Because it is printed outside the
untrusted-content block, it is one line of at most 160 letters, digits, spaces and `.,;:()'/-`;
anything else refuses to start. A notice holding a credential the client sent fails closed like
such a banner.

**Session high-water and flow checks: extend aflock, do not invent.** aflock's `DataFlowPolicy`
already has the shape: `classify` maps labels to tool patterns, a read adds the label to the
session's material taint (`MaterialClassification`), `flowRules` deny `source->sink`, and a denial
is recorded and surfaces as a failed `dataflow:` check in verification. Badger keeps that
vocabulary so one signed policy can drive both, and changes four things:

1. Labels are markings with a dominance lattice, not flat strings with pairwise rules. `a`
   dominates `b` when a's level is at least b's (U < CUI < CONFIDENTIAL < SECRET < TOP SECRET),
   a's SCI, SAP and CUI-category sets include b's, a's restrictive dissemination controls
   (NOFORN, ORCON, NOCON, ...) include b's, and a's releasability (`REL TO`) is a subset of b's
   (NOFORN releases to no one). The rule is one line: deny a flow to a sink whose accredited
   marking does not dominate the session high-water mark (no write down). `marking.Dominates(a,
   b)` and `marking.Join(a, b)` (an upper bound of both, the high-water update) ship
   with table tests, since every check builds on them. A classified sink dominates CUI categories
   but not CUI controls it does not carry, and a classified marking with no REL TO counts as
   releasable to USA only, so `SECRET//REL TO USA, FVEY` does not dominate plain `SECRET`.
   `Join` refuses, with `ErrNoBanner` and no marking, a combination at the controlled-unclassified
   level that holds FGI, atomic-energy or non-IC markings, since no banner prints it, and with
   `ErrBannerTooLong` a join whose banner would be longer than `Parse` accepts. A session whose
   join is refused must fail closed.
2. The source label is the marking of the connector the session read from, not a tool-name
   pattern.
3. Read versus write comes from the connector's tool registration (`Tool.Write`), not from
   whether "write" appears in the tool name (aflock's `isWriteOperation` heuristic).
4. Sinks: the model gateway (its accredited marking; content above it is never sent), write tools
   on a lower-marked connector (read from SECRET Confluence, write to UNCLASSIFIED Jira), and git
   push through pushgate (the repository's marking). A denial goes into the evidence record.

The check itself lives in OpenCode and the gateway and lands with the admission change.

**Relation to the existing data marking.** Badger already stamps a deployment data marking on
session records and lets a marking admin set a per-connector marking
(`packages/util/src/security-marking.ts`, `packages/core/src/connector-marking.ts`). That model
orders two flat values. This lattice generalizes it, and the admission change should make the
TypeScript side use the same order (a port of `Dominates` and `Join` checked against the Go table
tests) rather than keep two. One difference is deliberate: a connector's marking here comes only
from the signed profile; nobody lowers it at runtime.

**Markings are labels, not a security boundary.** A marking tells a person and a policy engine
what the content is. It does not stop anything by itself, and a connector misconfigured with a
low marking under-reports. The enforcement is the accreditation of the gateway and model the
session talks to, the per-session high-water check above, and the enclave's own network and
system accreditation. Do not accredit a system on the strength of the banner.

Sources: DoDM 5200.01 Vol 2, Marking of Information, Change 4, 2020
(https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodm/520001m_vol2.pdf);
32 CFR 2001 Subpart C, 2001.20-2001.26 (https://www.ecfr.gov/current/title-32/subtitle-B/chapter-XX/part-2001/subpart-C);
ISOO, Marking Classified National Security Information, Rev 4, 2018
(https://www.archives.gov/files/isoo/training/marking-booklet-revision.pdf);
ICD 710, Classification Management and Control Markings System, 2013
(https://archive.dni.gov/files/documents/ICD/ICD-710.pdf), which makes the CAPCO Register and
Manual authoritative for IC markings (the Register itself is not publicly released);
32 CFR 2002, 2002.20 (https://www.ecfr.gov/current/title-32/subtitle-B/chapter-XX/part-2002);
NARA CUI Registry, Limited Dissemination Controls (https://www.archives.gov/cui/registry/limited-dissemination);
NARA CUI Marking Handbook (https://www.archives.gov/files/cui/documents/20161206-cui-marking-handbook-v1-1.pdf);
DoDI 5200.48, Controlled Unclassified Information, 2020, para 3.4 and the CUI designation
indicator in Figure 2 (https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodi/520048p.PDF).
DoD documents also need the CUI designation indicator block (Controlled by, CUI Category,
Dissemination Control, POC) on the first page; a connector reports markings, it does not author
documents, so the indicator is out of scope for connector output.

## GitLab connector

`gitlab/`, GitLab self-managed REST API v4. The base URL is the API root
(`https://gitlab.example.invalid/api/v4`). Merge request diffs use `/diffs`, so GitLab 15.7 or
later.

**Settings** (profile only, like the shared ones): `--auth=private-token|bearer`
(`BADGER_CONNECTOR_GITLAB_AUTH`, default `private-token`: the `PRIVATE-TOKEN` header for personal
or project access tokens; `bearer` for OAuth tokens), registered through `Spec.Flags`.

**Tested against** GitLab CE 19.5.1: `testdata/live/` holds scrubbed exchanges recorded from it,
replayed by `TestLiveExchanges` with exact request paths and queries. **Known limit:** a file whose
path contains `;` cannot be read; its escaped path holds `%3B`, which the egress lock refuses as a
path parameter, so the call fails closed.

**Read tools.** `gitlab_get_project` (numeric id or full path), `gitlab_search_issues` (state,
labels, search), `gitlab_get_issue` (with up to 100 discussion threads, system notes left out),
`gitlab_list_merge_requests` (state, labels, search, branches), `gitlab_get_merge_request` (with
its discussion threads from `/discussions`, which carry each review comment's file and line),
`gitlab_get_merge_request_diff` (8 KiB per file, 40 KiB per call, paged by file), `gitlab_get_file` (raw text at a ref, default branch if none; binary files
refused; 40 KiB), `gitlab_list_pipelines` (or, with `pipeline_id`, that pipeline's jobs, whose ids
feed the log tool), `gitlab_get_job_log` (last N lines, at most 2000 and 32 KiB; every terminal
escape, including OSC clipboard and hyperlink sequences, other control characters and section
markers removed; it reads only the end of the log through `Tail`, so a log over the
8 MiB response cap works). Lists take `page` and `per_page` (1-100, default 20) and report the next
page from `X-Next-Page`.

**Write tools** (only with `--enable-writes`): `gitlab_create_issue` (title, description, labels)
and `gitlab_add_note` (issue or merge request). `gitlab_create_issue` sends each label trimmed of
Unicode whitespace and invisible format characters, as GitLab will store it, and refuses one that is
then empty, holds a comma or is over 255 characters. Labels carry no classification meaning. Both
tools refuse a description or comment with a line starting with `/`, because GitLab runs such
lines as quick actions (`/label`, `/close`, `/assign`) with the connector's credential.

**Deliberately absent.** No tool pushes commits, creates or edits files, creates branches or tags,
approves or merges a merge request, retries or cancels pipelines, or changes project, member, CI
variable or webhook settings. Code reaches a repository through pushgate, where it is attested and
gated; a connector that could push would be a path around it. Add none of these here.

**Input checks**, all before any request: a project is a numeric id or `/`-separated segments of
letters, digits, `_`, `-` and `.` with no `..`, escaped as one segment (`group%2Fsub%2Fproject`); a
file path is relative with no empty, `.`, `..`, backslash or control-character segment, escaped the
same way; a ref follows `git check-ref-format` (so `release/v1.2.3+build` and `feature/@alice`
pass; `..`, `@{`, control characters, space, `~^:?*[\`, empty or dot-led components and `.lock`
endings do not), may not start with `-`, and travels in the query; IIDs and job ids are positive integers; enum arguments are
checked. GitLab error bodies (`{"message": ...}`, field maps, `{"error": ...}`), read from
`HTTPError.Body`, become one line of at most 300 bytes.

**Classification.** A GitLab instance holds one classification. Every result carries the
connector's administrator-set marking, and the connector reads nothing about classification from
GitLab: labels, topics and file contents never change the banner. Every project-scoped read still
fetches the project first (to resolve the path and the default branch); a project or item that
comes back null or without its identifying fields stops the read.

## Admission (later change, `packages/server/src/managed.ts`)

Not changed here. The plan: profile v2 rejects unknown keys, so connectors arrive as a new
signed profile schema version with a `connectors` array. Each entry:

```json
{
  "name": "jira",
  "binarySha256": "<64 hex: digest of the pinned connector binary in the release>",
  "baseUrl": "https://jira.example.invalid",
  "tokenPath": "/run/badger/tokens/jira.token",
  "caPath": "/etc/badger/enclave-ca.pem",
  "writes": false,
  "classification": "CUI//SP-CTI",
  "permissions": { "jira_*": "allow", "jira_add_comment": "ask" }
}
```

Admission runs before upstream initialization: the binary's digest must match, the base URL must
be https, the marking must parse, and any invalid or unsigned entry fails the whole profile
closed. `managed.ts` then stops removing `opencode.config.mcp` for exactly these entries,
compiling each into a local stdio MCP server whose command and flags come from the entry, while
`mcp.add`, `mcp.connect`, plugin install and user or repo MCP config stay refused. The worker's
network policy gets one allowance per entry (base URL host and port). Tool output still passes
through ToolOutputRedaction, and every call is recorded in the evidence record like a model call.

### The gateway ceiling

**Rule.** A signed profile cannot admit a connector whose marking the model gateway's accredited
marking does not dominate. A connector's classification is the one the administrator set in the
profile; nothing is read from the content it returns. With the ceiling, anything a connector can
return is already within the gateway's accreditation, so the gateway reads no classification from
request bodies. Admission refuses such a profile (`packages/cli/src/managed-connectors.ts`), and
gateway v3 refuses every request while one is admitted (`testifysec/gateway`, README). The
no-write-down rule between connectors (a call to a lower connector after calling a higher one) is
enforced by the worker's high-water check.

**Future option.** Admitting a connector above the gateway, with the per-session high-water check
keeping its content from the gateway, needs the connector traffic observed outside the worker:
connectors run by the broker, or an egress proxy that labels what each connector returns. Until
one of those exists, the ceiling is the rule.

### As built

- Profile v3 (`testifysec/managed/profile-v3.ts`) carries `gateway: {classification}` and the
  `connectors` array above, with `flags` for the connector-specific settings the release lists
  instead of free-form arguments. Admission parses both markings with `testifysec/marking`, the
  TypeScript port of `internal/marking`, which replays the contract model's vectors. A name outside
  the catalog is a plugin behind the connector pod: admission (and the portal, which signs v3)
  accepts any name `conngw` accepts for a connector and any flag it would pass the plugin (not a
  shared flag, not `notice`), and keeps every other entry check. The pinned binary is the bridge,
  read from the release's `connectors/` directory under the entry's name, so the release must ship
  the bridge under that name. `cmd/conngw/testdata/connector-names.json` is the corpus `conngw`,
  admission and the portal all test, so the rules cannot drift.
- A managed build compiled with `--connector-admission-sha256` runs that verifier on
  `/run/badger/profile.dsse.json` before the server starts and refuses to start on any failure
  (`packages/cli/src/managed-connectors.ts`). Each binary is read from the release's `connectors/`
  directory beside the executable, checked against its pin, and the checked bytes are what runs,
  from a 0700 directory under the badger state directory (never the system temp directory), after
  a check that it allows execution. The verifier runs the same way.
  Connectors start with their admitted flags and an empty environment, so a `BADGER_CONNECTOR_*`
  variable cannot set anything (`packages/server/src/managed-connectors.ts`).
- The high-water check (`packages/server/src/managed-flow.ts`) keeps one label per Badger state
  directory, as the connector pod keeps one per workspace: the join of the profile markings of
  every connector that state directory has ever called. Nothing is read from what a connector
  returns, and sessions, subagents, forks and resumed sessions all share the label, so no lineage
  is tracked. The label rises when a call is allowed, before the connector runs, and never goes
  down. A cancelled or declined connector call still raises the label; reset is an admin action.
  That over-labels and never under-labels, and is intended. A call that waits for the
  user's approval is not checked again when it is approved, even if the label rose meanwhile: the
  only content a call sends is its arguments, which were fixed before evaluation, when the label
  was dominated by the connector, and the label only rises, so nothing above that connector existed
  when they were written. This holds while an approval cannot edit a call's arguments (a reply is
  once, always or reject with optional feedback text); a test pins that reply shape. Every call to a connector, read or write, is refused when the connector's marking does not
  dominate the label, because a read's arguments (a search query) carry content to that system
  too; this is stricter than item 3 above. A send the gateway's marking does not dominate is
  refused before it reaches the socket (a second check, since the ceiling above already rules it
  out). Decisions go to `connector-flow.jsonl` in the state directory, each flushed to disk, and a transfer at or into a
  label above the lowest whose decision cannot be written is refused. At start the label is
  rebuilt as the join of every allowed call that file records; a file that cannot be read stops
  the start. Connector calls are refused from the signed profile's expiry on. A call already
  waiting for the user's approval at expiry can run once when approved; every later call is
  refused, and the gateway refuses the next model request, so the window is one human-approved
  call. After a write to it fails, nothing more is written or allowed until a restart: a
  partial record is cut back where possible, and a restart that still finds one stops. **Trust boundary.** This check runs in the worker and is defense in depth.
  Changing or removing the state directory, `connector-flow.jsonl` included, is a reset, and
  protecting it from the workspace user is a deployment responsibility (the Audit row of
  [Shared responsibility and IL6](../docs/security/shared-responsibility.md)). The enforcement that
  survives tampering with the worker is the connector pod's server-side per-workspace label
  (#239), which the workspace cannot reach. One process owns the file at a time through a kernel lock (flock) on
  `connector-flow.jsonl.lock`, which the kernel drops when the owner dies and which holds across
  PID namespaces, so a second start, in another container too, is refused rather than missing the
  first one's calls. Only an administrator resets the label,
  by removing the state directory and recording why; a signed reset record may come later.
- Not yet: the worker network allowance per entry and the repository marking for pushgate. In managed builds the runtime per-connector marking
  (`connector-marking.ts`, its RPC plugin) is switched off: a connector's marking comes only from
  the signed profile.

### The workspace's starting label

The workspace's label starts at the lowest marking, and only connector calls raise it: a
connector's marking is the one its administrator set, and nothing is read from content. Content
that reaches the workspace any other way (repository files, user input, model output) is not
labelled. Keeping that content within what the workspace's lowest admitted connector may receive
is a deployment and customer responsibility, recorded with the others in
[Shared responsibility and IL6](../docs/security/shared-responsibility.md).
A higher-marked workspace with a lower connector is therefore a deployment decision, not one
Badger can see. **Future option:** a signed starting marking in the profile, which the label would
start from.

## Plugins

A plugin is an executable (which speaks MCP over stdio and takes settings only from the shared
flags), shipped in a vendor image, plus a bundle directory. The vendor's image is never run: the
plugin's container runs the platform's `plughost` image, built from this repository, and mounts the
vendor image read-only as a Kubernetes image volume. On the first stream for a digest `plughost`
copies the executable from there into its own staging directory (under `TMPDIR`, which must be
memory-backed: an emptyDir with `medium: Memory`; `plughost` refuses to start on a disk) while
hashing it, and keeps the copy only if its sha256 is the digest the hello names
(from the signed profile); otherwise it closes the stream and logs the digest it found. The copy
is what runs, sandboxed: the bytes executed are the bytes hashed, the mount may be noexec, and a
plugin cannot write the copy. The mounted path must be a regular file of at most 256 MiB. The
host keeps one copy, in a directory per socket that it empties at start, so restarts on the same
emptyDir reclaim earlier copies.

**Plugins must be statically linked.** `plughost` runs only an ELF executable for the node's
architecture that names no interpreter (`PT_INTERP`). A script's interpreter or a dynamic
executable's libraries would be files in the vendor's image that no signature covers. Scripts,
dynamically linked executables and ELF files for another architecture are refused with the reason
in the host's log. Build recipe: `CGO_ENABLED=0 go build` with the default build mode, not
`-buildmode=pie` (Go's PIE without cgo has an `INTERP` header and is refused). A plugin that must
use cgo links with `-ldflags '-linkmode=external -extldflags=-static-pie'` (with `-buildmode=pie`)
or `-extldflags=-static`. Check the result before signing: `readelf -l plugin` shows no `INTERP`. The
kernel loads only the file itself when there is no interpreter (it never acts on `NEEDED` entries),
so the signed digest covers all the code that starts. After it starts, the plugin can read only
the digest-pinned platform image (the `plughost` image), its verified copy and its own stream's
token snapshot: nothing vendor-supplied besides the verified copy. Its Landlock ruleset handles
execute as well as read and write: the only file it may execute is its verified copy, and its read
rules leave out the whole vendor image volume (`plughost -vendor <mountPath>`, which must be a mount
point and hold `-plugin`), the mounted token's directory and the staging directory (but for its own
snapshot). A `caPath` beside the token (a projected service-account volume puts `token` and `ca.crt`
together) works: `plughost` checks it (inside its own directory, not the token, a regular file up to
1 MiB of parsing PEM CERTIFICATE blocks and nothing else) and gives the plugin a per-stream copy of
the certificates as `--ca-file`, never the original; otherwise the stream is refused with the
reason. Any library a plugin loads by itself from the image is platform-signed bytes, the same
trust as `plughost` itself; so the `plughost` image stays minimal.

| File | What it is |
|---|---|
| `manifest.json` | `{"schema":1,"name","version","digest":"sha256:<executable digest>","tools":[{name,description,write,inputSchema}]}` |
| `manifest.sig` | base64 ed25519 signature over `manifest.json`'s exact bytes, by the plugin's signer |

A plugin has no socket API and no network of its own: its seccomp filter kills `socket`,
`socketpair`, `connect`, `bind`, `listen`, `accept` and `accept4`. Its one way out is descriptor
3, named by the only variable in its environment, `BADGER_EGRESS_FD=3`: for each connection to its
service it writes one byte there, and `plughost` answers with one byte `K` and, as `SCM_RIGHTS`, a
TCP connection it dialled to the profile's `baseUrl` host and port (or `E` if that dial failed).
`plughost` chooses the destination from the gateway's signed profile, never from what the plugin
sends, logs each dial, and takes nothing back but the request byte. The plugin runs TLS itself, end
to end, to the `baseUrl` host name. `sdk` does all of this; a plugin in another language must do the
same where it would open a TCP connection.

A plugin built on `sdk` prints the tool part with `plugin --manifest`. `plugintool manifest -exe
plugin -out tools.json` runs it and writes that list; run it where the signing key is not, since
it runs plugin code. `plugintool pack -manifest tools.json -digest sha256:<sha256sum of the executable> -key vendor.key
-out <dir>` then adds that digest and signs, and never runs plugin code.
`plugintool keygen` writes the private signing key encrypted (PBKDF2-HMAC-SHA256, 600000 rounds,
then AES-256-GCM with the versioned header as associated data). `keygen`, `pack` and `sign` read the
passphrase from `--passphrase-file` or `PLUGINTOOL_PASSPHRASE`, never from the command line, and
refuse one under 12 characters. A plaintext key is refused unless `--insecure-plaintext-key` is
given, which warns.
The manifest says what the executable is and which of its tools write. It never says what marking the plugin carries or who may
use it: any such field is ignored. In-process Go plugins were rejected: they share the gateway's
memory (service tokens, labels, TLS key), need the host's exact toolchain and module graph, and
cannot be built by a third party. A process per stream keeps the empty environment, discarded
stderr and kill-on-idle that connectors already had, and a container per plugin keeps each
plugin's files, user and token apart from the gateway's and from every other plugin's.

## Connector pod for hosted workspaces (`cmd/conngw`)

A hosted workspace can run its connectors in a separate connector pod instead of in its own
container, so the service tokens and the route to each service never enter the workspace. The
workspace's signed profile pins a bridge binary under each connector name; the bridge carries the
MCP stream over TLS to `conngw` in the connector pod, which carries it, checked, to the plugin's
own container in that pod.

- **Signed profile.** `conngw --config profile.json [--config-sig profile.json.sig] --admin-key
  admin.pub`. The administrator's key is pinned outside the profile; an unsigned profile, one
  signed by another key or one edited after signing refuses start. The profile lists the plugin
  signers it trusts (`signers`), `hostDigest` (the `plughost` image every plugin container runs)
  and, per connector, `bundle`, `digest` (the plugin executable's sha256),
  `signer`, `socket`, `uid` and `gid`.
- **Admission.** On start each bundle's manifest must verify against its signer and name the
  executable digest the profile pins (never the host's). Any failure refuses start.
- **Isolation.** Each plugin runs in its own container in the pod (named as the connector), as its
  own `uid` and `gid` (not root, not another connector's, not the gateway's), with only its own
  token mounted. `cmd/plughost` there listens on `socket`, on a volume only that container and the
  gateway's mount, and starts the plugin per stream with the hello's settings, sandboxed (Landlock)
  so it cannot write the filesystem: it cannot replace its socket or leave code for a later stream. The gateway runs as
  neither root nor a plugin's user, adds no capabilities and mounts no connector token; the
  labels file and the TLS key are in its container alone. Linux only.
- **Routing.** For each stream the gateway reads its own pod's status from the API server: the
  plugin's container must be running the pinned `plughost` image (`hostDigest`); a container
  substituted with any other image, the vendor's included, is refused. It connects to the socket, which must
  be answered by the plugin's uid and gid (`SO_PEERCRED`; a socket linked in from another plugin's
  volume is refused), the listener's process must be in exactly that container (its pid's cgroup
  path names the container id status reports; status can lag an image replacement, the cgroup
  cannot), and the container must be the same one after connecting. The pod shares one process
  namespace (`shareProcessNamespace: true`) so the gateway can see that pid; plugins then see the
  pod's process list and command lines, but not other users' environment, files or memory. Only then does it
  send the hello: the profile's settings, its marking, the executable's digest and the
  workspace's write setting. The pod's
  account needs `get` on its own pod, which the gateway names from `POD_NAME` and `POD_NAMESPACE`
  (Downward API `metadata.name` and `metadata.namespace`); without them it does not start.
- **Control requests.** Every request reaches the plugin under an id of the gateway's own, never
  the caller's. The requests that pass without the high-water check (`initialize`, `ping`,
  `tools/list`, `notifications/initialized`) reach it as the gateway's own fixed requests, never
  with the caller's params; other notifications are not carried.
- **Marking.** The profile's `classification` is passed to the plugin, raises the label, and is
  written into every result's `_meta` whatever the plugin put there. A result whose content is not
  text framed by that banner is replaced with a refusal. Banner-framed text is the only plugin
  output that reaches the caller. An error answer gets a fixed code (-32603) and message, with the
  profile's marking in `error.data._meta`. Every other field of a plugin's answer is dropped or
  replaced by the gateway's own value (the caller's id, `jsonrpc`, the content-free answers), and
  output that answers no request (notifications, progress, server requests) is not passed on.
- **Identity.** Each stream is an HTTP upgrade (`Upgrade: badger-mcp`) on `/connectors/<name>`
  with the workspace pod's projected service-account token as a bearer. `conngw` asks the API
  server (TokenReview) for the configured audience, and the status must confirm that audience; the
  service account, in one of the configured `namespaces`, is the workspace `<namespace>/<account>`
  (DNS labels, up to 63 characters). One gateway serves every namespace listed. Only that
  workspace's pod mounts its token. The pod's own account needs `system:auth-delegator` to create
  TokenReviews.
- **Grants.** Each connector's `grants` name `<namespace>/<account>` or `<namespace>/*`; an exact
  workspace wins over its namespace. `tools` is the read allowlist (left out: every read tool in the
  signed manifest; empty: none); `writeTools` are opt-in and need `writes: true` on the connector. Any other
  workspace is refused (403). A `tools/call` outside the grant, and any method other than
  `initialize`, `ping`, `tools/list` and `tools/call`, is answered by `conngw` and never reaches
  the plugin. The plugin starts with `--enable-writes` only for a workspace whose grant has write
  tools. The answers to `initialize`, `ping` and `tools/list` are the gateway's own (`tools/list`
  is the grant, from the manifest), so nothing a plugin says passes as content-free. Every
  forwarded request is re-encoded from what was checked. Whether a tool writes is the signer's
  statement; the hard control for read-only remains the scope of the service token.
- **Declaration.** The bridge sends what its signed profile admits for the connector
  (classification, writes, flags). A mismatch with the pod's configuration, writes meaning the
  workspace's grant, is refused (409), so the managed build's own high-water check and this one use
  one marking.
- **No write down, per workspace.** The label is the join of the markings of every connector
  whose answer the workspace has received; it rises before the answer is passed on. A request
  other than `initialize`, `ping` or `tools/list` to a connector whose marking does not dominate
  the label is answered by `conngw` and never reaches the connector. A line the connector library
  would not read as one request is dropped; an id already waiting for an answer is refused.

- **Durable labels.** Each raise is appended to the labels file (`labelsFile`) and synced before
  the answer is passed on; a raise that cannot be recorded ends the stream without it, and from then on every answer that
  raises a label is held back, for every workspace, until a restart reads the file back. On start the
  pod rebuilds every label from the file. The file must be on a persistent volume. A missing file,
  a file without its header line or any unreadable record refuses start: an empty or replaced
  volume cannot pass for a pod whose workspaces have read nothing. Only a torn last record, whose
  answer was never passed on, is dropped. The pod holds an exclusive lock on the file for its whole
  life and appends only, so a second conngw on the same file refuses to start: run one replica,
  with the Recreate deployment strategy, never a rolling update that overlaps two pods. A first install creates the file with
  `conngw --init-labels <path>`; an administrator's reset replaces it with a fresh one the same way.
- **Before the upgrade.** A request that declares a body is answered 400 and its connection closed
  before anything more is read. Headers are capped at 16 KiB and the connection at 10 s for headers,
  15 s to read and 30 s to write, and at most 128 connections may be open before their upgrade; past
  that a new one is closed at once. TokenReview calls time out after 10 s. Deadlines are cleared
  only on a stream that has been authenticated and taken over.
- **Bounds.** At most `maxStreams` streams in the pod (default 64) and `maxStreamsPerWorkspace` for
  one workspace (default 8), checked before a connector starts (429). A stream with no traffic
  either way for `idleMinutes` (absent: 30; 0: never) is closed, and each write to the caller has a 30-second
  deadline. A connector that outlives its caller gets two minutes, then is stopped.
- **Node audit.** A call the plugin's seccomp filter denies leaves no audit record (it returns EPERM
  before the kernel's audit hooks run). Calls the filter allows can be audited by the node's own
  rules, and a refused open's path name is the plugin's choice. STIG-style rules carry
  `-F auid!=unset` and skip container processes when the runtime has no login uid. Where a rule
  does match the plugins' uids, the node excludes them first (`-a never,exit -F uid=<plugin uid>`),
  which is a documented deviation. The connector deploy notes give the preflight.
  A plugin can still set its process name to a number, by running its own executable again
  through `/proc/self/fd/N` (same process, same sandbox). That name reaches only records about the
  process: audit records, which the node requirement above closes, and the kernel's OOM-kill line,
  at most once per stream (the plugin dies), carrying descriptor digits (about 20 bits). This is
  an accepted per-stream residual. The planned closure is an exec-once supervisor in plughost.
- **Kernel fault log.** A plugin can restore SIGSEGV's default action and fault at an address it
  picks. Where `debug.exception-trace` is 1 (the x86-64 default), the kernel then logs that address
  and registers the plugin set, rate-limited. Some of these lines (a bad signal frame, a vsyscall
  access) do not need the process to die, so they repeat at the printk rate limit. No sandbox setting
  stops this; the node must set `debug.exception-trace=0`. The connector deploy notes give the
  preflight and the AKS route.
- **Token in output.** A plugin holds its service token, because it must call the service with it.
  An SDK connector redacts the token from what it returns; a plugin that skips the SDK could return
  it inside banner-framed text, which the gateway passes on as marked content. So `plughost` checks
  every plugin's output for the stream's token, and the first time the output
  carries the token raw, as base64 (either alphabet, padded or not, at any alignment), as hex
  (either case) or URL-escaped (escape digits in either case), it ends the stream and logs one fixed
  line. A token under 16 bytes is refused, so every form can be matched. It checks whole lines (held
  until their newline, as the gateway passes only whole lines), as written and, when the line is
  JSON, with every key and string decoded, so a split token or JSON escaping of the line hides
  nothing. Each stream gets its own copy of the token, taken when it starts: the plugin is given
  that copy (`--token-file`) and the host scrubs for the same bytes, so a Secret rotated during a
  stream changes nothing for it, and the next stream takes the new token. To cut a token off at
  once, revoke it at the issuing service or restart the connector pod. A plugin reads only its own
  stream's snapshot: the staging directory is otherwise hidden from it, so a stream opened before a
  rotation cannot read a later stream's token. A plugin frame with a repeated JSON key at any depth, or nested deeper than
  64 levels, ends the stream at both `plughost` and the gateway, so the two never read different
  values and nesting cannot exhaust memory.
  **Accepted residual:** JSON embedded inside non-JSON text (for example a text value
  `BEGIN\n{"token":"...\/..."}\nEND`, whose `\/` or `\u` escapes are not decoded), and any
  encoding a plugin invents, pass the scrub. That is unavoidable: a hostile plugin can encrypt or
  transform its own token, so no output filter is a boundary. The scrub catches accidents and lazy
  copying. The boundary is the vendor's signature and the administrator's review before pinning the
  digest, and the token's scope limits the damage: give each connector its own read-only token,
  scoped to what its grants serve, never a personal admin token.
- **Logs.** Only fixed reasons, the reviewed workspace and configured names are logged, never text
  the caller sent.

Limits: a reset is an administrator replacing the file, not a signed record as the broker uses for
a device's high-water. One label per workspace is coarser than the managed build's per-session
label, which still applies inside the workspace. A shell command in the workspace can reach the pod
as the workspace does; it gets the same checks, which is why they run here and not only in the
workspace. The pod's connector settings come from its own signed profile, checked against each
caller's declaration, not from the workspace's signed envelope. "Teams" are namespaces; a finer
team grant would need group claims.

### Workspace controllers: ceilings, copies and send-up

When a workspace controller creates the hosted workspaces, a workspace's level changes only with the
user's say-so, and reading higher content happens in a copy of the workspace, never in place.

- **Registration.** With `floor` (a banner) and `admins` (`<namespace>/<account>` identities outside
  the workspace namespaces) in the profile, the admin API is on. It is authorized by TokenReview of
  the caller's projected token against `admins`; workspaces cannot call it.
  `POST /admin/register {"workspace","owner"}` records the workspace's owner (the controller's
  opaque id for a person) and its **ceiling**: the floor joined with what it has already read.
  `GET /admin/workspace?workspace=` reports label, ceiling and owner. Owners and ceilings are records
  in the labels file, written once and checked on load like labels.
- **Ceiling.** A registered workspace never rises above its ceiling. A request to a connector whose
  marking, joined with the label, the ceiling does not dominate is answered by `conngw` ("continue in
  a copy of this workspace at ...") and never reaches the connector; the label does not move. An
  answer that would lift it anyway ends the stream without being passed on. The managed build
  reads the same ceiling from `BADGER_RAISE_CEILING` and turns the refusal into the user's warning
  ("This read is X. Continue in a X copy of this workspace, or cancel."). The refused call is the
  raise record, `GET /managed/raise` on `serve`'s listener (the same token as every request):
  `{"raise":{"sessionID","server","tool","level"}}`, `?session=<id>` for one session's, and a JSON 404
  when none is pending. No other `/managed` path exists, and none reaches the server or the web UI.
  Workspaces nobody registered behave as before.
- **Copies.** `POST /admin/fork {"parent","child","owner","ceiling"}` seeds a workspace nothing has
  used (no label, no registration) at the parent's label, for the parent's owner, with a ceiling
  that must dominate the parent's label; it is durable before the controller creates the copy's
  pod. The parent's label and ceiling do not change, and nothing the copy reads reaches it.
- **Send-up.** With `inboxDir` (on the labels volume) a workspace may send a file to another
  workspace of the same owner whose label dominates its own: `POST /sendup {"to","name","data"}`
  with its own token. The answer is `delivered` or `refused`, nothing else. The receiver lists, reads
  and acknowledges its inbox (`GET /inbox`, `GET` / `DELETE /inbox/<id>`); each item records its
  sender and the sender's label at the time. No workspace can read another's inbox, and nothing is
  sent down or sideways. Items are written whole and synced before `delivered`. A sender may send 64
  items in 24 hours; nothing the receiver does changes a sender's answers, so the first store failure
  (a full volume) stops send-up until a restart. Size the volume for the senders' quotas. An item a
  receiver may no longer read (after an administrator lowers its label) is hidden from list, get and
  delete alike. `cmd/sendup` is the workspace's client; its listing shows any field holding a control
  or format character escaped.

## Testing

- Library unit tests (this change): base URL refusals, path and redirect off-base refused,
  http refused without the test flag, header schemes, per-request token reads, malformed token
  files, response cap, status mapping, and a sentinel token that never appears in errors, tool
  output or logs even when the service echoes it; write tools hidden with writes off; output
  wrapper, cap and tag defusing; strict arguments; a full stdio JSON-RPC session.
- Connectors: table tests per tool against `fakeserver` with fixtures recorded from a real
  self-managed instance and scrubbed to `example.invalid` hosts and made-up names. Assert both
  the text the model sees and the exact requests sent (method, path, query, body, header).
- A small contract kit per service: the same fixtures replayed against a live disposable
  instance in an opt-in job, so fixture drift shows up.
- Admission (later): signed profile with one connector loads it and its tools appear behind the
  permission rules; tampered entry, digest mismatch, and user or repo config entries are refused
  before init; `mcp add` and plugin install still refused; no runtime download.
- The plugin-host and gateway tests (`internal/launch`, `cmd/conngw`) need an executable tmpfs for
  the host's staging directory: `/dev/shm`, `$XDG_RUNTIME_DIR`, the system temp directory (`/tmp`),
  or the directory `LAUNCH_TEST_TMPFS` names. Without one they fail and say so. In Docker, run with
  `--tmpfs /dev/shm:exec` or `--tmpfs /tmp:exec` (Docker's default `/dev/shm` is noexec).

## Changes in the series

1. This change: design, shared library, reference connector.
2. Classification markings (parser, token tables, banner, `_meta`, `Dominates`, `Join`).
3. Jira, Confluence and GitLab connectors, one change each, stacked on 1.
4. Admission through the signed profile in `managed.ts`, worker egress allowance, flow checks.
