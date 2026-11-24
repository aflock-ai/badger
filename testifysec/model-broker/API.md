# Admin API

For an admin page that shows and edits the pipeline policy. All endpoints are on the **admin
listener** under `/admin/v1/`. The edge routes people's admin requests there (for example
`/broker/admin/v1/...` at the edge becomes `/admin/v1/...` at the broker). The edge, internal and
provision listeners have no admin endpoints, and the admin listener refuses model-traffic
credentials (`403 pipeline_forbidden` for a pipeline payload, `403 model_credential_forbidden` for
the principal header or any `Authorization` header).

Model: `formal/BadgerBroker/PolicyAdmin.lean`. Theorem names below are the properties each rule
implements.

## Authentication

The broker does not authenticate people itself. It reads three headers the edge sets after it has
verified the person's sign-in and stripped any copy the caller sent (names are operator config):

| Header (example name) | Meaning |
|---|---|
| `x-broker-user-id` | stable identity of the person (an immutable id, not an email); recorded as the author or approver |
| `x-broker-user` | display name for the audit log (optional) |
| `x-broker-role` | the person's role as the edge computed it |

Every endpoint, reads included, requires `x-broker-role` to be one of `admin_roles`.

A request that carries the pipeline payload header is refused with `403 pipeline_forbidden` on every
endpoint, whatever identity or role headers ride along (`payload_makes_pipeline`,
`pipeline_cannot_administer`). A pipeline cannot reach these endpoints through the edge either: the
edge admits bearer requests only to `POST` the chat path.

An `Origin` header, if present, must be in `allowed_origins`. Writes must send
`Content-Type: application/json`, which a cross-site form cannot. A request other than `GET` or
`HEAD` that carries `Sec-Fetch-Site` with any value but `same-origin` (a browser acting for another
site) is refused with `403 cross_site`; clients that are not browsers send no such header.

## Errors

Every error is JSON:

```json
{"error": {"code": "stale_version", "message": "the policy changed; reload and edit again", "current_version": 8}}
```

| Status | `code` | When |
|---|---|---|
| 400 | `bad_json` | body is not the expected JSON, or names a field the policy does not have (for example `issuer`) |
| 400 | `bad_if_match` | `If-Match` is not one version number |
| 401 | `no_identity` | identity or role header missing or repeated |
| 403 | `pipeline_forbidden` | the request carries a pipeline payload |
| 403 | `not_admin` | role is not an admin role |
| 403 | `bad_origin` | `Origin` not allowed |
| 403 | `same_author` | approving your own proposal |
| 404 | `not_found` | no such version, or no such open proposal |
| 412 | `stale_version` | `If-Match` (or a proposal's base) is not the current version; `current_version` says which is |
| 413 | `too_large` | body over 256 KiB |
| 415 | `json_required` | write without `Content-Type: application/json` |
| 422 | `invalid_policy` | the policy breaks a rule; `details` lists each problem |
| 428 | `if_match_required` | write without `If-Match` |
| 503 | `store_unavailable` | the version store failed its integrity checks or a write failed; nothing was saved |

Refusals (401/403) are written to the audit log as `refused`.

## Types

**Entry** (as written):

```json
{"id": "release-bot-spike", "kind": "named_branch", "project_path": "platform/release-bot",
 "ref": "spike/summaries", "sources": ["web"], "models": ["model-a"],
 "trigger_users": ["alice", "bob"], "expires_at": "2027-01-29T00:00:00Z", "enabled": true}
```

| Field | Rule |
|---|---|
| `id` | `^[a-z0-9][a-z0-9-]{0,62}$`, unique |
| `kind` | `protected_branch` (token must say `ref_protected: "true"`) or `named_branch` (exactly this unprotected branch, `ref_protected: "false"`) |
| `project_path` | `group/project` (nested groups allowed), no `@` |
| `ref` | branch name, `[A-Za-z0-9._/-]`, no `..`, no `@` |
| `sources` | non-empty subset of the operator's `sources` |
| `models` | non-empty subset of routed models |
| `trigger_users` | CI usernames. Empty means anyone for `protected_branch`; required for `named_branch` |
| `expires_at` | RFC 3339 or `null`. Required for `named_branch`, at most `max_named_branch_ttl_seconds` after the write |
| `minted_before` | RFC 3339 or `null`: admit only tokens whose `iat` is earlier |
| `enabled` | `false` keeps the entry on file without admitting anything |

At most one entry per (`project_path`, `ref`) and one `protected_branch` entry per project.

**Entry** (as read) adds `"principal"`: `ci:<project_path>` or `ci:<project_path>@<ref>`.

**Version**: `version`, `entries`, `author`, `author_name`, `approver` (two-person rule only),
`comment`, `created`, `sha256` (of the entries), `active`.

## Endpoints

### `GET /admin/v1/config`

What the operator configured, so the page can build its forms. Read-only; no secrets, keys or
upstream addresses.

```json
{"issuers": [{"id": "gitlab-1", "issuer": "https://gitlab.example.com", "audience": "badger-broker",
   "type": "gitlab", "primary": true, "max_token_lifetime_seconds": 3600,
   "config_ref_template": "gitlab.example.com/{project_path}//.gitlab-ci.yml@refs/heads/{ref}"}],
 "models": ["model-a", "model-b"], "sources": ["web", "push", "schedule"], "admin_roles": ["superAdmin"],
 "two_person_rule": true, "max_named_branch_ttl_seconds": 1209600,
 "kinds": ["protected_branch", "named_branch"]}
```

### `GET /admin/v1/policy`

The active version, with `ETag: "<version>"`. With no active policy (empty store, or a stored
version the current operator config no longer allows), `{"version": N, "entries": [], "active": false}`
where `N` is the latest stored version; every pipeline is denied until a valid version is written.

### `PUT /admin/v1/policy`

Replace the whole entry list. Headers: `If-Match: "<version you loaded>"` (use `"0"` for an empty
store), `Content-Type: application/json`. Body:

```json
{"entries": [ ... ], "comment": "why (optional, at most 1000 bytes)"}
```

| Result | Status | Body |
|---|---|---|
| saved | 201 | the new version, `ETag: "<n>"` |
| needs a second admin | 202 | `{"proposal": {...}, "message": "..."}` |
| based on an old version | 412 | `stale_version` with `current_version` |
| invalid | 422 | `invalid_policy` with `details` |

Concurrency: the broker compares `If-Match` with the current version under one lock, so of two
admins editing version 7 the first save becomes 8 and the second gets 412 (`stale_put_refused`). The
page should then reload, show what changed, and let the admin reapply their edit.

A saved version is active for the next request; there is no restart. Its diff (entries removed and
added) and author go to the audit log (`change_is_admin_versioned_audited`). Nothing in the body can
change operator settings: the policy has no such fields and unknown fields are refused
(`operator_immutable`).

### `GET /admin/v1/policy/versions`

`{"versions": [{"version": 1, "author": "...", "approver": "", "created": "...", "sha256": "...", "entries": 4}, ...]}`,
oldest first.

### `GET /admin/v1/policy/versions/{n}`

One stored version. Versions are never edited or deleted (`versions_append_only`). To roll back,
`PUT` an old version's entries as a new version.

### `GET /admin/v1/proposals`

Open proposals: `{"proposals": [{"id": 3, "base_version": 7, "entries": [...], "author": "...",
"author_name": "...", "comment": "...", "created": "...", "open": true}]}`.

### `POST /admin/v1/proposals/{id}/approve`

Approve another admin's proposal (`two_person_rule`). No body. Results: 201 with the new version
(its `author` is the proposer, its `approver` you); 403 `same_author`; 404 if not open; 412 if the
policy changed since the proposal was made (the proposer must propose again); 422 if it is no longer
valid (for example its expiry is now past the TTL).

### `POST /admin/v1/proposals/{id}/reject`

Close a proposal without applying it. Any admin, including its author. 200 `{"rejected": id}`.

### `GET /admin/v1/audit?after=<seq>&limit=<n>`

Audit records with `seq > after`, oldest first, at most `limit` (default 100, max 500). Page by
passing the last `seq` you saw.

```json
{"records": [
 {"seq": 41, "time": "...", "prev": "<sha256 of record 40>", "kind": "write", "actor": "<id>",
  "actor_name": "...", "policy_version": 8, "removed": [...], "added": [...], "comment": "..."},
 {"seq": 42, "time": "...", "prev": "...", "kind": "decision", "decision": "deny", "reason": "no_match",
  "policy_version": 8, "issuer": "gitlab-1", "project_path": "platform/other", "ref": "main", "pipeline_source": "web",
  "user_login": "alice"}
]}
```

Kinds: `write`, `propose`, `approve`, `reject`, `refused`, `decision` (admitted pipeline calls
only; denials go to the broker's log), `token_issue`, `token_revoke`. Decision reasons in the log: `no_policy`,
`bad_claims`, `wrong_issuer`, `wrong_audience`, `token_expired`, `token_lifetime`, `wrong_operation`, `no_match`,
`model_missing`, `model_not_allowed`.

A `no_match` line also carries `detail`: the check that failed for the closest entry of that issuer
and project (`issuer` when the issuer has no entries, `project` when none names the project,
otherwise `disabled`, `expired`, `ref`, `ref_type`, `protected`, `config_ref`, `source`,
`minted_before` or `trigger_user`), with the token's `ref_type` and `source`. The response to the
pipeline is the same for every `no_match`, so a caller learns nothing about the policy from it.
Denials stay out of the audit file so a flood of refused tokens cannot fill the volume; ship the
broker's log.

### `GET /admin/v1/usage`

Today's counts (UTC day; `since` is UTC midnight, or when the usage ledger was first opened if
that is later): `{"day": "...", "since": "...", "principals": {"ci:platform/release-bot":
{"model-a": {"requests": 3, "prompt_tokens": 900, "completion_tokens": 120}}}}`.

Each count has `cached_prompt_tokens` (the part of `prompt_tokens` the provider served from its
prompt cache) and, when the model's route sets `price_usd_per_million` (`input`, `cached_input`,
`output`), `cost_usd`: what the calls were charged at the rates in force when each ran (uncached
input, cached input and output), rounded to a millionth of a dollar. Changing a price never
rewrites past costs. No price and no charge means no `cost_usd`, never a cost of zero. The same
fields appear in `GET /v1/usage`. When the usage ledger cannot be read, this, `GET /v1/usage` and the spend in `GET
/admin/v1/quotas` answer 503 `usage_unavailable`: unknown usage is never reported as zero.

`?from=YYYY-MM-DD&to=YYYY-MM-DD` (inclusive, at most 92 days) returns past days instead:
`{"since": "...", "days": {"2026-10-19": {<principal>: {<model>: {...}}}}}`. Days with no use are
left out. A bad range is 400 `bad_range`. With a range, `kind=person|pipeline` keeps one kind of
principal (a pipeline is `ci:...`) and `model=<name>` one model; any other `kind` is 400
`bad_filter`.

### `GET /admin/v1/usage/principals?from=YYYY-MM-DD&to=YYYY-MM-DD[&kind=][&model=]`

The same range, bound, filters and errors, as rows for the console's Usage tab: one per principal,
model, pipeline owner and the CI user who started the run (`triggered_by`; both empty for a
person), with `kind`, the counts and `cost_usd` as above, and `last_used` (the last counted call):
`{"since": "...", "rows": [{"principal": "ci:group/app", "kind": "pipeline", "model": "model-a",
"owner": "alice@example.com", "triggered_by": "carol", "requests": 4, ..., "last_used": "..."}]}`.

Every counted call is appended to `<store_dir>/usage/<UTC day>.jsonl` (0600, one JSON line per
call: time, principal, model, prompt, cached prompt and completion tokens), so counts survive a restart. The
ledger is plain text for an auditor: `jq` over a day file reproduces the API's numbers. If the
directory cannot be written, the broker logs it and counts in memory only.

### `GET /v1/limits` (internal listener)

A workspace's owner's managed-agent limits, by its token alone:
`{"steps", "context", "output", "timeout_seconds"}`, each the owner's value, else the default, else
`null` (the managed build then uses its compiled value). The managed build reads it once at start
through its gateway. The broker cannot hold an agent to steps, context or timeout; it enforces
output and spend on every call.

### `GET /admin/v1/quotas`, `PUT /admin/v1/quotas`

Every limit an admin sets, as a deployment default and per principal. Monthly spend in USD at the
routes' prices (UTC month) is `default_usd` and `principals`; the rest are `defaults` and
`people`, each `{"daily_usd", "call_usd", "steps", "context", "output", "timeout_seconds"}`, any
field omitted. GET returns those with `"seeded"`, `"month": "YYYY-MM"`, `"used_usd"` and
`"today_usd"` (`{<principal>: usd}`), and `"technical"` (the largest context, output and timeout the
system can serve), with `ETag: "<version>"`. PUT takes `{"default_usd", "principals", "defaults",
"people", "comment"}` with `If-Match` (412 if someone saved first). Amounts are finite and not
negative; steps at least 1; context 1 to 262144 tokens (a 1 MiB request), output below context, and
timeout under `upstream.request_seconds`: those three are technical limits, refused with 422
`invalid_quota` naming the reason. Each write is an audit record of kind `quota` listing every
limit, with `changes` (per target and field, `old` and `new`) and `self` when an admin changed
their own limits or a pipeline whose policy entry they own. Such a write must carry a `comment`
(the reason), or it is refused with 422 `reason_required`. `seed_limits` in the config fills each default once (`seeded` names those filled); it
never overwrites a value an admin set, "no limit" included.

A principal's value for each field is its own, else the default's. `daily_usd` is checked the same
way as the monthly quota below, over the UTC day. `output` sets `max_completion_tokens` on every
call to at most that; `call_usd` lowers it further to what the cap buys at the model's output price,
and is what a running call counts at (instead of the route's `max_call_usd`). `steps`, `context`
and `timeout_seconds` are served to the managed agent, which the broker cannot hold to them.

A principal's limit is its own entry, else `default_usd`, else none. Before each model call the
broker compares this month's spend with the limit: at or over it, 429 `quota_exceeded` and the call
does not reach the model; from 80% the answer carries `X-Broker-Quota-Warning`. Every limited call
also carries `X-Broker-Quota-USD` and `X-Broker-Quota-Used-USD`. The check is before the call, so
the last call allowed can take a principal past its limit. The model request outlives a client that
disconnects (within `request_seconds`) so the usage at the end of a stream is still charged. A
successful reply with no usage is recorded with `usage_unknown`; that principal's limited calls are
then refused (503 `quota_unavailable`) for the rest of the month. Each call is written to the
ledger as pending before it goes to the model; one still pending after the longest a call can run
(`server_write_seconds` plus a minute: the broker stopped mid-call) lost its result, and that
principal's limited calls are refused the same way. A call left pending by a broker that then
restarts is released at once, as unknown spend, by the restarted broker (when `POD_NAME` names the
pod); one left by a pod that was deleted counts once its window passes. A call still running (on
another replica, or one whose result is being written again after a database error) counts at its
route's `max_call_usd`, unbounded without one: 429 `quota_exceeded` when it and this call could pass
the limit together. The check and the pending record it admits are one transaction under a lock
per principal that every replica takes, so calls admitted at once on different replicas are never
checked against the same balance. A ledger that cannot be read refuses every limited call. An unpriced model costs nothing against a quota. If the quotas document cannot be
read, every model call is refused (503 `quota_unavailable`) until it is repaired.

The admin console (`/admin/v1/ui/`, Quotas and Agent limits tabs) shows spend against each limit and
edits them.

### `GET /admin/v1/owners`, `PUT /admin/v1/owners`

Every pipeline policy entry is a non-human identity and must be owned by one of the configured
people. GET returns `{"version", "owners": {<entry id>: <person>}, "entries": [{"id", "principal",
"enabled", "owner"}], "humans": [...]}` with an `ETag`. PUT takes `{"owners", "comment"}` with
`If-Match`; each owner must be in `human_principals`; each write is an audit record of kind `owner`.

A pipeline the policy allows is still refused (403, reason `nhi_unowned` in the log) when its entry
has no owner. This check runs after the policy decision, outside the Lean model, and can only turn an
allow into a deny. An allowed decision record carries `owner`; the answer carries `X-Broker-Owner`;
the usage ledger records `owner` and `triggered_by` (the GitLab `user_login`); usage reports carry
`owners` (pipeline principal to person). An unreadable owners document refuses every pipeline.

## Page guidance

* Load `config` and `policy` together; keep the `ETag`.
* Show each entry's `principal`, and mark `named_branch` entries as admitting an unprotected
  branch, with their trigger users and expiry.
* On 202, tell the admin a second admin must approve, and list open proposals for other admins.
* On 412, reload and show the diff before letting them save again.
* Never send or display tokens; the API has none.

## Provisioning API (provision listener)

For the component that creates workspaces. Every request needs
`Authorization: Bearer <provisioning key>` (the operator's `provisioner_key_file`); network policy
must admit only that component.

### `POST /provision/v1/tokens`

Body `{"workspace": "badger-<id>", "principal": "<owner as listed in human_principals, in any case>",
"marking": "<banner>"}`. `marking` is optional: the workspace's own label, which its requests run
at (the lowest label when absent); it must be a banner the marking package reads, at or below
`ceiling_marking`. 201 `{"token": "bbt_...", "expires_at": "..."}`: store the token in a secret
mounted only into that workspace; it is never shown again. Any earlier token for the workspace stops
working. 422 `refused` if the workspace name is malformed (`^[a-z0-9][a-z0-9-]{0,62}$`), the
principal is not a listed person (a `ci:` name never is), or the marking is unreadable or above the
ceiling. 401 without the key.

### `DELETE /provision/v1/tokens/{workspace}`

204. The workspace's token stops working at once. Issue and revoke are audited (`token_issue`,
`token_revoke`, with workspace and principal, never the token).

## Device sign-in (edge and internal listeners)

Only when `device_login` is on; otherwise these paths are 404.

### `GET /device/authorize?challenge=&port=&state=&device=` (edge listener)

Exactly these four parameters, once each: `challenge` 43 base64url characters (S256 of the
verifier), `port` 1024-65535, `state` and `device` 16-128 base64url characters. 400 otherwise. 401
unless the edge set one listed person in the principal header and no pipeline payload. Returns
the consent page (HTML, `X-Frame-Options: DENY`, `frame-ancestors 'none'`).

### `POST /device/authorize?...` (edge listener)

Form body `nonce=<from the consent page>`, with `Sec-Fetch-Site: same-origin`. The nonce is single
use, five minutes, bound to the same person and parameters; 403 otherwise. 303 to
`http://127.0.0.1:<port>/callback?code=<code>&state=<state>`.

### `POST /device/token` (internal listener)

JSON `{"code": "...", "verifier": "...", "port": 49152}`. 201
`{"token": "bbt_...", "expires_at": "...", "principal": "..."}`. 400 `invalid_grant` for an unknown,
used, expired or mismatched code (any attempt consumes it). Audited as `token_issue` with actor
`device-login`.

### `DELETE /device/token` (internal listener)

`Authorization: Bearer <device token>`. 204, and the token stops working. 401 for an unknown token,
403 for a workspace token. Audited as `token_revoke` with actor `device-logout`.
