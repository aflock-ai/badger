# badger-broker

Lives in the badger repo at `testifysec/model-broker` (moved from the standalone `badger-broker`
repository with its history; `testifysec/broker` is the unrelated session broker). Run every
command below from this directory.

A small model broker that sits between an OpenAI-compatible client and the model endpoints it may
use. People reach it through an authenticating edge proxy; CI pipelines reach it with their own
OIDC job token. The broker decides which pipeline may call which model from a versioned policy
that admins change at runtime, with every change audited.

It is a single static Go binary with no dependencies outside the standard library. The decision
logic and the admin rules are specified and proved in Lean 4 (`formal/`), and a shared corpus of
668 cases ties the Lean model, a Python mirror and the Go code together.

## Why

A pipeline that wants a model usually gets a long-lived API key in a CI variable. That key outlives
the job, works from anywhere, and says nothing about which branch or person used it. CI systems
already mint a short-lived, signed token for every job (GitLab `id_tokens`, for example) that names
the project, the branch, whether it is protected, what triggered the run and who. badger-broker
lets that token be the credential:

1. The edge verifies the token's signature against keys pinned in its own config, the issuer, a
   single exact audience, expiry and a lifetime cap. It strips every identity header a caller sent
   and forwards the verified payload to the broker in a header only it sets.
2. The broker matches the payload against its policy and derives the principal from the entry that
   matched. Nothing the caller says about itself is believed.
3. Admins change the policy through an API (for an admin page) instead of a redeploy. Each change is
   a new immutable version, checked against the version it was based on.

## Four listeners

| Listener | Who can reach it (network policy) | What it serves |
|---|---|---|
| `internal` (default `:8080`) | the edge and workspaces | people, by a **per-workspace broker token** (`Authorization: Bearer bbt_...`); `/v1/chat/completions`, `/v1/models`, `/v1/usage`, `/` |
| `edge` (default `:8081`) | the edge only | pipelines, by the verified payload: `POST /v1/chat/completions`; people the edge signed in, by the principal header |
| `provision` (default `:8082`) | the provisioner only (the component that creates workspaces) | issuing and revoking workspace tokens, with the provisioning key |
| `admin` (default `:8083`) | the edge only, on its admin route | the admin API `/admin/v1/*` and anything mounted beside it (the management portal at `/admin/portal/`), for people the edge signed in with an `admin_roles` group |

The two surfaces never mix. The admin listener refuses any request carrying a model-traffic
credential (the pipeline payload, the principal header, or any `Authorization` header), and the
`edge` and `internal` listeners refuse any request carrying an admin identity header
(`admin_id`, `admin_name`, `admin_role`). An admin session is never served as a model user.

Headers are trusted only on the edge and admin listeners, and only because nothing but the edge
can reach them. The internal listener ignores every identity header: a workspace is served as the owner its
token was issued for, and never as a pipeline (it refuses any request carrying a pipeline
payload, and a token can never be issued for a `ci:` name). If your network cannot keep the edge
and provisioning listeners to their one client each, do not deploy this.

### Workspace tokens

The provisioner calls `POST /provision/v1/tokens` with `{workspace, principal}` when it creates
or wakes a workspace, stores the returned token in a secret mounted only into that workspace, and
calls `DELETE /provision/v1/tokens/{workspace}` when it stops one. Issuing again for a workspace
replaces its token at once; the old one is refused from the next request. The broker keeps only
each token's SHA-256 (the `broker.tokens` table), its owner and its expiry
(`workspace_token_ttl_hours`). The token is returned once and never logged.

### Device sign-in

For a person running Badger on their own computer, with `device_login` on. Badger opens the
browser at the edge's `/device/authorize?challenge=<S256 of a verifier>&port=<loopback port>&state=..&device=<device id>`.
The edge signs the person in with its identity provider and routes the request to the edge
listener with the principal header set, as for any signed-in person. The broker shows a consent
page naming that person; on approval it redirects the browser to
`http://127.0.0.1:<port>/callback?code=..&state=..` with a code good for 120 s. Badger posts
`{code, verifier, port}` to `/device/token` on the internal listener and gets a token for the
device. The device is named `dev-<hash of person and device id>`, so signing in again on the same
device replaces its token. `DELETE /device/token` with the device token signs it out.

Device records are marked as such in the registry: the provisioner cannot issue over or revoke
them, and device sign-in cannot replace a workspace record or another person's device
(`DeviceTokens.lean`). Codes and pending consents are in memory only; a code is consumed by any
attempt to redeem it. The edge must route `/device/authorize` like any other signed-in request,
pass `POST /device/token` through without a session, and send `Bearer bbt_...` requests to the
internal listener; network policy must then admit the edge to the internal listener too.

## Threat model

Trusted, not proved (Lean assumptions B1-B3, P1-P2, W1-W5):

* **The edge** verifies tokens correctly, strips caller-supplied copies of the payload and identity
  headers, and is the only client of the edge listener.
* **The CI system** fills claims truthfully. Only people who may push or merge to a protected branch
  can run a pipeline whose token says `ref_protected: "true"`. For a named (unprotected) branch entry
  the broker also trusts `user_login`.
* **Clocks** are roughly right; token expiry allows `clock_skew_seconds`.
* **The database.** Anyone with write access to the database outside the service (a superuser, the owner role) can rewrite history. The audit log is
  hash-chained and every version file must match its audit write record, so an edit, a deleted
  version or a planted one is detected at the next start (the broker then denies every pipeline and
  refuses admin writes). It is not prevented, and a rewrite of the whole chain is not detected on
  the volume alone: each write also logs `policy write version=... sha256=... audit_head=...` to
  stdout, so keep the broker's logs somewhere the volume's writers cannot edit.

Accepted risks, stated plainly:

* **Bearer replay.** A job token is a bearer token until it expires: the broker accepts the same
  token for every call in its lifetime and keeps no record of `jti`. That is deliberate. A CI job
  gets one token and an agent in it makes many model calls, so a one-use `jti` would refuse the
  job's own second call, and a thief who holds the token can use it first anyway. A replay cache
  would also have to be shared by every replica and survive restarts to mean anything. What bounds
  a stolen token instead: its audience is this broker only, its lifetime is capped (the edge's
  `max_lifetime`, and `max_token_lifetime_seconds` per issuer), it is decided against the entry for
  its own project and ref, and its calls count against that entry's quota and show in usage under
  the owner. Keep lifetimes short, never print tokens, and grant one model per entry where you can.
* **Unprotected branches.** A named-branch entry admits a branch anyone with push access can change.
  The trigger-user list limits who may *run* it, not who may *write* the code it runs. That is why
  such entries require trigger users and an expiry, and by default a second admin (below).
* **Project path reuse.** Entries bind to `project_path`. A project deleted and recreated at the same
  path inherits its entries.

## Policy

```json
{"entries": [
  {"id": "release-bot", "kind": "protected_branch", "project_path": "platform/release-bot", "ref": "main",
   "sources": ["schedule", "web"], "models": ["model-a"], "trigger_users": [], "expires_at": null, "enabled": true},
  {"id": "release-bot-spike", "kind": "named_branch", "project_path": "platform/release-bot",
   "ref": "spike/summaries", "sources": ["web"], "models": ["model-a"], "trigger_users": ["alice", "bob"],
   "expires_at": "2027-01-29T00:00:00Z", "enabled": true}
]}
```

Entries match a **subject**, not raw claims. Each trusted issuer maps its own claims to the same
fields (see "Issuers" below): `project`, `ref`, `ref_type`, `protected`, `source`, `triggered_by`,
`config_ref`. For GitLab these are `project_path`, `ref`, `ref_type`, `ref_protected`,
`pipeline_source`, `user_login` and `ci_config_ref_uri`.

An entry matches a token when it is enabled and unexpired (`expires_at`, by the broker's clock),
the token is from the entry's `issuer` (an issuer id; omitted means the primary issuer), the token
was minted before `minted_before` if the entry sets one (an `iat` bound, for edges that cannot see
the request time), and the subject's `project` and `ref` equal the entry's `project_path` and `ref`,
`ref_type` is `branch`, `config_ref` is the project's own CI file on that branch (from the issuer's
`config_ref_template`, when the issuer maps one), `source` is in `sources`, `triggered_by` is in
`trigger_users` when the entry lists any, and `protected` is the string `"true"` for
`protected_branch` and `"false"` for `named_branch` (if the branch becomes protected, replace the
entry with a protected one). The principal is `ci:<project_path>` for a protected-branch entry and
`ci:<project_path>@<ref>` for a named one; an entry of a non-primary issuer is qualified,
`ci:<issuer id>:<project_path>`, so the same project under two issuers is two identities. Usage,
quota and audit are kept per principal.

A policy is refused unless: every model is routed and every source allowed by the operator; a
`named_branch` entry lists trigger users and expires within `max_named_branch_ttl_hours` of the
write; every entry names a configured issuer; ids, principals and (issuer, project, branch) triples
are unique, so at most one entry ever matches a token.

A request is denied, and the denial logged with its reason (to stdout only, so a flood of refused
tokens cannot fill the volume; admitted requests go to the audit log too), when the payload is missing or
unparseable, the payload's issuer is not the one whose header carried it, a mapped claim is missing
or not a string, the audience is wrong, the token has expired or lives longer than its issuer
allows, the operation is not a chat
completion, no entry matches, the request names no model, or the model is not on the entry. There
is no default principal.

## Changing the policy

See [API.md](API.md). Every write needs `If-Match` with the version it was based on; a write against
an older version is refused with 412. Each accepted write is a new immutable file, its diff goes to
the audit log with the author, and the next request uses it. No restart.

**Two-person rule** (`two_person_rule`, default on): a change that adds an enabled `named_branch`
entry is held as a proposal until a different admin approves it. Removing or disabling access never
needs a second person. Set it to `false` to let one admin do everything.

**Seed.** On first start, with an empty store, the broker writes `seed_policy_file` as version 1
(author `operator:seed`). The seed is the operator's authority and skips the two-person rule; review
it where you review the rest of the deployment. A non-empty store ignores the seed.

## Configuration

`badger-broker -config /etc/badger-broker/config.json`; see [examples/config.json](examples/config.json).
Unknown fields are refused. Everything in this file is operator-only: the admin API cannot change
any of it.

| Field | Meaning |
|---|---|
| `listen.internal`, `listen.edge`, `listen.provision`, `listen.admin` | listen addresses; must differ |
| `provisioner_key_file`, `workspace_token_ttl_hours` | the provisioning key (re-read on every request) and each workspace token's lifetime, 1-744 h |
| `device_login`, `device_token_ttl_hours`, `max_device_tokens` | device sign-in (below); off by default. Token lifetime 1-24 h (default 8), live device tokens per person 1-50 (default 5) |
| `admin_ui.brand`, `admin_ui.nav` | display only: the admin console header's product name (default "Model broker") and `{label, href}` links to sibling admin pages; an href must be a same-origin path |
| `issuers[]` | the OIDC issuers whose workload tokens are accepted; see "Issuers" |
| `clock_skew_seconds` | allowance on token `exp`, 0-300 |
| `sources` | pipeline sources an entry may list (e.g. `web`, `push`, `schedule`) |
| `headers.*` | header names: `principal` (people, edge listener), `admin_id`, `admin_name`, `admin_role` (set by the edge for people on the edge listener). They and every issuer's `claims_header` must differ |
| `human_principals` | people the broker serves (by token or edge header); none may start with `ci:`. Matched ignoring ASCII case (a UPN is case-insensitive), and what the broker stores uses the spelling listed here; two entries that differ only in case are refused |
| `admin_roles` | values of `headers.admin_role` that may read and write the policy |
| `two_person_rule` | see above; default `true` |
| `max_named_branch_ttl_hours` | longest life of a named-branch entry from the time it is written |
| `allowed_origins` | browser origins accepted on people's requests and the admin API; pipeline requests must carry none |
| `database` | `dsn_file` (the service role's connection string, a `postgres://` URL, in a mounted secret; to any host but loopback it must be authenticated TLS, `sslmode=verify-full` with `sslrootcert=<CA file>` (or `verify-ca`), and anything else stops the service at start; only `sslmode`, `sslrootcert`, `sslcert`, `sslkey`, `sslsni`, `connect_timeout` and `application_name` are accepted as parameters), `owner_dsn_file` (the owner role's; when set, migrations run at start), `service_role` (granted in migrations). All state lives here: see "State" below |
| `ceiling_marking` | the deployment's accreditation ceiling, a banner the marking package parses; admin, provisioner and pipeline transactions run at it |
| `import_state_dir` | optional: a state directory from before the database, imported once into an empty database (see "State"); needs `portal.import_data_dir`, or `portal.import: "none"`, when the portal is configured |
| `seed_policy_file` | version 1 for an empty store |
| `upstream` | `response_header_seconds` (first byte from the model, default 180), `request_seconds` (whole call, default 240), `server_write_seconds` (listener write deadline, default 250); must satisfy header <= request < write. Reasoning models can think for minutes; a 30 s header timeout turned slow answers into 502s. The edge's route timeout must exceed `request_seconds` |
| `seed_limits` | optional: the first deployment defaults for the limits admins edit in the admin console, `{"default_usd", "defaults": {"daily_usd", "call_usd", "steps", "context", "output", "timeout_seconds"}}`. Each field is applied once, when the broker first sees it, and never over an admin's value (API.md, quotas) |
| `routes[]` | `model`, `upstream_url`, `auth_header` (`api-key`, `Ocp-Apim-Subscription-Key` or `Authorization`), `key_file` (re-read on every request, so rotation needs no restart), `api_version`, `reasoning_map`, `no_reasoning_with_tools`, `price_usd_per_million`, `max_call_usd` (the most one call can cost: a call still running counts at it against a quota; without it a limited principal's next call is refused while another is running) |

### Issuers

Each entry of `issuers[]` is one OIDC issuer (a GitLab instance, GitHub Actions, a Kubernetes
cluster's service-account issuer, any workload issuer that signs JWTs). The edge verifies the
signature with that issuer's pinned keys and forwards the verified payload in that issuer's own
header; the broker decides a payload only as the issuer bound to the header it arrived in.

| Field | Meaning |
|---|---|
| `id` | short name, `[a-z0-9-]`, up to 32; policy entries name it in `issuer` |
| `issuer` | the exact `iss`; unique |
| `audience` | the single `aud` accepted; a list-valued `aud` is refused |
| `claims_header` | the header the edge's provider for this issuer forwards the payload in (base64url JSON); unique |
| `max_token_lifetime_seconds` | `exp - iat` cap, 1-86400 (0 allowed for `gitlab`: the edge enforces it) |
| `type` | `gitlab` (built-in mapping) or `generic` (`mapping` below) |
| `primary` | at most one issuer; entries without `issuer` are its, with unqualified principals |
| `mapping` | `generic` only: subject field to `{"claim": "name"}`, `{"claim": ["outer", "inner"]}` or `{"const": "value"}`. `project`, `ref`, `ref_type`, `protected` and `source` are required; `triggered_by`, `config_ref` and `sub` optional. A mapped claim that is absent or not a string refuses the token |
| `require` | claims every token must carry with exactly this string value (e.g. `repository_owner`) |
| `ref_prefix` | stripped from the mapped ref and required (GitHub: `refs/heads/`) |
| `config_ref_template` | `{project_path}` then `{ref}`, once each; required exactly when `config_ref` is mapped |

A constant `protected` is the operator's assertion, not the issuer's: use it only where the
issuer itself restricts who can obtain the token (for example with `require`).

Why files on a volume and not a database or a ConfigMap: the broker needs no Kubernetes API
credentials and no extra service, writes are rare, and an append-only directory is easy to back up
and inspect. The cost is one writer; the broker is a single replica anyway.

## The edge contract

Any proxy that can verify a JWT against local keys and forward the payload works. With Envoy, one
`jwt_authn` provider per issuer, each with `issuer` set (so a key of one issuer never verifies a
token naming another), its own pinned key set and its own `forward_payload_header`; bearer requests
`requires_any` of them:

```yaml
# jwt_authn provider for pipelines
issuer: https://gitlab.example.com
audiences: [badger-broker]
local_jwks: {filename: /etc/pipeline-jwks/jwks.json}
from_headers: [{name: authorization, value_prefix: "Bearer "}]
forward: false
require_expiration: true
max_lifetime: 3600s
forward_payload_header: x-broker-ci-claims   # base64url, no padding
payload_in_metadata: pipeline_jwt_payload
```

Then: strip every issuer's claims header and every identity header from callers before `jwt_authn` runs;
require the `aud` claim to be the single string (an RBAC metadata matcher does this, since
`jwt_authn` accepts a list containing it); allow bearer requests only to `POST` the chat path with
no `Origin`; route them to the edge listener. Route people's admin requests (`/admin/`) to the
admin listener with `admin_id` (the IdP subject), `admin_name` and `admin_role` (the IdP group)
set from the verified sign-in, strip `Authorization` on that route, and set the admin headers on
no other route.

## Building and testing

```sh
go test -race ./...                 # Go
python3 formal/gen_corpus.py --check  # corpus and Corpus.lean are current
(cd formal && lake build)           # Lean 4.34.1 (elan); proves every theorem and every corpus case
```

The database-backed tests need Postgres. Point `BADGER_TEST_PG` at a scratch server you can throw away
(a superuser connection string; the tests create and drop their own roles and databases):

```sh
BADGER_TEST_PG='postgres://postgres:<password>@127.0.0.1:5432/postgres?sslmode=disable' go test -race ./...
```

Without it those tests are skipped, each with the message `BADGER_TEST_PG not set: ...`
(`go test -v` lists them). Such a run has not tested the database: run the suite against Postgres
before relying on it. The test roles log in without a password, so the scratch server must trust
local connections and be reachable by nothing else.

This directory is the broker library. The service binary, `badger-broker`, is built from
`../portal/cmd/badger-broker`: the broker and the management portal (mounted on the admin
listener at `/admin/portal/`) in one process and one image:

```sh
cd .. && docker build -f portal/cmd/badger-broker/Dockerfile.gomod -t <registry>/badger-gomod:<commit> .   # needs network; push it, note the digest
docker build -f portal/cmd/badger-broker/Dockerfile --build-arg GOMOD_IMAGE=<registry>/badger-gomod@sha256:<digest> -t badger-broker .   # no network
```

The image build reaches no network. Its third-party modules come from a module-cache image built
from `portal/cmd/badger-broker/Dockerfile.gomod` where network is allowed and pinned by digest
where images are built (`--build-arg GOMOD_IMAGE=...@sha256:...`; there is no default). The build
runs `go mod verify` against this repository's go.sum files before compiling, so a missing or
altered module fails it whatever the cache image holds.

## Formal model

| File | What it proves |
|---|---|
| `BrokerPolicy.lean`, `BrokerPolicyTheorems.lean` | soundness for both entry kinds (`allow_sound`, `protected_requires_protected_ref`, `named_requires_trigger_user_and_expiry`), distinct principals (`distinct_principals`, `kinds_distinct`, `at_most_one_match`), least privilege (`allow_least_privilege`, `edge_served_least_privilege`), fail closed (`no_policy_denies`, `missing_payload_denies`, `expired_token_denies`, `wrong_issuer_denies`, `wrong_audience_denies`, `not_chat_denies`, `no_match_denies`, `unlisted_project_denies`, `disabled_entry_inert`, `expired_entry_inert`, `unlisted_trigger_user_inert`, `unprotected_ref_inert_for_protected`, `protected_ref_inert_for_named`, `foreign_config_inert`, `tag_inert`, `source_not_listed_inert`), no header principal and no default (`edge_ignores_principal_header`, `internal_never_pipeline`, `served_principal_listed`, `render_ciForm`), `user_login_irrelevant_without_triggers` |
| `WorkspaceTokens.lean` | `workspace_served_as_owner`, `workspace_never_ci`, `issue_refuses_ci`, `rotate_denies_old`, `revoke_denies`, `expired_token_refused`, `unauthorized_provision_noop`, `provision_inv` |
| `PolicyAdmin.lean` | `operator_immutable`, `versions_append_only`, `change_is_admin_versioned_audited`, `only_admin_changes_policy`, `pipeline_cannot_administer`, `payload_makes_pipeline`, `stale_put_refused`, `two_person_rule` |
| `Corpus.lean` (generated) | each of the 668 corpus cases and 12 validity checks, `by decide` |

The proofs cover the model. That the Go code implements it is shown by tests, each citing the
theorem it exercises, and by the shared corpus.

## Open decisions

* Two-person rule on or off (default on).
* Whether admin reads should need a lower role than writes (today one role list covers both).
* Audit retention: `audit.jsonl` grows without bound; ship it off the volume and rotate.

## License

MIT, as the rest of the badger repo. See [LICENSE](LICENSE).

## State

Everything the service keeps is in one Postgres database, reached as two roles: an owner that
runs the migrations (`pgdb.Migrate`: numbered, forward-only, under an advisory lock) and owns every
object, and a service role with grants only, no superuser and no `BYPASSRLS`. At start the service checks its connection is exactly `database.service_role` (the session's own role, not only the current one; and a connection string may carry only `sslmode`, `sslrootcert`, `sslcert`, `sslkey`, `sslsni`, `connect_timeout` and `application_name`, with `PGOPTIONS` unset, since the driver sends any other parameter to the server as a setting at connect and a privileged login could take on the service role that way), not a superuser, not a role that bypasses row-level security, not able to create roles, without the replication attribute, the owner of no object in the database (nor of the database), and not a member of any other role (it holds its grants directly, so `SET ROLE` can give it nothing more), and refuses to start otherwise. The broker's tables
are in `schema.sql`, the portal's in `../portal/internal/store/schema.sql`; each table says why it
is marked or not. Marked tables (the audit logs, signed profile versions) carry the canonical
banner and its lattice form (`badger.label`); row-level security, forced on the owner too, lets a
transaction read only rows its session label dominates and insert only at exactly that label, and
nothing at all without a label. The service sets the label per transaction (`SET LOCAL
badger.label`) from the caller: the deployment's ceiling for admins, the provisioner and
pipelines, the workspace's own label for a workspace token, the lowest for people the edge signs
in. Dominance in SQL (`badger.dominates`) is checked against the marking package on every pair of
the contract vectors. An unreachable database fails closed: no pipeline decision, no workspace
token, no limited call, no admin write.

`import_state_dir` carries a file-backed broker's state over once: policy versions, the audit log
(each record keeps its bytes, so the chain continues), open proposals, owners, quotas, tokens and
the usage ledger. A call that was pending when the old broker stopped is imported as finished with
unknown usage. The import runs in one transaction and refuses, leaving the database untouched, on
any of: a path that is not a directory holding broker state, a state directory it cannot list, a
file it does not know (a leftover temporary file included), a broken chain, an unreadable ledger
line, or a database that already holds state of any kind. It logs what it copied
(`versions=... audit=... proposals=... documents=... tokens=... usage_calls=... usage_opened=...`) for the operator
to check against the source. The portal's data directory moves with it: `portal.import_data_dir`
(required whenever `import_state_dir` is set and the portal is configured, unless `portal.import: "none"`) imports profiles,
assignments, the portal audit log, users, role requests and the bootstrap markers under the same
rules, so a bootstrap subject retired before the move stays retired; a data directory with no records, or with signed profiles but no audit log, is refused. A version written from a proposal closes it, as the file-backed store's replay did, so a log whose broker stopped before appending the approve record imports. `portal.data_dir` is refused
with a message saying so.

A deployment whose portal never kept data in files has nothing to import for it, and an empty
directory would be refused (and must not pass for one). It says so instead with `portal.import:
"none"` (the only value, never with `portal.import_data_dir`): the broker's state is imported and
the portal's import is recorded as `none (declared by config)` in `portal.meta`, once, on a database
whose portal tables are empty. With `import_state_dir` set and neither option, the service still
refuses to start. A data directory offered after a `none` record is refused, not imported on top.
To import one anyway, while the portal tables are still empty, the database owner removes that
record and the service is restarted with `portal.import_data_dir`:

```sql
DELETE FROM portal.meta WHERE key = 'imported_from' AND value = 'none (declared by config)';
```

Once the portal holds state of its own, an import is refused whatever the record says: nothing is
ever merged.
