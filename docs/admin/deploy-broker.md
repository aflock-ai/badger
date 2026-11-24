---
title: Deploy badger-broker
description: Build and run badger-broker, the one service that holds the model routes, decides which pipeline may call which model, and serves the admin API and the management portal.
sidebarLabel: Deploy badger-broker
sidebarPosition: 10
---

# Deploy badger-broker

`badger-broker` is one Go binary and one image. It holds the model routes and their keys, decides
model access for people, workspaces and pipelines, keeps usage, quotas and the audit log, and serves
the admin API and the management portal. It sits behind an authenticating edge proxy that you run.

The broker and the portal keep all their state in one Postgres database (below, "State").

## State

Everything the broker and the portal keep is in one Postgres database, reached as two roles
(`testifysec/model-broker/README.md`, "State"):

- `database.dsn_file` holds the service role's connection string. That role has grants only: the
  service refuses to start if it is a superuser, bypasses row-level security, can create roles,
  owns any object or is a member of another role.
- `database.owner_dsn_file`, when set, holds the owner role's connection string, and the service
  runs the migrations with it: numbered, forward-only, under an advisory lock.
- `database.service_role` names the service role the connection must be.

Marked tables (the audit logs, signed profile versions) are protected by row-level security on the
session's label. An unreachable database fails closed: no pipeline decision, no workspace token, no
limited call and no admin write.

Moving from a file-backed broker is a one-time import: `import_state_dir` names the old broker state
directory and `portal.import_data_dir` the old portal data directory (or `portal.import: "none"` if
the portal never kept files). The import runs in one transaction and refuses, leaving the database
untouched, on anything it does not recognise or on a database that already holds state; it logs what
it copied. `portal.data_dir` is refused. Every key is in the
[configuration reference](../reference/config.md).

## Build the image

From `testifysec/`, with no module download (the Dockerfile pins both base images by digest):

```sh
docker build -f portal/cmd/badger-broker/Dockerfile -t badger-broker .
```

The image runs `/badger-broker -config /etc/badger-broker/config.json` as user 65532.

## Listeners and the edge

| Listener | Default | Only this client may reach it | Serves |
|---|---|---|---|
| `internal` | `:8080` | the edge and workspaces | people and workspaces by broker token: `/v1/chat/completions`, `/v1/models`, `/v1/usage`, device token exchange |
| `edge` | `:8081` | the edge | pipelines by the verified job token payload, and people the edge signed in |
| `provision` | `:8082` | the provisioner (what creates workspaces) | issuing and revoking workspace tokens |
| `admin` | `:8083` | the edge, on its admin route | `/admin/v1/*` (policy, usage, quotas, owners) and the portal at `/admin/portal/` |

The broker trusts identity headers only on `edge` and `admin`, and only because nothing but the edge
can reach them. Enforce that with network policy. If your network cannot keep the `edge` and
`provision` listeners to their one client each, do not deploy the broker.

The edge must:

- Strip every identity header and every issuer's claims header from callers before it verifies
  anything.
- Verify pipeline job tokens with one JWT provider per issuer, each with its own pinned keys, and
  forward the verified payload in that issuer's `claims_header`. See
  [add a pipeline issuer](identity-issuers.md).
- Allow pipeline job tokens (bearer JWTs from a trusted issuer) only to `POST` the chat path, with
  no `Origin`, routed to `edge`. Send `Bearer bbt_...` broker tokens (workspaces and devices) to
  `internal` instead, which is why the edge is also a client of `internal`.
- With `device_login` on, route `/device/authorize` like any signed-in request and pass
  `POST /device/token` through to `internal` without a session.
- Route `/admin/` to `admin` with `admin_id` (the IdP subject), `admin_name` and `admin_role` (the
  IdP group) set from the verified sign-in, strip `Authorization` there, and set those headers on
  no other route.
- Allow a route timeout longer than `upstream.request_seconds`.

An Envoy example is in the broker's
[README](https://github.com/aflock-ai/badger/blob/main/testifysec/model-broker/README.md#the-edge-contract).

## Configuration

Start from `testifysec/model-broker/examples/config.json`. Unknown keys are refused, and nothing in
this file can be changed through the admin API. Every key, with its type, is in the
[configuration reference](../reference/config.md#model-broker-and-portal-badger-broker). The ones
every deployment sets:

| Key | Set it to |
|---|---|
| `listen.*` | Four different addresses |
| `routes[]` | One entry per model: `model`, `upstream_url`, `auth_header`, `key_file` (re-read on every request, so a rotated key needs no restart), and `price_usd_per_million` if you want spend and quotas |
| `upstream` | Timeouts; defaults 180 s to the first byte, 240 s for the call, 250 s write deadline, with header <= request < write |
| `issuers[]`, `sources`, `seed_policy_file` | The pipeline side; see [add a pipeline issuer](identity-issuers.md) |
| `headers.*` | The header names your edge sets |
| `human_principals`, `admin_roles` | The people the broker serves, and the IdP groups that may administer it |
| `allowed_origins` | Browser origins for people's requests and the admin pages |
| `provisioner_key_file`, `workspace_token_ttl_hours` | Workspace tokens; see [quotas and tokens](quotas-and-tokens.md) |
| `database.dsn_file`, `database.owner_dsn_file`, `database.service_role` | The Postgres database and its two roles (above, "State") |
| `ceiling_marking` | The deployment's accreditation ceiling, a banner the marking package parses. Admin sessions, pipelines and the provisioner run at it; a workspace runs at its own label, never above it |
| `import_state_dir` | Optional. A file-backed broker's state directory, imported once into an empty database (above, "State") |
| `portal` | The management portal (below) |

### The portal section

| Key | Meaning |
|---|---|
| `portal.import_data_dir`, `portal.import` | A file-backed portal's data, imported once, or `"none"` when there was none (above, "State"). `portal.data_dir` is refused: the portal's state is in the database |
| `portal.signing_key_file` | Required. The ECDSA P-256 profile signing key, mounted from your key vault. It is read at start and is reachable only from the admin listener |
| `portal.tenant_id`, `portal.minimum_sequence` | The tenant and the first sequence for signed profiles |
| `portal.bootstrap` | IdP subjects given a role (`admin`, `approver`) only until a provisioned user holds it, so the first admin and approver can grant real roles |

## Run it

Mount the configuration read-only at `/etc/badger-broker/`, and the database connection-string
files, route keys, provisioner key and signing key from your secret store. Run one replica with
`strategy: Recreate`.

Publish no listener to a shared network. Give each one an ingress rule that admits its one client
and nothing else. In Kubernetes, with your own labels for the edge, the provisioner and the
workspace namespaces:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: badger-broker
spec:
  podSelector: { matchLabels: { app: badger-broker } }
  policyTypes: [Ingress]
  ingress:
    - from: [{ podSelector: { matchLabels: { app: edge } } }]
      ports: [{ port: 8080 }, { port: 8081 }, { port: 8083 }]
    - from: [{ namespaceSelector: { matchLabels: { role: workspace } } }]
      ports: [{ port: 8080 }]
    - from: [{ podSelector: { matchLabels: { app: provisioner } } }]
      ports: [{ port: 8082 }]
```

A `podSelector` with no `namespaceSelector` matches pods in the broker's own namespace only. Check
that your network plugin enforces NetworkPolicy before you rely on it: one that ignores it admits
everything, and anything that reaches `edge` or `admin` can set the identity headers.

On first start with an empty database, the broker writes `seed_policy_file` as policy version 1. After
that, policy changes go through the admin API or the admin console (`/admin/v1/ui/`), each one a new immutable version
in the audit log.

## Keep the logs out of the database's reach

The audit log is hash-chained and checked at every start: an edited, deleted or planted version is
detected, and the broker then denies every pipeline and refuses admin writes. Anyone with write
access to the database outside the service (a superuser, the owner role) can still rewrite the
whole chain, which is not detected from the database alone, so ship the broker's stdout, which
logs every policy write with its digest and the audit head, somewhere those roles cannot edit.
