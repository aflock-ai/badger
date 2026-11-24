---
title: Quotas, usage and tokens
description: Set monthly spend limits per principal, read usage, and manage the workspace and device tokens badger-broker issues.
sidebarLabel: Quotas and tokens
sidebarPosition: 70
---

# Quotas, usage and tokens

`badger-broker` counts every model call under the principal that made it, prices it at the route's
rates, and refuses calls past a principal's monthly limit. It also issues the tokens workspaces and
people's computers use for model traffic.

Usage, quotas, owners and tokens live in the broker's Postgres database
([deploy the broker](deploy-broker.md#state)). If it cannot be reached, nothing that depends on them
proceeds: no workspace token is issued and no limited call is made.

## Prices

Spend is computed only for a route with `price_usd_per_million` (`input`, `cached_input`,
`output`). A call on an unpriced route costs nothing against a quota, and usage shows no cost for it,
never a cost of zero. Changing a price never rewrites past costs.

## Monthly limits

Limits are in USD per UTC month. Read them with `GET /admin/v1/quotas` and write them with
`PUT /admin/v1/quotas`, sending the version you read in `If-Match`:

```json
{ "default_usd": 50, "principals": { "ci:platform/release-bot": 200 }, "comment": "release month" }
```

A principal's limit is its own entry, else `default_usd`, else none. Before each call the broker
compares this month's spend with the limit:

| Spend | Result |
|---|---|
| Below 80% | The call runs; the answer carries `X-Broker-Quota-USD` and `X-Broker-Quota-Used-USD` |
| 80% or more | The call runs, with `X-Broker-Quota-Warning` |
| At or over the limit | 429 `quota_exceeded`; the call never reaches the model |

The check is before the call, so the last call allowed can take a principal past its limit. A reply
with no usage figures marks that principal `usage_unknown`, and its limited calls are refused (503
`quota_unavailable`) for the rest of the month. A usage ledger that cannot be read refuses every
limited call, and if the quotas document in the database cannot be read, every model call is
refused (503 `quota_unavailable`) until an administrator repairs it
(`testifysec/model-broker/API.md`). Each write is an audit record of kind `quota`. The admin console
(`/admin/v1/ui/`; the old `/admin/v1/ui/usage` opens its Usage tab) shows spend against each limit
and edits them, and adds pipelines with an owner and a quota from one form.

## Usage

`GET /admin/v1/usage` returns today's requests, tokens and cost per principal and model;
`?from=YYYY-MM-DD&to=YYYY-MM-DD` returns up to 92 past days. People see their own with
`GET /v1/usage`. Every counted call is a row in the usage ledger in the broker's database.

## Workspace tokens

The provisioner, the component that creates hosted workspaces, calls the `provision` listener with
the key in `provisioner_key_file`:

- `POST /provision/v1/tokens` with `{"workspace", "principal"}` when it creates or wakes a workspace.
  It mounts the returned `bbt_...` token only into that workspace. Issuing again replaces the old
  token at once.
- `DELETE /provision/v1/tokens/{workspace}` when it stops one.

The broker keeps only each token's SHA-256, owner and expiry (`workspace_token_ttl_hours`, 1 to 744).
A token can never be issued for a `ci:` principal.

## Device tokens

With `device_login` on, a person running Badger on their own computer signs in through the edge in
the browser and approves the device; the device gets its own token for `device_token_ttl_hours`
(1 to 24, default 8), at most `max_device_tokens` per person (1 to 50, default 5). Signing in again on
the same device replaces its token, and `DELETE /device/token` signs it out. The edge must route
`/device/authorize` like any signed-in request and pass `POST /device/token` through without a
session.

The admin API is described endpoint by endpoint in
[API.md](https://github.com/aflock-ai/badger/blob/main/testifysec/model-broker/API.md).
