---
title: Add a pipeline issuer
description: Let CI pipelines from a GitLab instance, GitHub Actions or another OIDC issuer call models through badger-broker with their own job tokens, and write the policy entries that admit them.
sidebarLabel: Pipeline issuers
sidebarPosition: 60
---

# Add a pipeline issuer

A pipeline calls a model with the short-lived OIDC token its CI system mints for each job, not with
a stored API key. Each CI system that signs those tokens is an issuer. `badger-broker` accepts
several, keeps them apart, and decides each request from policy entries written against neutral
fields, not raw claims.

## 1. Pin the issuer's keys at the edge

Give the edge one JWT provider for the issuer, with:

- the issuer's exact `iss` and its public keys, pinned locally (never fetched at request time);
- the single audience your broker accepts (the edge must refuse a list-valued `aud` too; an RBAC
  match on the claim does it);
- `max_lifetime` for the token;
- a payload header of its own, such as `x-broker-ci-claims-gitlab-2`, which the edge strips from
  every caller.

## 2. Add the issuer to the broker

Add an entry to `issuers[]` in the broker's configuration and restart it. A GitLab instance uses
the built-in mapping:

```json
{
  "id": "gitlab-2",
  "type": "gitlab",
  "issuer": "https://gitlab-2.example.invalid",
  "audience": "badger-broker",
  "claims_header": "x-broker-ci-claims-gitlab-2",
  "max_token_lifetime_seconds": 3600,
  "config_ref_template": "gitlab-2.example.invalid/{project_path}//.gitlab-ci.yml@refs/heads/{ref}"
}
```

Any other issuer is `generic` and maps its claims to the neutral fields. GitHub Actions, for example:

```json
{
  "id": "actions-1",
  "type": "generic",
  "issuer": "https://token.actions.example.invalid",
  "audience": "badger-broker",
  "claims_header": "x-broker-ci-claims-actions-1",
  "max_token_lifetime_seconds": 600,
  "require": { "repository_owner": "example-org" },
  "ref_prefix": "refs/heads/",
  "mapping": {
    "project": { "claim": "repository" },
    "ref": { "claim": "ref" },
    "ref_type": { "claim": "ref_type" },
    "protected": { "claim": "ref_protected" },
    "source": { "claim": "event_name" },
    "triggered_by": { "claim": "actor" },
    "config_ref": { "claim": "job_workflow_ref" }
  },
  "config_ref_template": "{project_path}/.github/workflows/ci.yml@refs/heads/{ref}"
}
```

| Key | Rule |
|---|---|
| `id` | `[a-z0-9-]`, up to 32 characters; policy entries name it |
| `issuer`, `claims_header` | Unique across issuers |
| `audience` | One string |
| `max_token_lifetime_seconds` | `exp - iat` cap, 1 to 86400 (0 is allowed for `gitlab`, where the edge enforces it) |
| `primary` | At most one issuer. Entries with no `issuer` are its, and keep the unqualified principal `ci:<project>` |
| `mapping` | `generic` only. `project`, `ref`, `ref_type`, `protected` and `source` are required; `triggered_by`, `config_ref` and `sub` are optional. A claim is a name, a path (`["outer", "inner"]`) or a constant |
| `require` | Claims every token must carry with exactly this value |
| `ref_prefix` | Stripped from the ref, and required |
| `config_ref_template` | Required exactly when `config_ref` is mapped |

Map `protected` to a claim the issuer sets from its own branch protection. GitHub Actions lists
`ref_protected` in its issuer's discovery document (`claims_supported`); the broker reads it only as
the JSON string `"true"` or `"false"` and refuses a boolean as `bad_claims`, so decode one real
token from your issuer before you rely on the entry. A constant is your assertion, not the issuer's: use one only for an issuer that
issues tokens for protected refs and nothing else. Requiring the owning organization does not make
a ref protected, since any branch in that organization gets a token.

## 3. Write policy entries for it

An entry names its issuer and matches the neutral fields. Its principal is `ci:<issuer id>:<project>`
(add `@<ref>` for a named branch), so the same project under two issuers is two identities with two
quotas:

```json
{"id": "release-bot", "issuer": "gitlab-2", "kind": "protected_branch", "project_path": "platform/release-bot",
 "ref": "main", "sources": ["schedule", "web"], "models": ["model-a"], "trigger_users": [], "expires_at": null, "enabled": true}
```

Change the policy through the admin API (`PUT /admin/v1/policy` with `If-Match`) or the usage
page. A `named_branch` entry must list trigger users and expire within
`max_named_branch_ttl_hours`; with `two_person_rule` on (the default), a second admin approves it.
Then give the entry an owner from `human_principals` (`PUT /admin/v1/owners`): an entry without an
owner is refused even when the policy allows it.

## How a request is decided

The broker refuses, with 401 and the reason in its log, in this order: no policy (`no_policy`); more
than one issuer header, or a malformed one (`bad_claims`); a payload whose `iss` is not the issuer
bound to its header (`wrong_issuer`); the wrong audience (`wrong_audience`); an expired token
(`token_expired`); a token that lives longer than its issuer allows (`token_lifetime`); a missing
or mistyped mapped claim (`bad_claims`). Then come the operation, the matching entry, the model, the
owner and the quota. A request with an issuer the broker does not know never reaches the policy.
The full policy rules are in the broker's
[README](https://github.com/aflock-ai/badger/blob/main/testifysec/model-broker/README.md#policy).
