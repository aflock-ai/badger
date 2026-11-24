---
title: Let a pipeline call a model
description: Trust a second GitLab instance as a pipeline issuer, admit one project's protected branch to one model, give it an owner and a limit, and read the decisions the broker logs.
sidebarLabel: Pipeline calls a model
sidebarPosition: 30
---

# Let a pipeline call a model

A CI job calls a model with the OIDC token its CI system mints for that job, never with a stored
key. This walkthrough adds a second GitLab instance, `gitlab-2`, as an issuer, admits the `main`
branch of `platform/release-bot` there to one model, and checks both the admitted call and the
refusals. The full rules are in [add a pipeline issuer](../admin/identity-issuers.md).

It assumes `badger-broker` runs as in [your first deployment](first-deploy.md), with a route for
`model-a`.

## 1. Pin the issuer at the edge

Give the edge one JWT provider for `gitlab-2`: its exact issuer URL, its public keys pinned in the
edge's configuration (never fetched per request), the single audience `badger-broker`, a maximum
token lifetime, and the payload header `x-broker-ci-claims-gitlab-2`. The edge strips that header
from every caller before it verifies anything, and routes a verified bearer `POST
/v1/chat/completions` with no `Origin` to the broker's `edge` listener.

**Check.** A request carrying a hand-written `x-broker-ci-claims-gitlab-2` header and no token gets
no further than the edge.

## 2. Add the issuer to the broker

Add the entry to `issuers[]` and restart the broker:

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

`config_ref_template` makes an entry accept only a pipeline whose top-level CI configuration is the
project's own `.gitlab-ci.yml` on the entry's branch, so a project that points its pipeline at a
configuration file elsewhere does not match. It does not see `include:`: a job loaded from another
project or a remote file runs under the same top-level reference and matches. Restrict includes
with GitLab's own controls, such as protected branches and required review of CI changes. Make sure
the job's pipeline source (`push`, `schedule`, `web`) is in the broker's `sources`.

## 3. Write the policy entry, then give it an owner

Read the policy, add the entry, and write it back with the version you read in `If-Match`
(`PUT /admin/v1/policy`), or use the usage page:

```json
{"id": "release-bot", "issuer": "gitlab-2", "kind": "protected_branch", "project_path": "platform/release-bot",
 "ref": "main", "sources": ["push", "schedule"], "models": ["model-a"], "trigger_users": [], "expires_at": null, "enabled": true}
```

The entry's principal is `ci:gitlab-2:platform/release-bot`. The same project path under another
issuer is a different principal with its own usage and limit.

Then name the person accountable for it, one of `human_principals`, with `PUT /admin/v1/owners`. An
entry with no owner is refused even though the policy allows it.

## 4. Give it a limit

Add the principal to the quotas (`PUT /admin/v1/quotas`), as in
[quotas and tokens](../admin/quotas-and-tokens.md#monthly-limits):

```json
{ "default_usd": 50, "principals": { "ci:gitlab-2:platform/release-bot": 20 }, "comment": "release-bot pilot" }
```

## 5. Call the model from the job

In the project's `.gitlab-ci.yml` on `main`:

```yaml
summarize:
  id_tokens:
    BADGER_ID_TOKEN:
      aud: badger-broker
  script:
    - >
      printf 'header = "Authorization: Bearer %s"\n' "$BADGER_ID_TOKEN" |
      curl -fsS -K - https://models.example.invalid/v1/chat/completions
      -H 'Content-Type: application/json'
      -d '{"model":"model-a","messages":[{"role":"user","content":"Summarize the changelog in one line."}]}'
```

The token goes to curl on standard input, not in its arguments. A pipeline request must name its
model. The job never holds a model key: the token lives for the
job, names the project, branch and pipeline, and is useless to any other audience.

**Check.** The broker's stdout has a `ci decision=allow` line with
`principal=ci:gitlab-2:platform/release-bot`, `issuer=gitlab-2` and `model=model-a`, and
`GET /admin/v1/usage` counts the call under that principal.

## 6. Check the refusals

Each of these is refused before the model is reached. The broker's refusals log a
`ci decision=deny` line with the reason; the answer itself never says which check failed.

| Try | Refused because |
|---|---|
| The same job on a feature branch | No entry matches: the entry is for `main` (`no_match`) |
| `"model": "model-b"` | The model is not on the entry |
| No `model` in the body | A pipeline request must name one |
| A token minted with another `aud` | The edge's provider refuses it; the broker checks again (`wrong_audience`) |
| A token from another trusted issuer for the same project path | It is another issuer's identity, and no entry for that issuer matches |
| Past the limit | 429 `quota_exceeded` |

The order the broker checks in, and every reason code, is in
[how a request is decided](../admin/identity-issuers.md#how-a-request-is-decided).

## Named branches

To let a feature branch call a model for a while, write a `named_branch` entry instead: it must
list the users who may trigger it and expire within `max_named_branch_ttl_hours`, and with
`two_person_rule` on (the default) a second administrator approves it. Its principal is
`ci:gitlab-2:platform/release-bot@<branch>`.
