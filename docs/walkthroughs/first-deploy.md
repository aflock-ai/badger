---
title: Your first deployment
description: From an empty cluster to one developer's first model call through badger-broker and the model gateway, with a check at every stage.
sidebarLabel: First deployment
sidebarPosition: 10
---

# Your first deployment

This walkthrough takes one deployment from nothing to a developer's first audited, counted model
call. Each stage links to the page that holds the full procedure and ends with a check, so you know
the stage works before you build on it. It uses one model route, one hosted workspace and no
connectors; [add a connector](connector-marking.md) after it works.

What you end with:

```
badger (managed build) --unix socket--> hardened-gateway --HTTPS--> your TLS front
    --> badger-broker internal listener --> model endpoint
```

The workspace holds no provider key. The gateway holds a broker token for that one workspace, the
broker holds the provider key, and both write an audit record for the call.

## Before you start

- A Kubernetes cluster whose network plugin enforces NetworkPolicy, and an authenticating edge
  proxy you control (Envoy or similar) with your IdP behind it.
- A model endpoint and its API key in your secret store.
- Go and Bun on a build machine, and this repository checked out there.

## 1. Run badger-broker

Follow [deploy badger-broker](../admin/deploy-broker.md): build the image, write the
configuration with one entry in `routes[]`, mount the route's `key_file` from your secret store,
and apply the NetworkPolicy so each listener admits only its client.

The broker serves plain HTTP. Put TLS in front of the `internal` listener with the edge or your
service mesh; the gateway in stage 3 refuses cleartext.

**Check.** From the edge's pod, which the NetworkPolicy admits to port 8080:

```sh
curl -s http://badger-broker:8080/readyz
```

`{"ok":true}` means every route's key file is readable. A 503 means at least one is not; fix the
mount before you go on, since a route with no key cannot serve a call.

## 2. Issue a workspace token

The provisioner (whatever creates your workspaces) asks the `provision` listener for a token with
the key in `provisioner_key_file`. By hand, for the first workspace, from the provisioner's pod
(the only client the NetworkPolicy admits to port 8082):

```sh
printf 'header = "Authorization: Bearer %s"\n' "$(cat provisioner.key)" | curl -s -K - -H 'Content-Type: application/json' \
  -d '{"workspace":"ws-first","principal":"alice@example.invalid"}' \
  http://badger-broker:8082/provision/v1/tokens
```

`printf` is a shell builtin and `curl -K -` reads the header from standard input, so the key never
appears in a process's arguments. The answer carries a `bbt_...` token. The broker keeps only its SHA-256. Details are in
[quotas and tokens](../admin/quotas-and-tokens.md#workspace-tokens).

**Check.** The broker's stdout has a `workspace token issued workspace=ws-first` line.
`GET /v1/models` on the internal listener with that token lists your route; the same call with no
token is refused.

## 3. Start the model gateway in the workspace

Follow [install the model gateway](../admin/install-gateway.md). Set `providerURL` to the HTTPS
address of the broker's internal listener and `model` to the route's `model`. Hand the gateway
the `bbt_` token over `providerTokenFd`, so it never touches disk, and point `collectorURL` at
your log collector.

**Check.** The gateway's own UAT (`python3 uat.py` in `testifysec/gateway/`) passes on the build
machine, and in the workspace the socket exists at `/run/hardened-gateway/gateway.sock`.

## 4. Sign and publish a profile

Follow [publish a profile](../admin/publish-profile.md): sign version 1 in the portal, export the
trust input, assign the version to your deployment, build the admission executable from that trust
input, and add `signedProfileFile`, `admissionExecutable` and `admissionSha256` to the gateway's
configuration. Restart the gateway.

**Check.** A model request through the gateway succeeds. Replace the envelope with one byte changed
and the next request is refused and spooled as `profile-refused`. Put the real envelope back.

## 5. Make the first call

Step 4 already made a request through the gateway, so note the request count `GET /admin/v1/usage`
shows for `alice@example.invalid` now. Build the managed binary as in
[run Badger as a developer](../developer/run-badger.md) and, in the workspace:

```sh
badger models                       # managed/approved, or the models the gateway profile lists
badger run "say hello in one line"
```

**Check.** You should find three records of this call:

| Where | What |
|---|---|
| The gateway's audit stream at your collector | One terminal record with the tenant, session, profile digest, model and status |
| `GET /admin/v1/usage` on the broker | One more request under `alice@example.invalid` than before the call, for the route's model, with a cost if the route is priced |
| The usage ledger in the broker's database | One new row for the call, which is what the usage API sums |

## 6. Set a limit

Give the deployment a default monthly limit before anyone else signs in, as in
[quotas and tokens](../admin/quotas-and-tokens.md#monthly-limits). A route with no
`price_usd_per_million` is never counted against a limit, so price every route you want limited.

## Next

- [Turn on a connector with a marking](connector-marking.md)
- [Let a pipeline call a model](pipeline-issuer.md)
- [Rotate keys and tokens](rotate-keys.md)
