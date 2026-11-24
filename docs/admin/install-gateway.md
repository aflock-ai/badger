---
title: Install the model gateway
description: Build and configure hardened-gateway, the service that holds the model credential, audits every request and checks the signed profile.
sidebarLabel: Install the gateway
sidebarPosition: 20
---

# Install the model gateway

The model gateway, `hardened-gateway`, is the only way a managed Badger session reaches a model.
It forwards `POST /v1/chat/completions` (or, if configured, `POST /v1/responses`) from a Unix
socket to one HTTPS endpoint and one model that you choose. The session never sees the provider
credential.

Status: available on `main`, in `testifysec/gateway/`. It does not claim FIPS 140-3 validation.

## Build

With a Go toolchain already installed (the gateway uses only the standard library):

```sh
cd testifysec/gateway
CGO_ENABLED=0 go build -trimpath -o /protected/bin/hardened-gateway .
go test ./...
```

## Write the configuration

The configuration, the credentials and the audit spool belong to the gateway's own service user.
The gateway refuses a configuration or credential file that is not a regular file readable only by
its owner, in a directory whose mode is exactly `0700`. Keep credentials off persistent disk: the
example takes the provider token over an inherited pipe and reads the collector token from a
memory-backed file system.

```json
{
  "schema": "testifysec.hardened-opencode.gateway/v1",
  "socket": "/run/hardened-session/gateway.sock",
  "spool": "/var/lib/hardened-session/audit",
  "providerURL": "https://model.example.invalid/v1/chat/completions",
  "providerTokenFd": 3,
  "collectorURL": "https://collector.example.invalid/v1/logs",
  "collectorTokenFile": "/run/hardened-session/collector.token",
  "model": "approved",
  "tenant": "example-tenant",
  "session": "example-session",
  "agent": "spiffe://platform.example.invalid/tenant/example/agent/example",
  "profileDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "maxRecords": 1000,
  "maxOfflineSeconds": 300,
  "timeoutSeconds": 120,
  "developmentLoopback": false,
  "platformConfigFile": "/etc/hardened-session/platform.json"
}
```

| Key | Meaning |
|---|---|
| `socket` | The Unix socket the gateway listens on. Mount this one file into the session at `/run/hardened-gateway/gateway.sock`, the path the managed build is compiled with. |
| `spool` | Directory for the audit spool. One gateway per spool; a lock refuses a second. |
| `providerURL` | The model endpoint. The protocol path may sit under a prefix, such as `/broker/v1/chat/completions`. |
| `protocol` | Optional. `chat-completions` (default) or `responses`, which accepts only the stateless subset with `store: false`. |
| `providerTokenFile` or `providerTokenFd` | Where the provider credential comes from. See below. |
| `providerCertSha256` | Optional. Lowercase hex SHA-256 of the provider's SubjectPublicKeyInfo, for a provider no system root signs. |
| `collectorURL`, `collectorTokenFile` | OTLP/HTTP log endpoint for audit events, and its bearer token. An empty token path is only for a collector whose TLS boundary already authorizes the gateway. |
| `model` | The exact model name sent to the provider, and the default when the profile allows several. |
| `tenant`, `session`, `agent`, `profileDigest` | Recorded in every audit event. |
| `maxRecords`, `maxOfflineSeconds` | When the spool holds this many undelivered records, or delivery has failed this long, new requests get 503 and no provider call. |
| `timeoutSeconds` | Upper bound on one provider call. |
| `developmentLoopback` | Allows cleartext to literal loopback addresses, for the test harness only. |
| `platformConfigFile` | The TestifySec platform session check. Required unless `developmentLoopback` or `administratorIdentity` is true; see [the platform page](../concepts/platform.md). |
| `administratorIdentity` | Optional. `true` for a network with no TestifySec platform: the agent's identity is what the administrator provisioned (the signed profile and the provider credential). Needs schema v3, a signed or unsigned profile and `collectorTokenFile`, and excludes `platformConfigFile` and `developmentLoopback`, so every endpoint is HTTPS. Audit records say `identity.source` `administrator-provisioned`. |
| `signedProfileFile`, `admissionExecutable`, `admissionSha256` | The signed profile and the pinned admission executable that verifies it before every provider request. |
| `profileFile` | Schema v3 only, instead of the three above: an unsigned profile the gateway reads itself, pinned by `profileDigest` (the SHA-256 of the file). It lists the models a session may choose (`GET /v1/models`). See `testifysec/gateway/README.md`, Unsigned profile. |

Unknown keys are refused. Production URLs need TLS with normal certificate and hostname checks,
and the gateway ignores proxy environment variables. There is no switch to turn TLS verification
off; install your enclave's roots in the host trust store, or pin the provider's key.

## Provide the credentials

**Provider token.** With `providerTokenFd`, the gateway reads the token from an inherited file
descriptor (3 or higher) that the process starting it, such as the session broker, holds open:
each line replaces the token in memory, an invalid line or a closed pipe clears it, and with no
token the gateway makes no provider call. The token never touches disk, the command line or the
environment. `providerTokenFile` exists for test harnesses; a plaintext token file on persistent
storage does not meet the hardening requirement.

**Collector token.** `collectorTokenFile` is read from a file, again before each export, so a
short-lived token renewed in place (atomic rename) is picked up; if the file is missing or not
private, export stops and records stay in the spool. Put it on a memory-backed file
system such as `/run`, in a `0700` directory owned by the gateway's user, and write it at service
start from your secret store. Do not leave it as a plaintext file under `/etc`.

## Run it

```sh
hardened-gateway -config /etc/hardened-session/gateway.json
```

Run one gateway per session. The socket is a bearer capability: anyone who can open it can send
model requests as that session, so never share one between sessions or expose it through a
network listener.

## What the audit records

Before each provider call, the gateway writes a start record to the spool and syncs it; the
terminal record replaces it when the call ends. Records hold IDs, timestamps, the tenant,
session, agent, profile and model, the outcome, status and byte counts. They never hold prompts,
source code, response bodies, headers or credentials. Denied requests are recorded too. Records
are delivered to the collector at least once; deduplicate on `event.id`.

Collector templates for Loki and OpenSearch are in `testifysec/gateway/`. They are starting
points, not tested deployments.

## Check it

`python3 uat.py --go /absolute/path/to/go --report /tmp/gateway-uat.json` compiles the gateway
and runs it against synthetic provider and collector services on loopback: streaming, credential
isolation, denied-request auditing, offline bounds, restart recovery. The report is an unsigned
local observation.
