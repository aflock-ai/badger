# Native approved-model gateway and durable audit

`hardened-gateway` is a compiled Go service. A worker receives only its private
session gateway Unix socket at `/run/hardened-gateway/gateway.sock`; it never receives a
provider credential, collector credential, Docker socket or general egress.
The gateway forwards `POST /v1/chat/completions` by default, or explicitly
configured `POST /v1/responses`, to one administrator-selected HTTPS endpoint
and exact model. It has no destination, credential, identity,
redirect, plugin or package-install option in the worker request.

One other route exists: `GET /v1/limits`, with no body and no query, asks the provider for this
workspace's managed-agent limits at the provider URL's origin and path prefix (`.../v1/limits`, the
model broker's route), with the provisioned credential and nothing from the request. A JSON object
of at most 1 KiB is passed back; anything else is a fixed 404, and the managed agent keeps its
compiled limits. It does not take the session's one model slot, and it is audited like every
request (`limits-served`, `limits-unavailable`).

With an unsigned profile (below), a request may name any model in the profile's `models`, matched
exactly; otherwise only `model`. `GET /v1/models`, with no body and no query, returns the profile's
allowlist and the default (`model`) as the gateway's own JSON, `{"default":"...","models":[{"id",
"name"[, "context", "output"]}]}`; the provider is not asked. With no profile allowlist it is a fixed
404. It does not take the model slot and is audited (`models-served`, `models-unavailable`). The
audit's `gen_ai.request.model` is the model the request named, when it is a well-formed ID.

### Unsigned profile

`profileFile` (gateway v3 only, instead of `signedProfileFile`, `admissionExecutable` and
`admissionSha256`) is the administrator's profile as a plain private JSON file. The gateway reads
it itself at start and before every model request; `profileDigest` is the SHA-256 of its exact
bytes, so a changed file refuses every request. No signature says who wrote it: it is as trusted
as the gateway's own configuration, and the audit says `profile.signature` `unsigned` (`signed`
or `none` otherwise). The start log prints `profile=unsigned sha256=... default=... models=...`.

```json
{
  "schema": "testifysec.hardened-opencode.profile.unsigned/v1",
  "tenantId": "example-tenant",
  "notBefore": "2026-11-03T00:00:00Z",
  "expiresAt": "2027-11-03T00:00:00Z",
  "gateway": {"classification": "UNCLASSIFIED"},
  "connectors": [],
  "models": [
    {"id": "gpt-5.6-sol", "name": "GPT-5.6 Sol"},
    {"id": "gpt-5.6-luna", "name": "GPT-5.6 Luna"}
  ]
}
```

Every key is required except a model's `context` and `output` (positive integers, which can only
lower what the managed agent asks for). `tenantId` must equal `tenant`; the profile is refused
outside its window. Models: 1 to 32, IDs `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` and distinct, names
1 to 64 characters of letters, digits, space and `.,:_()/+-`; the configured `model` must be one
of them. `connectors` lists `{"name","classification"}` for each connector a session may use, and,
as under a signed v3 profile, every request is refused while one is marked above
`gateway.classification`.

Every parsed HTTP request reserves a durable bounded audit record, including
requests subsequently denied. A start record reaches disk before a provider
call. Completion atomically replaces it with the bounded terminal observation.
Disk failure blocks new actions; a retained start becomes `incomplete-after-restart`
on recovery, without replaying the model request. A bounded private temporary
file left before atomic rename is discarded; the committed start remains available. Requests arriving after audit
capacity or maximum offline age is exhausted receive 503 without a provider call.
At that point the unavailable audit store cannot record additional denials.
Terminal persistence faults emit a fixed service fault message. Transport/header failures rejected by
Go's HTTP server before the handler are outside this request ledger.

The spool contains metadata only: generated request/event IDs, timestamps,
provisioned tenant/session/agent/profile/model, outcome, status and byte counts.
It excludes prompts, source code, response bodies, headers and credentials.
Streaming responses are forwarded with bounded size, line length and duration.
For Chat Completions, a complete provider SSE `[DONE]` event is required; premature EOF aborts the
stream and records `response-interrupted`. `provider-stream-ended` describes the
observed provider marker, not semantic model correctness. Each retry by
the worker is a separate gateway request with its own ID. Provider errors and
response headers are not copied to the worker: a refusal is a fixed 502, except a
429 whose body carries the model broker's `quota_exceeded` code, which becomes a
fixed gateway-written 429 quota answer with `X-Should-Retry: false` (outcome
`provider-quota-exceeded`) so the session stops instead of retrying. Responses terminal events and
structured model failure/refusal outcomes follow the distinct rules below. No
request sampling is used.

The exporter sends stable start/terminal events through OTLP/HTTP JSON at
`/v1/logs`. It retains records on network failure, malformed acknowledgment or
partial rejection. Delivery is at least once; consumers should deduplicate by
`event.id`, which differs between start and terminal events and remains stable
across retries. An OTLP acknowledgment transfers responsibility to the collector;
it does not establish final backend persistence. The collector needs its own
protected durable queue, retention and tenant access controls.

Production configuration requires a private `platformConfigFile` for the
[native platform session client](../platform/README.md). Before every model
request the gateway performs a fresh authenticated, nonce-bound platform check
against the assigned tenant, agent and immutable repository. Revocation or
unavailability blocks the provider call. The attributed start is durable before
forwarding. Audit records say `identity.source=platform-online-check` and retain
the check time and separate historical enrollment reference. That identity check
is not a model authorization grant; the protected gateway/profile assignment
remains an independent requirement. Historical enrollment AAL never proves a
currently present human. Development loopback fixtures may omit the platform
configuration and retain `identity.source=administrator-provisioned`; they do
not authenticate an agent. Measured service identity and ALPS qualification
remain separate integration work. This
component does not claim FIPS validation or IL6 authorization. Native Linux
separate-user installation and private socket placement are deployment duties;
a Docker Desktop development fixture does not qualify that installation.

## Build and UAT

Use an already provisioned Go toolchain; no runtime package manager is needed.

```sh
CGO_ENABLED=0 go build -trimpath -o /protected/bin/hardened-gateway .
go test ./...
python3 uat.py --go /absolute/path/to/go --report /tmp/gateway-uat.json
```

UAT compiles the real executable and runs synthetic provider/collector services
on loopback. It exercises actual IPC/HTTP, SSE, credential isolation, ambiguous
requests, denied-request auditing, offline bounds, partial acknowledgments,
restart replay and interrupted-call recovery. Unit tests cover malformed OTLP
acknowledgments, filesystem faults and stable event identities. Reports bind
source and executable hashes and disclose dirty builds. They are unsigned local
observations, not release attestations.

## Protected configuration

The configuration, credentials and spool belong to the gateway's service user.
Use private regular credential/config files (0600), private socket and spool
directories (0700), and protected ancestors. The worker can access only the
precisely mounted socket file, not those directories. Run one gateway per
session; a spool lock prevents two processes from using the same queue.
All config fields below are required. An empty collector token path permits
only deployments whose separately configured TLS boundary already authorizes
the gateway; otherwise provision a purpose-specific collector bearer.

```json
{
  "schema": "testifysec.hardened-opencode.gateway/v1",
  "socket": "/run/hardened-session/gateway.sock",
  "spool": "/var/lib/hardened-session/audit",
  "providerURL": "https://model.example.test/v1/chat/completions",
  "providerTokenFile": "/etc/hardened-session/provider.token",
  "collectorURL": "https://collector.example.test/v1/logs",
  "collectorTokenFile": "/etc/hardened-session/collector.token",
  "model": "approved",
  "tenant": "example-tenant",
  "session": "example-session",
  "agent": "spiffe://platform.example.test/tenant/example/agent/example",
  "profileDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "maxRecords": 1000,
  "maxOfflineSeconds": 300,
  "timeoutSeconds": 120,
  "developmentLoopback": false,
  "platformConfigFile": "/etc/hardened-session/platform.json"
}
```

`developmentLoopback` permits cleartext only to literal loopback IP addresses,
for the local harness. Production URLs require TLS with normal certificate and
hostname verification; ambient HTTP proxy variables are ignored. Install the
customer trust roots through the protected host trust store. No insecure TLS
switch exists. A provider whose certificate no system root signs (a self-signed edge,
for example) can instead be pinned with `providerCertSha256`: the SHA-256 of its
SubjectPublicKeyInfo, lowercase hex. The provider host must then present exactly that
key; every other host, the collector included, is still verified against the system
roots. `providerURL` may put the protocol path under a clean prefix, such as
`/broker/v1/chat/completions`. In a network with no TestifySec platform, set
`administratorIdentity: true` instead of `platformConfigFile` (schema v3 with a signed or unsigned
profile and a collector token; no `developmentLoopback`): the audit records then say `administrator-provisioned`. The collector
token file is read before each export, so a renewed token is used. The Unix socket is a bearer capability: do not share one between
tenants or sessions, and do not expose it through a public listener.

## Centralized logging profiles

The example collector configurations are deployment templates, not signed
runtime profiles or evidence of a deployed collector. They require a pinned,
approved collector distribution and customer-provisioned TLS/authentication
material. Validate against that exact distribution before release qualification.

- [Loki profile](collector-loki.yaml) uses the native OTLP endpoint, with service
  as a low-cardinality resource and request/agent IDs retained as structured
  metadata. See [Loki's OTLP ingestion documentation](https://grafana.com/docs/loki/latest/send-data/otel/).
- [OpenSearch profile](collector-opensearch.yaml) uses the collector's OpenSearch
  exporter and a fixed customer-controlled index. See the [exporter configuration](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/opensearchexporter).

The wire acknowledgment and retry behavior follows the [OTLP specification](https://opentelemetry.io/docs/specs/otlp/).
Backend queries should reconcile distinct request IDs with start/terminal events,
alert on incomplete requests and provider failures, and monitor the collector's
queue/refusal metrics. Agent IDs and session IDs are fields, not index names or
Loki labels. Backend deployment/UAT and production platform availability remain required
before claiming end-to-end production audit coverage.

## Per-request signed-profile admission

Production configuration also requires `signedProfileFile`, `admissionExecutable`
and `admissionSha256`. The file is a private DSSE envelope and the executable is
the protected, digest-pinned native admission launcher from the same managed
bundle used by the broker. Its provisioned trust and tenant/deployment/profile
assignment remain authoritative. The gateway neither accepts worker-supplied
trust nor implements a second profile-signature parser.

Before each provider request, the gateway rereads the protected envelope, checks
the native launcher digest, and executes that exact launcher with a fixed
minimal environment and bounded input/output/time. It requires the returned
payload digest to match `profileDigest`, the tenant to match the gateway, the
exact envelope hash, valid lifetime and a verified signer. Expiry is checked
again after the platform call and immediately before sending provider traffic.
Invalid/missing profiles and substituted executables or native libraries block
new requests and create a `profile-refused` audit record. An already admitted
stream may finish; this is not a continuous cancellation policy.

Only explicit local development mode may omit all three profile fields. Partial
configuration is refused in every mode. Protected service UID/installation
custody and synchronized OS time remain assumptions. No persistent rollback
counter, hardware attestation or qualified FIPS cryptographic boundary is implied.

Run the actual native profile/gateway fixture with an existing, matching managed
host build and its synthetic profile fixtures:

```sh
python3 -B uat-profile.py --go /absolute/go \
  --admission-directory /absolute/native-host-build \
  --fixtures /absolute/matching-profile-fixtures --report /tmp/gateway-profile.json
```

This exercises real Rookery verification, live profile replacement, expiry,
wrong key, tampering, missing/FIFO files, executable/library substitution and
durable refusal records. The provider is a local fixture; production platform
identity is covered by the separate platform/gateway UAT.

### Gateway v3: the connector ceiling

Schema `testifysec.hardened-opencode.gateway/v3` reads signed profile v3
(`testifysec/managed/profile-v3.ts`): the v1 assignment plus `gateway.classification`, the marking
this gateway is accredited for, and the admitted `connectors`. It requires a signed profile and no
backend assignment. A connector's classification is the one the administrator set in the profile,
and nothing is read from the content it returns. The gateway refuses every request with 403 and
the audit outcome `classification-refused` while the profile admits a connector whose marking the
accreditation does not dominate, since the worker could have read it. Within that ceiling anything
a connector can return is within the accreditation, so the gateway reads no classification from
request bodies. Markings use `testifysec/connectors/marking`, the lattice the connectors use. The
managed worker's high-water check (`packages/server/src/managed-flow.ts`) keeps content
from flowing down between connectors.

### Explicit Responses protocol (local integration phase)

The administrator can select `"protocol":"responses"` and an exact provider URL
ending in `/v1/responses`. The mounted session socket then accepts only POST
`/v1/responses`. Omitted protocol, or `"chat-completions"`, preserves the existing
`/v1/chat/completions` behavior. A caller cannot select the protocol, provider,
model, identity or credentials. This phase does not enable Responses in the
protected OpenCode worker, integrate the OAuth plugin host, or qualify a release.

Responses admission supports a deliberately limited stateless text/function
subset of the installed OpenAI SDK's serialization: exact approved model,
`store:false`, text messages, function tools and their results, encrypted
reasoning history, selected text/reasoning options and optional streaming.
Missing/true storage, background jobs, hosted tools, remote files/images,
conversation or stored item references, unknown fields and duplicate JSON keys
are refused before provider contact. Tools advertised to the provider remain
untrusted suggestions; this gateway grants no tool execution permission.
Prompt cache controls, service tier, extra reasoning context and other SDK
options remain unsupported. Configuring the SDK with `store:false` is required;
it is not the SDK's default.

For the exact administrator-approved model `gpt-6-astra`, the gateway accepts
`reasoning.effort` values `low`, `medium`, `high`, `xhigh` and `max`. It refuses
`none`, `minimal`, `temperature` and `top_p`, following the reviewed
[Astra model contract](https://developers.openai.com/api/docs/models/gpt-6-astra)
and [parameter guidance](https://developers.openai.com/api/docs/guides/latest-model).
Omitted effort retains the provider default. Other exact model identifiers keep
the existing effort subset through `xhigh`; this change does not authorize `max`
for prefixes, aliases or unreviewed models. Model matching still happens against
the protected administrator configuration before request validation. No model
selection, credential, signed-profile or persisted audit schema is changed.
This is protocol support, not proof of Astra account entitlement or live service
compatibility; the gateway still supports only its existing stateless subset.

The existing audit/profile/live identity pipeline applies before each provider
effect. Its metadata record and OTLP scope remain version 1; no new persisted
fields are introduced. Responses adds terminal outcome strings
`provider-response-completed`, `provider-response-refused`,
`provider-response-failed` and `provider-response-incomplete`. Model refusal is a
valid model outcome. Failed and incomplete responses are not reported as
completion. `response-interrupted` denotes malformed/truncated transport, and
`response-limit` denotes a streamed byte limit. Audit `status` continues to be
the upstream HTTP status, not an assertion that a model completed successfully.
No prompt, response text or credential is added to audit records.

For SSE, creation and terminal response IDs/models must agree, sequence numbers
must be nonnegative integers and strictly increase, supported event/output
shapes are validated, and each complete frame is at most 64 KiB. The terminal
frame is retained until clean EOF; a second terminal, subsequent data event,
partial frame, unknown event, `[DONE]` or plain EOF cannot establish completion.
Nonterminal deltas may already have reached the caller when a later error aborts
the stream. The gateway does not prove semantic consistency between all text
and function deltas and the final model output. Response totals remain bounded
at 16 MiB; request totals remain bounded at 1 MiB. Exact model matching also
applies to provider responses, so deployments must approve a concrete model
identifier whose returned identifier matches; alias expansion is not inferred.

The harness's client is 2.0's own provider code: `@opencode/ai`'s OpenAI
Responses route (serializer and parser), checked against the OpenAI
[Responses streaming event reference](https://developers.openai.com/api/reference/resources/responses/streaming-events),
reaching the gateway through the managed build's own transport
(`ManagedProfile.gatewayFetch`) over the Unix socket. The local harness compiles
both the native gateway and that client (`build-sdk.ts`), exercises generation,
streaming, encrypted reasoning plus function history, provider/collector
failures and refused inputs, and records the tested binary and the client's
selected source hashes.

```sh
python3 -B uat-responses.py --go /path/to/go --bun /path/to/cached/bun \
  --report /private/tmp/hc-gateway-responses-uat.json
python3 -B uat-responses.py --go /path/to/go --bun /path/to/cached/bun \
  --model gpt-6-astra --binary-output /private/tmp/hc-gateway-astra \
  --report /private/tmp/hc-gateway-astra-uat.json
python3 -B uat-profile.py --protocol responses --go /path/to/go \
  --admission-directory /path/to/native-admission-bundle \
  --fixtures /path/to/matching-signed-fixtures \
  --report /private/tmp/hc-gateway-responses-profile-uat.json
```

`go test -race .` includes actual native TLS identity-client checks before every
Responses effect (revocation, outage, nonce/repository binding, expiry and
historical enrollment AAL). Its TLS authority is synthetic. The separate
platform UAT owns evidence that the real platform authenticates enrolled agents;
this protocol phase does not manufacture a current human-presence or ALPS claim.
Run the original `uat.py` as the unchanged Chat Completions regression.

The Astra run uses the actual installed SDK for `max` in generation, streaming,
encrypted reasoning and function history, then checks the native provider saw
the exact model and effort. Invalid efforts, duplicate fields, wrong model/path,
unsupported options and existing stream terminal failures are refused or audited
through the same native pipeline. The optional fresh `--binary-output` path keeps
the exact tested gateway executable. All provider/collector credentials are
synthetic fixtures; no live API calls or OAuth session are used.
