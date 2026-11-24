# HC-04: native platform session identity

`platformsession.Client.Check` authenticates an existing enrolled agent against
live TestifySec platform state before an operation. The server uses the existing
constant-time refresh-credential authentication and tenant privacy filters,
checks activation, expiry and revocation, and matches the exact enrolled
`ProductRepository` UUID. It derives the stable SPIFFE name from its configured
trust domain and authenticated principal; caller-supplied names are not identity.

The new `POST /api/agent/session-check` response is **identity only**. Its
`authorization` is always `none`. An authenticated agent still needs independent
signed-profile authorization for a model or tool operation. This endpoint does
not mint signing, upload, federation or model tokens and never activates a
pending principal. Existing signing/upload JWTs cannot replace the refresh
credential. No credentials are taken from an ambient login or environment.

The human is recorded separately as the enrollment's platform user UUID and
Kratos identity reference. `enrollment_aal` records the historical ceremony and
`enrollment_gitoid` is the platform's evidence reference, not an independently
verified evidence result. `human_presence` is explicitly `not-asserted`. The
adapter refuses an unavailable delegation rather than substituting an email or
claiming a current human session. `MinimumEnrollmentAAL` may require a historical
AAL2/AAL3 record; `RequireCurrentHumanAAL` fails closed until the separate current
human ceremony exists. Neither setting is an AAL qualification claim.

## Native integration

This separate Go module uses only the standard library. The runtime needs no
Python, Node, npm, Bun or Go installation. The package is importable:

```go
client, err := platformsession.New(config)
if err != nil { return err }
defer client.Close()
identity, err := client.Check(ctx)
if err != nil { return err }
// Separately enforce the operation's signed profile.
// Use identity.SPIFFEID and identity.Delegation for their distinct audit roles.
```

`Check` generates a fresh 256-bit nonce, rereads the protected credential and
makes a new HTTPS request every time. It validates the exact tenant, agent,
repository, trust domain, purpose, nonce, time, expiry and historical assurance.
It caches neither credentials nor success. TLS uses an explicitly provisioned CA
bundle and TLS 1.3, with redirects and ambient proxies disabled. Request duration
is bounded to five seconds and the response to 16 KiB. Duplicate keys, case
aliases, missing fields, unknown fields, null and malformed JSON are refused.

Configuration, CA and credential files must be absolute, regular, `0600` and
owned by the service user; final-component symlinks are refused. Their containing
directories and the executable must also be protected by deployment. These files
are service inputs and must never be mounted in an agent worker. The refresh
credential remains a bearer: this adapter does not provide a hardware-bound key,
proof of possession or an X.509 SPIFFE SVID.

Example configuration shape (identifiers and paths are placeholders):

```json
{
  "endpoint": "https://platform.example/api/agent/session-check",
  "caFile": "/protected/platform-ca.pem",
  "credentialFile": "/protected/agent-refresh-credential",
  "tenantID": "11111111-1111-4111-8111-111111111111",
  "agentID": "22222222-2222-4222-8222-222222222222",
  "repositoryID": "33333333-3333-4333-8333-333333333333",
  "trustDomain": "platform.example",
  "minimumEnrollmentAAL": "aal2",
  "requireCurrentHumanAAL": ""
}
```

`repositoryID` is the exact platform repository row, not its URL or a GitHub ID.
The endpoint supports existing `LISTED` enrollments with an explicit current
tenant binding; empty scopes, legacy unbound repositories and future `ALL`
enrollments fail closed. Its independent source-address rate limit is 60/minute,
3,600/hour with burst 20 and a 6,000/minute global ceiling. Fleet deployments
must size and review that admission budget; identity checks never borrow the
signing exchange's rate-limit bucket.

## Local UAT

From this directory, with an installed Go toolchain and cached monorepo
dependencies:

```sh
GOWORK=off go build -trimpath -o /tmp/hardened-session-check ./cmd/hardened-session-check
# Parked: uat.py compiled the platform's agent-session handler from a monorepo
# checkout, and that handler is not available to this repository. It refuses
# with that message. The client is covered by client_test.go (hostile servers)
# and by cmd/session-platform-fixture, which vm/uat-session.py runs.
GOWORK=off python3 -B uat.py --go /absolute/go --report /tmp/hc04-uat.json
GOWORK=off python3 -B uat.py --gateway --go /absolute/go --report /tmp/hc04-gateway-uat.json
```

The harness disables dependency fetching. It compiles the real native client,
runs its malicious-response tests, then invokes that binary from the actual
platform handler tests over local TLS. The platform uses its real ent/SQLite
credential lookup, privacy, repository and revocation code with synthetic
enrollment records. Positive authentication is not served by a handwritten mock.
Negatives cover live revocation between operations, pending/expired/contained
principals, changed repository scope, real signing/upload-token substitution,
JSON ambiguity, forged response bindings, TLS trust, redirects and unsupported
current-human assurance. Reports bind source hashes and the native executable.

`--gateway` also compiles the native model gateway and connects its real platform
client to that handler. A synthetic provider verifies that authenticated audit
attribution is durable before receiving a request. The journey removes repository
scope, revokes the agent and breaks the TLS connection between operations; each
denial must produce no additional provider traffic. Forged worker identity fields
and headers cannot replace the platform identity. The collector checks distinct
agent and historical human delegation fields without claiming current human
presence. Startup tests reject absent production authentication, mismatched
assignments and unprotected configuration. Loopback provider and collector URLs
are enabled explicitly for this fixture; the platform check remains required.

A check describes platform state at that request; it is not an atomic lease
against a later revocation. Call immediately before each operation, deny on
outage, and never persist an old success as authorization. New or historical
enrollment, current Kratos ceremonies, model grants, hardware attestation and
release qualification remain separate interfaces.
