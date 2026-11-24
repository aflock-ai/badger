# Badger management portal

> **Now one service with the model broker.** The portal runs inside `badger-broker` on its admin
> listener at `/admin/portal/`, behind the broker's admin check (IdP sign-in with an admin group;
> the portal's directory then decides admin, approver or auditor by IdP subject). Its state is in
> the service's Postgres database, and its signing key is a mounted key file behind `sign.Signer`.
> The separate VM program, its mTLS client certificates, systemd credential and data directory
> described below are gone; read those parts as history.

Status: design plus a first vertical slice (sign a profile, prove admission accepts it, list
it). Code: [`portal/`](portal/). API: [`portal/api/openapi.yaml`](portal/api/openapi.yaml).
Conformance suite: [`portal/contract/`](portal/contract/).

## Purpose

An enclave administrator needs one place to say what every Badger workstation may do: which
signed profile it runs, which connectors it may use and at what classification, which model
gateway it talks to, and which devices are enrolled. The portal is that place. It runs on one
VM inside an air-gapped enclave with no TestifySec platform, no internet and no package
registry. It authors and signs; workstations pull. It never pushes into a workstation.

The portal does not run sessions, hold model or service credentials, or evaluate evidence.
It produces signed configuration that the existing native admission path already verifies.

## Deployment

- **One static Go binary** (`portal`, `CGO_ENABLED=0`), one JSON config file, one data
  directory that the installer creates (0700); the portal refuses to create it, so its entry
  is durable before any version is acknowledged. Linux VM, systemd unit, its own unprivileged user. No container runtime needed.
- **TLS only.** The listener serves HTTPS with the enclave's server certificate and verifies
  client certificates against the enclave CA (`clientCa`). There is no plaintext port.
  `/healthz` answers without a client certificate; everything else needs one.
- **One process per data directory.** The portal takes an exclusive lock on the audit log
  for its lifetime; a second process on the same directory refuses to start.
- **Offline.** No outbound connections. The binary embeds its HTML; there is no JavaScript
  build and, in v1, no JavaScript at all (`Content-Security-Policy: default-src 'none'`).
- **Signing key** is never plaintext on disk. It is a systemd encrypted credential:
  `portal -generate-key | systemd-creds encrypt --with-key=tpm2 --name=portal-signing-key -
  /etc/credstore.encrypted/portal-signing-key` (`--with-key=host+tpm2` or `host` where the VM
  has no TPM), and the unit has `LoadCredentialEncrypted=portal-signing-key`. systemd
  decrypts it at start onto a non-swappable ramfs only the service can read; the portal loads
  it only from `$CREDENTIALS_DIRECTORY` (config `signingKeyCredential`) and refuses to start
  without one. A copied disk or backup holds only the sealed blob. A PKCS#11 token comes
  later. The key never leaves the process; the API has no export.
- **Backup:** stop the service (or snapshot the VM), copy the data directory. Every file
  in it is append-only or write-once, so a copy taken between writes is consistent. The
  signing key is backed up separately under the enclave's key-custody procedure, or not at
  all if it lives in an HSM. **Restore:** copy back, start, run `portal verify-audit` (PR 9),
  then check that the highest stored sequence of each profile is at least what workstations
  last saw. Restoring an older backup and signing again would reuse sequence numbers; the
  portal refuses to start if the data directory's audit head is older than the last
  exported anchor (PR 9).

### Decisions

| Decision | Choice | Why |
|---|---|---|
| Module | `testifysec/portal` is its own Go module, like `broker`, `gateway`, `native` | Separate dependency graph and review surface; the connectors module stays dependency-free |
| Dependencies | Production binary: **0 third-party modules** (`go list -deps .` is stdlib plus the portal's own packages). Tests: Rookery `attestation v0.1.0` plus its 9 indirect modules, at the exact versions `testifysec/native` pins (41 `go.sum` lines) | The binary signs with stdlib crypto. The tests verify with the same library and version the native verifier links, which is the only honest way to claim compatibility |
| Storage | Plain files: `profiles/<id>/<sequence>.json` written once via `link(2)`; `audit.jsonl` append-only with a hash chain | Writes are a few per day. Files need no driver (the pure-Go SQLite driver is about 15 modules), back up with `cp`, and make write-once a filesystem property. Revisit if queries over devices get heavy; `DeviceRegistry` can move to SQLite without touching callers |
| Interfaces | `ProfileStore`, `AuditSink`, `DeviceRegistry` (`internal/store`), `Signer` (`internal/sign`), `Authenticator` (`internal/web`) | Each is the seam a platform-backed implementation replaces |
| UI | `html/template`, server-rendered, forms posting to the same API | No npm, no build step, works in a locked-down enclave browser |

## Objects and lifecycle

| Object | Lifecycle | Notes |
|---|---|---|
| Profile | created by first version; never deleted | ID is an admission identifier. Bound to one deployment for life |
| Profile version | draft → approved by a second person → signed → activated | Immutable once signed. Sequence assigned by the server: `max(minimumSequence, latest + 1)` |
| Activation record | per deployment: signed → served to every device in it → superseded | "Deployment X runs profile digest D at sequence N, valid until T". The broker verifies it, moves its pinned digest and raises its persisted high-water sequence (below) |
| Rollback | sign a new version whose content equals an older one, then activate it | Never re-pins an old digest; the sequence still increases |
| Assignment | device group = deployment → profile | Decided: a deployment is the device group; a staged rollout puts canary devices in their own deployment. Admission binds tenant, deployment and profile in its trust input; the activation record names the digest |
| Connector entry | per profile: name, base URL, marking, writes, token source | Rides in profile schema v3 (below); admission does not accept it yet |
| Model gateway | endpoint, accredited marking | Same: profile v3 |
| High-water reset record | admin requests → approver approves → signed → served to one device → consumed | The only way to lower a device's high-water (below) |
| Device | pending → enrolled → revoked | A cilock-enrolled identity: the device key (TPM or Secure Enclave custody) and its proof of possession. Keyed by the key's SPKI SHA-256 |
| Audit record | append-only | who, role, action, object, before/after digest, previous-line hash |

## Screens

1. Profiles: list (this change), version history, diff between versions, sign, publish, roll back.
2. Profile editor: validity window, deployment, and (v3) connectors, gateway, permissions.
3. Approvals queue (two-person rule, PR 10).
4. Connectors catalog: the release's signed connectors (Jira, Confluence, GitLab) with digests.
5. Model gateways: endpoint and accredited marking.
6. Devices: pending enrollments, enrolled, revoked; per-device assigned profile and last pull.
7. Trust export: the admission trust input for the build administrator.
8. Audit: filter, view, export (JSONL and signed bundle).

## HTTP API

Open spec in `portal/api/openapi.yaml`. Paths are under `/api/v1`. The tenant comes from
the deployment (or, on a platform, the credential), never from the path. JSON bodies reject
unknown fields. Errors are RFC 9457 `application/problem+json` with an extra `error` member
holding the stable code, so a client that reads a bare `{"error": code}` body also works.

| Method and path | Role | Status |
|---|---|---|
| `GET /api/v1/profiles` | admin, approver, auditor | this change |
| `POST /api/v1/profiles/{id}/versions` | admin | this change (sign directly; becomes "draft" with PR 10) |
| `GET /api/v1/profiles/{id}/trust` | admin, auditor | this change |
| `GET /api/v1/profiles/{id}/versions[/{seq}[/envelope]]` | admin, approver, auditor | PR 2b (history newest first; envelope byte-for-byte with `ETag`) |
| `GET/PUT /api/v1/deployments/{id}/assignment` | read: all roles; write: admin | PR 2b: forward only (an older sequence or another profile is 409 `rollback`); audited |
| `GET/PUT /api/v1/connectors`, `GET/PUT /api/v1/gateways` | admin | PR 7 |
| `POST /api/v1/devices` (cilock enrollment request), `POST /api/v1/devices/{id}/approve`, `.../revoke` | device; admin | PR 8 |
| `GET /api/v1/device/nonce`, `POST /api/v1/device/profile` | enrolled device | spec'd; PR 8 |
| `POST /api/v1/deployments/{id}/activations` | admin | PR 6 |
| `POST /api/v1/devices/{id}/resets` | admin | PR 6 |
| `POST /api/v1/approvals/{id}/approve`, `.../reject` (versions, activations, resets) | approver | PR 10 |
| `GET /api/v1/audit?after=` , `GET /api/v1/audit/export` | auditor, admin | PR 9 |
| `POST /api/v1/evidence` | enrolled device | spec only; out of v1 |
| `GET /.well-known/badger-portal` | none | PR 2b: discovery (`specVersion`, `apiBase`, payload type, authentication); names no tenant, deployment or key |

**Workstation pull.** The device authenticates with its cilock device key, the same
proof-of-possession pattern cilock enrollment uses: `GET /api/v1/device/nonce`, then
`POST /api/v1/device/profile` with `{nonce, proof}`, where `proof` is a compact ES256 JWS by
the enrolled device key over the nonce, the key thumbprint and the portal's audience. The
portal checks the device is enrolled and not revoked, finds its deployment, and returns
`{envelope, activation}`: the profile envelope and the current activation record, both
byte-for-byte as signed. A revoked or unknown device gets 403 and nothing else. The
workstation polls (every 15 minutes and at session start), admits both, and keeps its last
admitted pair if the portal is unreachable or the new pair is refused. Pull is the only
path; the portal holds no workstation address.

**Evidence ingest (spec only).** `POST /api/v1/evidence` takes one DSSE envelope (session
record signed by the workstation's enrolled key) and returns `{"gitoid": ...}`, the same
upload/download-by-gitoid contract as the open-source Archivista API, so a deployment can
put a real Archivista behind the portal later. v1 stores nothing; the endpoint is reserved.

## Authentication and roles

- **mTLS client certificates** (CAC/PIV) now: the TLS layer verifies the chain against
  `clientCa`, and the verified leaf's subject is the person's identity. A presented but
  unverified certificate is refused (tested). Roles come from the user directory below.
- **Enclave OIDC** (Keycloak, ADFS, on-premises Entra) next (PR 11): authorization code with
  PKCE against the configured issuer, roles from a group claim. A second `Authenticator`.
- No local password database, ever.
- Roles: **admin** (author, sign, assign, connectors, devices), **approver** (approve or
  reject a signed draft), **auditor** (read everything, export audit). A principal has one role.
- **Users** (PR 3, 3a, 3b; model: `formal/onboarding`): a directory of people the enclave
  already vouches for: identity, status (`pending`, `active`, `offboarded`), one role or none,
  deployment memberships. No passwords or local accounts; only active people with a role act
  (else 401).
  - **Invite, activate, grant.** Admin invites (pending) or requests a role for an active
    user; an approver who is neither requester nor subject approves. Drop-role is immediate.
  - **A person's authorized classification level is not the portal's.** The data
    classification level a person is authorized for is delegated to an external service; the
    portal neither stores nor decides it, and membership does not check it. The portal handles
    classification markings only, on connectors, gateways and deployments.
  - **Offboard** (IdP or admin) is final: role, memberships, owned devices and pending
    requests all cleared in one step. Each successful write appends one audit record.
  - **Bootstrap.** Config `bootstrap` names one subject per role (`admin`, `approver`) and
    works only until a user first holds that role; then it ends for good (a durable marker),
    even if every holder is later offboarded. Recovery is an offline operator step.
- **Two-person publish** (decided, PR 10) is a portal workflow with one signing key: an
  admin's version, activation or reset stays a draft until a different principal with the
  approver role approves it, and only then does the portal sign. Admission sees one
  signature, so this rule protects against a single rogue admin account, not against
  whoever controls the portal VM or its key (threat model). Two independent signatures
  (admission `threshold: 2`) stay available later; the signer and the slice test already
  support them.

## Signing

`Signer` is `KeyID()`, `PublicKeyPEM()`, `Sign(message)`. The credential key wraps any
`crypto.Signer`; a PKCS#11 module exposes the same interface, so an HSM is a new constructor
and nothing else. Only ECDSA P-256 is accepted. Every signature uses DSSE v1
pre-authentication encoding, SHA-256, ASN.1 ECDSA, and `keyid` = hex SHA-256 of the SPKI
PEM, which is what Rookery computes.

**Decided: admission verifies certificate chains.** The portal and the platform both sign
with a leaf certificate that chains to a root CA pinned in admission's trust (the enclave
CA, or the platform's), instead of admission pinning each signing key. Rotating a portal
key then needs a new leaf, not a new admission build. Rookery's DSSE signature already has
`certificate` and `intermediates` fields; today `native/verify.go` refuses them, so:

1. Now (this change): the envelope has exactly `payloadType`, `payload`,
   `signatures[{keyid, sig}]`, which today's admission accepts, and the trust export lists
   the portal's public key.
2. PR 3 (native and broker): admission trust gains `rootCas` (PEM) and a signer identity
   constraint (subject or SAN the leaf must carry, plus extended key usage); the verifier
   builds the chain at the profile's `notBefore`, checks the constraint, and keeps the
   pinned-key path for existing builds. One trust input selects one mode, no fallback.
   Decided: no CRLs. Portal leaves are short-lived (7 days) and re-issued by the enclave
   CA. The verifier checks the chain at the signed `notBefore` and also requires the whole
   signed window `[notBefore, expiresAt)` to lie inside the leaf's validity. Without that
   second rule a stolen leaf key could sign a backdated `notBefore` and a far `expiresAt`
   and outlive the leaf; with it, a stolen key's signatures die with the leaf.
3. PR 5 (portal): `Signer` gains `Chain() [][]byte`; the portal makes a CSR from its key,
   the enclave CA issues the leaf, and every signature carries `certificate` and
   `intermediates`. The trust export lists the root, not the key.

## Mapping to native admission

Payload (`managed/profile.ts`, payload type
`application/vnd.testifysec.hardened-opencode.profile.v1+json`):

| Admission field | Portal source | Rule enforced by the portal before signing |
|---|---|---|
| `schemaVersion` | constant `1` | v2 (`backend`) in PR 2c |
| `profileId` | path `{id}` | identifier grammar; fixed to one deployment for life |
| `tenantId` | config `tenantId` | identifier |
| `deploymentId` | request `deploymentId` | identifier; must equal the profile's first version |
| `sequence` | server: `max(minimumSequence, latest + 1)` | 1 to 2^53−1; never client-chosen (400) |
| `notBefore`, `expiresAt` | request | `YYYY-MM-DDTHH:MM:SSZ`, round-trips (no Feb 30), end after start |
| `controls` | constant `{false, "broker-only", "required"}` | the only value v1 accepts |
| envelope `payloadType` | constant above | |
| `signatures[].keyid` | hex SHA-256 of the signer's SPKI PEM | equals Rookery's `KeyID()` (tested) |
| `signatures[].sig` | ECDSA P-256 over SHA-256(PAE) | verified by Rookery (tested) |
| envelope size | | ≤ 65 536 bytes, the broker's bound |

Trust input (`managed/README.md`, compiled into `hardened-admission` at build time), from
`GET /api/v1/profiles/{id}/trust`:

| Trust field | Portal source |
|---|---|
| `publicKeys` | every configured signer's PEM |
| `threshold` | number of signers |
| `tenantId`, `deploymentId`, `profileId` | the profile's latest version |
| `minimumSequence` | the latest sequence (the build administrator may choose lower) |

Admission output, then checked by `broker/admission.go` and `broker/vzbackend/admission.go`:
`payloadSha256` = the version's `payloadSha256`, which the broker policy pins as
`profileSha256`; `envelopeSha256` = the version's `envelopeSha256`; `signerKeyIds` = the
version's `signerKeyIds`. The slice test checks all three against Rookery's own output.

**What the test proves.** `internal/issue/admission_test.go` signs through the portal, then
verifies the way native admission does: Rookery `dsse`/`cryptoutil` v0.1.0 with pinned SPKI
keys and threshold, exact envelope and signature fields, and a Go port of `admitProfile`
(exact keys, number grammar, identifier, sequence, instant, controls, assignment, validity,
rollback floor). It accepts portal output with one and two signers, and refuses a tampered
envelope, another portal's key, a raised floor (`profile-rollback`), a moved deployment
(`assignment-mismatch`) and an expired window (`profile-time-invalid`). Changing the PAE
prefix makes it fail.

**Against the compiled executable** (`portal/uat.py`): `cmd/portal-uat-fixtures` signs
through the portal's own issuer and writes the trust input the portal exports; the UAT builds
`hardened-admission` from it with `managed/build.py` and runs the executable. The current
version is admitted with the portal's recorded payload digest, envelope digest, signer key IDs
and sequence; the previous version is `profile-rollback`, a tampered envelope and another
portal's key are `profile-signature-invalid`, and a profile for another deployment is
`assignment-mismatch`. Run it with `python3 portal/uat.py --go GO --bun BUN --report R` from a
git checkout (the native build records the revision); it is not yet a pushgate step.

**Profile v3** (`managed/profile-v3.ts`, payload type
`application/vnd.testifysec.hardened-opencode.profile.v3+json`). A create request with
`"schemaVersion": 3` adds `gateway` (`{classification}`, the marking the model gateway is
accredited for) and `connectors` (the entries admission v3 reads; `[]` for none). Without
`schemaVersion`, or with 1, the portal signs v1 exactly as before, and refuses `gateway` or
`connectors`. The same key and envelope rules apply. Before signing the portal refuses what a
consumer would refuse later (`internal/profile/v3.go`): every admission v3 rule (connector
catalog and flags, or for a plugin outside the catalog the connector pod's name and flag
rules, binary pin, https base URL, absolute paths, permission keys, notice text,
markings, at most 16 entries, no repeated name), any connector the gateway's marking does not
dominate (`managed-connectors.ts` and gateway v3 refuse such a profile), and a profile whose
admission output would exceed 16 384 bytes, the most gateway v3 reads from admission. The
base URL check fails closed: it is stricter than admission's WHATWG parser wherever the two
could read a URL differently, and refuses some URLs admission would accept. Refused: a non-ASCII,
%-escaped or punycode (`xn--`, valid or not) host; a numeric last label that is not a dotted-quad
IPv4 address; brackets around anything but an IPv6 literal (so no IPv4-mapped or zoned
addresses); an empty label or trailing dot; an underscore; port 0. Use a plain ASCII DNS name,
IPv4 address or IPv6 literal.
`GET .../trust` returns `schemaVersion` 3 for a profile whose latest version is v3, since an
admission build accepts one schema. `internal/issue/v3_test.go` signs through the portal,
verifies with Rookery under the v3 payload type, admits with a Go port of `admitProfileV3`,
reads the admission line as gateway v3 does, and refuses each payload field changed after
signing. The connector pod (`conngw`) is not configured from this profile: it checks each
bridged stream's declaration (classification, writes, flags) against its own profile, which is
signed separately with an ed25519 administrator key.

**Activation record (decided; PR 4 against the broker, PR 6 in the portal).** DSSE payload
type `application/vnd.testifysec.badger.activation.v1+json`, same signing rules:

```json
{
  "schemaVersion": 1,
  "tenantId": "tenant-example",
  "deploymentId": "deploy-a",
  "profileId": "engineering",
  "profileSha256": "<64 hex: payloadSha256 of the activated version>",
  "profileSequence": 12,
  "sequence": 40,
  "notBefore": "2026-10-22T00:00:00Z",
  "expiresAt": "2026-10-29T00:00:00Z"
}
```

`sequence` is the activation's own counter per deployment, assigned by the portal like a
profile sequence. The broker verifies the record, requires its tenant, deployment and
profile to match its trust, requires `sequence` above its persisted activation high-water
and `profileSequence` at or above its persisted profile high-water, writes both new
high-waters durably, and only then replaces its pinned `profileSha256`. A profile envelope
whose payload digest is not the activated digest is refused. Rollback is a new version and
a new activation, both higher.

**High-water state and reset (decided; PR 4).** The broker keeps two counters per device
(activation and profile high-water) in a 0600 state file, written with fsync and rename
before a new pin takes effect. A missing file never resets them:

- At install, the installer writes a **first-install marker** beside the state file. With
  the marker present and no state yet, the broker accepts the compiled floor once, writes
  state, and from then on the marker records "activated".
- With the marker in the activated state and the state file missing or unreadable, the
  broker **fails closed**: it refuses every session until it admits a reset record.
- A **reset record** (`application/vnd.testifysec.badger.reset.v1+json`) is the only way to
  lower or re-establish the counters: `{schemaVersion, tenantId, deploymentId,
  deviceKeySpkiSha256, resetSequence, profileFloor, activationFloor, notBefore,
  expiresAt}`, signed by the portal after two-person approval, bound to one device key,
  with `resetSequence` above the last reset the device consumed (kept in the same state).
  The pull response carries it when one is pending for that device.

Residual: a device administrator who deletes both the marker and the state makes the
device look newly installed, so it falls back to the compiled floor. Files owned by root
cannot stop root. Where the device has a TPM (cilock enrollment already uses one), PR 4b
moves the counters into a TPM NV index, which deleting files does not touch.

**What the Go broker checks itself.** The contract model (`formal/contract`, AsBuilt) found
that the schema-1 Go path (`broker/admission.go`) binds the profile only through the pinned
payload digest and never reads tenant, deployment, profile or sequence (the native
verifier it runs does check the assignment against its compiled trust), and that with the
development flag set and no verifier configured it admits a request with no envelope. PR 4
makes the broker check tenant, deployment, profile and sequence itself against the
activation record and refuses the no-envelope case outside an explicitly named test build.

**Profile schema v3 (connectors and gateway).** v1 controls are fixed and v2 adds only
`backend`, so neither can carry connectors. CONNECTORS.md already plans a new schema version
with a `connectors` array (`name`, `binarySha256`, `baseUrl`, `tokenPath`, `caPath`,
`writes`, `classification`, `permissions`). The portal will add `gateway: {endpoint,
classification}` beside it and emit v3 only after admission accepts v3. Markings are
validated with the connectors `marking` package (PR 7 moves it out of `internal/`), so a
banner the portal accepts is one a connector accepts.

## Threat model

| Threat | Control | Residual |
|---|---|---|
| Compromised admin account | Role separation; two-person publish (PR 10); every action audited with actor and digests | One admin can sign alone until PR 10. After it, anyone who controls the portal VM, its process or its signing key can still publish alone, because admission sees one signature; admission `threshold: 2` with a second, separately held key is the future fix |
| Stolen session | No bearer cookies in v1: each request carries a client certificate from the card. OIDC sessions (PR 11) will be short, bound to the TLS session, and re-authenticated for signing | A logged-in workstation left unlocked |
| Cross-site request forgery | Browsers send the CAC certificate on every request, so state-changing requests must pass Go's cross-origin check (`Sec-Fetch-Site`/`Origin`) and carry `Content-Type: application/json`, which no cross-origin form or CORS-simple request can send (tested) | A same-origin XSS would bypass it; the pages run no script and send `default-src 'none'` |
| Malicious profile edit | Server-side validation mirrors admission; the server, not the client, sets tenant, sequence and controls; a profile cannot move deployment | An authorized admin can still widen a v3 profile; that is what review is for |
| Replay of an old envelope or activation | Sequences increase on every signature; rollback re-signs; after PR 4 the broker keeps a persisted per-device high-water and refuses anything below it | Until PR 4 the floor is compiled in and does not ratchet, so an old envelope at or above it stays valid until `expiresAt` (7 days, re-signed on a schedule). After PR 4, deleting the state file fails closed; deleting the state and the first-install marker falls back to the compiled floor until the TPM-backed counter (PR 4b) |
| Rollback by restoring a backup | Audit hash chain and exported anchors (PR 9) | Before PR 9, an operator restoring an old backup can reissue used sequences |
| Signing key theft | systemd encrypted credential (TPM2-sealed where available), decrypted only into the service's ramfs; never exported; HSM later; after PR 3/5 the key is a short-lived leaf under the enclave CA, and admission requires the signed window inside the leaf's 7-day validity, so a stolen key stops working when its leaf expires | Root on the running VM can read the decrypted credential; a host-key-only seal (no TPM) is as safe as the host key file; no CRLs, so a stolen key is good for up to 7 days |
| Audit tampering | Hash chain: editing or deleting a line breaks the next line's `prev` (tested). A failed write or fsync stops all further appends, and so all signing, until an operator reopens the log; reopening refuses a torn last line or a broken chain (tested) | Truncating the tail is invisible until heads are anchored in signed exports (PR 9) |
| Network attacker on pull | TLS, device-key proof bound to a portal nonce; the envelope and activation are signed, so the transport cannot alter them | A blocked pull leaves the device on its last admitted profile until it expires |
| Rogue device | Enrollment is a cilock device-key enrollment approved by an admin; revocation refuses pulls with 403 | A revoked device that stays offline keeps its last admitted pair until the activation's `expiresAt` (at most 7 days) |

## Open spec and platform compatibility

Badger is open source; the portal API is a Badger specification (`api/openapi.yaml` plus
`contract/`). A platform plugs in by implementing the spec and passing the suite: `contract.Run`
takes the base URL and an HTTP client per role, so it runs from a test against any
implementation. Badger's own portal runs it in-process:

```sh
go test -run TestContractInProcess ./internal/web
```

so the two cannot drift silently. Against a live implementation it writes signed test
profiles, so point it at a test deployment.

Where the TestifySec platform already has the concept, roughly:

| Spec capability | Platform today | Gap the platform would close |
|---|---|---|
| Signed, immutable versions with explicit binding | Has signed policy releases and bindings | Profiles and activation records are new objects. The platform signs with leaf certificates, but they live minutes, not days. Under the window-inside-leaf rule its profiles would expire in minutes, so PR 3 must also accept a trusted RFC 3161 timestamp as proof the signature was made inside the leaf's life, or the platform issues 7-day leaves for profiles |
| Device approval and revocation | Has administrator approval and revocation of devices | Map an approved device to a deployment assignment; serve `POST /api/v1/device/profile` |
| Device identity | Uses cilock agent enrollment with TPM or Secure Enclave device keys | Same identity in both: the portal's registry accepts cilock-enrolled device keys, so a device enrolls the same way against either |
| Evidence upload by gitoid | Has an Archivista-compatible store | Accept the session-record envelope at `POST /api/v1/evidence` |
| Admin audit | Has an internal admin audit log | Expose it as the spec's JSONL and signed export |
| Error bodies | Similar `{"error": code}` bodies | Compatible: the spec's problem documents carry `error` too |
| Connectors, markings, gateway accreditation | None | New in this spec |

**Platform-backed mode** changes implementations, not callers: `ProfileStore`,
`DeviceRegistry` and `AuditSink` become API clients of the platform, `Signer` becomes a
leaf-certificate signer under the platform's CA, and `Authenticator` accepts the platform's tokens. Alternatively a
workstation is pointed straight at the platform's implementation of the spec. Either way
the envelope bytes and admission are unchanged.

## Settled decisions (2026-10-22)

1. Admission verifies signatures through a certificate chain to a pinned root CA; the portal
   and the platform sign with leaf certificates.
2. The portal signs activation records, one per deployment; the broker verifies them, moves
   its pinned digest and keeps a persisted per-device high-water sequence, reset only by a
   portal-signed reset record.
3. Device identity reuses cilock's device-key enrollment (TPM EK, Secure Enclave); no
   parallel scheme.
4. Two-person publish is an approver click in the portal with one signing key. Portal
   signing leaves are 7-day certificates re-issued by the enclave CA, no CRLs.
5. Defaults: 7-day validity with scheduled re-signing; deployment = device group; v1 sized
   for hundreds of devices (plain files are enough); the portal exports trust files and does
   not drive admission rebuilds.

## Answers to the contract model's portal questions (`formal/contract/Contract/Portal.lean`)

1. **Rollback** is a republish of version N's content as a new, higher sequence, activated
   by a new, higher activation record. Re-pinning N's digest is never offered; after PR 4
   the broker refuses it through its high-water.
2. **Revocation** is enforced where profiles are delivered: a revoked device gets 403 from
   the pull and never receives a new profile or activation. An offline revoked device is
   bounded by the activation's `expiresAt`, at most 7 days; nothing else bounds it.
   Activation is per deployment, so revoking one device never needs a new activation for
   the others.
3. **Enrollment** binds a cilock device key to the tenant (the portal's) and to a deployment
   (the device group the admin approves it into). The binding the broker reads is the
   activation record, signed by the portal, replacing today's locally written assignment
   digest.
4. **Trust:** today the portal's public key is exported for the build's trust input. After
   PR 3 admission pins the enclave root CA instead and the portal signs with a leaf under
   it, so rotating the portal key is a new leaf, not a rebuild. The root itself changes only
   through a new trust file and build.
5. **High-water** lives on the device in a broker-owned state file (TPM NV index where
   available, PR 4b). It is reset only by a portal-signed, device-bound reset record after
   two-person approval. A missing state file after first activation fails closed; it never
   resets the counters.
6. **Floor:** yes. The native verifier (`managed/profile.ts`) refuses a sequence below the
   compiled `minimumSequence` with `profile-rollback`; the Go broker does not re-check it
   today (PR 4 adds the check).

## Follow-up changes (each ≤ 600 lines)

1. **This change.** Design, module, interfaces, sign-and-verify slice, profile list page,
   open spec for the slice, contract suite and runner.
2. Portal: `portal/uat.py`, which runs the compiled `hardened-admission` on portal output
   2b: version history and envelope read, deployment assignment, discovery
   document. 2c: profile v2 (`backend`).
2u. Portal users. PR 3: directory, identities from the verified certificate, bootstrap,
   provisioning, audited. PR 3a: role requests with approver decisions (no
   self-approval), activation of pending users, immediate drop-role. PR 3b: deployment
   membership add and remove (no authorized classification level; see above). PR 3c (this change): offboard,
   pending-request queue, read-only users page (`/users`). Replay of the onboarding model's
   vectors follows once they are on main.
3. **Native and broker: certificate-chain admission.** `native/verify.go` accepts
   `certificate`/`intermediates`, verifies the chain to `rootCas` at the profile's
   `notBefore`, enforces the signer identity constraint; trust schema and `profile.ts` gain
   the chain mode; existing pinned-key builds unchanged. Fixtures and UAT cases for wrong
   root, expired leaf, missing constraint.
4. **Broker: activation records and high-water.** Verify the activation record through the
   same native verifier, check tenant/deployment/profile/sequence in Go, persist the
   high-waters with the first-install marker and fail-closed rule, verify reset records,
   move the pinned digest, refuse the no-envelope development path outside a named test
   build. Contract vectors for the device high-water (`admissionSequence`).
   4b. Broker: high-water counters in a TPM NV index when the device has a TPM.
5. Portal: leaf-certificate signer (CSR, chain in every signature), trust export of the
   root, 7-day leaf renewal from the enclave CA, scheduled re-signing inside the current
   leaf's validity.
6. Portal: activation records per deployment (`POST /api/v1/deployments/{id}/activations`),
   rollback as republish plus activation, device reset records
   (`POST /api/v1/devices/{id}/resets`) delivered in the pull.
7. Portal: connectors catalog and gateways; move `connectors/internal/marking` to
   `connectors/marking`; profile v3 behind a flag until admission accepts it.
8. Portal: devices from cilock enrollment (device key, custody kind, proof), approve into a
   deployment, revoke, nonce plus proof pull returning `{envelope, activation}`; pull
   client in `enrollment/`.
9. Portal: audit list, JSONL export, signed export bundle, `verify-audit`, refuse to start
   on an older head.
10. Portal: two-person approval (approver click, one signing key) for versions,
    activations and resets; drafts and approver queue.
11. Portal: enclave OIDC `Authenticator`; denied requests audited.
12. Portal: PKCS#11 `Signer` constructor, tested against SoftHSM.
13. Portal: evidence ingest endpoint backed by an optional Archivista.

## Open questions

None blocking. Recorded consequences of the decisions:

1. The platform's leaf certificates live minutes. With the window-inside-leaf rule its
   profiles cannot carry a 7-day window unless PR 3 also accepts an RFC 3161 timestamp, or
   the platform issues longer leaves for profile signing. PR 3 should pick one.
2. The profile's signed window must fit inside the signing leaf's 7-day life, so the portal
   needs a fresh leaf from the enclave CA at least as often as it re-signs. If the enclave
   CA cannot issue leaves that often, the window shrinks to what remains of the current leaf.
3. Reset by signed record only is as strong as the device's state storage: file-based
   counters stop a deleted state file, not a deleted install. The TPM counter (PR 4b) closes
   that where a TPM exists.
