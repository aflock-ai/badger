---
title: Portal API reference
description: The Badger management portal's HTTP API, generated from its OpenAPI specification.
sidebarLabel: Portal API
sidebarPosition: 20
---

# Portal API reference

The management portal's API is an open specification, so that the offline portal and the
TestifySec platform can serve the same contract. Paths are under `/api/v1`. The tenant comes from
the deployment or the credential, never from the path. JSON request bodies refuse unknown fields.
Errors are RFC 9457 `application/problem+json` documents whose `error` member holds a stable code.

Every route except discovery and the device routes requires a client certificate that the
portal verifies against the enclave CA. The certificate subject identifies the user, and the role
(`admin`, `approver` or `auditor`) comes from the portal's user directory.

The portal is on `main`. Operations marked "specified, not built" are part of the contract and
have no implementation yet.

<!-- BEGIN GENERATED: portal-api -->
Generated from `testifysec/portal/api/openapi.yaml`: Badger management portal API, version 0.7.0, OpenAPI 3.1.0.

| Method | Path | Status | Summary |
|---|---|---|---|
| GET | `/api/v1/profiles` | implemented | Latest signed version of every profile (admin, approver, auditor) |
| GET | `/api/v1/profiles/{profileId}/versions` | implemented | Every version of a profile, newest first, without envelopes (admin, approver, auditor) |
| POST | `/api/v1/profiles/{profileId}/versions` | implemented | Sign the next version (admin). The server assigns tenant and sequence. |
| GET | `/api/v1/profiles/{profileId}/trust` | implemented | Build-provisioned admission trust input for this profile (admin, auditor) |
| GET | `/api/v1/profiles/{profileId}/versions/{sequence}` | implemented | One version, without its envelope (admin, approver, auditor) |
| GET | `/api/v1/profiles/{profileId}/versions/{sequence}/envelope` | implemented | The DSSE envelope exactly as signed (admin, approver, auditor) |
| GET | `/api/v1/deployments/{deploymentId}/assignment` | implemented | The version a deployment (device group) runs (admin, approver, auditor) |
| PUT | `/api/v1/deployments/{deploymentId}/assignment` | implemented | Point a deployment at a signed version of its profile (admin) |
| GET | `/.well-known/badger-portal` | implemented | Discovery; public, names no tenant, deployment or key |
| GET | `/api/v1/users` | implemented | The user directory (admin, approver, auditor) |
| POST | `/api/v1/users` | implemented | Provision an identity the enclave PKI or IdP issued (admin). Pending, no role, until an approver activates it. Inviting a pending user with no open activation request issues one; otherwise 409. |
| POST | `/api/v1/users/{userId}/drop-role` | implemented | Remove an active user's role at once (admin); body {} |
| PUT | `/api/v1/users/{userId}/deployments/{deploymentId}` | implemented | Add an active user to a deployment (admin); body {} |
| DELETE | `/api/v1/users/{userId}/deployments/{deploymentId}` | implemented | Remove a membership (admin); body {} |
| POST | `/api/v1/users/{userId}/offboard` | implemented | Offboard (admin, not self); final. Clears role and memberships and drops pending requests by or about the user; body {} |
| GET | `/api/v1/role-requests` | implemented | The approver queue, pending requests only (admin, approver, auditor) |
| POST | `/api/v1/users/{userId}/role-requests` | implemented | Request a role for an active user (admin); nothing changes until an approver decides |
| POST | `/api/v1/role-requests/{requestId}/approve` | implemented | Approve (approver who is neither the requester nor the user) |
| POST | `/api/v1/role-requests/{requestId}/reject` | implemented | Reject (same rule as approve) |
| GET | `/api/v1/device/nonce` | specified, not built | One-use nonce for a device-key proof |
| POST | `/api/v1/device/profile` | specified, not built | A workstation pulls its signed profile, its deployment's activation record and any pending reset |

### GET /api/v1/profiles

Latest signed version of every profile (admin, approver, auditor)

Status: implemented. Authentication: `idpSession`.

Response `200`: Versions, without envelopes

`application/json`:

| Field | Type | Required | Description |
|---|---|---|---|
| `items` | array of `Version` | yes |  |

Response `default`: Error

`application/problem+json`: `Problem`

### GET /api/v1/profiles/{profileId}/versions

Every version of a profile, newest first, without envelopes (admin, approver, auditor)

Status: implemented. Authentication: `idpSession`.

| Parameter | In | Type | Required |
|---|---|---|---|
| `profileId` | path | `Identifier` | yes |

Response `200`: Versions

`application/json`:

| Field | Type | Required | Description |
|---|---|---|---|
| `items` | array of `Version` | yes |  |

Response `default`: Error

`application/problem+json`: `Problem`

### POST /api/v1/profiles/{profileId}/versions

Sign the next version (admin). The server assigns tenant and sequence.

Without schemaVersion (or with 1) the server signs a v1 profile. schemaVersion 3 signs a v3 profile (testifysec/managed/profile-v3.ts) and requires gateway and connectors; the server refuses any entry admission v3 would refuse, any connector marked above the gateway, and a profile whose admission output would exceed gateway v3's 16384-byte bound.

Status: implemented. Authentication: `idpSession`.

| Parameter | In | Type | Required |
|---|---|---|---|
| `profileId` | path | `Identifier` | yes |

Request body:

`application/json`:

| Field | Type | Required | Description |
|---|---|---|---|
| `schemaVersion` | `1`, `3` | no |  |
| `deploymentId` | `Identifier` | yes |  |
| `notBefore` | `Instant` | yes |  |
| `expiresAt` | `Instant` | yes |  |
| `gateway` | object | no |  |
| `connectors` | array of `Connector` (at most 16) | no |  |

Response `201`: Signed and stored

`application/json`: `Version`

Response `default`: Error

`application/problem+json`: `Problem`

### GET /api/v1/profiles/{profileId}/trust

Build-provisioned admission trust input for this profile (admin, auditor)

Exactly the schema testifysec/managed/README.md accepts; minimumSequence is the latest sequence.

Status: implemented. Authentication: `idpSession`.

| Parameter | In | Type | Required |
|---|---|---|---|
| `profileId` | path | `Identifier` | yes |

Response `200`: Trust input

`application/json`:

| Field | Type | Required | Description |
|---|---|---|---|
| `schemaVersion` | `1` | yes |  |
| `publicKeys` | array of string (at least 1, at most 16) | yes |  |
| `threshold` | integer (minimum 1) | yes |  |
| `tenantId` | `Identifier` | yes |  |
| `deploymentId` | `Identifier` | yes |  |
| `profileId` | `Identifier` | yes |  |
| `minimumSequence` | `Sequence` | yes |  |

Response `default`: Error

`application/problem+json`: `Problem`

### GET /api/v1/profiles/{profileId}/versions/{sequence}

One version, without its envelope (admin, approver, auditor)

Status: implemented. Authentication: `idpSession`.

| Parameter | In | Type | Required |
|---|---|---|---|
| `profileId` | path | `Identifier` | yes |
| `sequence` | path | string (pattern `^[1-9][0-9]{0,15}$`) | yes |

Response `200`: Version

`application/json`: `Version`

Response `default`: Error

`application/problem+json`: `Problem`

### GET /api/v1/profiles/{profileId}/versions/{sequence}/envelope

The DSSE envelope exactly as signed (admin, approver, auditor)

Status: implemented. Authentication: `idpSession`.

| Parameter | In | Type | Required |
|---|---|---|---|
| `profileId` | path | `Identifier` | yes |
| `sequence` | path | string (pattern `^[1-9][0-9]{0,15}$`) | yes |

Response `200`: Envelope bytes; sha256 equals the version's envelopeSha256

`application/vnd.dsse.envelope.v1+json`:

| Field | Type | Required | Description |
|---|---|---|---|

Response `default`: Error

`application/problem+json`: `Problem`

### GET /api/v1/deployments/{deploymentId}/assignment

The version a deployment (device group) runs (admin, approver, auditor)

Status: implemented. Authentication: `idpSession`.

| Parameter | In | Type | Required |
|---|---|---|---|
| `deploymentId` | path | `Identifier` | yes |

Response `200`: Assignment

`application/json`: `Assignment`

Response `default`: Error

`application/problem+json`: `Problem`

### PUT /api/v1/deployments/{deploymentId}/assignment

Point a deployment at a signed version of its profile (admin)

Forward only. An older sequence, or a different profile once one is assigned, is 409 rollback; roll back by signing a new version.

Status: implemented. Authentication: `idpSession`.

| Parameter | In | Type | Required |
|---|---|---|---|
| `deploymentId` | path | `Identifier` | yes |

Request body:

`application/json`:

| Field | Type | Required | Description |
|---|---|---|---|
| `profileId` | `Identifier` | yes |  |
| `sequence` | `Sequence` | yes |  |

Response `200`: Assignment

`application/json`: `Assignment`

Response `default`: Error

`application/problem+json`: `Problem`

### GET /.well-known/badger-portal

Discovery; public, names no tenant, deployment or key

Status: implemented. Authentication: none.

Response `200`: Discovery document

`application/json`:

| Field | Type | Required | Description |
|---|---|---|---|
| `specVersion` | string | yes |  |
| `apiBase` | string | yes |  |
| `profilePayloadType` | string | yes |  |
| `authentication` | array of `idp` | yes |  |

### GET /api/v1/users

The user directory (admin, approver, auditor)

Status: implemented. Authentication: `idpSession`.

Response `200`: Users

`application/json`:

| Field | Type | Required | Description |
|---|---|---|---|
| `items` | array of `User` | yes |  |

Response `default`: Error

`application/problem+json`: `Problem`

### POST /api/v1/users

Provision an identity the enclave PKI or IdP issued (admin). Pending, no role, until an approver activates it. Inviting a pending user with no open activation request issues one; otherwise 409.

Status: implemented. Authentication: `idpSession`.

Request body:

`application/json`:

| Field | Type | Required | Description |
|---|---|---|---|
| `kind` | `oidc` | yes |  |
| `subject` | string | yes | IdP subject |

Response `201`: The pending user and its activation request

`application/json`:

| Field | Type | Required | Description |
|---|---|---|---|
| `user` | `User` | yes |  |
| `activation` | `RoleRequest` | yes |  |

Response `default`: Error

`application/problem+json`: `Problem`

### POST /api/v1/users/{userId}/drop-role

Remove an active user's role at once (admin); body {}

Status: implemented. Authentication: `idpSession`.

| Parameter | In | Type | Required |
|---|---|---|---|
| `userId` | path | `Digest` | yes |

Response `200`: User

`application/json`: `User`

Response `default`: Error

`application/problem+json`: `Problem`

### PUT /api/v1/users/{userId}/deployments/{deploymentId}

Add an active user to a deployment (admin); body {}

Status: implemented. Authentication: `idpSession`.

| Parameter | In | Type | Required |
|---|---|---|---|
| `userId` | path | `Digest` | yes |
| `deploymentId` | path | `Identifier` | yes |

Response `200`: User

`application/json`: `User`

Response `default`: Error

`application/problem+json`: `Problem`

### DELETE /api/v1/users/{userId}/deployments/{deploymentId}

Remove a membership (admin); body {}

Status: implemented. Authentication: `idpSession`.

| Parameter | In | Type | Required |
|---|---|---|---|
| `userId` | path | `Digest` | yes |
| `deploymentId` | path | `Identifier` | yes |

Response `200`: User

`application/json`: `User`

Response `default`: Error

`application/problem+json`: `Problem`

### POST /api/v1/users/{userId}/offboard

Offboard (admin, not self); final. Clears role and memberships and drops pending requests by or about the user; body {}

Status: implemented. Authentication: `idpSession`.

| Parameter | In | Type | Required |
|---|---|---|---|
| `userId` | path | `Digest` | yes |

Response `200`: User

`application/json`: `User`

Response `default`: Error

`application/problem+json`: `Problem`

### GET /api/v1/role-requests

The approver queue, pending requests only (admin, approver, auditor)

Status: implemented. Authentication: `idpSession`.

Response `200`: Pending requests

`application/json`:

| Field | Type | Required | Description |
|---|---|---|---|
| `items` | array of `RoleRequest` | yes |  |

Response `default`: Error

`application/problem+json`: `Problem`

### POST /api/v1/users/{userId}/role-requests

Request a role for an active user (admin); nothing changes until an approver decides

Status: implemented. Authentication: `idpSession`.

| Parameter | In | Type | Required |
|---|---|---|---|
| `userId` | path | `Digest` | yes |

Request body:

`application/json`:

| Field | Type | Required | Description |
|---|---|---|---|
| `role` | `admin`, `approver`, `auditor` | yes |  |

Response `201`: Request

`application/json`: `RoleRequest`

Response `default`: Error

`application/problem+json`: `Problem`

### POST /api/v1/role-requests/{requestId}/approve

Approve (approver who is neither the requester nor the user)

Status: implemented. Authentication: `idpSession`.

| Parameter | In | Type | Required |
|---|---|---|---|
| `requestId` | path | string (pattern `^[0-9a-f]{32}$`) | yes |

Response `200`: Request

`application/json`: `RoleRequest`

Response `default`: Error

`application/problem+json`: `Problem`

### POST /api/v1/role-requests/{requestId}/reject

Reject (same rule as approve)

Status: implemented. Authentication: `idpSession`.

| Parameter | In | Type | Required |
|---|---|---|---|
| `requestId` | path | string (pattern `^[0-9a-f]{32}$`) | yes |

Response `200`: Request

`application/json`: `RoleRequest`

Response `default`: Error

`application/problem+json`: `Problem`

### GET /api/v1/device/nonce

One-use nonce for a device-key proof

Status: specified, not built. Authentication: none.

Response `200`: Nonce, valid for 60 seconds

`application/json`:

| Field | Type | Required | Description |
|---|---|---|---|
| `nonce` | string | yes |  |

### POST /api/v1/device/profile

A workstation pulls its signed profile, its deployment's activation record and any pending reset

The device proves possession of its cilock-enrolled device key (TPM or Secure Enclave custody): proof is a compact ES256 JWS by that key over the nonce, the key thumbprint and this portal's audience. Returns both documents exactly as signed for the device's deployment. 403 when unknown or revoked. The portal never pushes.

Status: specified, not built. Authentication: none.

Request body:

`application/json`:

| Field | Type | Required | Description |
|---|---|---|---|
| `nonce` | string | yes |  |
| `proof` | string | yes |  |

Response `200`: The current pair

`application/json`:

| Field | Type | Required | Description |
|---|---|---|---|
| `envelope` | object | yes | Profile DSSE envelope |
| `activation` | object | yes | Activation record DSSE envelope |
| `reset` | object | no | Pending device-bound high-water reset record (DSSE), present only when one awaits this device |

Response `default`: Error

`application/problem+json`: `Problem`

### Schemas

#### User

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | `Digest` | yes |  |
| `kind` | `oidc` | yes |  |
| `subject` | string | yes |  |
| `role` | ``, `admin`, `approver`, `auditor` | yes |  |
| `status` | `pending`, `active`, `offboarded` | yes |  |
| `createdAt` | string (date-time) | yes |  |
| `createdBy` | string | yes |  |
| `deployments` | array of `Identifier` | no |  |

#### RoleRequest

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes |  |
| `kind` | `activate`, `grant` | yes |  |
| `userId` | `Digest` | yes |  |
| `role` | ``, `admin`, `approver`, `auditor` | yes |  |
| `requestedBy` | string | yes |  |
| `requesterId` | `Digest` | yes |  |
| `requestedAt` | string (date-time) | yes |  |
| `status` | `pending`, `approved`, `rejected`, `dropped` | yes |  |
| `decidedBy` | string | no |  |
| `decidedAt` | string (date-time) | no |  |

#### Assignment

| Field | Type | Required | Description |
|---|---|---|---|
| `deploymentId` | `Identifier` | yes |  |
| `profileId` | `Identifier` | yes |  |
| `sequence` | `Sequence` | yes |  |
| `payloadSha256` | `Digest` | yes |  |
| `assignedAt` | string (date-time) | yes |  |
| `assignedBy` | string | yes |  |

#### Identifier

string (pattern `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

#### Instant

string (pattern `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

#### Sequence

integer (minimum 1, maximum 9007199254740991)

#### Digest

string (pattern `^[0-9a-f]{64}$`)

#### Connector

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | `jira`, `confluence`, `gitlab` | yes |  |
| `binarySha256` | `Digest` | yes |  |
| `baseUrl` | string | yes | https URL with a host; no credentials, query or fragment |
| `tokenPath` | string | yes | Absolute path |
| `caPath` | string,null | no | Absolute path, or null (also when left out) |
| `writes` | boolean | yes |  |
| `classification` | string | yes | The connector's marking; the gateway's must dominate it |
| `notice` | string (pattern `^[A-Za-z0-9 .,;:()'/-]{1,160}$`) | no |  |
| `flags` | object | yes | Only the flags the release lists for this connector |
| `permissions` | object | yes | Each key is the connector name, an underscore, then a tool name or * |

#### Version

| Field | Type | Required | Description |
|---|---|---|---|
| `profileId` | `Identifier` | yes |  |
| `tenantId` | `Identifier` | yes |  |
| `deploymentId` | `Identifier` | yes |  |
| `sequence` | `Sequence` | yes |  |
| `notBefore` | `Instant` | yes |  |
| `expiresAt` | `Instant` | yes |  |
| `payloadSha256` | `Digest` | yes |  |
| `envelopeSha256` | `Digest` | yes |  |
| `signerKeyIds` | array of `Digest` | yes |  |
| `createdAt` | string (date-time) | yes |  |
| `createdBy` | string | yes | Authenticated principal (IdP subject) |

#### Problem

RFC 9457 problem document; "error" repeats the stable code.

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes |  |
| `title` | string | yes |  |
| `status` | integer | yes |  |
| `detail` | string | no |  |
| `error` | `unauthenticated`, `forbidden`, `cross-origin`, `invalid-request`, `invalid-profile`, `sequence-conflict`, `rollback`, `not-found`, `store`, `issue-failed`, `assign-failed`, `conflict`, `invalid-state`, `users-failed` | yes |  |
<!-- END GENERATED: portal-api -->
