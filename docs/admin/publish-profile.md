---
title: Author, approve and publish a profile
description: Sign a profile version in the management portal, build the admission verifier that trusts it, and point the gateway at both.
sidebarLabel: Publish a profile
sidebarPosition: 30
---

# Author, approve and publish a profile

A profile takes effect when a component that verifies it, the model gateway or the session
broker, is given the signed envelope and an admission executable built to trust its signer. This
guide signs a version in the portal, builds that executable, and configures the gateway.

| Step | Status |
|---|---|
| Sign a version, assign it, export the trust input and the envelope in the portal | Available on `main` |
| Build the admission executable from a trust input | Available on `main` |
| Configure the gateway with the envelope and the executable | Available on `main` |
| Second-person approval, activation records, workstation pull | Designed, not built |

The portal is served by `badger-broker` on its admin listener at `/admin/portal/`, reached only
through your edge's admin route after IdP sign-in (see [deploy badger-broker](deploy-broker.md)).
The examples call its API with curl and whatever sign-in your edge accepts from a command line,
here a session cookie kept in a cookie file readable only by you. Never put the cookie itself on
the command line or in an environment variable: process arguments are visible to other users of
the host, and the cookie signs profiles until it expires.

```sh
PORTAL=https://edge.example.invalid/admin/portal
umask 077                                   # the cookie file is yours alone
portal() { curl -fsS -b ~/.config/badger/edge-cookies.txt "$@"; }
```

## 1. Sign a version in the portal

As a person with the portal's `admin` role, ask the portal for the next version of a profile. You supply
the deployment and the validity window. The portal supplies the tenant and the sequence; a request
that names a sequence is refused.

```sh
portal \
  -H 'Content-Type: application/json' \
  -d '{"deploymentId":"managed-linux-example","notBefore":"2026-11-01T00:00:00Z","expiresAt":"2026-11-08T00:00:00Z"}' \
  "$PORTAL/api/v1/profiles/managed-engineering/versions"
```

The response (201) describes the signed version: sequence, digests of the payload and the
envelope, the signer key IDs, and who created it. The sequence is the larger of the configured
minimum and one more than the latest version. A profile stays bound to the deployment its first
version names.

Every signature is recorded in the portal's hash-chained audit log with the time, the signer's
IdP subject, the role, and the digests.

Today one administrator signs alone. The two-person rule, where a different principal
with the `approver` role must approve a draft before the portal signs it, is designed and not
built.

## 2. Export the trust input

```sh
portal \
  "$PORTAL/api/v1/profiles/managed-engineering/trust" > trust.json
```

`trust.json` holds the portal's public key, the threshold, the tenant, deployment and profile, and
a minimum sequence equal to the latest version. It is the build administrator's input in the next
step.

## 3. Assign the version and download its envelope

Point the deployment at the version. An assignment only moves forward: an older sequence, or a
different profile once one is assigned, is refused with 409 `rollback`.

```sh
portal -X PUT \
  -H 'Content-Type: application/json' -d '{"profileId":"managed-engineering","sequence":12}' \
  "$PORTAL/api/v1/deployments/managed-linux-example/assignment"

portal \
  "$PORTAL/api/v1/profiles/managed-engineering/versions/12/envelope" > profile.dsse.json
```

The envelope comes back byte for byte as signed. `GET .../versions` lists a profile's history,
newest first.

## 4. Build the admission executable

On the build machine, with Go and Bun already installed:

```sh
cd testifysec/managed
python3 build.py --go "$(command -v go)" --bun "$(command -v bun)" --trust /protected/build/trust.json --output /protected/build/managed-bundle
/protected/build/managed-bundle/hardened-admission < profile.dsse.json
```

The trusted keys and the assignment are compiled into `hardened-admission`. Nothing at run time
can add a key. To trust a new signer or raise the minimum sequence, build again.

> [!NOTE]
> `build.py` needs the Rookery attestation library from outside this repository, so a standalone
> checkout cannot complete it yet.

## 5. Point the gateway at the profile

Add the envelope and the executable's digest to the gateway configuration (see
[configure the model gateway](install-gateway.md)):

```json
{
  "signedProfileFile": "/etc/hardened-session/profile.dsse.json",
  "admissionExecutable": "/protected/bin/hardened-admission",
  "admissionSha256": "<sha256 of hardened-admission>"
}
```

The gateway runs admission before every provider request. A refused profile stops the request and
is recorded as `profile-refused` in the audit spool.

## Roll back

Sign a new, higher version whose content equals the older one you want, and deploy it. Never
re-deploy an old envelope: its sequence is lower, and once persisted sequence floors exist it will
be refused.

## Not built yet

- Activation records, so workstations know which version is live, and the pull that delivers
  them. See [enroll a device](enroll-device.md).
- Certificate-chain signing with short-lived leaf certificates.
