---
title: Rotate keys and tokens
description: Replace every credential a Badger deployment holds, in an order that keeps it serving, with the check that shows the new one is in use.
sidebarLabel: Rotate keys and tokens
sidebarPosition: 50
---

# Rotate keys and tokens

Most credentials in a Badger deployment are files that their reader opens again on every use, so
rotating one is replacing a file. A few are read once at start, and two are compiled into a build.
This walkthrough goes through each, cheapest first.

Replace a file atomically: write the new one beside it and rename it over the old one, so a reader
never sees half a key. Keep the mode and owner the reader requires (the gateway refuses anything
but a regular file readable only by its owner, in a `0700` directory).

## Read on every use: replace the file

| Credential | Reader | When the new one takes effect |
|---|---|---|
| A model route's `key_file` | `badger-broker` | The next call on that route |
| `provisioner_key_file` | `badger-broker`, `provision` listener | The next provisioning request; the old key is refused from then on |
| The gateway's `collectorTokenFile` | `hardened-gateway` | The next export; if the file is missing or not private, records wait in the spool |
| A connector's `tokenPath` in the managed build | The connector | The next request to the service |

**Route key.** Put the new key in the provider first, swap the file, then revoke the old key at the
provider. `GET /readyz` on the broker answers 503 while any route's key file is unreadable, so check
it right after the swap.

**Provisioner key.** There is one key, with no overlap. Swap the broker's file and the
provisioner's copy together, at a moment the provisioner is not creating workspaces; a request with
the old key in between gets 401 and can be retried.

**Connector tokens (managed build).** Issue the new personal access token at the service, swap the
file, then revoke the old one. The next tool call uses the new token; nothing restarts. A
connector's service token in `conngw` is copied per stream instead; see
[connector plugins](#connector-plugins-vendor-keys-the-administrators-key-and-service-tokens).

## Handed over a pipe: send a new line

The gateway's provider credential comes over `providerTokenFd`. Each line the starting process
writes replaces the token in memory, so rotation is writing one more line. A closed pipe or an
invalid line clears the token, and with no token the gateway makes no provider call, so a mistake
fails closed.

In the deployment from [your first deployment](first-deploy.md), that credential is the workspace's `bbt_` broker token. Issue a new one
with `POST /provision/v1/tokens` for the same workspace: the broker replaces the old token at once,
so write the new one to the gateway's pipe straight after. See
[workspace tokens](../admin/quotas-and-tokens.md#workspace-tokens).

## Read at start: replace and restart

**`conngw`'s TLS certificate.** `conngw` loads `certFile` and `keyFile` when it starts. Workspace
bridges pin the CA that issued it (`--ca-file`), not the certificate, so a new certificate from the
same CA needs only a `conngw` restart. Open streams end on the restart. A new CA takes an overlap,
because `--ca-file` is a PEM bundle: put both CAs in the file every bridge pins, restart `conngw`
with a certificate from the new CA, and remove the old CA from the bundle once no `conngw` serves
an old certificate.

**The portal's profile signing key.** `badger-broker` reads `portal.signing_key_file` at start,
and every admission executable has the matching public key compiled in. Nothing at run time adds a
key, so the gateways switch keys by switching executables:

1. Put the new key in your key vault and restart `badger-broker` with it.
2. Export the trust input (`GET .../profiles/<id>/trust`); it now names the new public key.
3. Build a new admission executable from it, as in
   [publish a profile](../admin/publish-profile.md#4-build-the-admission-executable).
4. Sign the next version of the profile with the new key and assign it.
5. On each gateway, change `admissionExecutable`, `admissionSha256` and `signedProfileFile`
   together. The old executable refuses the new envelope and the new executable refuses the old
   one, so a gateway with one changed and not the other refuses every request.
6. If managed builds admit connectors and their v3 profile is signed with this key, their verifier has the old key compiled in too, and the
   build pins the verifier's digest (`--connector-admission-sha256`). Rebuild the managed binary
   with the new verifier's digest and roll it out with the new envelope; a managed build with the
   old pin refuses the new envelope at start.

**Check.** After steps 5 and 6 a model call through each gateway succeeds, and its audit record carries
the new profile digest. Destroy the old signing key once no gateway runs the old executable.

## Workspace and device tokens

These expire on their own (`workspace_token_ttl_hours`, `device_token_ttl_hours`). To end one now,
revoke it: `DELETE /provision/v1/tokens/{workspace}` for a workspace, `DELETE /device/token` from
the device. Issuing a new token for the same workspace or device replaces the old one.

## A pipeline issuer's signing keys

The broker holds no issuer keys; the edge pins them. When an issuer rolls its key, add the new
public key to that issuer's provider on the edge before the issuer starts signing with it, and
remove the old one once every token it signed has expired (the provider's maximum lifetime).
Tokens from the other issuers are not affected, since each issuer has its own provider.

## Connector plugins: vendor keys, the administrator's key and service tokens

`conngw` reads its signed profile, the bundles and the administrator's public key once, at start.
Run one replica with the Recreate strategy, so a restart is the cut-over. The steps use
`plugintool` from `testifysec/connectors/cmd/plugintool`; every private key it writes is encrypted,
and the passphrase comes from `--passphrase-file` or `PLUGINTOOL_PASSPHRASE`.

**A vendor's signing key.** The profile names the signers it trusts and which one signs each
connector, so the new key goes in beside the old one:

1. The vendor makes a new key (`plugintool keygen -out vendor-2 -passphrase-file vendor.pass`) and
   packs the same executable again with it (`plugintool pack ... -key vendor-2.key -out bundle-2/`).
2. Add the new public key under a new name in `signers`, point the connector's `bundle` at the new
   bundle and its `signer` at the new name. The `digest` is unchanged: it is the executable's.
3. Sign the profile (`plugintool sign -key admin.key -passphrase-file admin.pass -in conngw.json`)
   and restart the pod. Start refuses if the new bundle does not verify against its signer.
4. Remove the old signer from `signers` once no connector names it, sign and restart again.

A new plugin version is the same procedure with a new executable: pin its new `digest` and replace
the vendor image in the pod.

**The administrator's key.** It is pinned on `conngw`'s command line, outside the profile, so the
profile signature and the pinned key change together. Make the new key, sign the profile with it,
and restart with `--admin-key` set to the new public key. A profile signed with the old key no
longer starts the gateway, which is the point: keep the old private key until you are sure you will
not roll back to a profile it signed.

**A connector's service token.** Each stream copies the token when it starts, so a stream already
open keeps using the token it took, and the next stream takes whatever the Secret holds then.

- **Planned rotation.** Issue the new token at the service, put it in the Secret, and restart the
  connector pod. The kubelet updates a mounted Secret some time after the change, so without the
  restart a stream opened after the update can still copy the old token; the new pod mounts the
  new Secret and the restart ends every stream that held the old one. Then revoke the old token at
  the service. Nothing fails along the way.
- **Emergency cut-off.** Revoke the old token at the service at once, put a new one in the Secret,
  and restart the connector pod. Open streams fail with 401 on their next call to the service. A
  new stream copies whatever the mounted Secret holds, which the kubelet updates some time after the
  change; after the restart every stream uses the new token.
