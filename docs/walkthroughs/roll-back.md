---
title: Roll back a change
description: Undo a profile, policy, quota or binary change in a deployment, always forward, and know which changes cannot be undone by redeploying the old thing.
sidebarLabel: Roll back a change
sidebarPosition: 60
---

# Roll back a change

Badger rolls back forward. A profile, a policy and a quota table each carry a version that only
goes up, and the component reading them refuses an older one, so "roll back" means publishing a
new version whose content equals the old one. Redeploying an old file is refused or, where the check
is not built yet, a hole you should not depend on.

> [!WARNING]
> The broker and the portal keep their state in a Postgres database whose migrations run forward
> only. An older image does not undo a migration, and this release documents no way to run one
> against a newer schema: after an upgrade that migrated, roll forward. Restoring a backup taken
> before the upgrade also rewinds the usage ledger, so calls made since then stop counting against
> quotas: do it only if nothing was written since the backup, or keep traffic closed until that
> usage is accounted for.

## A profile

1. List the versions (`GET .../profiles/<id>/versions`, newest first) and read the deployment of
   the one you want back (`GET .../versions/<n>`).
2. Sign the next version for that deployment with a validity window that is current now, never the
   old version's window, which may have expired. The portal sets the controls of a schema v1
   profile itself, so deployment and window are the whole of its content; it also assigns the
   higher sequence.
3. Assign it and deploy the new envelope, as in
   [publish a profile](../admin/publish-profile.md).

Assigning the old sequence directly is refused with 409 `rollback`. Copying an old envelope onto a
gateway is not refused yet, because admission checks only the compiled minimum sequence, not the
highest it has seen (see [profiles](../concepts/profiles.md)); do not rely on that.

**Check.** The gateway's audit records carry the new version's profile digest.

## The broker's pipeline policy

Every saved policy is an immutable version. To return to version 7:

```sh
curl -fsS "$ADMIN/admin/v1/policy/versions/7"     # the entries you want back
curl -fsS -D - "$ADMIN/admin/v1/policy"           # the ETag header is the current version
```

`PUT /admin/v1/policy` with version 7's entries, `If-Match` set to the current version, and a
comment saying why. With `two_person_rule` on, an entry change may need a second administrator to
approve the proposal. The new version is active on the next request; nothing restarts.

**Check.** `GET /admin/v1/policy/versions` lists the new version with you as author, and the audit
log (`GET /admin/v1/audit`) has its diff.

## Quotas

`PUT /admin/v1/quotas` with the old limits and the current version in `If-Match`. Spend already
counted is never rewritten, so lowering a limit below this month's spend refuses that principal's
next call at once.

## A connector

To take a connector out, sign a new profile version without its entry (managed build), or, for
`conngw`, remove its entry from the gateway's profile, sign the profile again with the
administrator's key (`plugintool sign`, as in
[rotate keys](rotate-keys.md#connector-plugins-vendor-keys-the-administrators-key-and-service-tokens)),
and restart: `conngw` refuses to start on a profile whose signature does not verify. Labels do not go down when a connector is removed: a
workspace that has read at a marking stays there until an administrator resets its label.

## Binaries

| Component | How |
|---|---|
| `hardened-gateway` | Put the previous binary back and restart the session's gateway. Its configuration schema is versioned, and unknown keys are refused, so a configuration that uses a newer key fails at start instead of being ignored |
| The managed `badger` build | Rebuild from the earlier commit with the same build flags, including `--connector-admission-sha256` if connectors are in use |
| `badger-broker` | Run the previous image only against the database schema it was built for (see the warning above). The audit chain is checked at start; if it fails, the broker denies every pipeline and refuses admin writes, so check its log before reopening traffic |
| `conngw` | Run the previous binary with the same labels file. The labels file only records rises, so a rollback never lowers a workspace's label |

## What does not roll back

- A rotated signing key. The old executable trusts the old key only; going back means going back
  to the old executable and the old key together, if the old key still exists.
- A label. Only an administrator lowers it, by resetting the state directory or the labels file.
- Usage. Spend, once counted, stays counted.
