---
title: Identities
description: Who and what Badger's services recognize (people, workspaces, devices and pipelines), the credential each one presents, and what checks it.
sidebarLabel: Identities
sidebarPosition: 25
---

# Identities

Badger's services never take a caller's word for who it is. Each kind of caller presents one
credential, one component checks it, and the result is a principal that usage, quotas and audit
records are kept under.

| Caller | Credential | Checked by | Principal |
|---|---|---|---|
| A person in a browser (admin pages, the portal) | Identity provider sign-in at the edge | The edge, which sets `admin_id`, `admin_name` and `admin_role` only on the admin route | The IdP subject; the admin role is the IdP group, which must be in `admin_roles` |
| A hosted workspace's model traffic | Per-workspace broker token (`bbt_...`), issued by the provisioner when the workspace starts | `badger-broker`'s internal listener, against the token's SHA-256 | The owner the token was issued for |
| A hosted workspace's connector calls | The pod's projected service-account token | `conngw`, with a Kubernetes TokenReview for its audience | `namespace/account` |
| A person's own computer | Device token from device sign-in, 1 to 24 hours | `badger-broker`'s internal listener | The person; each device is `dev-<hash>` |
| A CI pipeline | The job's OIDC token (for example GitLab `id_tokens`) | The edge verifies the signature with that issuer's pinned keys; `badger-broker` maps the claims and matches a policy entry | `ci:<project>` for the primary issuer, `ci:<issuer id>:<project>` for any other, with `@<ref>` for a named branch |
| The web UI of a hosted workspace (`badger serve`) | The identity provider's JWT for the workspace's owner, forwarded by the edge | The managed build, against a JWKS file of public keys | The workspace owner (`BADGER_SERVE_SUBJECT`) |

## Rules that hold for every caller

- **Admin and model traffic never mix.** The admin listener refuses any request carrying a model
  credential, and the model listeners refuse any request carrying an admin header. An admin session
  is never served as a model user.
- **No principal is chosen by the caller.** A pipeline's principal comes from the policy entry that
  matched its token, not from a header. A workspace is served as the owner its token was issued
  for. There is no default principal.
- **Every pipeline has a human owner.** A policy entry must be owned by one of the configured
  people (`human_principals`), or its pipeline is refused even when the policy allows it.
- **Issuers are kept apart.** A token is decided only as the issuer whose header carried it, and
  the same project under two issuers is two principals with two quotas.

## Where to configure each

- People and admin roles: the edge's identity provider, `admin_roles`, and the portal's directory
  roles (admin, approver, auditor), bootstrapped by IdP subject. See
  [deploy badger-broker](../admin/deploy-broker.md).
- Pipelines: [add a pipeline issuer](../admin/identity-issuers.md).
- Workspace tokens and device sign-in: [quotas and tokens](../admin/quotas-and-tokens.md).
- Connector access for workspaces: [connectors](../admin/connectors.md).
- The model gateway's own identity check (the TestifySec platform, or administrator-provisioned):
  [install the model gateway](../admin/install-gateway.md).
