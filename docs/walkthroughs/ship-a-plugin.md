---
title: Ship a connector plugin
description: Build a connector outside this repository against the plugin interface, sign it, and load it into the connector gateway for the workspaces granted it.
sidebarLabel: Ship a connector plugin
sidebarPosition: 40
---

# Ship a connector plugin

A vendor builds a connector outside this repository, packs and signs it; an administrator trusts
the signer, pins the executable's digest, grants its tools to workspaces and runs it behind the
connector gateway. Read [connectors](../concepts/connectors.md#plugins) for what a plugin may and may
not do, and [connectors](../admin/connectors.md#run-connectors-in-the-connector-gateway) for the
gateway's profile and pod.

## 1. Build a static executable (vendor)

A plugin's `main` is `sdk.Main(spec)` from the public `testifysec/connectors/sdk` package, which
carries the egress lock to the base URL, the credential scrub, the result cap, the untrusted-content
wrapper and the banners. The repository's
[reference connector](https://github.com/aflock-ai/badger/blob/main/testifysec/connectors/example/main.go)
shows a read tool and a write tool, and
[`cmd/conngw/testdata/acme`](https://github.com/aflock-ai/badger/tree/main/testifysec/connectors/cmd/conngw/testdata/acme)
is a plugin built in its own module that imports only `sdk`.

Build it statically. `plughost` runs only an ELF executable for the node's architecture that names
no interpreter, and refuses scripts and dynamically linked executables:

```sh
CGO_ENABLED=0 go build -trimpath -o plugin .   # the default build mode; not -buildmode=pie
readelf -l plugin | grep INTERP                 # must print nothing
sha256sum plugin
```

Go's PIE without cgo has an `INTERP` header and is refused. A plugin that needs cgo links with
`-ldflags '-linkmode=external -extldflags=-static'`, or `-buildmode=pie` with
`-extldflags=-static-pie`.

## 2. Pack and sign it (vendor)

Make the signing key once. `plugintool keygen` writes the private key encrypted (PBKDF2-HMAC-SHA256,
600000 rounds, then AES-256-GCM). The passphrase comes from a file or `PLUGINTOOL_PASSPHRASE`, never
the command line, and must be at least 12 characters:

```sh
plugintool keygen -out vendor -passphrase-file vendor.pass   # vendor.key (encrypted, 0600), vendor.pub
```

Write the tool list on a machine that does not hold the key, since this step runs plugin code:

```sh
plugintool manifest -exe plugin -out tools.json
```

Then, where the key is, add the digest and sign. `pack` never runs plugin code:

```sh
plugintool pack -manifest tools.json -digest sha256:<sha256sum of plugin> \
  -key vendor.key -passphrase-file vendor.pass -out bundle/
plugintool verify -bundle bundle/ -pub vendor.pub   # prints the digest the bundle names
```

The bundle is `manifest.json` (name, version, digest and every tool, with which ones write) and
`manifest.sig`. The manifest never sets a marking or who may use the plugin; any such field is
ignored.

Ship the executable in an image of your own, for example one that holds only `/plugin`. That image
is never run: it is mounted as a volume. Give the administrator the image digest, the bundle and
`vendor.pub`.

## 3. Trust, pin and grant (administrator)

Review the plugin before you pin its digest: the signature says who built it, not that it is safe.
Then add it to the gateway's profile:

```json
{
  "signers": { "acme": "<contents of vendor.pub>" },
  "hostDigest": "sha256:<digest of the plughost image>",
  "namespaces": ["team-a"],
  "connectors": [{
    "name": "acme",
    "bundle": "/etc/conngw/bundles/acme",
    "digest": "sha256:<the digest plugintool verify printed>",
    "signer": "acme",
    "socket": "/run/conngw/acme/plugin.sock",
    "uid": 10001,
    "gid": 10001,
    "baseUrl": "https://acme.example.invalid/api",
    "tokenPath": "/var/run/secrets/acme/token",
    "caPath": "/var/run/secrets/acme/ca.crt",
    "writes": false,
    "classification": "CONFIDENTIAL",
    "flags": {},
    "grants": [{ "workspaces": ["team-a/*"], "tools": ["acme_get_ticket"] }]
  }]
}
```

The gateway's own keys (`listen`, `certFile`, `keyFile`, `audience`, `labelsFile`) are in the
[configuration reference](../reference/config.md#connector-gateway-conngw).`caPath` must sit beside the token,
in the same directory (a projected volume holding `token` and `ca.crt`), and hold only PEM
certificates. Give the connector its own read-only service token, scoped to what the grants serve.
Sign the profile with the administrator's key, not the vendor's:

```sh
plugintool sign -key admin.key -passphrase-file admin.pass -in conngw.json
```

## 4. Add the plugin's container

In the connector pod, add a container named as the connector. It runs the `plughost` image whose
digest is `hostDigest`, as the connector's `uid` and `gid`, with the vendor's image mounted
read-only as an image volume and a memory-backed `/tmp`:

```yaml
volumes:
  - name: acme-vendor
    image: { reference: "registry.example.invalid/acme-plugin@sha256:<image digest>" }
  - name: acme-tmp
    emptyDir: { medium: Memory }
containers:
  - name: acme
    image: "registry.example.invalid/plughost@sha256:<hostDigest>"
    args: ["-socket", "/run/conngw/acme/plugin.sock", "-vendor", "/vendor",
           "-plugin", "/vendor/plugin", "-gateway-uid", "<the gateway's uid>"]
    securityContext: { runAsUser: 10001, runAsGroup: 10001, runAsNonRoot: true,
                       allowPrivilegeEscalation: false, capabilities: { drop: ["ALL"] } }
    volumeMounts:
      - { name: acme-vendor, mountPath: /vendor, readOnly: true }
      - { name: acme-tmp, mountPath: /tmp }
      - { name: acme-socket, mountPath: /run/conngw/acme }   # shared with the gateway only
      - { name: acme-token, mountPath: /var/run/secrets/acme, readOnly: true }
```

Mount the bundle where the gateway reads it, restart the pod (one replica, Recreate) and start
`conngw` with the administrator's public key. The rest of the pod (`shareProcessNamespace`, the
Downward API variables, the account's permissions, the node settings) is in
[connectors](../admin/connectors.md#the-pod).

## 5. Check it

- **Admission.** `conngw` starts only if the bundle verifies against `acme` in `signers` and names
  the pinned digest. Change one byte of `manifest.json`, or pin another digest, and it refuses
  start.
- **The copy.** On the first stream `plughost` hashes the executable as it copies it; another
  executable in the vendor's image closes the stream and logs the digest found. A dynamically
  linked build is refused with the reason in `plughost`'s log.
- **The grant.** From a workspace in `team-a`, `tools/list` on `acme` returns `acme_get_ticket` only.
  A workspace outside the grant is refused (403), and a call to any other tool is answered by
  `conngw` without reaching the plugin.
- **The marking.** Every result carries the profile's classification, whatever the plugin writes,
  and the workspace's label rises to it before the answer is passed on. A later call to a connector
  the label is above is refused, as for the in-repo connectors
  ([turn on a connector with a marking](connector-marking.md)).

To rotate the vendor's key or the administrator's, see [rotate keys](rotate-keys.md).
