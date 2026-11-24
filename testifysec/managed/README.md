# Aflock managed signed-profile admission (HC-02)

This component builds the native `hardened-admission` launcher, the compiled
`hardened-runtime`, and the digest-pinned Rookery shared library. The launcher
checks the runtime digest, rejects command-line arguments, and replaces the
environment before starting Bun. This blocks inherited `BUN_OPTIONS` preload
hooks before JavaScript starts. The executable accepts one DSSE envelope on standard input.
Its signature, strict payload schema, deployment assignment, validity interval,
and minimum sequence must pass before an admission result is returned. It never
imports upstream OpenCode or starts a model, plugin, shell, or tool. HC-03 must
provide a qualified execution boundary before a managed runtime is exposed.

The public trust keys and assignment are compiled into the executable from a
build-administrator input. Runtime requests, environment variables, local
configuration, and repository files cannot supply or replace these values.
This is a bounded SPKI trust prototype, not the platform's Fulcio/TSA policy
release or activation ceremony. A verified profile signer is not automatically
an authenticated human, tenant owner, or activation actor.

## Build and local UAT

Run from this directory with trusted, preinstalled build tools:

```sh
python3 uat.py --go /absolute/path/to/go --bun /absolute/path/to/bun --report /tmp/hc02-uat.json
python3 build.py --go /absolute/path/to/go --bun /absolute/path/to/bun --trust /protected/build/trust.json --output /tmp/managed-bundle
/tmp/managed-bundle/hardened-admission < /path/to/profile.dsse.json
```

The UAT generates ephemeral ECDSA keys and real Rookery DSSE fixtures, discards
the private keys, builds the executable, and runs it from a foreign directory
with no runtime package manager or compiler on the caller's `PATH`; the launcher
supplies its fixed system environment. It checks valid, tampered,
wrong-key, expired, future, wrong-assignment, rollback, unknown-field, duplicate
JSON, invalid-encoding, weakened-control, trust-injection, native-substitution,
executable-command rejection, preload injection, and runtime-substitution cases. Reports bind the tested executable,
library, trust input, envelopes, payloads, and outputs by SHA-256. Manifests also
retain the selected contract version, backend assignment for v2, staged managed
source hashes, native source hashes, selected non-standard Go package/module
inputs (including Rookery), Go/Bun executable hashes, the Git revision, and
worktree dirty status. Selected inputs are compared again after compilation;
a revision alone does not identify an uncommitted development build. These are
bounded source and executable-path observations, not a complete SBOM, reproducible
build proof, hardware measurement, or verification of system compiler/SDK and
standard-library source. Reports are
local unsigned observations, not platform evidence or release attestations.

Build dependencies must already be available; this harness does not install
packages. Dependency download and checksum policy remains the build operator's
responsibility. An offline cached development build is not release qualification.

## Build-provisioned trust schema

Every field is required; unknown fields and duplicate object keys are rejected.
Identifiers are bounded ASCII identifiers. Keys are public SPKI PEMs; the native
verifier validates their encoding and enforces distinct signer thresholds.
All numeric tokens in these schemas must be canonical unsigned decimal integers
from `0` through `9007199254740991` (with per-field constraints applied afterward).
Negative numbers including `-0`, decimal fractions, exponent notation, and larger
integers are rejected before conversion to JavaScript numbers. This deliberately
restricts JSON syntax so signed values cannot round across a version or rollback
boundary. The same raw-token validation applies to build-provisioned trust input.

```json
{
  "schemaVersion": 1,
  "publicKeys": ["-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"],
  "threshold": 1,
  "tenantId": "tenant-example",
  "deploymentId": "managed-linux-example",
  "profileId": "managed-engineering",
  "minimumSequence": 10
}
```

Chain-mode trust replaces `publicKeys` with `rootCas` and `signerIdentity`
(`{"san": ..., "extendedKeyUsage": "codeSigning"}`); see `../native/README.md`, "Trust modes".
A chain-mode profile's window must lie inside every counted signer's leaf
(`profile-outside-signer-certificate`). V2 takes the same two shapes; `runtime/host.ts` stays
pinned-key.

The profile's DSSE payload type is
`application/vnd.testifysec.hardened-opencode.profile.v1+json`. Its signed JSON
has exactly these fields:

```json
{
  "schemaVersion": 1,
  "profileId": "managed-engineering",
  "tenantId": "tenant-example",
  "deploymentId": "managed-linux-example",
  "sequence": 10,
  "notBefore": "2026-09-08T00:00:00Z",
  "expiresAt": "2026-09-09T00:00:00Z",
  "controls": {
    "runtimePackageDownloads": false,
    "execution": "broker-only",
    "audit": "required"
  }
}
```

Those controls state the requirements of the later managed runtime. Admission
validates them; it does not claim an execution broker or audit service ran.
Validity starts inclusively at `notBefore` and ends exclusively at `expiresAt`.
Sequence must be a positive safe integer at least the build-provisioned floor.

## V2 backend assignment approval

V2 has a distinct DSSE payload type:
`application/vnd.testifysec.hardened-opencode.profile.v2+json`. Both its protected
trust input and signed profile require `schemaVersion: 2` and this additional
exact field; every other field follows the v1 rules above:

```json
{
  "backend": {
    "kind": "darwin-vz/v1",
    "manifestSha256": "<64 lowercase hexadecimal characters>"
  }
}
```

The signed backend kind and digest must exactly equal the values in the
build-provisioned trust input. The build administrator chooses the accepted
version once. A v1 build accepts only v1 and a v2 build accepts only v2; there
is no retry using a different version. V1 successful output retains its exact
existing shape. V2 successful output uses `schemaVersion: 2` and includes the
verified `backend` in `profile`, alongside the existing assignment/time fields.
The native verifier authenticates the original v2 payload type and exact signed
payload bytes before schema admission. A validation-only view reuses common
v1 field rules after strict v2 decoding; that view is never verified or signed.

This approves a **reference to a manifest**. Admission does not read a real
backend manifest or measure an executable, kernel, or root disk. It does not
authorize VM boot or establish that a VZ backend ran. The compatibility harness
uses an explicitly non-executable synthetic manifest. A future protected VZ
broker must validate the actual manifest and files, bind the selected backend
to execution and artifact observations, and recheck admission immediately before
startup. The existing VM fixture and production preflight are unchanged.

The current Linux reference broker, gateway, managed host, and Pushgate handoff
remain v1 consumers. The broker and gateway reject v2 admission output; the
legacy host builder rejects v2 trust before invoking tools or creating output.
Pushgate still requires the v1 media type and profile schema. V2 admission alone
does not enable any of those consumers or model traffic through the gateway.

Run the retained, compiled compatibility harness from this directory:

```sh
python3 uat-v2.py --go /absolute/path/to/go --bun /absolute/path/to/bun --output /tmp/aflock-profile-v2-uat
```

The output directory must be new. It retains public fixtures signed by the same
ephemeral key for both versions, both native bundles, build manifests, and a
digest-bound report. It tests valid v1/v2 admission, signed backend/pin and
version/type conflicts, expiry, rollback, malformed/duplicate/numerically
ambiguous JSON, trust validation, and runtime attempts to replace the assignment.
It also compiles isolated tests of the actual v1 broker and gateway admission
functions with positive v1 controls and v2 refusals, and runs the existing v1
component UAT. The isolated consumer tests start no engine, provider, or service.
Pushgate refusal is a source inventory finding here, not a newly executed
Pushgate workflow. No fixture private key is persisted and no runtime packages
are downloaded.

## V3 connectors and gateway marking

V3 (`application/vnd.testifysec.hardened-opencode.profile.v3+json`, trust `schemaVersion: 3`
with the v1 trust fields) adds two exact fields to the v1 payload: `gateway` and `connectors`
(testifysec/CONNECTORS.md). Every other field follows the v1 rules, and as with v2 a build
accepts exactly one version.

```json
{
  "gateway": { "classification": "SECRET" },
  "connectors": [{
    "name": "jira",
    "binarySha256": "<64 lowercase hex: the release's pinned connector binary>",
    "baseUrl": "https://jira.example.invalid",
    "tokenPath": "/run/badger/tokens/jira.token",
    "caPath": "/etc/badger/enclave-ca.pem",
    "writes": false,
    "classification": "SECRET",
    "flags": { "marking-field": "customfield_10001" },
    "permissions": { "jira_*": "allow", "jira_add_comment": "ask" }
  }]
}
```

`name` is one of the release's connectors (`jira`, `confluence`, `gitlab`) or a plugin served by
the connector pod under any name that pod accepts (a lowercase letter, then up to 31 lowercase
letters, digits or hyphens), at most once each and at most 16 entries. `baseUrl` is https with a host and no credentials, query or fragment.
`tokenPath` and `caPath` (or `null`) are absolute paths without relative segments. Both
classifications must parse as configured banners with the shared lattice
(`testifysec/marking`, the port of the connectors' `marking` package). `flags` holds only the
connector-specific settings the release lists for that connector (`profile-v3.ts`, `catalog`), or
for a plugin any flag the pod would pass it (the same name rule, not a shared flag or `notice`);
the shared ones (base URL, token, CA, classification, writes) come from their own fields, and the
loopback test flag has no field at all. `permissions` keys must start with the connector's own
name, so an entry cannot grant another tool. The broker provisions tokens read-only at
`/run/badger/tokens/<name>.token` (name `[a-z0-9-]{1,32}`) and the admitted envelope at
`/run/badger/profile/profile.dsse.json`, one fresh mount per execution. Any invalid entry fails the whole profile. The
admission output carries the admitted `gateway` and `connectors` in `profile`.

## Security boundary and remaining work

The launcher, compiled runtime, shared library, parent directories, loader environment, and
system clock must be protected by deployment controls. Hashing before `dlopen`
does not prevent concurrent replacement by a writer; this phase provides no
same-user, process, VM, or hardware isolation. Install-time signing and protected
launch belong to distribution and sandbox qualification. The launcher is the
only supported entrypoint. The deployment must prevent privileged launch of
`hardened-runtime` directly; the runtime alone does not sanitize Bun's pre-start
environment or establish an OS security boundary.

The rollback floor is fixed in the build. Accepting sequence 12 does not persist
a new floor or prevent subsequently accepting 11 when the compiled floor is 10.
A trusted state service and freshness/revocation protocol are follow-on work.
Keys and assignments change through a new trusted build in this phase. Runtime
profile retrieval, platform identity, certificate chains, timestamps, activation,
and production trust rotation are not implemented here. No ALPS, FIPS, or IL6
qualification follows from passing this component's UAT.
