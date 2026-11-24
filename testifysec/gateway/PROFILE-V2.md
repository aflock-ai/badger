# Explicit profile versions at the native gateway

The administrator selects `testifysec.hardened-opencode.gateway/v2` and supplies
an exact `backend` object with `kind: "darwin-vz/v1"` and `manifestSha256`.
Every model request requires the pinned native Rookery admission bundle to
accept a v2 signed profile whose backend reference matches that assignment.
Gateway v1 retains its original profile contract. Neither version falls back
to the other when verification fails. Worker request fields and headers do not
select the profile version, backend or trust roots.

This check matches an authenticated **manifest reference**. It does not open
the backend manifest, verify its files, boot a VM, authenticate a platform
agent, or register a finalized signing record. The existing VM relay remains
on its explicit v1 gateway contract until a separate launch adapter binds all
of those inputs. A profile signature alone does not authorize installation or
release activation.

Run the local native UAT from the OpenCode subtree with existing cached tools:

```sh
GOCACHE=/private/tmp/hardened-opencode-gocache \
python3 testifysec/gateway/uat-profile-v2.py \
  --go /absolute/path/to/go \
  --bun /absolute/path/to/bun \
  --output /private/tmp/aflock-gateway-profile-v2-NEW
```

The harness compiles the actual gateway from a source snapshot, generates fresh
ephemeral signed fixtures, and builds actual v1/v2 native admission bundles.
It exercises Chat Completions and Responses against a local synthetic provider:
valid controls; expired, future, wrong-key, assignment, rollback, tampered,
weakened-control and backend-pin refusals; live profile restoration; crossed
config/verifier/envelope versions; and missing/invalid backend configuration.
Direct native refusal controls establish that each signed negative reaches its
intended admission rule. Gateway refusals must produce zero additional provider
requests and a terminal audit record. On accepted requests, the fixture observes
the persisted start record before returning the provider response.

The unchanged v1 `uat-profile.py` runs separately for both protocols. Selected
gateway/platform source hashes, staged Go inputs, native bundle source/tool/file
manifests, public fixture hashes, logs and audit observations are retained in the
new output directory. Reports distinguish administrator-provisioned fixture
identity labels from authenticated platform identity and current human presence.
All subprocesses and fixture servers are owned locally; failures retain evidence.
There are no customer credentials, live model calls, VM boots or installations.
These unsigned local observations do not establish FIPS, IL6, ALPS or production
release qualification.
