# HC-07: offline bundle verification and patch reconstruction

This implements a local release component, not a published or qualified product.
`hardened-bundle-verify` is a native Go executable using the in-tree Rookery DSSE
verifier. Its runtime needs neither Python nor Node/npm/Bun/Go installation. It
verifies supplied bytes and can stage the exact verified inventory into a new
private directory. It never activates, executes, fetches or publishes them. The supplied product binaries still need their own UAT evidence.

The packager consumes an existing native-builder output directory. It produces
an uncompressed `bundle.tar` and **unsigned** `manifest.unsigned.json`; it does
not mint a production signature. A separate approved release signer must sign
the manifest bytes with DSSE payload type:

```text
application/vnd.testifysec.hardened-opencode.release.v1+json
```

The consumer requires independently provisioned **release** trust. It never
imports public keys from the manifest or archive. A profile signer, authenticated
human, activation actor, and release authority remain distinct roles. Successful
verification is neither an activation authorization nor an installation decision.

## Local build and UAT

Run from this directory with cached Go dependencies and trusted build tools:

```sh
CGO_ENABLED=0 GOWORK=off go build -trimpath -o /tmp/hardened-bundle-verify .
python3 -B uat.py --go /absolute/go --artifacts /absolute/native-builder-output \
  --upstream /absolute/local-upstream-checkout --report /tmp/hc07-uat.json
```

The UAT builds the actual native verifier, packages the supplied native artifacts
and preserved OpenCode license, and signs with ephemeral ECDSA test keys through
Rookery. Private keys never leave the Go test process. It runs the verifier with
no package tools on `PATH`. The fixtures are synthetic signing ceremonies, never
production attestations. Builds disable dependency fetching and therefore fail
if their pinned Go dependencies are absent from the local cache.

The report includes the exact native-verifier digest, archive/artifact hashes,
test-source hashes, revision and dirty paths. Negatives cover signed releases
with wrong assignment, time, sequence, upstream or license; mutated manifest
bytes; wrong trust purpose; and correctly signed archives containing traversal,
symlink, hardlink, duplicate, missing, extra, altered, or appended content. Those
archive fixtures pass manifest admission before structural rejection, so a bad
signature cannot accidentally satisfy their negative assertions.

## Packaging and verification

```sh
python3 package.py --artifacts /absolute/native-builder-output \
  --source /absolute/badger --output /tmp/new-release \
  --tenant enclave-example --channel development --sequence 10 \
  --not-before 2026-09-08T00:00:00Z --expires-at 2026-09-09T00:00:00Z

# After an approved release signer produces manifest.dsse.json:
/tmp/hardened-bundle-verify --trust /protected/release-trust.json \
  --manifest /tmp/new-release/manifest.dsse.json --archive /tmp/new-release/bundle.tar
```

Use current, deliberately chosen validity dates. The trust schema is:

```json
{
  "schema": "testifysec.release-trust/v1",
  "purpose": "release-verification",
  "product": "hardened-opencode",
  "tenant": "enclave-example",
  "channel": "development",
  "minimumSequence": 10,
  "upstreamCommit": "EXACT_40_CHARACTER_UPSTREAM_COMMIT",
  "upstreamTree": "EXACT_40_CHARACTER_UPSTREAM_GIT_TREE",
  "upstreamLicenseSha256": "EXACT_64_CHARACTER_SHA256_OF_PINNED_UPSTREAM_LICENSE",
  "publicKeys": ["ADMINISTRATOR_PROVISIONED_SPKI_PUBLIC_KEY_PEM"],
  "threshold": 1
}
```

The verifier rejects duplicate/case-aliased JSON fields, invalid UTF-8, fractional
integer fields, unsafe paths, non-regular archive members, unexpected file modes,
extra/missing files and trailing nonzero archive data. Both the complete archive
and every artifact are bound by the signed manifest. The preserved license must
match the administrator's independently pinned upstream-license digest.

Input archives are bounded to 2 GiB and 4,096 files. This is a conservative
Linux/Darwin bundle format using regular USTAR members and ASCII paths, not a
general-purpose tar extractor. Verification uses one archive file handle and
does not extract files unless native staging is explicitly requested. Staging
uses the same read stream for verification and extraction; later promotion
still requires protected custody and established release-policy verification.

Minimum sequence is an administrator-provisioned floor, not a persistent
highest-seen version. OS time, trust provisioning and executable integrity need
deployment protection. Raw SPKI test trust does not implement platform Fulcio
certificate identity, RFC3161 time, revocation, production key custody, SBOM
policy or the complete existing release-policy/VSA contract.

## Native verified staging

Pass `--stage-root /absolute/protected/staging` with the same trust, manifest and
archive options to retain the verified inventory. The root must already exist,
be private and service-owned, and have protected, non-symlink ancestors. A
root-owned sticky temporary ancestor is supported for local UAT.

The native process opens the archive once and hashes the same bytes it writes
into a fresh private staging directory. It verifies the signed complete archive
length/digest and every member before returning the directory path. Failed
attempts remove their own partial directory and report cleanup failures. Existing
staged results remain untouched. Directory depth and count are bounded as well
as file count and bytes. Input symlinks and FIFOs are refused without blocking.

The result explicitly says `offline-release-staging-only` and `activated: false`.
No executable runs, service starts, current-release pointer changes or rollback
counter advances. A protected installer still must verify the existing platform
release-policy/VSA evidence and deployment assignment before promotion. Staging
under a trusted service UID is not protection against that same UID or root.
A process crash can leave a `.staging-*` directory; it is never a completed
result and must not be promoted. Successful output is an observation by the
trusted verifier, not an independently signed activation record.

The local native UAT checks exact extracted bytes/modes, malicious signed
archives, failed-attempt cleanup, existing-result preservation, private ancestor
checks and FIFO/symlink refusal. No package manager is available on its PATH.

## Exact upstream patch export and replay

Only a committed monorepo revision is exported. Working files are deliberately
not attributed to `HEAD`. Run after the intended implementation commits exist:

```sh
python3 patches.py export --upstream /absolute/local-upstream-checkout \
  --repo /absolute/badger --revision COMMITTED_REVISION --output /tmp/new-patch

python3 patches.py reapply --upstream /absolute/local-upstream-checkout \
  --package /tmp/new-patch --upstream-commit PINNED_UPSTREAM_COMMIT \
  --upstream-tree PINNED_UPSTREAM_TREE --downstream-tree INDEPENDENT_DOWNSTREAM_TREE
```

The independent downstream tree comes from the trusted source revision, e.g.
`git rev-parse COMMITTED_REVISION^{tree}`, or later from an authenticated
release statement. Do not treat `patch.json`'s self-reported expected tree as
authentication. Export includes a binary Git patch covering upstream edits and
the TestifySec overlay. Reapply checks the exact resulting Git tree, file modes,
symlinks and unchanged upstream license in a disposable checkout. Git hooks,
filters and global Git configuration are disabled; no upstream programs or
package installers execute. Existing local Git objects are required; no network
fetch or public mirror mutation occurs.

## Minimal future monorepo registration

No shared workflow or publisher is changed by this component.

1. Extend `.github/workflows/release-fanout.yml`'s `build-binaries` and blocking
   `verify` lanes with the qualified controller/library/broker/tool-pack matrix
   and these phase UATs. Reuse the monorepo version and source/build evidence;
   attest and verify the final bytes after any OS signing or repackaging.
2. Extend `subtrees/rookery/site/scripts/publish-release.mjs` deliberately: its
   `TOOLS` allowlist currently contains only `cilock` and `jctl`, with a
   `.tar.gz` naming contract. Add the hardened product's archive, detached DSSE,
   SBOM/provenance and offline-verification descriptors together with their
   consumers. This component's uncompressed tar is not already compatible.
3. Add the platform download surface and a protected installer that validates
   the established platform release-policy/VSA evidence plus the exact bundle
   bytes. Supplying our SPKI manifest alone must not bypass that existing gate.
4. Configure an OSS target in `jade/cmd/release_mirror.go` only after approving
   public source scope, dependency closure and licensing. The existing
   `.github/workflows/oss-mirror.yml` remains a separate advisory post-GA output.
   Current relative in-tree Rookery module replacements need a self-contained
   export contract, and inherited upstream release triggers must be neutralized.

No release tags, credentials, signatures, mirror targets, buckets or deployments
are provisioned here. FIPS, IL6 and ALPS qualification remain separate work.
