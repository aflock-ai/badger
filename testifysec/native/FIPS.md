# Pinned Go cryptographic module build candidate

`fips-build.py` builds and exercises the native Rookery library with an exact
frozen Go cryptographic module. It produces **unqualified component evidence**.
It neither certifies the product nor changes the current managed runtime bundle.
Python, Go and a C compiler are build/UAT tools, not new shipping dependencies.

As reviewed on 2026-09-08, the Go documentation identifies v1.0.0 as covered by
CMVP certificate #5247; v1.26.0 is described as in process. `GOFIPS140` selects
the frozen implementation and enables its FIPS mode by default. Runtime
`crypto/fips140.Enabled()` and `Version()` expose mode and version. The `only`
debug setting is for assessment and testing, not production.
[Go FIPS documentation](https://go.dev/doc/security/fips140).

NIST lists certificate #5247 as active, overall level 1, with an approved-mode
caveat. Its June 12, 2026 Security Policy includes v1.0.0 and v1.0.1, identifies
the exact ZIP hashes, and describes the build-information check in section 11.1.
The installed Go 1.26.5 toolchain contains the v1.0.0 snapshot used here.
[Certificate #5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247),
[Security Policy, pages 97–99](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5247.pdf).

| Exact GOFIPS140 selection | Security Policy ZIP SHA256 |
| --- | --- |
| `v1.0.0-c2097c7c` | `daf3614e0406f67ae6323c902db3f953a1effb199142362a039e7526dfb9368b` |
| `v1.0.1` | `0a9bfccef9f8011257e3303788d3420dee2677b2ceafc38b81450cc60799d007` |

The harness accepts those exact snapshots only. It refuses `latest`, `certified`,
`inprocess`, `off`, a missing snapshot, a mismatched ZIP, a modified unpacked
module, or a mismatched toolchain/build setting. It never substitutes another
version or fetches a dependency. Provision a supported toolchain and the existing
module dependencies before running it; v1.0.1 is not bundled with our local
Go 1.26.5 distribution.

## Build and local UAT

Run from any directory with the explicit installed Go executable and a new
output directory:

```sh
python3 -B testifysec/native/fips-build.py \
  --go /absolute/go1.26.5/bin/go \
  --expected-go-version go1.26.5 \
  --module v1.0.0-c2097c7c \
  --output /absolute/new-fips-candidate
```

The builder uses native Linux/Darwin compilation, `GOENV=off`, `GOTOOLCHAIN=local`,
`GOWORK=off`, `GOPROXY=off`, `GOSUMDB=off`, `-mod=readonly`, `-trimpath`,
`CGO_ENABLED=1`, and `-buildmode=c-shared` for Rookery. It supplies no inherited
GOFLAGS, GOEXPERIMENT, GODEBUG or compiler overrides. Module dependencies must
already be cached. Their recorded versions and local Rookery source hashes are
separate from the cryptographic module's NIST-bound source snapshot.

An isolated Go overlay adds an initialization guard and `RookeryFIPSStatus` to
the candidate library without editing the normal native source. The guard checks
both the short module version and the exact `GOFIPS140` build setting, including
the v1.0.0 suffix, and refuses disabled mode before accepting verification calls.
The status allocation uses the existing `RookeryFree` ownership rule. The normal
Rookery C ABI remains available. A separate compiled native probe exercises
ECDSA P-256/SHA-256 generation, signature verification and tamper refusal.

The UAT runs the existing native verifier tests under the same module selection,
then loads the actual shared library in a fresh build-time Python process and
verifies synthetic valid and wrong-key DSSE requests through its C ABI. Private
fixture keys remain inside the test process. Two fresh-process negatives set
`GODEBUG=fips140=off` and require the probe and library to refuse that downgrade.
The harness never uses `fips140=only`.

`fips-build-report.json` binds the requested/resolved module, NIST ZIP digest,
unpacked source inventory, Go executable/version/settings, compiler version,
native artifact hashes and build metadata, generated overlay hashes, local
source revision/dirty state, runtime status, and synthetic verification results.
Failures produce `passed: false` and a nonzero exit. A partial failed output
directory is diagnostic material and must not be promoted. A fresh output path
is required on every run.

## Integration and qualification boundary

The existing Rookery builder's `--fips` / `fips_mode` handling emits a
`//go:debug fips140=...` directive; it does not independently pin `GOFIPS140`.
The existing `native/build.py` also does not select a frozen module. This new
path makes that selection explicit for its generated library candidate. To use
the candidate in managed admission, the protected host bundle must be rebuilt
against the new exact library digest and its complete UAT rerun. No current
bundle, service, release signature or activation is changed here.

Every report retains `releaseQualified: false`,
`productFIPSComplianceClaim: false`, and `deploymentQualification: not-assessed`.
An optional `--qualification-record /protected/evidence.json` records only its
hash and `provided-unvalidated` status. It cannot flip those fields. A customer
compliance claim requires independently provisioned and reviewed qualification
evidence covering the exact artifact, platform/operating environment, module
installation policy, approved algorithms and parameters, entropy, key custody,
self-test behavior and the rest of the product's cryptographic paths. This
harness does not perform that approval.

Mode enabled is not an algorithm/parameter allowlist for every Rookery API.
Profiles, imported keys, certificates and signature algorithms still need their
own qualified restrictions. Bun, upstream OpenCode, model-provider TLS,
gateway/collector TLS and other dependencies are not certified by this probe.
FIPS module evidence establishes neither IL6 authorization, ALPS qualification,
hardware attestation nor human AAL2/AAL3 authentication.
