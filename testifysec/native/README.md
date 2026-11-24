# Native verification component · HC-01

The compiled `rookery-verify` diagnostic calls Rookery through Bun FFI and the C ABI. It is a component acceptance tool, not a managed OpenCode launcher. Go, Bun and a C compiler are build-time dependencies only.

```sh
python3 testifysec/native/build.py --output /tmp/hardened-native-bundle
python3 testifysec/native/uat.py --report /tmp/hardened-native-uat.json
```

Use `--go /absolute/go --bun /absolute/bun` to select installed build tools. The local harness generates ephemeral ECDSA fixtures and runs the real compiled executable from an unrelated directory with an empty package-tool PATH. No private signing keys are exported. Results include source and artifact digests, toolchain versions and working-tree status.

The public entrypoint is a CGO-disabled Go launcher. It checks the internal runtime digest and replaces itself with that runtime under a fixed environment before Bun can process preload settings. Both CLIs accept stdin only; no runtime options are forwarded. The internal runtime also checks a compiled-in library digest and disables configuration/dotenv autoload. `openVerifier` validates ABI version and frees every returned native allocation. Go's c-shared runtime is retained for process lifetime: [unloading is unsupported](https://github.com/golang/go/issues/11100). A new native release requires process restart.

Installation must protect the executable, library and their parent directories from worker writes for the full process lifetime. The digest check before loading does not solve a privileged concurrent replacement. This phase establishes neither installation privilege separation nor FIPS validation.

The launcher's own OS loader is another boundary: an environment variable processed before native `main` cannot be cleared by that `main`. Darwin bundles are development artifacts pending protected launch/signing qualification. Workers must never be able to invoke the internal Bun runtime under controller credentials; hiding its filename is not access control.

The diagnostic accepts caller-provided public keys because it tests cryptographic verification. It must not be used as the authority for managed profile admission: that component supplies trust from protected installation policy and checks signed payload semantics separately.

## Trust modes

A request selects one mode, never both and never a fallback. **Pinned keys** (`publicKeys`,
`threshold`): signatures are exactly `{keyid, sig}`; a certificate is refused, not ignored.
**Certificate chain** (`rootCas`, `signerIdentity`, `threshold`): every signature carries a
`certificate` (and any `intermediates`) chaining to one of at most eight pinned roots at the time
of verification; only end-entity leaves with digital-signature key usage, the code-signing EKU and
the exact `signerIdentity.san` (URI, email or DNS) count, and one key under two certificates is
refused. The response adds `signerCertificates`, each counted leaf's `notBefore` and `notAfter`.

The verifier does not parse the payload, so the **window-inside-leaf** rule is the caller's:
`managed/profile.ts` refuses a profile whose `[notBefore, expiresAt)` is not inside every counted
leaf (`profile-outside-signer-certificate`), so a stolen leaf key's signatures die with the leaf.
Since admission also requires `notBefore <= now < expiresAt`, checking the chain now is the same,
for the leaf, as checking it at the signed `notBefore`. No CRLs; leaves are short-lived instead.
Timestamps on a signature are refused in both modes (below).

## Decided: seven-day signing leaves for the platform (2026-10-22)

The platform's build-attestation leaves live minutes; under the window-inside-leaf rule a
profile signed with one could be valid only for those minutes. Decision: the platform's CA issues
**dedicated leaves of at least seven days** (the longest window it signs) for profiles, activation
records and reset records, separate from its build leaves and told apart by their own SAN, which
admission's `signerIdentity.san` pins. A stolen signing key is good until its leaf expires, at
most seven days, the same residual as the portal's. Nothing in admission, the broker or the
contract model changes, and timestamps stay refused. The platform side (Judge) implements it; the
requirement is in `../PRODUCT-CONTRACT.md`.

Not chosen: accepting an RFC 3161 timestamp as proof of signing time. It needs a second pinned
root (the TSA), a timestamp parser inside admission, a TSA the enclave can reach, a model change,
and a hard seven-day cap on `expiresAt - genTime`, or a key stolen in its leaf's few minutes signs
a ten-year profile. If it is ever added, it ships with that cap.
