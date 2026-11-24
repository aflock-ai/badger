# Runtime config v4

`testifysec.vm-config/v4` connects a service-assigned backend manifest reference to an explicitly selected `testifysec.hardened-opencode.gateway/v2` configuration. The native host checks the gateway's exact backend `{kind:"darwin-vz/v1", manifestSha256}`, session and profile against the runtime config before creating VZ devices, and checks the gateway file digest again when the relay connects.

V4 requires `backendManifestSha256`, `gatewayConfigFile` and `gatewayConfigSha256`. Missing, null, malformed, duplicate or incorrectly named binding fields fail closed. Config v2/v3 retain gateway/v1 and reject the new manifest field, including null. No version is inferred from file contents and there is no fallback.

Two digests remain separate:

- `backendManifestSha256` pins the exported backend manifest, including its host, kernel, root disk and provenance references.
- The existing job `binding.backendSha256` remains SHA256 of `kernelSha256 + "\n" + rootDiskSha256 + "\n"`. V4 does not change this value's meaning.

The protected service must create runtime config v4 **after** backend export gives it the manifest digest. `build.py --protocol 3` emits the v3 build fixture (the existing builder default remains protocol 2); do not insert the exported manifest digest into that build fixture or regenerate `build.json` with it. The exported manifest hashes `build.json`, so feeding the manifest digest back would create a circular dependency.

Managed job and guest result schemas remain v3; HCMDL2 framing remains unchanged. Config v4 emits `testifysec.vm-observation/v4`, adding independent `serialReaderDrained` and `serialEOFObserved` booleans. Only a successful empty serial read proves EOF; a caught read error can complete the reader task while EOF remains false. V4 full completion requires both flags. Config v2/v3 preserve their original observation shapes. The host still reports `admissionIntegrated:false` and `developer-only-unqualified`. This check does not verify profile signatures, establish platform identity, independently validate the exported manifest/files, or authorize boot. Those decisions belong to the protected launch service. The nested host observation must remain intact when that service adds its own result wrapper.

Run the bounded local configuration UAT on macOS:

```sh
python3 testifysec/vm/uat-config-v4.py \
  --output /private/tmp/aflock-vm-config-v4-uat
```

The harness compiles the actual host sources twice: the normal host, and a probe with only the production `@main` attribute removed and a fixture entry added. Both call the exact same `validatedVMInputs` function. Positive probes stop after validation; negative cases also run the normal host and require the intended refusal before any Runner starts. Public dummy kernel/root files exercise byte pins but are deliberately not bootable VM artifacts. Real local pipe cases also exercise empty/data EOF, a read exception and a held writer, then check the production observation assembly function preserves old shapes and refuses v4 completion without both drain and EOF. This suite proves version dispatch, digest separation, serial-reader observations and config/refusal behavior; a real worker/VM/provider journey is a separate integration test.

The report records selected source bytes, the narrowly changed fixture entry source, tool and executable digests, exact case results and retained bounded logs. Hashes are local path-readback observations, not runtime measurements or signatures. The harness uses no credentials, provider calls, VM boot, release upload or package download.
