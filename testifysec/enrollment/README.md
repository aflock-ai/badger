> **Parked: not buildable from this repository.** `build.py` compiles
> `rookery/cilock/enrollment`, which no longer exists in any reachable source
> (public rookery or the current monorepo tree), and it expects a monorepo
> checkout around this one. It refuses with that message instead of failing on a
> missing path. The parked Pushgate handoff component has the same root cause and is not part of this repository.

Aflock by TestifySec provides the user-facing `aflock enroll` command. The native enrollment backend reuses Cilock's existing human approval ceremony. Aflock bundles this executable inside its compiled app; users do not install Cilock, Node or an npm package. This slice implements native enrollment and a callable native credential loader. Frontend command wiring and native signing/upload are separate consumers.

Build and verify using an installed, pinned Go toolchain:

```sh
GOCACHE=/private/tmp/hardened-opencode-gocache python3 testifysec/enrollment/build.py \
  --go /absolute/path/to/go --output /private/tmp/hc-enroll --uat
```

The harness runs the canonical `internal/auth` tests and new enrollment tests, then actual compiled local enrollment. Tests use synthetic secrets and private temporary stores. No real account, human ceremony, enrollment, paid API call or upload is performed. The unsigned build manifest binds the executable's path readback, Go executable, and selected in-tree source/module inputs before and after compilation and UAT. It is not release authorization or runtime measurement.

The embedded process accepts only argv `enroll` and one exact JSON object on stdin, bounded to 16 KiB:

```json
{"schema":"testifysec.hardened-code.enroll/v1","trustMode":"platform","stateDirectory":"/canonical/private/product-base","platformURL":"https://platform.testifysec.com","name":"Aflock","repository":"owner/repository","ttlSeconds":28800,"noBrowser":false}
```

`trustMode` defaults to `platform` only when omitted. Explicit empty, unknown, duplicate, case-alias, null and trailing JSON are refused. Platform URLs must be exact HTTPS origins. The URL defaults to `https://platform.testifysec.com`; name, repository and lifetime are browser prefill hints, never enrollment authority. The platform selects and authenticates the actual tenant, repository UUID scope, lifetime, fresh AAL2 ceremony, stable agent UUID and SPIFFE identity. No current human presence, future AAL3 or hardware custody claim is added by this client.

The frontend creates a canonical private product directory; the native helper checks owner, permissions, symlinks and ancestor replacement rights, then uses fixed `platform` or `local-self-signed` children. Platform enrollment sets `CILOCK_STATE_DIR` only inside its dedicated native process. It never reads the user's ordinary Cilock store or a human session. All platform HTTPS requests refuse redirects and inherited HTTP proxies. The app must supply a controlled child environment; system TLS roots remain the platform trust source.

The canonical browser flow retains its P256 ECDH/HKDF/AES-GCM sealed loopback delivery, pending/active store distinction, activation-before-success and compare-and-swap promotion. The callback is not an authenticated identity source. The final SPIFFE value comes from the platform activation response, checked against the delivered tenant/agent, then confirmed against the stored active record. Initial trust-domain pinning retains Cilock's trust-on-first-use limitation. The browser still renders Cilock's canonical credential-received callback page. This does not replace the platform's human approval UI.

Stdout contains `testifysec.hardened-code.command-event/v1` JSONL with `event: ceremony|enrolled|error`. `ceremony` includes `platformURL`, `url`, `trustMode` and an explicit `browserOpened` boolean. A successful opener receives the full URL; the frontend receives only redacted state and sealing-public-key parameters. If no browser starts, the full one-time URL is emitted only for immediate human terminal presentation; it must not enter application logs, model context, saved transcripts or audit payloads. The flag reports opener start, not observed browser navigation. Errors contain a static code and message, never raw platform error text. The frontend must retain the exit code and must not infer success from a ceremony event.

`enrolled` includes `trustMode`, `assurance`, `identityReference` and the actual mode-specific `stateDirectory`. Platform results additionally include `platformURL`, `tenantID`, `agentID`, `spiffeID` and recorded `expiresAt`. There are no refresh credentials or signing/upload tokens in the event stream.

For explicit `local-self-signed`, omit platform URL, name, repository and lifetime. This creates or verifies one persistent P256 key in `identity-key.pem` (PKCS8), `identity-public.pem` (SPKI), and `local-identity.json`, all private 0600 files. Metadata schema `testifysec.hardened-code.local-identity/v1` records `trustMode`, `assurance: local-self-signed-untrusted`, `createdAt`, fixed key filenames and `publicKeySha256`. The identity reference is `urn:testifysec:local-self-signed:sha256:<SHA256 DER SPKI>`. Re-enrollment preserves the key; mismatches, incomplete transactions and unsafe permissions refuse instead of rotating or overwriting it. The signer must independently derive and check that fingerprint from the loaded key. Local enrollment creates no platform tenant, SPIFFE principal, trusted timestamp or enrollment evidence. Platform failure never selects this mode.

Native signing code can import `github.com/aflock-ai/rookery/cilock/enrollment` and call `LoadActivePlatformAgent(stateDirectory, platformURL)`. The state directory must exactly match the native process's explicit `CILOCK_STATE_DIR` and end in `platform`. The loader uses canonical `auth.LookupAgent`, accesses no human store, performs no network call, and does not redeem a pending credential. It returns native-only `PlatformAgent` fields including `RefreshCredential` (excluded from JSON; String redacts it). The native consumer must freshly exchange that credential and validate exact expected tenant, agent and trust-domain binding; stored metadata alone is not authentication. This avoids exporting refresh credentials to Bun or an intermediate credential file.

Darwin and Linux use OS-user custody. A hostile process with the same UID is outside that boundary. Windows may compile but deliberately refuses enrollment until persistent store DACL custody is implemented and executed on a Windows runner; a chmod check is not used as a substitute. Windows browser opening likewise remains an explicit manual URL fallback. A pending credential retained after an outage can be recovered through canonical native activation logic, but this first public command does not expose a separate resume/status operation. Runtime Python is unnecessary; Python is only a build/UAT tool.

The frontend resolves `AFLOCK_TRUST_MODE` and the selected platform from trusted application settings. LLM tool arguments do not select trust mode, platform authority or credential-store paths. The native request remains explicit so the protected bridge can bind those settings; its TestifySec wire schema identifiers and internal `CILOCK_STATE_DIR` compatibility boundary remain unchanged.
