# Badger enrollment and attestation

`badger enroll` and `badger attest` use embedded native helpers. Both default to
`https://platform.testifysec.com` in `platform` mode. A build must include the
native asset manifest to provide these commands; earlier previews lack it.

The LLM does not fill in signing claims. The field ownership is:

| Fields | Source |
| --- | --- |
| Trust mode, platform origin, local state location | Operator settings, environment or explicit command flags |
| Proposed enrollment name, repository and lifetime | Optional operator settings or flags; the platform ceremony decides authority |
| Agent ID, tenant, SPIFFE identity, expiry | Verified platform enrollment and native credential exchange |
| Session, commit, artifacts, profile binding | Revalidated finalized runtime record; an optional session argument is only a selector |
| Signature, timestamp, upload acknowledgment | Native signer and the platform response |

For settings, precedence is **command flag → environment → user settings →
default**. The environment variables are `AFLOCK_TRUST_MODE`,
`AFLOCK_PLATFORM_URL`, and `AFLOCK_STATE_DIR`. `--settings /absolute/file.json`
selects an explicit operator file. Without that flag, the settings file is:

| OS | Path |
| --- | --- |
| macOS | `~/Library/Application Support/TestifySec/Aflock/settings.json` |
| Linux | `$XDG_CONFIG_HOME/aflock/settings.json`, defaulting to `~/.config/aflock/settings.json` |
| Windows | `%APPDATA%/TestifySec/Aflock/settings.json` (native command runtime remains unqualified and refuses) |

Implicit Linux discovery honors only absolute `XDG_CONFIG_HOME` and `XDG_STATE_HOME` values; relative or empty values use `~/.config` and `~/.local/state`, while explicit `--settings` and `AFLOCK_STATE_DIR` selections retain their existing behavior.

```json
{
  "schema": "testifysec.aflock.settings/v1",
  "trustMode": "platform",
  "platformURL": "https://platform.testifysec.com",
  "enrollment": {
    "name": "developer-workstation",
    "repository": "testifysec/example"
  }
}
```

On Unix the file must be owned by the current user and private (`chmod 600`).
The path must not traverse symlinks or directories that another user can replace.
It is bounded JSON, with unknown fields, duplicate keys and malformed values
rejected. Enrollment lifetimes must be between 900 and 604800 seconds, matching
the native platform ceremony. No project config, inline OpenCode config, plugin or prompt is merged
into these settings. The loader does not expand templates or execute commands.

Use `badger enroll --trust-mode local-self-signed` for an explicitly untrusted
local identity. This mode has its own state child directory and ignores platform
defaults from the settings file; explicit `--platform` or
`AFLOCK_PLATFORM_URL` conflicts are refused. It never falls back from a failed
platform request. `badger attest --trust-mode local-self-signed` reuses the local
identity and saves local evidence without platform upload.

`enroll --no-browser` shows its one-time enrollment link only on an interactive
terminal. JSON and redirected output omit that link and explain how to continue.

`attest` defaults to the current workspace's finalized protected session, or
accepts `--session ID`. It will not sign ordinary preview chat history as
execution evidence. A missing finalized record produces a refusal. Credentials,
private keys and arbitrary attestation payloads are not command arguments.

These are operator preferences, not a new isolation boundary. The current
development preview runs tools as the user's account, so a compromised tool
could change that user's settings or invoke commands. Protected execution must
keep the worker away from operator settings and signer credentials and must
independently enforce the signed profile. A settings value cannot prove hardware
attestation, ALPS level, FIPS validation or deployment qualification.

Local verification: run `bun test ./testifysec/commands/*.test.ts` from the Badger root and
`bun test test/enroll-attest.test.ts` from `packages/cli`. The 2.0 managed build does not embed
the native helpers yet, so `uat-cli.py` still needs a 1.x binary: run `python3 testifysec/commands/uat-cli.py --binary BADGER_BINARY --report REPORT.json`
from the Badger root. The CLI harness uses temporary state and a macOS
network-denial guard. Protected fixture evidence is exercised separately by the
native upload harness; these tests do not attest an ordinary preview transcript.
