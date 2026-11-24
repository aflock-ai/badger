# Retired: bundled plugin host and Codex OAuth compatibility (1.x)

Badger 2.0 ships the managed build only. That build loads only its precompiled plugins (no
plugin directory, npm install or import from disk), has no provider login, and holds no provider
credential: the administrator's gateway does.

What lived here in 1.x, so nobody re-adds it by accident:

- `host.ts` and `codex.ts`: a bundled-plugin host that ran upstream's `CodexAuthPlugin` with its
  full hook surface, and `uat.py`, 22 compiled checks of synthetic device login and refresh and the
  normal hook lifecycle.
- `responses.ts`: the OpenAI Responses route the preview used with a Codex or API-key credential.
- `browser/`: the Codex browser OAuth callback hardening (bind port 1455 to `127.0.0.1`, close the
  listener on bind failure and when the callback settles) and nine loopback/PKCE/cleanup scenarios.
  That patch was never carried into 2.0: `packages/core/src/plugin/provider/openai.ts` is upstream's
  file, which binds `localhost` and has its own fallback port.

Upstream's Codex plugin is upstream's to test. If a bring-your-own-provider build is ever wanted
again, that is a product decision first; start from the 1.x history of this directory.
