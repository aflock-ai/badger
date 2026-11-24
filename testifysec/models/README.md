# Retired: reviewed model catalog augmentation (1.x)

Badger 2.0 ships the managed build only. That build has no bring-your-own-provider path: its
compiled profile offers one model, `managed/approved`, through the administrator's gateway; the
models.dev catalog is empty and is never fetched or read from disk.

What lived here in 1.x, so nobody re-adds it by accident:

- `augment.ts` added `openai/gpt-6-astra` to a pinned models.dev snapshot at build time, with
  input/effective/provenance digests, for the unmanaged interactive preview's OpenAI and Codex
  OAuth providers.
- `uat.py` compiled that catalog through the upstream provider code and checked SDK
  serialization, pricing and the Codex OAuth model filter offline.

Upstream 2.0 already carries `gpt-6-astra` in its own catalog and ChatGPT plugin, and testing
upstream's catalog is upstream's job. If a bring-your-own-provider build is ever wanted again, that
is a product decision first; start from the 1.x history of this directory, not from here.
