# Compiled Model Startup Regression

The independent Badger preview failed in `SystemPrompt.environment` before its
first provider request. Building location services traversed a dependency array
containing an undefined `FileSystemSearch.node`.

`filesystem.ts` depends on `filesystem/search.ts`. Search imported runtime
`Entry` and `Match` constructors back through `filesystem.ts`. When Search was
evaluated first, the cycle read its node before initialization. Source execution
reported a ReferenceError; the compiled bundle captured undefined and later
failed during layer traversal.

The repair imports these constructors directly from
`@opencode-ai/schema/filesystem`, preserving only a type import from FileSystem.
It does not defer dependency construction or suppress a missing service.

## Provenance

On 2026-09-10, the pre-existing uncommitted diagnostic in
`subtrees/opencode/packages/core/src/effect/layer-node.ts` in a separate local Judge checkout
and its `make-undefined-dependency.test.ts` were inspected read-only with the
operator's permission. They had intentionally not been exported to Badger.
That change detects an undefined dependency; it does not fix the import cycle.

Badger's small `LayerNode.make` guard is an independently written implementation
of that known diagnostic approach, with a different message and regression cases
covering undefined, null, named nodes, and a nonzero dependency index. No source
tree was copied, and the original checkout was not edited.

The actual Search schema-import repair and fresh-process import-order test were
developed in the independent Badger source after the compiled diagnostic named
FileSystem dependency 2. Both new regression cases were run failing before their
respective implementation changes, then passing afterward.

## Verification

- Run core `test/effect/layer-node`, `test/filesystem-import.test.ts`, and the
  filesystem/search behavior tests from `packages/core`.
- A fresh compiled binary must also complete a loopback model turn, not merely
  print its version. The local fixture requests actual `pushgate_requirements`
  and `bash` calls before its final response.
- The disabled Requirements result and redacted synthetic credential output
  must appear in both the persisted transcript and subsequent provider input.
- Build and test with external networking denied. No live provider, enrollment,
  activation, installation, or signing is required for this regression.

This is development-preview validation, not a production sandbox or live-provider
qualification. The diagnostic guard is deliberately retained to identify future
malformed dependency declarations at their owner rather than during traversal.
