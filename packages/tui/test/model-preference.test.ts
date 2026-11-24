import { expect, test } from "bun:test"
import path from "node:path"
import { createModelPreferenceRepository, decodeModelPreference, fallbackModel } from "../src/model-preference"
import { tmpdir } from "./fixture/fixture"

test("repairs known model preferences and preserves unrelated fields", () => {
  expect(
    decodeModelPreference({
      unrelated: { keep: true },
      recent: [{ providerID: "openai", modelID: "gpt-5", ignored: true }, null],
      favorite: "malformed",
      variant: { "openai/gpt-5": "high", default: "default", invalid: 42 },
    }),
  ).toEqual({
    unrelated: { keep: true },
    recent: [{ providerID: "openai", modelID: "gpt-5" }],
    favorite: [],
    variant: { "openai/gpt-5": "high", default: "default" },
  })
})

test("atomically serializes model preference updates", async () => {
  await using tmp = await tmpdir()
  const file = path.join(tmp.path, "model.json")
  await Bun.write(file, JSON.stringify({ unrelated: "keep", favorite: [], variant: {} }))
  const repository = createModelPreferenceRepository(file)
  const openai = { providerID: "openai", modelID: "org/gpt-5" }
  const anthropic = { providerID: "anthropic", modelID: "claude/sonnet" }

  await Promise.all([
    repository.addRecent(openai),
    repository.saveVariant(openai, "high"),
    repository.saveVariant(anthropic, "low"),
  ])
  expect(await Bun.file(file).json()).toEqual({
    unrelated: "keep",
    recent: [openai],
    favorite: [],
    variant: { "openai/org/gpt-5": "high", "anthropic/claude/sonnet": "low" },
  })

  await repository.saveVariant(openai, "default")
  expect(await repository.resolveVariant(openai)).toBeUndefined()
  expect((await Bun.file(file).json()).variant).toEqual({
    "openai/org/gpt-5": "default",
    "anthropic/claude/sonnet": "low",
  })
})

test("a configured model wins, and an unusable configured model is not replaced by another one", () => {
  const gw = { providerID: "gw", modelID: "approved" }
  const other = { providerID: "other", modelID: "chat" }
  const missing = { providerID: "gw", modelID: "missing" }
  const valid = (model: { providerID: string; modelID: string }) => model.providerID !== "gw" || model.modelID === "approved"

  expect(fallbackModel({ configured: gw, recent: [other], first: other }, valid)).toEqual(gw)
  expect(fallbackModel({ configured: missing, recent: [other], first: other }, valid)).toBeUndefined()
  expect(fallbackModel({ requested: other, configured: missing, recent: [], first: other }, valid)).toEqual(other)
  expect(fallbackModel({ recent: [missing, other], first: gw }, valid)).toEqual(other)
  expect(fallbackModel({ recent: [], first: gw }, valid)).toEqual(gw)
  expect(fallbackModel({ recent: [] }, valid)).toBeUndefined()
})
