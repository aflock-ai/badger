import { expect, test } from "bun:test"
import { chooseModel } from "./model-choice"

const gw = { providerID: "gw", modelID: "approved" }
const other = { providerID: "other", modelID: "chat" }
const missing = { providerID: "gw", modelID: "missing" }
const valid = (model: { providerID: string; modelID: string }) => model.providerID !== "gw" || model.modelID === "approved"

test("a picked model wins, then the configured one, and an unusable configured model is not replaced", () => {
  expect(chooseModel({ picked: [undefined, other], configured: missing, recent: gw, first: gw }, valid)).toEqual(other)
  expect(chooseModel({ picked: [missing], configured: gw, recent: other, first: other }, valid)).toEqual(gw)
  expect(chooseModel({ picked: [], configured: missing, recent: other, first: other }, valid)).toBeUndefined()
  expect(chooseModel({ picked: [], recent: other, first: gw }, valid)).toEqual(other)
  expect(chooseModel({ picked: [], recent: missing, first: gw }, valid)).toEqual(gw)
  expect(chooseModel({ picked: [] }, valid)).toBeUndefined()
})
