import { expect, test } from "bun:test"
import { MemoryCustody } from "./memory-custody.js"

test("restriction is one-way: nothing re-enables memory diagnostics once a secret was held", () => {
  expect(MemoryCustody.restricted()).toBe(false)
  MemoryCustody.restrict("test secret")
  expect(MemoryCustody.restricted()).toBe(true)
  MemoryCustody.restrict("again")
  expect(MemoryCustody.restricted()).toBe(true)
})
