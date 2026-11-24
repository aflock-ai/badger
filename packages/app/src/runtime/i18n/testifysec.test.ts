import { expect, test } from "bun:test"
import en from "./en"
import { dict as testifysec } from "./testifysec"
import { dict as uiEn } from "@opencode/ui/i18n/en"

test("TestifySec strings never shadow an upstream key", () => {
  const upstream = new Set([...Object.keys(en), ...Object.keys(uiEn)])
  expect(Object.keys(testifysec).filter((key) => upstream.has(key))).toEqual([])
})
