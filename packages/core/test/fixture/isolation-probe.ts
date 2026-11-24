import { expect, test } from "bun:test"
import os from "os"
import path from "path"
import { Global } from "@opencode/util/global"

// Run by isolation.test.ts as a plain `bun test` of this file, so only the preload isolates it.
test("isolated", () => {
  const home = process.env.OPENCODE_TEST_HOME
  expect(home).toBeDefined()
  expect(home).not.toBe("/nonexistent-real-home")
  expect(process.env.HOME).toBe(home)
  expect(Global.Path.config).toBe(path.join(home!, ".config", "opencode"))
  expect(Global.Path.data).toBe(path.join(home!, ".local", "share", "opencode"))
  expect(os.tmpdir()).toBe(path.join(home!, "tmp"))
  expect(process.env.OPENAI_API_KEY).toBeUndefined()
  expect(process.env.OPENCODE_CONFIG).toBeUndefined()
})
