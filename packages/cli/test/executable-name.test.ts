import { expect, test } from "bun:test"
import { executableName } from "../script/executable"

test("a managed build installs as badger; every other build keeps opencode", async () => {
  expect(await executableName(true)).toBe("badger")
  expect(await executableName(false)).toBe("opencode")
})
