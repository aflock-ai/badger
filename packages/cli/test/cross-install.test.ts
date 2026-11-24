import { expect, test } from "bun:test"
import { crossPlatformInstall } from "../script/cross-install"

// The build fetches every platform's native packages so it can cross-compile. `bun install` with
// package names saves them like `bun add`, rewriting package.json (re-sorted, workspace entries
// dropped) and the lockfile, so a build in a clean checkout left it dirty.
test("the build's cross-platform install never writes package.json or the lockfile", () => {
  const args = crossPlatformInstall({ "@opentui/core": "catalog:", "@opencode-ai/pty": "0.2.0" })
  expect(args).toContain("--no-save")
  expect(args.slice(0, 2)).toEqual(["bun", "install"])
})

test("it fetches every OS and CPU variant of exactly the pinned native packages", () => {
  const args = crossPlatformInstall({ "@opentui/core": "catalog:", "@opencode-ai/pty": "0.2.0" })
  expect(args).toContain("--os=*")
  expect(args).toContain("--cpu=*")
  expect(args.filter((arg) => !arg.startsWith("-") && arg !== "bun" && arg !== "install")).toEqual([
    "@opentui/core@catalog:",
    "@opencode-ai/pty@0.2.0",
  ])
})
