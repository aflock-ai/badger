import { afterAll, setDefaultTimeout } from "bun:test"
import fs from "fs"
import os from "os"
import path from "path"
import { isolatedEnvironment } from "./fixture/isolation"

// `bun run test` (script/test.ts) starts the suite already isolated. A plain `bun test`, from an
// editor or for one file, did not: isolate it here, before any test module loads, so no test can
// reach the real home or a real credential. Only os.homedir() stays the process's own (Bun reads it
// once at start); everything here reads OPENCODE_TEST_HOME or HOME instead.
if (process.env.OPENCODE_TEST_HOME === undefined) {
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "oc-")))
  fs.mkdirSync(path.join(home, "tmp"))
  const isolated = isolatedEnvironment(process.env, home)
  for (const name of Object.keys(process.env)) if (!(name in isolated)) delete process.env[name]
  for (const [name, value] of Object.entries(isolated)) {
    if (value === undefined) delete process.env[name]
    else process.env[name] = value
  }
  // A preload's afterAll runs once after the whole run; bun test does not emit process "exit".
  afterAll(() => fs.rmSync(home, { recursive: true, force: true }))
}

process.env.OPENCODE_DB = ":memory:"
process.env.NPM_CONFIG_AUDIT = "false"

// The same 30 s the script passes, so a plain bun test does not time out slower tests at Bun's 5 s.
setDefaultTimeout(30_000)
