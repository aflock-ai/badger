import fs from "fs/promises"
import path from "path"
import { isolatedEnvironment } from "../test/fixture/isolation"
import { tmpdir } from "../test/fixture/tmpdir"

await using directory = await tmpdir("oc-")
const home = directory.path
await fs.mkdir(path.join(home, "tmp"))

const environment = { ...isolatedEnvironment(process.env, home), OPENCODE_TEST_RUNNER: "1" }

const child = Bun.spawn({
  // The 30s default timeout matches cli and tui; npm.test's Git package installs ran past Bun's 5s default on Windows.
  cmd: [process.execPath, "test", "--only-failures", "--timeout=30000", ...process.argv.slice(2)],
  env: environment,
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
})
const interrupt = () => child.kill("SIGINT")
const terminate = () => child.kill("SIGTERM")
process.once("SIGINT", interrupt)
process.once("SIGTERM", terminate)
const result = await child.exited
process.off("SIGINT", interrupt)
process.off("SIGTERM", terminate)

process.exitCode = result
