import { expect, test } from "bun:test"
import path from "path"

// The suite is isolated however it is started: through `bun run test` (script/test.ts) or a plain
// `bun test`, as an editor or a single-file run does. A plain run must not reach the real home.
test("a plain bun test run gets the same isolated home, XDG roots and scrubbed environment", async () => {
  const probe = path.join(import.meta.dir, "fixture", "isolation-probe.ts")
  const child = Bun.spawn([process.execPath, "test", probe], {
    cwd: path.join(import.meta.dir, ".."),
    // Start from the real environment, the way a developer's shell would, plus a provider secret.
    env: {
      ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("OPENCODE_"))),
      HOME: "/nonexistent-real-home",
      XDG_CONFIG_HOME: "/nonexistent-real-home/.config",
      OPENAI_API_KEY: "sk-real-key",
      // Recording mode keeps OPENAI_API_KEY on purpose; this probe checks the ordinary scrub.
      RECORD: "false",
      OPENCODE_CONFIG: "/nonexistent-real-home/opencode.json",
    },
    stdout: "pipe",
    stderr: "pipe",
  })
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ])
  expect({ code, output: code === 0 ? "" : stdout + stderr }).toEqual({ code: 0, output: "" })
})
