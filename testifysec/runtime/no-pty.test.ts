import { expect, test } from "bun:test"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { noPty } from "./no-pty"

const binding = path.resolve(import.meta.dir, "../../packages/core/src/persistent-pty/pty-binding.ts")

// Compile a program that loads core's PTY binding, the way a UAT probe reaching core does, and run it.
async function compiled(plugins: Bun.BunPlugin[]) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "no-pty-"))
  try {
    const entry = path.join(dir, "entry.ts")
    await writeFile(entry, `import binding from ${JSON.stringify(binding)}\nconsole.log(String(binding))\n`)
    const outfile = path.join(dir, "probe")
    const build = await Bun.build({ entrypoints: [entry], compile: { outfile }, plugins })
    expect(build.success).toBe(true)
    const run = Bun.spawnSync([outfile], { stdout: "pipe", stderr: "pipe" })
    return { code: run.exitCode, stdout: run.stdout.toString().trim(), stderr: run.stderr.toString() }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

test("a compiled probe that reaches core's PTY binding fails without the stub", async () => {
  const run = await compiled([])
  expect(run.code).not.toBe(0)
  expect(run.stderr).toContain("@opencode-ai/pty-")
}, 60_000)

test("with the stub it starts and sees no PTY binary", async () => {
  expect(await compiled([noPty])).toEqual({ code: 0, stdout: "undefined", stderr: "" })
}, 60_000)
