import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"

// Builds the Linux worker entry (`build.ts --managed --worker`) the way the runtime and VM boundaries
// receive it, once as a release build and once with the UAT fixture model, and checks both from the
// outside. The fixture model is a compile-time-only UAT provider: a release build must not contain it.
const work = await fs.mkdtemp(path.join(os.tmpdir(), "badger-managed-worker-"))
const fixtureSocket = "/tmp/hardened-fixture-model.sock"
// The managed build's output binary name under <target>/bin: the product command (see script/executable.ts).
const binary = "badger"
const binaries: Record<"release" | "fixture", string> = { release: "", fixture: "" }

async function build(name: keyof typeof binaries, flags: string[]) {
  const outdir = path.join(work, name)
  const child = Bun.spawn(
    [process.execPath, "run", "script/build.ts", "--single", "--skip-install", "--skip-web-ui", "--managed", "--worker", ...flags, `--outdir=${outdir}`],
    { cwd: path.join(import.meta.dir, ".."), stdout: "ignore", stderr: "pipe" },
  )
  const [stderr, code] = await Promise.all([new Response(child.stderr).text(), child.exited])
  if (code !== 0) throw new Error(`${name} worker build failed: ${stderr.slice(-2000)}`)
  const [target] = await fs.readdir(outdir)
  binaries[name] = path.join(outdir, target!, "bin", binary)
}

beforeAll(async () => {
  await build("release", [])
  await build("fixture", ["--fixture-model"])
}, 900_000)

afterAll(() => fs.rm(work, { recursive: true, force: true }))

const contains = async (file: string, text: string) => Buffer.from(await Bun.file(file).arrayBuffer()).includes(text)

describe("managed worker build", () => {
  test("a release worker contains no fixture model; the fixture build does", async () => {
    expect(await contains(binaries.fixture, fixtureSocket)).toBe(true)
    expect(await contains(binaries.release, fixtureSocket)).toBe(false)
    expect(await contains(binaries.release, "hardened-worker-verified")).toBe(false)
  })

  test("the worker refuses to start outside its managed boundary", async () => {
    for (const args of [[], ["serve"]]) {
      const child = Bun.spawn([binaries.release, ...args], { cwd: work, stdin: "pipe", stdout: "pipe", stderr: "pipe" })
      // The worker refuses and exits without reading its prompt, so the pipe may already be closed
      // when the prompt is written: EPIPE is that refusal arriving first. The exit code and stderr
      // below are the check either way.
      try {
        child.stdin.write(JSON.stringify({ schema: "testifysec.hardened-opencode.prompt/v1", prompt: "hi", profileDigest: "a".repeat(64) }))
        await child.stdin.end()
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EPIPE") throw err
      }
      const [stdout, stderr, code] = await Promise.all([
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
        child.exited,
      ])
      expect({ code, stdout, stderr }).toEqual({ code: 1, stdout: "", stderr: "managed worker unavailable\n" })
    }
  })
})
