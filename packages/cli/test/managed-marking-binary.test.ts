import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { executableName } from "../script/executable"

// The real managed binary (`build.ts --managed`), built once with a compiled data marking and once
// without, then run with the environment trying to lower, unset or supply the marking.
const work = await fs.mkdtemp(path.join(os.tmpdir(), "badger-managed-marking-"))
const binaries: Record<"marked" | "unmarked", string> = { marked: "", unmarked: "" }

const build = async (name: keyof typeof binaries, flags: string[]) => {
  const outdir = path.join(work, name)
  const child = Bun.spawn(
    [
      process.execPath,
      "run",
      "script/build.ts",
      "--single",
      "--skip-install",
      "--skip-web-ui",
      "--managed",
      ...flags,
      `--outdir=${outdir}`,
    ],
    { cwd: path.join(import.meta.dir, ".."), stdout: "ignore", stderr: "pipe" },
  )
  const [stderr, code] = await Promise.all([new Response(child.stderr).text(), child.exited])
  if (code !== 0) throw new Error(`managed build failed: ${stderr.slice(-2000)}`)
  const [target] = await fs.readdir(outdir)
  binaries[name] = path.join(
    outdir,
    target!,
    "bin",
    (await executableName(true)) + (process.platform === "win32" ? ".exe" : ""),
  )
}

beforeAll(async () => {
  await build("marked", ["--data-marking=CUI", "--allowed-markings=UNCLASSIFIED,CUI"])
  await build("unmarked", [])
}, 1_200_000)

afterAll(() => fs.rm(work, { recursive: true, force: true }))

const about = async (binary: string, extra: Record<string, string>) => {
  const home = await fs.mkdtemp(path.join(work, "home-"))
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: home,
    XDG_CONFIG_HOME: path.join(home, "xdg"),
    XDG_DATA_HOME: path.join(home, "data"),
    XDG_STATE_HOME: path.join(home, "state"),
    XDG_CACHE_HOME: path.join(home, "cache"),
    ...extra,
  }
  const child = Bun.spawn([binary, "about"], { cwd: home, env, stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ])
  return {
    code,
    stderr: code === 0 ? "" : stderr.slice(-2000),
    marking: stdout.split("\n").find((line) => line.startsWith("Data marking:")),
  }
}

describe("managed binary data marking", () => {
  test("the compiled marking applies with BADGER_DATA_MARKING unset, and the environment cannot lower it", async () => {
    expect(await about(binaries.marked, {})).toEqual({ code: 0, stderr: "", marking: "Data marking: CUI" })
    expect(await about(binaries.marked, { BADGER_DATA_MARKING: "UNCLASSIFIED" })).toEqual({
      code: 0,
      stderr: "",
      marking: "Data marking: CUI",
    })
  }, 60_000)

  test("built without a marking, it has none and refuses connector data, whatever the environment says", async () => {
    const none = { code: 0, stderr: "", marking: "Data marking: none (connector data is refused)" }
    expect(await about(binaries.unmarked, {})).toEqual(none)
    expect(await about(binaries.unmarked, { BADGER_DATA_MARKING: "CUI", BADGER_ALLOWED_MARKINGS: '["CUI"]' })).toEqual(
      none,
    )
  }, 60_000)
})
