import { expect, test } from "bun:test"
import { chmod, mkdtemp, realpath, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"

const entry = path.resolve(import.meta.dir, "../src/index.ts")

// Runs the real CLI entry compiled as a branded, upstream or managed worker build, with no AFLOCK_*
// variable. Bun's os.homedir() on macOS ignores HOME, so the commands get an explicit empty settings
// file instead of reading the operator's own.
async function cli(build: "branded" | "upstream" | "managed", ...args: string[]) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("AFLOCK_")))
  const child = Bun.spawn(
    [
      process.execPath,
      "--define",
      `HARDENED_BUILD:${build !== "upstream"}`,
      "--define",
      `TESTIFYSEC_MANAGED_WORKER:${build === "managed"}`,
      entry,
      ...args,
    ],
    { env, stdout: "pipe", stderr: "pipe" },
  )
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ])
  return { stdout, stderr, code }
}

async function withHome(run: (home: string) => Promise<void>) {
  // The settings loader refuses symlinked ancestors, and the macOS temp directory sits behind one.
  const home = await realpath(await mkdtemp(path.join(tmpdir(), "badger-enroll-attest-")))
  const settings = path.join(home, "settings.json")
  await writeFile(settings, JSON.stringify({ schema: "testifysec.aflock.settings/v1" }))
  await chmod(settings, 0o600)
  try {
    await run(home)
  } finally {
    await rm(home, { recursive: true, force: true })
  }
}

// As in 1.x, enroll and attest exist only in a branded build. An upstream build lists neither.
test("enroll and attest are listed only in a branded build", async () => {
  const branded = await cli("branded", "--help")
  expect(branded.stdout).toMatch(/^ +enroll +enroll this Badger agent with the attestation platform$/m)
  expect(branded.stdout).toMatch(/^ +attest +sign finalized session evidence and upload it to the attestation platform$/m)
  expect(branded.stdout).not.toMatch(/testifysec/i)
  const upstream = await cli("upstream", "--help")
  expect(upstream.code).toBe(0)
  expect(upstream.stdout).not.toMatch(/^ +(enroll|attest) /m)
}, 120_000)

// The flags reach the 1.x request builders: a platform origin is refused in local-self-signed mode
// before anything touches the network or a native helper.
test("enroll passes its flags to the request builder", () =>
  withHome(async (home) => {
    const result = await cli(
      "branded",
      "enroll",
      "--settings",
      path.join(home, "settings.json"),
      "--trust-mode",
      "local-self-signed",
      "--platform",
      "https://platform.example.test",
      "--state-dir",
      path.join(home, "state"),
      "--no-browser",
    )
    expect(result.code).not.toBe(0)
    expect(result.stderr).toContain("--platform / AFLOCK_PLATFORM_URL cannot be combined with local-self-signed mode")
  }), 120_000)

// A build without the embedded native helper says so instead of looking for one elsewhere.
test("attest without an embedded native helper reports it is not bundled", () =>
  withHome(async (home) => {
    const result = await cli("branded", "attest", "--settings", path.join(home, "settings.json"), "--trust-mode", "local-self-signed", "--state-dir", path.join(home, "state"))
    expect(result.code).not.toBe(0)
    expect(result.stderr).toContain("Native command unavailable: helper-not-bundled")
  }), 120_000)

// The managed worker never holds operator settings or signer credentials, so it refuses both.
test("a managed worker build refuses enroll and attest", async () => {
  for (const command of ["enroll", "attest"]) {
    const result = await cli("managed", command)
    expect(result.code).not.toBe(0)
    expect(result.stderr).toContain("This command is not available in this build")
  }
}, 120_000)
