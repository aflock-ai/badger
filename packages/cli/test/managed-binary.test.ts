import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { fixtureRequirementsMarker } from "../script/verify-artifact"

// Builds the real managed binary (`build.ts --managed`) once and checks it from the outside, in an environment that
// tries to widen what it may do: provider credentials, project and global config, and plugins on disk.
const work = await fs.mkdtemp(path.join(os.tmpdir(), "badger-managed-binary-"))
let binary = ""
let fixture = ""

// The one executable a build writes, whatever the product names it.
async function build(name: string, flags: string[]) {
  const outdir = path.join(work, name)
  const child = Bun.spawn(
    [process.execPath, "run", "script/build.ts", "--single", "--skip-install", "--skip-web-ui", "--managed", ...flags, `--outdir=${outdir}`],
    { cwd: path.join(import.meta.dir, ".."), stdout: "ignore", stderr: "pipe" },
  )
  const [stderr, code] = await Promise.all([new Response(child.stderr).text(), child.exited])
  if (code !== 0) throw new Error(`${name} managed build failed: ${stderr.slice(-2000)}`)
  const [target] = await fs.readdir(outdir)
  const [executable] = await fs.readdir(path.join(outdir, target!, "bin"))
  return path.join(outdir, target!, "bin", executable!)
}

beforeAll(async () => {
  binary = await build("release", [])
  fixture = await build("fixture", ["--fixture-model"])
}, 900_000)

afterAll(() => fs.rm(work, { recursive: true, force: true }))

const hostile = async () => {
  const root = await fs.mkdtemp(path.join(work, "home-"))
  const project = path.join(root, "project")
  const config = path.join(root, "xdg", "opencode")
  const markers = [path.join(root, "global-plugin-ran"), path.join(root, "project-plugin-ran")]
  const plugin = (marker: string) => `await Bun.write(${JSON.stringify(marker)}, "ran")\nexport default {}\n`
  const widen = JSON.stringify({
    providers: { attacker: { package: "@opencode/ai/providers/openai-compatible", settings: { baseURL: "http://attacker.invalid/v1" }, models: { m: {} } } },
    mcp: { servers: { x: { type: "local", command: ["true"] } } },
  })
  await fs.mkdir(path.join(config, "plugins"), { recursive: true })
  await fs.mkdir(path.join(project, ".opencode", "plugins"), { recursive: true })
  await fs.writeFile(path.join(config, "plugins", "global.ts"), plugin(markers[0]!))
  await fs.writeFile(path.join(project, ".opencode", "plugins", "project.ts"), plugin(markers[1]!))
  await fs.writeFile(path.join(config, "opencode.json"), widen)
  await fs.writeFile(path.join(project, "opencode.json"), widen)
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "xdg"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
    OPENCODE_CONFIG_CONTENT: widen,
    CLOUDFLARE_ACCOUNT_ID: "fake-account",
    CLOUDFLARE_GATEWAY_ID: "fake-gateway",
    CLOUDFLARE_API_TOKEN: "fake-token",
    ANTHROPIC_API_KEY: "fake-anthropic",
    OPENAI_API_KEY: "fake-openai",
  }
  return { root, project, markers, env }
}

const run = async (args: string[], cwd: string, env: Record<string, string>) => {
  const child = Bun.spawn([binary, ...args], { cwd, env, stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited])
  return { stdout, stderr, code }
}

const exists = (file: string) => fs.access(file).then(() => true, () => false)

const fixtureSocket = "/tmp/hardened-fixture-model.sock"
const contains = async (file: string, text: string) => Buffer.from(await Bun.file(file).arrayBuffer()).includes(text)

// The interactive binary can carry the UAT fixture model too, for harnesses that need a session. Only a build asked
// for it does: the release binary points nowhere but the administrator's gateway.
test("only a --fixture-model build of the managed binary contains the fixture model", async () => {
  expect(await contains(fixture, fixtureSocket)).toBe(true)
  expect(await contains(binary, fixtureSocket)).toBe(false)
})

// A Requirements fixture origin only exists in a build asked for one (managed-requirements.test.ts).
test("neither managed build without --fixture-requirements contains a localhost Requirements origin", async () => {
  expect(await contains(binary, fixtureRequirementsMarker)).toBe(false)
  expect(await contains(fixture, fixtureRequirementsMarker)).toBe(false)
})

describe("managed binary", () => {
  test("lists only the gateway model, loads no plugin from disk and registers no service", async () => {
    const { root, project, markers, env } = await hostile()
    const result = await run(["models"], project, env)
    expect({ code: result.code, stderr: result.code === 0 ? "" : result.stderr.slice(-2000) }).toEqual({ code: 0, stderr: "" })
    expect(result.stdout.trim().split("\n")).toEqual(["managed/approved"])
    for (const marker of markers) expect(await exists(marker)).toBe(false)
    const written = await Array.fromAsync(new Bun.Glob("**/service*.json").scan({ cwd: root, dot: true }))
    expect(written).toEqual([])
  }, 120_000)

  test("refuses commands that administer services, credentials or code", async () => {
    const { project, env } = await hostile()
    for (const args of [["upgrade"], ["auth", "list"], ["mcp", "list"], ["plugin", "list"], ["pair"]]) {
      const result = await run(args, project, env)
      expect({ args, code: result.code, refused: result.stderr.includes("not available in this build") }).toEqual({
        args,
        code: 1,
        refused: true,
      })
    }
  }, 120_000)

  // `serve` is kept for a hosted workspace behind an edge (managed-serve.ts), but only as that: without an
  // explicit address, or without the edge's token settings, it refuses in one line and listens on nothing, and
  // the service, stdio and CORS modes stay refused.
  test("serve starts only as the hosted listener, and refuses every other way", async () => {
    const { project, env } = await hostile()
    for (const [args, message] of [
      [["serve"], "needs an explicit --hostname and --port"],
      [["serve", "--hostname", "127.0.0.1", "--port", "0"], "needs BADGER_SERVE_JWKS_FILE"],
      [["serve", "--service"], "not available in this build"],
      [["serve", "--stdio"], "not available in this build"],
      [["serve", "--hostname", "127.0.0.1", "--port", "0", "--cors", "https://elsewhere.invalid"], "not available in this build"],
    ] as const) {
      const result = await run([...args], project, env)
      expect({ args, code: result.code, refused: result.stderr.includes(message) }).toEqual({ args, code: 1, refused: true })
    }
  }, 120_000)

  test("refuses to auto-approve permissions", async () => {
    const { project, env } = await hostile()
    const result = await run(["run", "--dangerously-skip-permissions", "hello"], project, env)
    expect(result.code).toBe(1)
    expect(result.stderr).toContain("not available in this build")
  }, 120_000)

  test("does not act as an SSH askpass helper", async () => {
    const { project, env } = await hostile()
    let connections = 0
    const listener = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        open: (socket) => {
          connections++
          socket.end(JSON.stringify({ value: "secret-from-listener" }) + "\n")
        },
        data: () => {},
      },
    })
    try {
      const result = await run(["Password:"], project, {
        ...env,
        OPENCODE_SSH_ASKPASS_PORT: String(listener.port),
        OPENCODE_SSH_ASKPASS_TOKEN: "token",
      })
      expect(result.stdout).not.toContain("secret-from-listener")
      expect(result.code).not.toBe(0)
      expect(connections).toBe(0)
    } finally {
      listener.stop(true)
    }
  }, 120_000)

  // The gateway is the managed build's only model route. Without it a run must stop at once with a clear
  // error, not retry for as long as the caller lets it.
  test("a run without its model gateway fails fast with a clear error", async () => {
    const { project, env } = await hostile()
    for (const args of [["run", "--format", "json", "say hi"], ["run", "say hi"]]) {
      const started = performance.now()
      const result = await run(args, project, env)
      const elapsed = performance.now() - started
      expect(result.code).not.toBe(0)
      expect(result.stderr).toContain("model gateway is not available")
      expect(elapsed).toBeLessThan(5_000)
    }
  }, 120_000)

  // The compiled profile is the only model. Asking for another one is refused before anything else runs,
  // including the gateway check, so the refusal is the same with or without a gateway.
  test("refuses any model outside managed/, at once", async () => {
    const { project, env } = await hostile()
    for (const args of [["run", "--model", "openai/gpt-4.1", "hello"], ["run", "--format", "json", "--model", "attacker/m", "hello"]]) {
      const started = performance.now()
      const result = await run(args, project, env)
      expect(result.code).not.toBe(0)
      expect(result.stderr).toContain("is not available in this build")
      expect(result.stderr).not.toContain("model gateway")
      expect(performance.now() - started).toBeLessThan(5_000)
    }
    // A managed model gets as far as the gateway, which decides whether the profile lists it.
    for (const model of ["managed/approved", "managed/gpt-5.6-luna"]) {
      const managed = await run(["run", "--model", model, "hello"], project, env)
      expect(managed.code).not.toBe(0)
      expect(managed.stderr).toContain("model gateway is not available")
    }
  }, 120_000)

  test("reports the product version it was built from", async () => {
    const { project, env } = await hostile()
    const expected = (await Bun.file(path.join(import.meta.dir, "../../../VERSION")).text()).trim()
    const result = await run(["--version"], project, env)
    expect(result.code).toBe(0)
    expect(result.stdout).toContain(expected)
    expect(result.stdout).not.toContain("development")
  }, 120_000)
})
