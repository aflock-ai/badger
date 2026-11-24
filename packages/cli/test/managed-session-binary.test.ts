import { afterAll, beforeAll, expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"

// The managed binary reaches no server but its own in-process one, and never fetches session data from a URL.
// Each refusal is one line and a nonzero exit, and nothing connects to the address it was given.
const work = await fs.mkdtemp(path.join(os.tmpdir(), "badger-managed-session-"))
const binaries = { managed: "", upstream: "" }

const build = async (name: keyof typeof binaries, flags: string[]) => {
  const outdir = path.join(work, name)
  const child = Bun.spawn(
    [process.execPath, "run", "script/build.ts", "--single", "--skip-install", "--skip-web-ui", ...flags, `--outdir=${outdir}`],
    { cwd: path.join(import.meta.dir, ".."), stdout: "ignore", stderr: "pipe" },
  )
  const [stderr, code] = await Promise.all([new Response(child.stderr).text(), child.exited])
  if (code !== 0) throw new Error(`${name} build failed: ${stderr.slice(-2000)}`)
  const [target] = await fs.readdir(outdir)
  const [executable] = await fs.readdir(path.join(outdir, target!, "bin"))
  binaries[name] = path.join(outdir, target!, "bin", executable!)
}

beforeAll(() => Promise.all([build("managed", ["--managed"]), build("upstream", [])]), 900_000)
afterAll(() => fs.rm(work, { recursive: true, force: true }))

// An HTTP listener that counts every connection made to it and answers with a valid empty session export.
const listen = () => {
  const seen = { connections: 0 }
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () => {
      seen.connections++
      return Response.json({ info: {}, messages: [] })
    },
  })
  return { url: `http://127.0.0.1:${server.port}`, seen, stop: () => server.stop(true) }
}

const run = async (binary: string, args: string[]) => {
  const home = await fs.mkdtemp(path.join(work, "home-"))
  const env = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: home,
    XDG_CONFIG_HOME: path.join(home, "config"),
    XDG_DATA_HOME: path.join(home, "data"),
    XDG_STATE_HOME: path.join(home, "state"),
    XDG_CACHE_HOME: path.join(home, "cache"),
  }
  const child = Bun.spawn([binary, ...args], { cwd: home, env, stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited])
  return { stdout, stderr, code }
}

test("control: upstream fetches session data from a URL and connects to --server", async () => {
  const target = listen()
  try {
    await run(binaries.upstream, ["session", "import", `${target.url}/session.json`])
    expect(target.seen.connections).toBeGreaterThan(0)
    const before = target.seen.connections
    await run(binaries.upstream, ["session", "list", "--server", target.url])
    expect(target.seen.connections).toBeGreaterThan(before)
  } finally {
    target.stop()
  }
}, 120_000)

test("refuses to import a session from a URL, in one line, without connecting", async () => {
  const target = listen()
  try {
    const result = await run(binaries.managed, ["session", "import", `${target.url}/session.json`])
    expect({ code: result.code, stdout: result.stdout, stderr: result.stderr }).toEqual({
      code: 1,
      stdout: "",
      stderr: "Importing a session from a URL is not available in this build\n",
    })
    expect(target.seen.connections).toBe(0)
  } finally {
    target.stop()
  }
}, 120_000)

test("refuses --server and --standalone on every command that takes them, in one line, without connecting", async () => {
  const target = listen()
  try {
    for (const args of [
      ["run", "--server", target.url, "hello"],
      ["run", "--standalone", "hello"],
      ["session", "list", "--server", target.url],
      ["session", "export", "--server", target.url],
      ["session", "delete", "--server", target.url, "ses_x"],
      ["session", "import", "--server", target.url, "missing.json"],
      ["models", "--server", target.url],
    ]) {
      const result = await run(binaries.managed, args)
      expect({ args, code: result.code, stdout: result.stdout, stderr: result.stderr }).toEqual({
        args,
        code: 1,
        stdout: "",
        stderr: "--server and --standalone are not available in this build\n",
      })
    }
    expect(target.seen.connections).toBe(0)
  } finally {
    target.stop()
  }
}, 120_000)
