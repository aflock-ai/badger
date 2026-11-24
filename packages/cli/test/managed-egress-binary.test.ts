import { afterAll, beforeAll, expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"

// During a session the managed binary talks to its model gateway's unix socket and nothing else. Every HTTP request
// Bun's fetch makes honours HTTP(S)_PROXY, so a counting proxy sees any request that leaves for the network; the
// upstream control shows the same binary family's fetch does reach it.
const work = await fs.mkdtemp(path.join(os.tmpdir(), "badger-managed-egress-"))
const binaries = { fixture: "", upstream: "" }
const fixtureSocket = "/tmp/hardened-fixture-model.sock"

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

beforeAll(() => Promise.all([build("fixture", ["--managed", "--fixture-model"]), build("upstream", [])]), 900_000)
afterAll(() => fs.rm(work, { recursive: true, force: true }))

// A proxy that counts every connection and refuses to forward anything.
const proxy = () => {
  const seen = { connections: 0 }
  const listener = Bun.listen({
    hostname: "127.0.0.1",
    port: 0,
    socket: {
      open: () => void seen.connections++,
      data: (socket) => void socket.end("HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"),
    },
  })
  const url = `http://127.0.0.1:${listener.port}`
  const env = { HTTP_PROXY: url, HTTPS_PROXY: url, http_proxy: url, https_proxy: url, ALL_PROXY: url, NO_PROXY: "" }
  return { env, seen, stop: () => listener.stop(true) }
}

const run = async (binary: string, args: string[], extra: Record<string, string>) => {
  const home = await fs.mkdtemp(path.join(work, "home-"))
  const env = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: home,
    XDG_CONFIG_HOME: path.join(home, "config"),
    XDG_DATA_HOME: path.join(home, "data"),
    XDG_STATE_HOME: path.join(home, "state"),
    XDG_CACHE_HOME: path.join(home, "cache"),
    ...extra,
  }
  const child = Bun.spawn([binary, ...args], { cwd: home, env, stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited])
  await Bun.sleep(500)
  return { stdout, stderr, code }
}

// The fixture model the --fixture-model build reaches instead of the gateway. Records the tools each request offers.
const fixtureModel = async () => {
  await fs.rm(fixtureSocket, { force: true })
  const tools: string[][] = []
  const reads: string[] = []
  const chunk = (delta: unknown, finish_reason: string | null = null) => ({
    id: "fixture",
    object: "chat.completion.chunk",
    created: 1,
    model: "approved",
    choices: [{ index: 0, delta, finish_reason }],
  })
  const server = Bun.serve({
    unix: fixtureSocket,
    fetch: async (request) => {
      // A gateway with no broker limits and no profile allowlist: the start reads get its 404.
      if (request.method === "GET") {
        reads.push(new URL(request.url).pathname)
        return new Response("unavailable", { status: 404 })
      }
      const body = (await request.json()) as { tools?: { function: { name: string } }[] }
      tools.push(body.tools?.map((tool) => tool.function.name) ?? [])
      const events = [chunk({ role: "assistant", content: "fixture reply" }), chunk({}, "stop")]
      return new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join("") + "data: [DONE]\n\n", {
        headers: { "content-type": "text/event-stream" },
      })
    },
  })
  return { tools, reads, stop: () => (server.stop(true), fs.rm(fixtureSocket, { force: true })) }
}

test("control: the proxy sees the binary's own fetch", async () => {
  const target = proxy()
  try {
    await run(binaries.upstream, ["session", "import", "http://example.invalid/session.json"], target.env)
    expect(target.seen.connections).toBeGreaterThan(0)
  } finally {
    target.stop()
  }
}, 120_000)

test("a session reaches the gateway socket and makes no other HTTP request", async () => {
  const target = proxy()
  const model = await fixtureModel()
  try {
    const result = await run(binaries.fixture, ["run", "say hi"], target.env)
    expect({ code: result.code, stderr: result.code === 0 ? "" : result.stderr.slice(-2000) }).toEqual({ code: 0, stderr: "" })
    expect(result.stdout).toContain("fixture reply")
    expect(model.tools.length).toBeGreaterThan(0)
    expect(target.seen.connections).toBe(0)
    // Besides the model calls, the session asks the gateway only its two fixed start routes.
    expect([...new Set(model.reads)].sort()).toEqual(["/v1/limits", "/v1/models"])
    // `execute` (code mode, whose `fetch` reaches any host), web fetch and web search are never offered to the model.
    for (const offered of model.tools) for (const name of ["execute", "webfetch", "websearch"]) expect(offered).not.toContain(name)
  } finally {
    target.stop()
    await model.stop()
  }
}, 120_000)
