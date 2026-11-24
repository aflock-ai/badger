import { afterAll, beforeAll, expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"

// The managed binary sends no telemetry of its own: OTEL_* in its environment cannot point its exporter anywhere.
// Upstream, the same environment exports logs and traces to the address it names. The variables still reach the
// processes the agent starts, which belong to the user's project.
const work = await fs.mkdtemp(path.join(os.tmpdir(), "badger-managed-otel-"))
const binaries = { managed: "", fixture: "", upstream: "" }
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

beforeAll(
  () => Promise.all([build("managed", ["--managed"]), build("fixture", ["--managed", "--fixture-model"]), build("upstream", [])]),
  900_000,
)
afterAll(() => fs.rm(work, { recursive: true, force: true }))

// A TCP listener that counts connections; it answers like an OTLP collector so an exporter does not retry.
const collector = () => {
  const seen = { connections: 0 }
  const listener = Bun.listen({
    hostname: "127.0.0.1",
    port: 0,
    socket: {
      open: () => void seen.connections++,
      data: (socket) => void socket.end("HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"),
    },
  })
  return { url: `http://127.0.0.1:${listener.port}`, seen, stop: () => listener.stop(true) }
}

const otel = (url: string) => ({
  OTEL_EXPORTER_OTLP_ENDPOINT: url,
  OTEL_EXPORTER_OTLP_HEADERS: "x-test=1",
  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: `${url}/v1/traces`,
  OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: `${url}/v1/logs`,
  OTEL_EXPORTER_OTLP_METRICS_ENDPOINT: `${url}/v1/metrics`,
  OTEL_RESOURCE_ATTRIBUTES: "service.name=test",
})

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
  // An exporter may still be flushing as the process exits; give a late connection time to land.
  await Bun.sleep(500)
  return { stdout, stderr, code }
}

// The fixture model the --fixture-model build reaches instead of the gateway. Given `command`, its first answer asks
// the shell tool to run it; every other answer is one short streamed reply.
const fixtureModel = async (command?: string) => {
  await fs.rm(fixtureSocket, { force: true })
  const chunk = (delta: unknown, finish_reason: string | null = null) => ({
    id: "fixture",
    object: "chat.completion.chunk",
    created: 1,
    model: "approved",
    choices: [{ index: 0, delta, finish_reason }],
  })
  const stream = (events: unknown[]) =>
    new Response(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join("") + "data: [DONE]\n\n", {
      headers: { "content-type": "text/event-stream" },
    })
  const server = Bun.serve({
    unix: fixtureSocket,
    fetch: async (request) => {
      // A gateway with no broker limits and no profile allowlist: the start reads (GET /v1/limits, /v1/models) get its 404.
      if (request.method === "GET") return new Response("unavailable", { status: 404 })
      const body = (await request.json()) as { messages: { role: string }[]; tools?: { function: { name: string } }[] }
      const shell = body.tools?.map((tool) => tool.function.name).find((name) => name === "bash" || name === "shell")
      if (command && shell && !body.messages.some((message) => message.role === "tool"))
        return stream([
          chunk({
            role: "assistant",
            tool_calls: [
              {
                index: 0,
                id: "call-1",
                type: "function",
                function: { name: shell, arguments: JSON.stringify({ command, description: "Read the environment", timeout: 10000 }) },
              },
            ],
          }),
          chunk({}, "tool_calls"),
        ])
      return stream([chunk({ role: "assistant", content: "fixture reply" }), chunk({}, "stop")])
    },
  })
  return () => (server.stop(true), fs.rm(fixtureSocket, { force: true }))
}

test("control: upstream exports telemetry where OTEL_* points", async () => {
  const target = collector()
  try {
    const result = await run(binaries.upstream, ["models"], otel(target.url))
    expect(result.code).toBe(0)
    expect(target.seen.connections).toBeGreaterThan(0)
  } finally {
    target.stop()
  }
}, 120_000)

test("ignores OTEL_* and exports nothing", async () => {
  const target = collector()
  try {
    const result = await run(binaries.managed, ["models"], otel(target.url))
    expect(result.code).toBe(0)
    expect(result.stdout.trim()).toBe("managed/approved")
    expect(target.seen.connections).toBe(0)
  } finally {
    target.stop()
  }
}, 120_000)

// The user's own project may use OTEL_*: the agent's shell sees the environment the user gave, unchanged.
test("exports nothing during a session, while the shell tool sees OTEL_* unchanged", async () => {
  const target = collector()
  const seen = path.join(work, `shell-saw-${Date.now()}`)
  const stop = await fixtureModel(`printf %s "$OTEL_EXPORTER_OTLP_ENDPOINT" > ${JSON.stringify(seen)}`)
  try {
    const result = await run(binaries.fixture, ["run", "say hi"], otel(target.url))
    expect({ code: result.code, stderr: result.code === 0 ? "" : result.stderr.slice(-2000) }).toEqual({ code: 0, stderr: "" })
    expect(result.stdout).toContain("fixture reply")
    expect(await Bun.file(seen).text()).toBe(target.url)
    expect(target.seen.connections).toBe(0)
  } finally {
    target.stop()
    await stop()
  }
}, 120_000)
