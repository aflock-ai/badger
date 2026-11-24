import { afterAll, beforeAll, expect, test } from "bun:test"
import { $ } from "bun"
import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { fixtureRequirementsMarker, verifyArtifact } from "../script/verify-artifact"

// The real managed binary, built with Requirements and the model pointed at local fixtures, signing in
// at launch and answering the pushgate_requirements tool. Linux and macOS only, like the build.
const work = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "badger-requirements-")))
const modelSocket = "/tmp/hardened-fixture-model.sock"
let binary = ""
let port = 0
let ca = ""

const tokens: string[] = []
const reads: string[] = []
let deviceCodes = 0
let hold: Promise<void> | undefined
// Off for the sidebar test, so the snapshot on screen can only come from the sidebar.
let callTool = true
const held = Promise.withResolvers<void>()

const repository = (name: string, id: string) => ({
  id: `github.com/acme/${name}`,
  repository_id: id,
  full_name: `acme/${name}`,
  clone_url: `https://github.com/acme/${name}.git`,
  private: true,
  installation_id: "7",
  account_login: "acme",
  account_type: "Organization",
})

// Device sign-in that approves at once, a catalog of one repository, and a Requirements snapshot for
// whatever exact target is asked about. Every bearer it issues is unique, so a read names its launch.
function requirementsServer(key: string, cert: string) {
  return Bun.serve({
    port,
    hostname: "localhost",
    tls: { key, cert },
    async fetch(request) {
      const url = new URL(request.url)
      const origin = url.origin
      if (url.pathname === "/oauth/device/code") {
        deviceCodes++
        return Response.json({
          device_code: `dc-${deviceCodes}`,
          user_code: `CODE-000${deviceCodes}`,
          verification_uri: `${origin}/auth/cli/device`,
          verification_uri_complete: `${origin}/auth/cli/device?user_code=CODE-000${deviceCodes}`,
          expires_in: 600,
          interval: 1,
        })
      }
      if (url.pathname === "/oauth/device/token") {
        const token = `pgr_fixture_${crypto.randomUUID().replaceAll("-", "")}`
        tokens.push(token)
        return Response.json({
          access_token: token,
          token_type: "Bearer",
          expires_in: 3600,
          scope: "pushgate:repo-read pushgate:policy-read",
        })
      }
      if (url.pathname === "/api/pushgate/repositories")
        return Response.json({
          tenant_id: "11111111-1111-4111-8111-111111111111",
          github_app_connected: true,
          partial: false,
          repositories: [repository("widgets", "42")],
        })
      if (url.pathname === "/api/requirements") {
        reads.push(request.headers.get("authorization") ?? "")
        const target = Object.fromEntries(url.searchParams)
        return Response.json({
          version: "pushgate.requirements.v1",
          state: "available",
          target,
          assignment_source: "connection_snapshot",
          applicability: "incomplete",
          connection: { generation: 3, created_at: "2026-09-01T00:00:00Z" },
          builtins: [{ id: "signed", mode: "block", availability: "supported" }],
          policies: [],
          last_decision: { state: "none", current_status: "unavailable" },
        })
      }
      return new Response("{}", { status: 404 })
    },
  })
}

// The model calls pushgate_requirements, then answers with the tool's result. The first launch's
// answer can be held, so a second launch runs while the first is still signed in.
function model() {
  return Bun.serve({
    unix: modelSocket,
    async fetch(request) {
      // A gateway with no broker limits and no profile allowlist: the start reads (GET /v1/limits, /v1/models) get its 404.
      if (request.method === "GET") return new Response("unavailable", { status: 404 })
      const body = (await request.json()) as {
        messages: { role: string; content: unknown }[]
        tools?: { function: { name: string } }[]
      }
      const names = body.tools?.map((tool) => tool.function.name) ?? []
      const result = body.messages.find((message) => message.role === "tool")
      const chunk = (delta: unknown, finish_reason: string | null = null) => ({
        id: "fixture",
        object: "chat.completion.chunk",
        created: 1,
        model: "approved",
        choices: [{ index: 0, delta, finish_reason }],
      })
      let events
      if (callTool && names.includes("pushgate_requirements") && !result)
        events = [
          chunk({
            role: "assistant",
            tool_calls: [
              {
                index: 0,
                id: "call-1",
                type: "function",
                function: { name: "pushgate_requirements", arguments: "{}" },
              },
            ],
          }),
          chunk({}, "tool_calls"),
        ]
      else {
        // Only the first answer after a hold is set waits for it.
        if (result && hold) {
          const wait = hold
          hold = undefined
          held.resolve()
          await wait
        }
        const text = result
          ? `REQUIREMENTS ${JSON.stringify(result.content)}`
          : names.length
            ? "no requirements tool"
            : "title"
        events = [chunk({ role: "assistant", content: text }), chunk({}, "stop")]
      }
      return new Response(
        events.map((event) => "data: " + JSON.stringify(event) + "\n\n").join("") + "data: [DONE]\n\n",
        {
          headers: { "content-type": "text/event-stream" },
        },
      )
    },
  })
}

let servers: { stop: (force?: boolean) => unknown }[] = []

beforeAll(async () => {
  const probe = Bun.serve({ port: 0, fetch: () => new Response() })
  port = probe.port!
  probe.stop(true)
  await $`openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost -addext subjectAltName=DNS:localhost -keyout ${work}/key.pem -out ${work}/cert.pem`.quiet()
  ca = path.join(work, "cert.pem")
  const outdir = path.join(work, "build")
  const child = Bun.spawn(
    [
      process.execPath,
      "run",
      "script/build.ts",
      "--single",
      "--skip-install",
      "--skip-web-ui",
      "--managed",
      "--fixture-model",
      `--fixture-requirements=https://localhost:${port}`,
      `--outdir=${outdir}`,
    ],
    { cwd: path.join(import.meta.dir, ".."), stdout: "ignore", stderr: "pipe" },
  )
  const [stderr, code] = await Promise.all([new Response(child.stderr).text(), child.exited])
  if (code !== 0) throw new Error(`managed build failed: ${stderr.slice(-2000)}`)
  const [target] = await fs.readdir(outdir)
  const [executable] = await fs.readdir(path.join(outdir, target!, "bin"))
  binary = path.join(outdir, target!, "bin", executable!)
  await fs.rm(modelSocket, { force: true })
  servers = [requirementsServer(await Bun.file(path.join(work, "key.pem")).text(), await Bun.file(ca).text()), model()]
}, 900_000)

afterAll(async () => {
  for (const server of servers) server.stop(true)
  await fs.rm(work, { recursive: true, force: true })
})

// A home whose project directory opted in to the fixture repository, as `--requirements` would leave it.
async function home() {
  const root = await fs.mkdtemp(path.join(work, "home-"))
  const project = path.join(root, "project")
  await fs.mkdir(project)
  await $`git init -q -b main && git -c user.email=t@t -c user.name=t commit -q --allow-empty -m init`.cwd(project)
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: root,
    XDG_CONFIG_HOME: path.join(root, "xdg"),
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_STATE_HOME: path.join(root, "state"),
    XDG_CACHE_HOME: path.join(root, "cache"),
    TMPDIR: path.join(root, "tmp"),
    NODE_EXTRA_CA_CERTS: ca,
  }
  await fs.mkdir(env.TMPDIR!)
  const config =
    process.platform === "darwin"
      ? path.join(root, "Library", "Application Support", "TestifySec", "Aflock")
      : path.join(env.XDG_CONFIG_HOME!, "aflock")
  // This directory's own choice file: named by a hash of the project's real path.
  await fs.mkdir(path.join(config, "requirements"), { recursive: true, mode: 0o700 })
  await fs.chmod(config, 0o700)
  await fs.writeFile(
    path.join(config, "requirements", `${createHash("sha256").update(project).digest("hex")}.json`),
    JSON.stringify({
      version: 1,
      enabled: true,
      directory: project,
      repo: "github.com/acme/widgets",
      repository_id: "42",
    }),
    { mode: 0o600 },
  )
  return { root, project, env }
}

const launch = (project: string, env: Record<string, string>) => {
  const child = Bun.spawn([binary, "run", "check the requirements"], {
    cwd: project,
    env,
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  })
  return Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]).then(
    ([stdout, stderr, code]) => ({ stdout, stderr, code }),
  )
}

async function files(dir: string): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => [])
  const nested = await Promise.all(
    entries.map((entry) => (entry.isDirectory() ? files(path.join(dir, entry.name)) : [path.join(dir, entry.name)])),
  )
  return nested.flat()
}

const contains = async (file: string, text: string) => Buffer.from(await Bun.file(file).arrayBuffer()).includes(text)

// The release check refuses exactly what this build compiled in.
test("the fixture build carries its localhost origin, and the release check refuses it", async () => {
  expect(Buffer.from(await Bun.file(binary).arrayBuffer()).includes(`${fixtureRequirementsMarker}:${port}`)).toBe(true)
  await expect(verifyArtifact(binary, [fixtureRequirementsMarker])).rejects.toThrow(fixtureRequirementsMarker)
})

test("an opted-in launch signs in, answers pushgate_requirements, and writes the bearer nowhere", async () => {
  const { root, project, env } = await home()
  const before = { tokens: tokens.length, codes: deviceCodes }
  const result = await launch(project, env)
  expect({ code: result.code, stderr: result.code === 0 ? "" : result.stderr.slice(-2000) }).toEqual({
    code: 0,
    stderr: "",
  })
  expect(result.stderr).toContain(`code CODE-000${before.codes + 1}`)
  expect(result.stdout).toContain("REQUIREMENTS")
  expect(result.stdout).toContain('\\"state\\":\\"available\\"')
  const token = tokens[before.tokens]!
  expect(reads).toContain(`Bearer ${token}`)
  for (const file of await files(root))
    expect({ file, bearer: await contains(file, token) }).toEqual({ file, bearer: false })
}, 120_000)

test("a second launch cannot use the first launch's bearer: it signs in for itself", async () => {
  const first = await home()
  const second = await home()
  const before = { tokens: tokens.length, codes: deviceCodes, reads: reads.length }
  const release = Promise.withResolvers<void>()
  hold = release.promise
  // The first launch stays signed in, holding its answer, while the second one runs.
  const running = launch(first.project, first.env)
  await held.promise
  const firstToken = tokens[before.tokens]!
  const other = await launch(second.project, second.env)
  release.resolve()
  const done = await running
  expect([done.code, other.code]).toEqual([0, 0])
  expect(deviceCodes - before.codes).toBe(2)
  const secondToken = tokens[before.tokens + 1]!
  expect(secondToken).not.toBe(firstToken)
  // The second launch's reads carry only its own bearer.
  expect(reads.slice(before.reads)).toContain(`Bearer ${secondToken}`)
  expect(other.stdout + other.stderr).not.toContain(firstToken)
  for (const file of [...(await files(first.root)), ...(await files(second.root))])
    expect({ file, bearer: await contains(file, firstToken) }).toEqual({ file, bearer: false })
}, 180_000)

test("--no-requirements opts the directory out: no sign-in now or at the next launch", async () => {
  const { project, env } = await home()
  const before = deviceCodes
  const child = Bun.spawn([binary, "run", "--no-requirements", "check the requirements"], {
    cwd: project,
    env,
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  })
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ])
  expect(code).toBe(0)
  expect(stderr).toContain("opted out")
  expect(stdout).toContain("no requirements tool")
  const again = await launch(project, env)
  expect(again.code).toBe(0)
  expect(again.stdout).toContain("no requirements tool")
  expect(deviceCodes).toBe(before)
}, 120_000)

// The interactive launch takes the same path before the TUI starts: it needs a terminal, so Linux's script(1).
test.skipIf(process.platform !== "linux")(
  "the TUI launch signs in before the TUI starts",
  async () => {
    const { project, env } = await home()
    const before = deviceCodes
    const child = Bun.spawn(["script", "-qfec", binary, "/dev/null"], {
      cwd: project,
      env: { ...env, TERM: "xterm-256color" },
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
    })
    let screen = ""
    const reader = child.stdout.getReader()
    const deadline = Date.now() + 60_000
    while (!screen.includes(`CODE-000${before + 1}`) && Date.now() < deadline) {
      const part = await reader.read()
      if (part.done) break
      screen += new TextDecoder().decode(part.value)
    }
    child.kill()
    await child.exited
    expect(screen).toContain(`code CODE-000${before + 1}`)
    expect(deviceCodes).toBe(before + 1)
  },
  120_000,
)

// The TUI's sidebar shows what the monitor reads for the session's directory, from the same source.
test.skipIf(process.platform !== "linux")(
  "a TUI session's sidebar shows the Requirements snapshot",
  async () => {
    const { project, env } = await home()
    callTool = false
    const child = Bun.spawn(["script", "-qfec", `stty cols 180 rows 50; exec ${binary}`, "/dev/null"], {
      cwd: project,
      env: { ...env, TERM: "xterm-256color" },
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
    })
    let screen = ""
    const reader = child.stdout.getReader()
    const until = async (done: () => boolean, ms: number) => {
      const deadline = Date.now() + ms
      while (!done() && Date.now() < deadline) {
        const part = await Promise.race([reader.read(), Bun.sleep(500).then(() => undefined)])
        if (part?.done) break
        if (part?.value) screen += new TextDecoder().decode(part.value)
      }
      return done()
    }
    try {
      // The prompt is up once the TUI has drawn its footer; then start a session.
      expect(await until(() => screen.includes("Build"), 60_000)).toBe(true)
      child.stdin.write("check the requirements\r")
      await child.stdin.flush()
      expect(await until(() => screen.includes("signed: block / supported"), 60_000)).toBe(true)
      expect(screen).toContain("Requirements")
    } finally {
      callTool = true
      child.kill()
      await child.exited
    }
  },
  180_000,
)
