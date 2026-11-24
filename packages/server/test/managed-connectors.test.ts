import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { expect } from "bun:test"
import { Effect } from "effect"
import { tmpdir } from "../../core/test/fixture/tmpdir"
import { it } from "../../core/test/lib/effect"
import { ServerFetch } from "../src/fetch"
import { ManagedProfile } from "../src/managed"
import { ManagedConnectors } from "../src/managed-connectors"

const sha = (bytes: string | Uint8Array) => createHash("sha256").update(bytes).digest("hex")

const entry = (overrides: Partial<ManagedConnectors.Connector> = {}): ManagedConnectors.Connector => ({
  name: "jira",
  binarySha256: sha("jira binary"),
  baseUrl: "https://jira.example.invalid",
  tokenPath: "/run/badger/tokens/jira.token",
  caPath: "/etc/badger/enclave-ca.pem",
  writes: false,
  classification: "SECRET",
  flags: { "marking-field": "customfield_10001" },
  permissions: { "jira_*": "allow", jira_add_comment: "ask" },
  ...overrides,
})

const release = Effect.fnUntraced(function* (files: Record<string, string>) {
  const tmp = yield* Effect.acquireDisposable(Effect.promise(() => tmpdir("badger-connectors-")))
  const dir = path.join(tmp.path, "release")
  yield* Effect.promise(async () => {
    await fs.mkdir(dir)
    for (const [name, body] of Object.entries(files)) await fs.writeFile(path.join(dir, name), body, { mode: 0o755 })
  })
  return { root: tmp.path, dir }
})

it.live("stages a connector whose binary matches its pin, privately and read-only, under the state directory", () =>
  Effect.gen(function* () {
    const { root, dir } = yield* release({ jira: "jira binary" })
    const state = path.join(root, "state")
    const [staged] = yield* Effect.promise(() => ManagedConnectors.stage([entry()], dir, state))
    const into = path.dirname(staged!.executable)
    expect(path.dirname(into)).toBe(state)
    expect(path.basename(staged!.executable)).toBe("jira")
    expect(yield* Effect.promise(() => fs.readFile(staged!.executable, "utf8"))).toBe("jira binary")
    expect((yield* Effect.promise(() => fs.stat(staged!.executable))).mode & 0o777).toBe(0o500)
    expect((yield* Effect.promise(() => fs.stat(into))).mode & 0o777).toBe(0o700)
  }),
)

it.live("refuses a state directory it cannot execute from, and leaves nothing behind", () =>
  Effect.gen(function* () {
    const { root } = yield* release({})
    const state = path.join(root, "state")
    yield* Effect.promise(() => fs.mkdir(state))
    const message = yield* Effect.promise(() =>
      ManagedConnectors.privateDir(
        state,
        "probe-",
        async (dir) => {
          // A file without execute permission stands in for a noexec mount.
          await fs.writeFile(path.join(dir, "jira"), "x", { mode: 0o400 })
          await ManagedConnectors.executable(path.join(dir, "jira"), "connector jira")
        },
        true,
      ).then(() => "ran", (error: Error) => error.message),
    )
    expect(message).toContain("connector jira cannot be executed")
    expect(yield* Effect.promise(() => fs.readdir(state))).toEqual([])
  }),
)

it.live("refuses every connector when one binary does not match its pin or is missing", () =>
  Effect.gen(function* () {
    const { dir } = yield* release({ jira: "jira binary, tampered", confluence: "confluence binary" })
    const confluence = entry({ name: "confluence", binarySha256: sha("confluence binary"), flags: {}, permissions: {} })
    const tampered = yield* Effect.promise(() =>
      ManagedConnectors.stage([confluence, entry()], dir, path.join(dir, "..", "state")).then(() => "staged", (error: Error) => error.message),
    )
    expect(tampered).toBe("connector jira does not match the digest the profile pins")
    const missing = yield* Effect.promise(() =>
      ManagedConnectors.stage([entry({ name: "gitlab" })], dir, path.join(dir, "..", "state")).then(() => "staged", (error: Error) => error.message),
    )
    expect(missing).toBe("connector gitlab is not in this release")
  }),
)

it.effect("starts each connector with its admitted flags only", () =>
  Effect.sync(() => {
    const staged = { ...entry(), executable: "/private/jira" }
    expect(ManagedConnectors.command(staged)).toEqual([
      "/private/jira",
      "--base-url=https://jira.example.invalid",
      "--token-file=/run/badger/tokens/jira.token",
      "--classification=SECRET",
      "--ca-file=/etc/badger/enclave-ca.pem",
      "--marking-field=customfield_10001",
    ])
    const writes = ManagedConnectors.command({ ...staged, writes: true, caPath: null, flags: {} })
    expect(writes).toEqual([
      "/private/jira",
      "--base-url=https://jira.example.invalid",
      "--token-file=/run/badger/tokens/jira.token",
      "--classification=SECRET",
      "--enable-writes",
    ])
    for (const line of [ManagedConnectors.command(staged), writes])
      expect(line.some((arg) => arg.includes("insecure-loopback"))).toBe(false)
    // An administrator's notice is passed as its own flag, never inside the classification.
    const notice = "TEST DATA - Not controlled. Markings are for test purposes only."
    const noticed = ManagedConnectors.command({ ...staged, notice })
    expect(noticed.filter((arg) => arg.includes(notice))).toEqual([`--notice=${notice}`])
  }),
)

it.effect("compiles admitted connectors into the managed config, and nothing without them", () =>
  Effect.sync(() => {
    expect(ManagedProfile.compile()).toBe(ManagedProfile.document)
    expect(ManagedProfile.removedFor()).toEqual(ManagedProfile.removed)
    const staged = [{ ...entry(), executable: "/private/jira" }]
    const info = ManagedProfile.compile(staged)
    expect(info.mcp).toEqual({
      servers: {
        jira: {
          type: "local",
          command: ManagedConnectors.command(staged[0]!),
          environment: {},
          inheritEnvironment: false,
          codemode: false,
        },
      },
    })
    // The defaults first, then the connector's rules, so they decide its tools and nothing else.
    expect(info.permissions).toEqual([
      ...ManagedProfile.document.permissions!,
      { action: "jira_jira_*", resource: "*", effect: "allow" },
      { action: "jira_jira_add_comment", resource: "*", effect: "ask" },
    ])
    expect(ManagedProfile.removedFor(staged)).not.toContain("opencode.config.mcp")
    expect(ManagedProfile.removedFor(staged)).toContain("opencode.mcp.codemode.defaults")
  }),
)

// The connector the profile admits starts, with only its admitted flags and no inherited
// environment; the MCP server that user and repository config name never does.
it.live("starts the admitted connector and not the one user config names", () =>
  Effect.gen(function* () {
    const tmp = yield* Effect.acquireDisposable(Effect.promise(() => tmpdir("badger-connectors-")))
    const out = path.join(tmp.path, "out")
    const global = path.join(tmp.path, "global")
    const project = path.join(tmp.path, "project")
    const releaseDir = path.join(tmp.path, "release")
    const fixture = path.join(import.meta.dir, "../../core/test/fixture/mcp-output-schema.ts")
    const userMarker = path.join(out, "user-server-ran")
    const connector = [
      "#!/bin/sh",
      `printf '%s\\n' "$@" > ${JSON.stringify(path.join(out, "args"))}`,
      `/usr/bin/env > ${JSON.stringify(path.join(out, "env"))}`,
      `exec ${JSON.stringify(process.execPath)} ${JSON.stringify(fixture)}`,
      "",
    ].join("\n")
    yield* Effect.promise(async () => {
      for (const dir of [out, global, project, releaseDir]) await fs.mkdir(dir, { recursive: true })
      await fs.writeFile(path.join(releaseDir, "jira"), connector)
      const widen = JSON.stringify({
        mcp: { servers: { x: { type: "local", command: ["/bin/sh", "-c", `: > ${JSON.stringify(userMarker)}`] } } },
      })
      await fs.writeFile(path.join(global, "opencode.json"), widen)
      await fs.writeFile(path.join(project, "opencode.json"), widen)
    })
    const staged = yield* Effect.promise(() =>
      ManagedConnectors.stage([entry({ binarySha256: sha(connector) })], releaseDir, path.join(tmp.path, "state")),
    )
    // A user's environment cannot turn writes on or point the connector elsewhere.
    process.env.BADGER_CONNECTOR_ENABLE_WRITES = "1"
    process.env.BADGER_CONNECTOR_BASE_URL = "https://attacker.example.invalid"
    yield* Effect.addFinalizer(() =>
      Effect.sync(() => {
        delete process.env.BADGER_CONNECTOR_ENABLE_WRITES
        delete process.env.BADGER_CONNECTOR_BASE_URL
      }),
    )
    const handler = yield* ServerFetch.make(
      {
        app: { version: "managed-test" },
        database: { path: ":memory:" },
        config: { directory: global },
        fs: { filewatcher: false },
        models: { fetch: false },
      },
      { overrides: ManagedProfile.replacements({ connectors: staged }) },
    )
    const url = new URL("/api/plugin", "http://badger.local")
    url.searchParams.set("location[directory]", project)
    const read = (file: string) => fs.readFile(path.join(out, file), "utf8").catch(() => undefined)
    let env: string | undefined
    for (let attempt = 0; attempt < 100 && env === undefined; attempt++) {
      yield* Effect.promise(() => handler(new Request(url)))
      yield* Effect.sleep("100 millis")
      env = yield* Effect.promise(() => read("env"))
    }
    expect(env).toBeDefined()
    expect(env).not.toContain("BADGER_CONNECTOR_")
    expect((yield* Effect.promise(() => read("args")))?.trim().split("\n")).toEqual(
      ManagedConnectors.command(staged[0]!).slice(1),
    )
    expect(yield* Effect.promise(() => fs.access(userMarker).then(() => true, () => false))).toBe(false)
  }),
)

// With admitted connectors, the managed build replaces the MCP layer with one that waits (bounded) for
// their first connection before the first prompt's tools are read, and reopens a closed stream with
// backoff (packages/core/test/mcp-lifecycle.test.ts covers both). Without connectors nothing changes.
it.effect("runs admitted connectors' MCP streams with a startup wait and reconnect", () =>
  Effect.sync(() => {
    expect(ManagedProfile.connectorMcp).toEqual({
      startupWaitMs: 20_000,
      reconnect: { initialMs: 1_000, maxMs: 60_000 },
    })
    const staged = { ...entry(), executable: "/private/jira" }
    expect(ManagedProfile.replacements({ connectors: [staged] }).length).toBe(ManagedProfile.replacements().length + 1)
    expect(ManagedProfile.replacements({ connectors: [] }).length).toBe(ManagedProfile.replacements().length)
  }),
)
