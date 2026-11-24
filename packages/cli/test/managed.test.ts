import { NodeFileSystem } from "@effect/platform-node"
import { Global } from "@opencode/util/global"
import { expect, test } from "bun:test"
import { Effect, Exit, FileSystem, Scope } from "effect"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { Commands } from "../src/commands/commands"
import { Runtime } from "../src/framework/runtime"
import { ManagedProfile } from "@opencode/server/managed"
import { Managed } from "../src/managed"
import { createMiniConnection } from "../src/mini"
import { ServerConnection } from "../src/services/server-connection"
import { ServiceConfig } from "../src/services/service-config"
import { OPENCODE_VERSION } from "../src/version"

async function withState<A>(run: (root: string, runPromise: <B, E>(effect: Effect.Effect<B, E, Global.Service | FileSystem.FileSystem | Scope.Scope>) => Promise<B>) => Promise<A>) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "badger-managed-"))
  const layer = Global.layerWith({
    config: path.join(root, "config"),
    state: path.join(root, "state"),
    data: path.join(root, "data"),
  })
  try {
    return await run(root, (effect) =>
      Effect.runPromise(effect.pipe(Effect.provide(layer), Effect.provide(NodeFileSystem.layer), Effect.scoped)),
    )
  } finally {
    await fs.rm(root, { recursive: true, force: true })
  }
}

// A managed build runs the server in-process with the managed profile: no background service is
// started, discovered or registered, and no other server can be chosen.
test("a managed build resolves only to the in-process server with the managed profile", () =>
  withState(async (root, runPromise) => {
    const info = await runPromise(
      Effect.gen(function* () {
        const resolved = yield* ServerConnection.resolve({ managed: true })
        expect(resolved.service).toBeUndefined()
        expect(resolved.fetch).toBeDefined()
        const response = yield* Effect.promise(() => resolved.fetch!(new URL("/api/info", resolved.endpoint.url)))
        // The server answers with the managed profile's one compiled config document.
        const project = path.join(root, "project")
        yield* Effect.promise(() => fs.mkdir(project, { recursive: true }))
        const url = new URL("/api/config", resolved.endpoint.url)
        url.searchParams.set("location[directory]", project)
        const config = yield* Effect.promise(() => resolved.fetch!(url).then((res) => res.json()))
        return { ...(yield* Effect.promise(() => response.json())), config }
      }),
    )
    expect(info.version).toBe(OPENCODE_VERSION)
    expect(info.config).toEqual([{ type: "document", info: ManagedProfile.document }])
    expect(await Bun.file(path.join(root, "state", ServiceConfig.filename())).exists()).toBe(false)
    for (const args of [{ server: "http://127.0.0.1:1" }, { standalone: true }]) {
      const exit = await runPromise(ServerConnection.resolve({ ...args, managed: true }).pipe(Effect.exit))
      expect(Exit.isFailure(exit)).toBe(true)
    }
  }), 30_000)

test("a managed build refuses the flags that auto-approve permissions", async () => {
  for (const flags of [{ auto: true }, { yolo: true }, { dangerouslySkipPermissions: true }]) {
    const input = { auto: false, yolo: false, dangerouslySkipPermissions: false, ...flags }
    expect(Exit.isFailure(await Effect.runPromise(Managed.permissionFlags(input, true).pipe(Effect.exit)))).toBe(true)
    expect(await Effect.runPromise(Managed.permissionFlags(input, false))).toBe(true)
  }
  const none = { auto: false, yolo: false, dangerouslySkipPermissions: false }
  expect(await Effect.runPromise(Managed.permissionFlags(none, true))).toBe(false)
})

// The profile's models are known only once the gateway answers; the flag takes any well-formed managed model, and the
// server and the gateway refuse one the profile does not list.
test("a managed build refuses any model but a managed one", async () => {
  const { providerID, model } = ManagedProfile.document.model!
  expect(Managed.approvedModel).toBe(`${providerID}/${model}`)
  for (const model of [undefined, Managed.approvedModel, "managed/gpt-5.6-luna", "managed/other"])
    expect(Exit.isSuccess(await Effect.runPromise(Managed.modelFlag(model, true).pipe(Effect.exit)))).toBe(true)
  for (const model of ["openai/gpt-4.1", `${Managed.approvedModel}#high`, "managed/openai/gpt-4.1", "managed/", "managed/ x", "approved", ""]) {
    expect(Exit.isFailure(await Effect.runPromise(Managed.modelFlag(model, true).pipe(Effect.exit)))).toBe(true)
    expect(Exit.isSuccess(await Effect.runPromise(Managed.modelFlag(model, false).pipe(Effect.exit)))).toBe(true)
  }
})

test("a managed build keeps the work commands and refuses the rest", async () => {
  const loaded = () => Promise.resolve({ default: () => Effect.void })
  const all = Runtime.handlers(Commands, {
    $: loaded, about: loaded, enroll: loaded, attest: loaded, upgrade: loaded, uninstall: loaded, acp: loaded, api: loaded,
    auth: { list: loaded, login: loaded, logout: loaded, export: loaded, import: loaded, switch: loaded },
    debug: { agents: loaded, config: loaded, paths: loaded },
    mcp: { list: loaded, add: loaded, auth: loaded, logout: loaded },
    plugin: { list: loaded, add: loaded, check: loaded, update: loaded, remove: loaded },
    models: loaded, stats: loaded, mini: loaded, run: loaded, pair: loaded, reload: loaded,
    session: { list: loaded, delete: loaded, export: loaded, import: loaded },
    service: { start: loaded, restart: loaded, status: loaded, stop: loaded, get: loaded, set: loaded, unset: loaded },
    serve: loaded,
  })
  const gated = Managed.gate(Commands, all, true)
  const runs = async (spec: unknown) => {
    const handler = gated.find((item) => item.spec === spec)!
    const module = await handler.load()
    return Exit.isSuccess(await Effect.runPromise(Effect.exit(Effect.scoped(module.default(undefined) as Effect.Effect<void, unknown, Scope.Scope>))))
  }
  for (const kept of [Commands.spec, Commands.commands.about.spec, Commands.commands.run.spec, Commands.commands.mini.spec, Commands.commands.models.spec, Commands.commands.stats.spec, Commands.commands.session.commands.list.spec, Commands.commands.serve.spec])
    expect(await runs(kept)).toBe(true)
  for (const refused of [Commands.commands.service.commands.start.spec, Commands.commands.upgrade.spec, Commands.commands.auth.commands.login.spec, Commands.commands.mcp.commands.add.spec, Commands.commands.plugin.commands.add.spec, Commands.commands.pair.spec, Commands.commands.api.spec, Commands.commands.reload.spec, Commands.commands.enroll.spec, Commands.commands.attest.spec])
    expect(await runs(refused)).toBe(false)
  expect(Managed.gate(Commands, all, false)).toBe(all)
})

test("a managed build's updater never checks, downloads or installs", async () => {
  const result = await Effect.runPromise(
    Effect.gen(function* () {
      const updater = yield* Managed.Updater
      return { run: yield* updater.run(), check: yield* updater.check(), apply: yield* Effect.exit(updater.apply("9.9.9")) }
    }).pipe(Effect.provide(Managed.updaterLayer)),
  )
  expect(result.run).toBeUndefined()
  expect(result.check?.type).toBe("unavailable")
  expect(Exit.isFailure(result.apply)).toBe(true)
})

// Every command a managed build keeps reaches the server through the resolved connection, so on
// the in-process server its client must carry the fetch, not just the unroutable base URL.
test("a resolved connection's client reaches an in-process server", () =>
  withState(async (_root, runPromise) => {
    const version = await runPromise(
      Effect.gen(function* () {
        const resolved = yield* ServerConnection.resolve({ managed: true })
        const info = yield* Effect.promise(() => ServerConnection.client(resolved).server.info())
        const mini = createMiniConnection({ endpoint: resolved.endpoint, fetch: resolved.fetch })
        const viaMini = yield* Effect.promise(() => mini.sdk.server.info())
        return [info.version, viaMini.version]
      }),
    )
    expect(version).toEqual([OPENCODE_VERSION, OPENCODE_VERSION])
  }), 30_000)

// The real `models` command, run with the managed build's compile-time defines, must work end to
// end against the in-process server. A command that built its client from the unroutable base URL
// alone would fail here, which calling the resolved fetch directly would not catch.
test("a kept command runs in a managed build", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "badger-managed-command-"))
  // Inside the package, so the probe resolves workspace dependencies; removed below.
  const entry = path.join(import.meta.dir, `.managed-probe-${process.pid}.ts`)
  try {
    const handler = path.resolve(import.meta.dir, "../src/commands/handlers/models.ts")
    await Bun.write(
      entry,
      [
        `import { NodeFileSystem } from "@effect/platform-node"`,
        `import { Global } from "@opencode/util/global"`,
        `import { Effect, Option } from "effect"`,
        `import models from ${JSON.stringify(handler)}`,
        `const root = ${JSON.stringify(directory)}`,
        `const layer = Global.layerWith({ config: root + "/config", state: root + "/state", data: root + "/data" })`,
        `await Effect.runPromise(models({ server: Option.none(), standalone: false } as never).pipe(`,
        `  Effect.provide(layer), Effect.provide(NodeFileSystem.layer), Effect.scoped) as never)`,
        `console.log("models-ok")`,
      ].join("\n"),
    )
    const project = path.join(directory, "project")
    await fs.mkdir(project)
    // The same compile-time defines the managed build sets (`build.ts --managed`).
    const child = Bun.spawn(
      [process.execPath, "--define", "TESTIFYSEC_MANAGED_WORKER:true", "--define", "HARDENED_BUILD:true", entry],
      { cwd: project, stdout: "pipe", stderr: "pipe" },
    )
    const [stdout, stderr, code] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ])
    expect({ code, stderr: code === 0 ? "" : stderr.slice(-2000) }).toEqual({ code: 0, stderr: "" })
    expect(stdout.trim().split("\n").at(-1)).toBe("models-ok")
    expect(await Bun.file(path.join(directory, "state", ServiceConfig.filename())).exists()).toBe(false)
  } finally {
    await fs.rm(entry, { force: true })
    await fs.rm(directory, { recursive: true, force: true })
  }
}, 120_000)
