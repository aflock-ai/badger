import { NodeFileSystem } from "@effect/platform-node"
import { Global } from "@opencode/util/global"
import { OPENCODE_VERSION } from "../src/version"
import { expect, test } from "bun:test"
import { OpenCode } from "@opencode/client/promise"
import { Plugin } from "@opencode/plugin/effect"
import { Effect, FileSystem, Scope } from "effect"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { ServerConnection } from "../src/services/server-connection"
import { ServiceConfig } from "../src/services/service-config"

function listeningPorts() {
  const out = Bun.spawnSync(["lsof", "-a", "-p", String(process.pid), "-iTCP", "-sTCP:LISTEN", "-Fn"]).stdout
  return new TextDecoder().decode(out).split("\n").filter((line) => line.startsWith("n"))
}

// The managed build runs the server inside the CLI: the TUI reaches it through a fetch function,
// so there is no port for anything else on the machine to connect to and no service to discover.
test("an in-process server answers through fetch, listens on no port and registers no service", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "badger-in-process-"))
  const layer = Global.layerWith({
    config: path.join(root, "config"),
    state: path.join(root, "state"),
    data: path.join(root, "data"),
  })
  const runPromise = <A, E>(effect: Effect.Effect<A, E, Global.Service | FileSystem.FileSystem | Scope.Scope>) =>
    Effect.runPromise(effect.pipe(Effect.provide(layer), Effect.provide(NodeFileSystem.layer), Effect.scoped))
  const before = listeningPorts()
  try {
    const result = await runPromise(
      Effect.gen(function* () {
        const resolved = yield* ServerConnection.inProcess({ overrides: [] })
        expect(resolved.service).toBeUndefined()
        expect(resolved.fetch).toBeDefined()
        const response = yield* Effect.promise(() => resolved.fetch!(new URL("/api/info", resolved.endpoint.url)))
        return { status: response.status, info: yield* Effect.promise(() => response.json()), during: listeningPorts() }
      }),
    )
    expect(result.status).toBe(200)
    expect(result.info.version).toBe(OPENCODE_VERSION)
    expect(result.during).toEqual(before)
    expect(await Bun.file(path.join(root, "state", ServiceConfig.filename())).exists()).toBe(false)
  } finally {
    await fs.rm(root, { recursive: true, force: true })
  }
}, 30_000)

// A managed session registers its in-binary plugins on the host, and only the ones it is given.
test("plugins passed to an in-process server are registered on it", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "badger-in-process-plugin-"))
  const project = path.join(root, "project")
  await fs.mkdir(project)
  const layer = Global.layerWith({
    config: path.join(root, "config"),
    state: path.join(root, "state"),
    data: path.join(root, "data"),
  })
  const runPromise = <A, E>(effect: Effect.Effect<A, E, Global.Service | FileSystem.FileSystem | Scope.Scope>) =>
    Effect.runPromise(effect.pipe(Effect.provide(layer), Effect.provide(NodeFileSystem.layer), Effect.scoped))
  // A plugin's effect runs when a location activates its plugins; listing that location's plugins
  // loads it. plugin.list itself reports only configured plugins, so the effect is the signal.
  const started = (ids: ReadonlyArray<string>) => {
    const ran: string[] = []
    return runPromise(
      Effect.gen(function* () {
        const resolved = yield* ServerConnection.inProcess({
          overrides: [],
          plugins: ids.length
            ? ids.map((id) => Plugin.define({ id, effect: () => Effect.sync(() => void ran.push(id)) }))
            : undefined,
        })
        const client = OpenCode.make({ baseUrl: resolved.endpoint.url, fetch: resolved.fetch })
        yield* Effect.promise(() => client.plugin.list({ location: { directory: project } }))
        // Activation follows the location's load asynchronously.
        const deadline = Date.now() + 5_000
        while (ran.length < ids.length && Date.now() < deadline) yield* Effect.sleep("25 millis")
        return ran
      }),
    )
  }
  try {
    expect(await started(["in-binary"])).toEqual(["in-binary"])
    expect(await started([])).toEqual([])
  } finally {
    await fs.rm(root, { recursive: true, force: true })
  }
}, 30_000)
