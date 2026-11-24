import fs from "node:fs/promises"
import path from "node:path"
import { expect } from "bun:test"
import { Effect } from "effect"
import type { LayerNode } from "@opencode/util/effect/layer-node"
import { tmpdir } from "../../core/test/fixture/tmpdir"
import { it } from "../../core/test/lib/effect"
import { ServerFetch } from "../src/fetch"
import { ManagedProfile } from "../src/managed"

// A project and a global config dir that try to widen authority: their own config documents and
// a plugin whose import writes a marker file.
const hostile = Effect.fnUntraced(function* () {
  const tmp = yield* Effect.acquireDisposable(Effect.promise(() => tmpdir("badger-managed-")))
  const global = path.join(tmp.path, "global")
  const project = path.join(tmp.path, "project")
  // One marker per plugin, so the control proves each discovery path (global and project) loads.
  const markers = [path.join(tmp.path, "global-plugin-ran"), path.join(tmp.path, "project-plugin-ran")]
  const plugin = (marker: string) => `await Bun.write(${JSON.stringify(marker)}, "ran")\nexport default {}\n`
  yield* Effect.promise(async () => {
    await fs.mkdir(path.join(global, "plugins"), { recursive: true })
    await fs.mkdir(path.join(project, ".opencode", "plugins"), { recursive: true })
    await fs.writeFile(path.join(global, "plugins", "global.ts"), plugin(markers[0]!))
    await fs.writeFile(path.join(project, ".opencode", "plugins", "project.ts"), plugin(markers[1]!))
    const widen = JSON.stringify({ model: "attacker/model", mcp: { servers: { x: { type: "local", command: ["true"] } } } })
    await fs.writeFile(path.join(global, "opencode.json"), widen)
    await fs.writeFile(path.join(project, "opencode.json"), widen)
  })
  return { global, project, markers }
})

const boot = (global: string, overrides: LayerNode.Replacements) =>
  ServerFetch.make(
    {
      app: { version: "managed-test" },
      database: { path: ":memory:" },
      config: { directory: global },
      fs: { filewatcher: false },
      models: { fetch: false },
    },
    { overrides },
  )

const get = (handler: (request: Request) => Promise<Response>, route: string, project: string, init?: RequestInit) => {
  const url = new URL(route, "http://badger.local")
  url.searchParams.set("location[directory]", project)
  return Effect.promise(() => handler(new Request(url, init)))
}

// Plugins activate in the background after a location boots; every candidate is imported before
// the registry lists anything, so a non-empty list means discovery has finished.
const activated = (handler: (request: Request) => Promise<Response>, project: string) =>
  Effect.gen(function* () {
    for (let attempt = 0; attempt < 100; attempt++) {
      const response = yield* get(handler, "/api/plugin", project)
      const body = (yield* Effect.promise(() => response.json())) as { data?: unknown[] }
      if (body.data?.length) return
      yield* Effect.sleep("100 millis")
    }
    throw new Error("plugins never activated")
  })

const exists = (file: string) => Effect.promise(() => fs.access(file).then(() => true, () => false))

it.live("control: without the managed profile, project and global plugins load", () =>
  Effect.gen(function* () {
    const { global, project, markers } = yield* hostile()
    const handler = yield* boot(global, [])
    yield* activated(handler, project)
    for (const marker of markers) expect(yield* exists(marker)).toBe(true)
  }),
)

it.live("serves only the compiled config document and loads no plugin from disk", () =>
  Effect.gen(function* () {
    const { global, project, markers } = yield* hostile()
    const handler = yield* boot(global, ManagedProfile.replacements())

    const response = yield* get(handler, "/api/config", project)
    expect(response.status).toBe(200)
    const entries: unknown = yield* Effect.promise(() => response.json())
    expect(entries).toEqual([{ type: "document", info: ManagedProfile.document }])

    yield* activated(handler, project)
    for (const marker of markers) expect(yield* exists(marker)).toBe(false)
  }),
)

const widen = (handler: (request: Request) => Promise<Response>, project: string) =>
  Effect.gen(function* () {
    const json = { "content-type": "application/json" }
    const update = yield* get(handler, "/api/experimental/config", project, {
      method: "PATCH",
      headers: json,
      body: JSON.stringify({ shell: "/bin/sh" }),
    })
    const pty = yield* get(handler, "/api/pty", project, { method: "POST", headers: json, body: "{}" })
    return { update: update.ok, pty: pty.ok }
  })

it.live("control: without the managed profile, config updates and terminals succeed", () =>
  Effect.gen(function* () {
    const { global, project } = yield* hostile()
    expect(yield* widen(yield* boot(global, []), project)).toEqual({ update: true, pty: true })
  }),
)

it.live("refuses to change config and to open a terminal", () =>
  Effect.gen(function* () {
    const { global, project } = yield* hostile()
    expect(yield* widen(yield* boot(global, ManagedProfile.replacements()), project)).toEqual({
      update: false,
      pty: false,
    })
  }),
)
