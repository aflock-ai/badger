import path from "node:path"
import fs from "node:fs/promises"
import { expect } from "bun:test"
import { Effect } from "effect"
import { FetchHttpClient } from "effect/http"
import type { LayerNode } from "@opencode/util/effect/layer-node"
import { tmpdir } from "../../core/test/fixture/tmpdir"
import { it } from "../../core/test/lib/effect"
import { ServerFetch } from "../src/fetch"
import { ManagedProfile } from "../src/managed"

// Every outbound request is recorded and answered locally (through FetchHttpClient.Fetch, the
// reference every default HTTP client reads at request time), so the tests see what the server
// reaches for without touching the network.
const requests: string[] = []
const record: typeof fetch = Object.assign(
  (input: string | URL | Request) => {
    requests.push(typeof input === "string" ? input : input instanceof URL ? input.href : input.url)
    return Promise.resolve(new Response("unavailable", { status: 503 }))
  },
  { preconnect: fetch.preconnect },
)

const boot = (global: string, overrides: LayerNode.Replacements) =>
  ServerFetch.make(
    { app: { version: "managed-test" }, database: { path: ":memory:" }, config: { directory: global }, fs: { filewatcher: false } },
    { overrides },
  )

const get = (handler: (request: Request) => Promise<Response>, route: string, project: string) => {
  const url = new URL(route, "http://badger.local")
  url.searchParams.set("location[directory]", project)
  return Effect.promise(() => handler(new Request(url)))
}

// Boots a location, waits for plugin activation, then lists plugins and models.
const exercise = (overrides: LayerNode.Replacements) =>
  Effect.gen(function* () {
    const tmp = yield* Effect.acquireDisposable(Effect.promise(() => tmpdir("badger-egress-")))
    const global = path.join(tmp.path, "global")
    const project = path.join(tmp.path, "project")
    yield* Effect.promise(() => Promise.all([fs.mkdir(global, { recursive: true }), fs.mkdir(project, { recursive: true })]))
    requests.length = 0
    const handler = yield* boot(global, overrides).pipe(Effect.provideService(FetchHttpClient.Fetch, record))
    let plugins: string[] = []
    for (let attempt = 0; attempt < 100 && plugins.length === 0; attempt++) {
      const response = yield* get(handler, "/api/plugin", project)
      const body = (yield* Effect.promise(() => response.json())) as { data?: { id: string }[] }
      plugins = (body.data ?? []).map((plugin) => plugin.id)
      if (plugins.length === 0) yield* Effect.sleep("100 millis")
    }
    yield* get(handler, "/api/model", project)
    yield* get(handler, "/api/provider", project)
    yield* Effect.sleep("500 millis")
    return { plugins, requests: [...requests] }
  })

const removed = [
  "opencode.provider.opencode",
  "opencode.websearch.exa",
  "opencode.tool.websearch",
  "opencode.tool.webfetch",
  "opencode.mcp.codemode.defaults",
  "opencode.wellknown",
  "opencode.warming",
  "opencode.browser",
  "badger.connector-marking",
]

it.live("control: upstream reaches the network and runs the Console, web and browser plugins", () =>
  Effect.gen(function* () {
    const { plugins, requests } = yield* exercise([])
    expect(requests.length).toBeGreaterThan(0)
    for (const id of removed) expect(plugins).toContain(id)
  }),
)

it.live("the managed profile makes no outbound request and runs none of those plugins", () =>
  Effect.gen(function* () {
    const { plugins, requests } = yield* exercise(ManagedProfile.replacements())
    expect(requests).toEqual([])
    expect(plugins.length).toBeGreaterThan(0)
    for (const id of removed) expect(plugins).not.toContain(id)
  }),
)
