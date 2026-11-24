import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { expect, test } from "bun:test"
import { Effect } from "effect"
import { Model } from "@opencode/schema/model"
import { Provider } from "@opencode/schema/provider"
import { tmpdir } from "../../core/test/fixture/tmpdir"
import { it } from "../../core/test/lib/effect"
import { ServerFetch } from "../src/fetch"
import { ManagedModels } from "../src/managed-models"
import { ManagedProfile } from "../src/managed"

// What the gateway serves at GET /v1/models for the example profile.
const served = {
  default: "gpt-5.6-sol",
  models: [
    { id: "gpt-5.6-sol", name: "GPT-5.6 Sol" },
    { id: "gpt-5.6-luna", name: "GPT-5.6 Luna", context: 65536, output: 8192 },
  ],
}

const sol = { providerID: Provider.ID.make("managed"), model: Model.ID.make("gpt-5.6-sol") }

test("accepts exactly the gateway's allowlist, and nothing else", () => {
  expect(ManagedModels.parse(JSON.stringify(served))).toEqual(served)
  const many = Array.from({ length: 33 }, (_, i) => ({ id: `m${i}`, name: `M ${i}` }))
  const luna = served.models[1]!
  for (const bad of [
    { ...served, permissions: [{ action: "*", effect: "allow" }] },
    { ...served, default: "approved" },
    { ...served, default: undefined },
    { ...served, models: [] },
    { default: "m0", models: many },
    { ...served, models: [served.models[0], served.models[0]] },
    { ...served, models: [served.models[0], { ...luna, id: "openai/gpt-5.6-luna" }] },
    { ...served, models: [served.models[0], { ...luna, id: "gpt-5.6-luna " }] },
    { ...served, models: [served.models[0], { ...luna, id: "x".repeat(129) }] },
    { ...served, models: [served.models[0], { ...luna, name: "" }] },
    { ...served, models: [served.models[0], { ...luna, name: "Luna\u0007" }] },
    { ...served, models: [served.models[0], { ...luna, name: "x".repeat(65) }] },
    { ...served, models: [served.models[0], { ...luna, context: 0 }] },
    { ...served, models: [served.models[0], { ...luna, output: 1.5 }] },
    { ...served, models: [served.models[0], { ...luna, context: null }] },
    { ...served, models: [served.models[0], { ...luna, baseURL: "https://elsewhere.invalid" }] },
    [served],
    null,
  ])
    expect(ManagedModels.parse(JSON.stringify(bad))).toBeUndefined()
  expect(ManagedModels.parse("models=gpt")).toBeUndefined()
  expect(ManagedModels.parse(JSON.stringify(served) + " ".repeat(ManagedModels.maxBytes))).toBeUndefined()
})

test("the allowlist is the compiled provider's models, each within the agent's limits", () => {
  expect(ManagedProfile.compile()).toBe(ManagedProfile.document)
  expect(ManagedProfile.compile([], undefined, undefined)).toBe(ManagedProfile.document)
  const info = ManagedProfile.compile([], undefined, served)
  expect(info.model).toEqual(sol)
  expect(info.providers?.managed?.models).toEqual({
    "gpt-5.6-sol": { name: "GPT-5.6 Sol", capabilities: { tools: true }, limit: { context: 131072, output: 16384 } },
    // A model's own context and output only lower the agent's.
    "gpt-5.6-luna": { name: "GPT-5.6 Luna", capabilities: { tools: true }, limit: { context: 65536, output: 8192 } },
  })
  const big = ManagedProfile.compile([], { steps: null, context: 32768, output: 4096, timeout_seconds: null }, {
    default: "big",
    models: [{ id: "big", name: "Big", context: 1_000_000, output: 500_000 }],
  })
  expect(big.providers?.managed?.models?.big?.limit).toEqual({ context: 32768, output: 4096 })
  // Everything else is the compiled document.
  expect(info.permissions).toEqual(ManagedProfile.document.permissions)
  expect(info.providers?.managed?.settings).toEqual(ManagedProfile.document.providers?.managed?.settings)
})

test("the start log says where the models came from", () => {
  expect(ManagedModels.summary(served)).toBe("models source=profile default=gpt-5.6-sol models=gpt-5.6-sol,gpt-5.6-luna")
  expect(ManagedModels.summary(undefined)).toBe("models source=compiled default=approved models=approved")
})

// Stands in for the gateway's socket, answering GET /v1/models as `answer` says.
const gateway = (answer: (request: Request) => Response | Promise<Response>) =>
  Effect.acquireRelease(
    Effect.promise(async () => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), "badger-models-"))
      const socket = path.join(dir, "gateway.sock")
      const seen: string[] = []
      const server = Bun.serve({
        unix: socket,
        fetch(request) {
          seen.push(`${request.method} ${new URL(request.url).pathname}`)
          return answer(request)
        },
      })
      return { socket, seen, server, dir }
    }),
    ({ server, dir }) =>
      Effect.promise(async () => {
        server.stop(true)
        await fs.rm(dir, { recursive: true, force: true })
      }),
  )

it.live("reads the allowlist once through the gateway socket", () =>
  Effect.gen(function* () {
    const { socket, seen } = yield* gateway(() => Response.json(served))
    expect(yield* Effect.promise(() => ManagedModels.read(socket))).toEqual(served)
    expect(seen).toEqual(["GET /v1/models"])
  }),
)

it.live("any failure to read it is none, so the compiled model holds", () =>
  Effect.gen(function* () {
    const missing = yield* gateway(() => new Response("models unavailable", { status: 404 }))
    expect(yield* Effect.promise(() => ManagedModels.read(missing.socket))).toBeUndefined()
    const widened = yield* gateway(() => Response.json({ ...served, mcp: { x: { type: "local" } } }))
    expect(yield* Effect.promise(() => ManagedModels.read(widened.socket))).toBeUndefined()
    const huge = yield* gateway(() => new Response(JSON.stringify(served) + " ".repeat(1 << 20)))
    expect(yield* Effect.promise(() => ManagedModels.read(huge.socket))).toBeUndefined()
    // A gateway that never answers costs the start at most the deadline.
    const silent = yield* gateway(() => new Promise<Response>(() => {}))
    expect(yield* Effect.promise(() => ManagedModels.read(silent.socket, 50))).toBeUndefined()
    expect(yield* Effect.promise(() => ManagedModels.read(path.join(missing.dir, "absent.sock")))).toBeUndefined()
  }),
)

it.live("the allowlist is what the session lists and defaults to, and a project's config still is not", () =>
  Effect.gen(function* () {
    const tmp = yield* Effect.acquireDisposable(Effect.promise(() => tmpdir("badger-models-config-")))
    const project = path.join(tmp.path, "project")
    yield* Effect.promise(async () => {
      await fs.mkdir(project, { recursive: true })
      await fs.writeFile(
        path.join(project, "opencode.json"),
        JSON.stringify({ model: "managed/attacker", providers: { managed: { models: { attacker: { name: "Attacker" } } } } }),
      )
    })
    const handler = yield* ServerFetch.make(
      {
        app: { version: "managed-test" },
        database: { path: ":memory:" },
        config: { directory: path.join(tmp.path, "global") },
        fs: { filewatcher: false },
        models: { fetch: false },
      },
      { overrides: ManagedProfile.replacements({ models: served }) },
    )
    const read = (route: string) =>
      Effect.promise(() => {
        const url = new URL(route, "http://badger.local")
        url.searchParams.set("location[directory]", project)
        return handler(new Request(url)).then((r) => r.json())
      })
    const entries = (yield* read("/api/config")) as Array<{ info: typeof ManagedProfile.document }>
    expect(entries).toHaveLength(1)
    expect(entries[0]!.info.model).toEqual(sol)
    for (let attempt = 0; attempt < 100 && ((yield* read("/api/plugin")) as { data?: unknown[] }).data?.length === 0; attempt++)
      yield* Effect.sleep("100 millis")
    const models = ((yield* read("/api/model")) as { data?: { id: string; providerID: string; name: string }[] }).data ?? []
    expect(models.map((model) => `${model.providerID}/${model.id} ${model.name}`).sort()).toEqual([
      "managed/gpt-5.6-luna GPT-5.6 Luna",
      "managed/gpt-5.6-sol GPT-5.6 Sol",
    ])
  }),
)
