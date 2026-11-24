import { afterEach, beforeEach, expect } from "bun:test"
import { SdkPlugins } from "@opencode/core/plugin/sdk"
import { define } from "@opencode/plugin/effect/plugin"
import { Rpc } from "@opencode/schema/rpc"
import type { Tool } from "@opencode/schema/tool"
import { Global } from "@opencode/util/global"
import { Context, Effect, Layer, Schema } from "effect"
import { HttpEffect, HttpRouter, HttpServer } from "effect/http"
import { writeFile } from "node:fs/promises"
import path from "node:path"
import { tmpdirScoped } from "../../core/test/fixture/tmpdir"
import { it } from "../../core/test/lib/effect"
import { createEmbeddedRoutes } from "../src/routes"

const Gitlab = Rpc.define({
  id: "gitlab",
  methods: { ping: { input: Schema.Unknown, output: Schema.Null } },
  events: {},
})

const env = { ...process.env }
beforeEach(() => {
  process.env.BADGER_DATA_MARKING = "UNCLASSIFIED"
  process.env.BADGER_ALLOWED_MARKINGS = JSON.stringify(["UNCLASSIFIED", "CUI"])
})
afterEach(() => {
  process.env = { ...env }
})

const context: Tool.Context = {
  sessionID: "ses_test" as never,
  agent: "build" as never,
  messageID: "msg_test" as never,
  id: "call_test" as never,
  progress: () => Effect.void,
}

const serve = Effect.gen(function* () {
  const directory = yield* tmpdirScoped()
  const state = yield* tmpdirScoped()
  const ran = { connector: 0, plain: 0 }
  let tools: (() => Effect.Effect<ReadonlyArray<Tool.Info & { id: string }>>) | undefined
  const built = yield* Layer.build(
    createEmbeddedRoutes(
      {
        database: { path: ":memory:" },
        models: { fetch: false },
        config: { directory: directory.path, project: false, content: "{}" },
        fs: { filewatcher: false },
      },
      [Global.node.replace(Global.layerWith({ config: directory.path, state: state.path }))],
    ).pipe(Layer.provide(HttpServer.layerServices)),
  )
  const plugins = Context.get(built, SdkPlugins.Service)
  // A connector: registers its RPC and a tool from the same plugin.
  yield* plugins.register(
    define({
      id: "gitlab-connector",
      effect: (ctx) =>
        Effect.gen(function* () {
          tools = () => ctx.tool.list()
          yield* ctx.rpc.register(Gitlab, { ping: () => Effect.succeed(null) }).pipe(Effect.orDie)
          yield* ctx.tool.transform((editor) =>
            editor.add({
              name: "gitlab_search",
              description: "Search GitLab",
              input: Schema.Unknown,
              execute: () => Effect.sync(() => ({ content: `issue ${++ran.connector}`, metadata: { hits: 1 } })),
            }),
          )
        }),
    }),
  )
  // Not a connector: registers a tool and no RPC.
  yield* plugins.register(
    define({
      id: "plain-tools",
      effect: (ctx) =>
        ctx.tool.transform((editor) =>
          editor.add({
            name: "plain_echo",
            description: "Echo",
            input: Schema.Unknown,
            execute: () => Effect.sync(() => ({ content: `echo ${++ran.plain}` })),
          }),
        ),
    }),
  )
  const handler = Context.get(built, HttpRouter.HttpRouter).asHttpEffect().pipe(HttpEffect.toWebHandlerWith(built))
  const rpc = (method: string, input: unknown) => {
    const url = new URL(`/api/rpc/connector-marking/${method}`, "http://opencode.local")
    url.searchParams.set("location[directory]", directory.path)
    return Effect.promise(() =>
      handler(
        new Request(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ input }),
        }),
      ).then((response) => response.status),
    )
  }
  // Activate the location's plugins, then reach the registered tools.
  expect(yield* rpc("get", { connector: "gitlab" })).toBe(200)
  const run = (name: string) =>
    Effect.gen(function* () {
      const tool = (yield* tools!()).find((item) => item.name === name)
      if (!tool) throw new Error(`tool not registered: ${name}`)
      return yield* tool.execute(null, context)
    })
  return { run, rpc, ran, markings: path.join(state.path, "connector-markings.json") }
})

it.live(
  "a connector's tool result carries the connector's current data marking",
  () =>
    Effect.gen(function* () {
      const { run } = yield* serve
      const result = yield* run("gitlab_search")
      expect(result.metadata).toEqual({
        hits: 1,
        connectorMarking: { connector: "gitlab", marking: "UNCLASSIFIED", classification: "UNCLASSIFIED" },
      })
    }),
  30_000,
)

it.live(
  "raising a connector's marking applies to its later tool results",
  () =>
    Effect.gen(function* () {
      const { run, rpc } = yield* serve
      expect((yield* run("gitlab_search")).metadata?.connectorMarking?.marking).toBe("UNCLASSIFIED")
      expect(yield* rpc("set", { connector: "gitlab", marking: "CUI" })).toBe(200)
      expect((yield* run("gitlab_search")).metadata?.connectorMarking?.marking).toBe("CUI")
    }),
  30_000,
)

// Matches #66: with no readable marking the connector's data is refused, and the tool never runs.
it.live(
  "a connector tool is refused before it runs when its marking cannot be read",
  () =>
    Effect.gen(function* () {
      const { run, ran, markings } = yield* serve
      yield* Effect.promise(() => writeFile(markings, "{not json", { mode: 0o600 }))
      const failed = yield* run("gitlab_search").pipe(Effect.flip)
      expect(failed._tag).toBe("Tool.Error")
      expect(ran.connector).toBe(0)
    }),
  30_000,
)

it.live(
  "a tool from a plugin that is not a connector is not marked or gated",
  () =>
    Effect.gen(function* () {
      const { run, ran, markings } = yield* serve
      yield* Effect.promise(() => writeFile(markings, "{not json", { mode: 0o600 }))
      const result = yield* run("plain_echo")
      expect(result.metadata).toBeUndefined()
      expect(ran.plain).toBe(1)
    }),
  30_000,
)
