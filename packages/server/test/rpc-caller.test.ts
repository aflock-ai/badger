import { afterEach, expect } from "bun:test"
import { SdkPlugins } from "@opencode/core/plugin/sdk"
import { define } from "@opencode/plugin/effect/plugin"
import { Rpc } from "@opencode/schema/rpc"
import { Context, Effect, Layer, Schema } from "effect"
import { HttpEffect, HttpRouter, HttpServer } from "effect/http"
import { tmpdirScoped } from "../../core/test/fixture/tmpdir"
import { it } from "../../core/test/lib/effect"
import { createEmbeddedRoutes } from "../src/routes"

// A connector reports the caller role it was handed, so the test sees exactly what plugin code sees.
const Whoami = Rpc.define({
  id: "whoami",
  methods: { role: { input: Schema.Unknown, output: Schema.NullOr(Schema.String) } },
  events: {},
})

const env = { ...process.env }
afterEach(() => {
  process.env = { ...env }
})

let inProcess: (() => Effect.Effect<unknown, unknown>) | undefined

const serve = Effect.gen(function* () {
  const directory = yield* tmpdirScoped()
  const context = yield* Layer.build(
    createEmbeddedRoutes({
      database: { path: ":memory:" },
      models: { fetch: false },
      config: { directory: directory.path, project: false, content: "{}" },
      fs: { filewatcher: false },
    }).pipe(Layer.provide(HttpServer.layerServices)),
  )
  yield* Context.get(context, SdkPlugins.Service).register(
    define({
      id: "whoami-plugin",
      effect: (ctx) => {
        inProcess = () => ctx.rpc(Whoami).role(null)
        return ctx.rpc
          .register(Whoami, { role: (_, call) => Effect.succeed(call.caller.role ?? null) })
          .pipe(Effect.asVoid, Effect.orDie)
      },
    }),
  )
  const handler = Context.get(context, HttpRouter.HttpRouter).asHttpEffect().pipe(HttpEffect.toWebHandlerWith(context))
  const call = (headers: Record<string, string>) => {
    const url = new URL("/api/rpc/whoami/role", "http://opencode.local")
    url.searchParams.set("location[directory]", directory.path)
    return Effect.promise(async () => {
      const response = await handler(
        new Request(url, {
          method: "POST",
          headers: { "content-type": "application/json", ...headers },
          body: JSON.stringify({ input: null }),
        }),
      )
      expect(response.status).toBe(200)
      return ((await response.json()) as { output?: string | null }).output ?? null
    })
  }
  return { call }
})

it.live("a trusted role header reaches the RPC handler as the caller's role", () =>
  Effect.gen(function* () {
    process.env.BADGER_TRUSTED_ROLE_HEADER = "X-Verified-Role"
    const { call } = yield* serve
    expect(yield* call({ "x-verified-role": "marking-admin" })).toBe("marking-admin")
    expect(yield* call({})).toBeNull()
    expect(yield* call({ "x-verified-role": "  " })).toBeNull()
  }),
)

it.live("no caller role unless the deployment names a trusted header", () =>
  Effect.gen(function* () {
    delete process.env.BADGER_TRUSTED_ROLE_HEADER
    const { call } = yield* serve
    expect(yield* call({ "x-verified-role": "marking-admin" })).toBeNull()
  }),
)

it.live("a role sent under any other header name is ignored", () =>
  Effect.gen(function* () {
    process.env.BADGER_TRUSTED_ROLE_HEADER = "x-verified-role"
    const { call } = yield* serve
    expect(yield* call({ "x-role": "marking-admin", "x-badger-role": "marking-admin" })).toBeNull()
  }),
)

it.live("in-process callers carry no role", () =>
  Effect.gen(function* () {
    process.env.BADGER_TRUSTED_ROLE_HEADER = "x-verified-role"
    const { call } = yield* serve
    yield* call({ "x-verified-role": "marking-admin" }) // an HTTP caller's role does not stick
    expect(yield* inProcess!()).toBeNull()
  }),
)
