import { afterEach, beforeEach, expect } from "bun:test"
import { SdkPlugins } from "@opencode/core/plugin/sdk"
import { define } from "@opencode/plugin/effect/plugin"
import { Rpc } from "@opencode/schema/rpc"
import { Global } from "@opencode/util/global"
import { Context, Effect, Fiber, Layer, Schema } from "effect"
import { HttpEffect, HttpRouter, HttpServer } from "effect/http"
import { writeFile } from "node:fs/promises"
import path from "node:path"
import { tmpdirScoped } from "../../core/test/fixture/tmpdir"
import { it } from "../../core/test/lib/effect"
import { createEmbeddedRoutes } from "../src/routes"

const Gitlab = Rpc.define({
  id: "gitlab",
  methods: {
    sync: { input: Schema.Unknown, output: Schema.Number },
    // A guarded action: the connector asks the session's permission rules before it acts. The
    // caller's `confirmed` claim is ignored; in 2.0 the confirmation is the user's reply.
    push: {
      input: Schema.Struct({ sessionID: Schema.String, confirmed: Schema.optional(Schema.Boolean) }),
      output: Schema.Number,
      errors: { denied: Schema.Struct({}) },
    },
  },
  events: {},
})

const env = { ...process.env }
beforeEach(() => {
  process.env.BADGER_DATA_MARKING = "CUI"
  process.env.BADGER_ALLOWED_MARKINGS = JSON.stringify(["CUI", "UNCLASSIFIED"])
})
afterEach(() => {
  process.env = { ...env }
})

const serve = Effect.gen(function* () {
  const directory = yield* tmpdirScoped()
  const state = yield* tmpdirScoped()
  let ran = 0
  const context = yield* Layer.build(
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
  yield* Context.get(context, SdkPlugins.Service).register(
    define({
      id: "gitlab-connector",
      effect: (ctx) =>
        ctx.rpc
          .register(Gitlab, {
            sync: () => Effect.sync(() => ++ran),
            push: ({ sessionID }, call) =>
              ctx.permission
                .assert({
                  sessionID: sessionID as never,
                  action: "connector.gitlab.push",
                  resources: ["group/project"],
                })
                .pipe(
                  Effect.mapError(() => call.error("denied", "Pushing to GitLab is not permitted", {})),
                  Effect.andThen(Effect.sync(() => ++ran)),
                ),
          })
          .pipe(Effect.asVoid, Effect.orDie),
    }),
  )
  const handler = Context.get(context, HttpRouter.HttpRouter).asHttpEffect().pipe(HttpEffect.toWebHandlerWith(context))
  const request = (method: string, route: string, body?: unknown) => {
    const url = new URL(route, "http://opencode.local")
    url.searchParams.set("location[directory]", directory.path)
    return Effect.promise(async () => {
      const response = await handler(
        new Request(url, {
          method,
          headers: { "content-type": "application/json" },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        }),
      )
      const text = await response.text()
      return { status: response.status, body: (text ? JSON.parse(text) : {}) as Record<string, any> }
    })
  }
  const session = (effect: "deny" | "ask") =>
    request("POST", "/api/session", {
      location: { directory: directory.path },
      permissions: [{ action: "connector.gitlab.push", resource: "*", effect }],
    }).pipe(Effect.map((created) => created.body.data.id as string))
  const call = (rpcID: string, method: string, input: unknown) => {
    const url = new URL(`/api/rpc/${rpcID}/${method}`, "http://opencode.local")
    url.searchParams.set("location[directory]", directory.path)
    return Effect.promise(async () => {
      const response = await handler(
        new Request(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ input }),
        }),
      )
      return { status: response.status, body: (await response.json()) as Record<string, any> }
    })
  }
  return { call, request, session, ran: () => ran, markings: path.join(state.path, "connector-markings.json") }
})

it.live(
  "a connector action runs when its marking can be read",
  () =>
    Effect.gen(function* () {
      const { call, ran } = yield* serve
      expect((yield* call("gitlab", "sync", null)).status).toBe(200)
      expect(ran()).toBe(1)
    }),
  30_000,
)

// An action is logged with its connector's data marking; with no readable marking it is refused.
it.live(
  "a connector action is refused when its marking cannot be read, and never runs",
  () =>
    Effect.gen(function* () {
      const { call, ran, markings } = yield* serve
      yield* Effect.promise(() => writeFile(markings, "{not json", { mode: 0o600 }))
      const refused = yield* call("gitlab", "sync", null)
      expect(refused.status).toBe(400)
      expect(refused.body.type).toBe("rpc.marking_unavailable")
      expect(ran()).toBe(0)
      // The marking RPC itself stays reachable, so an admin can still repair it.
      expect((yield* call("connector-marking", "get", { connector: "gitlab" })).body.type).not.toBe(
        "rpc.marking_unavailable",
      )
    }),
  30_000,
)

// Ported from badger #21 (1.x connector invoke route): a deny rule beats any confirmation.
it.live(
  "a denied connector action is refused before it runs, even when the caller claims confirmation",
  () =>
    Effect.gen(function* () {
      const { call, session, ran } = yield* serve
      const sessionID = yield* session("deny")
      const refused = yield* call("gitlab", "push", { sessionID, confirmed: true })
      expect(refused.status).toBe(400)
      expect(refused.body.type).toBe("denied")
      expect(ran()).toBe(0)
    }),
  30_000,
)

// An ask rule needs confirmation: in 2.0 that is the user's reply to the permission request the
// action raises, never a flag in the caller's input.
it.live(
  "an ask-gated connector action does not run until the user approves it",
  () =>
    Effect.gen(function* () {
      const { call, request, session, ran } = yield* serve
      const sessionID = yield* session("ask")
      const pending = () =>
        request("GET", "/api/permission/request").pipe(
          Effect.map((listed) =>
            ((listed.body.data ?? []) as Array<{ id: string; sessionID: string }>).filter(
              (item) => item.sessionID === sessionID,
            ),
          ),
        )
      const waitFor = Effect.fn(function* () {
        for (let attempt = 0; attempt < 100; attempt++) {
          const requests = yield* pending()
          if (requests.length) return requests[0]!.id
          yield* Effect.sleep("50 millis")
        }
        throw new Error("the action raised no permission request")
      })

      // Rejected: the action never runs, however the caller labelled it.
      const rejected = yield* call("gitlab", "push", { sessionID, confirmed: true }).pipe(Effect.forkChild)
      const first = yield* waitFor()
      expect(ran()).toBe(0)
      expect(
        (yield* request("POST", `/api/session/${sessionID}/permission/${first}/reply`, { decision: "reject" })).status,
      ).toBeLessThan(300)
      expect((yield* Fiber.join(rejected)).status).not.toBe(200)
      expect(ran()).toBe(0)

      // Approved once: it runs.
      const approved = yield* call("gitlab", "push", { sessionID }).pipe(Effect.forkChild)
      const second = yield* waitFor()
      expect(ran()).toBe(0)
      expect(
        (yield* request("POST", `/api/session/${sessionID}/permission/${second}/reply`, { decision: "once" })).status,
      ).toBeLessThan(300)
      expect((yield* Fiber.join(approved)).status).toBe(200)
      expect(ran()).toBe(1)
    }),
  30_000,
)
