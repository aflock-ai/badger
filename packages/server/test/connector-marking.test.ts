import { afterEach, beforeEach, expect } from "bun:test"
import { Global } from "@opencode/util/global"
import { Context, Effect, Layer } from "effect"
import { HttpEffect, HttpRouter, HttpServer } from "effect/http"
import { tmpdirScoped } from "../../core/test/fixture/tmpdir"
import { it } from "../../core/test/lib/effect"
import { createEmbeddedRoutes } from "../src/routes"

const env = { ...process.env }
beforeEach(() => {
  process.env.BADGER_DATA_MARKING = "CUI"
  process.env.BADGER_ALLOWED_MARKINGS = JSON.stringify(["CUI", "UNCLASSIFIED"])
  process.env.BADGER_TRUSTED_ROLE_HEADER = "x-verified-role"
  process.env.BADGER_MARKING_ADMIN_ROLES = JSON.stringify(["marking-admin"])
})
afterEach(() => {
  process.env = { ...env }
})

const serve = Effect.gen(function* () {
  const directory = yield* tmpdirScoped()
  const state = yield* tmpdirScoped()
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
  const handler = Context.get(context, HttpRouter.HttpRouter).asHttpEffect().pipe(HttpEffect.toWebHandlerWith(context))
  const call = (method: string, input: unknown, headers: Record<string, string> = {}) => {
    const url = new URL(`/api/rpc/connector-marking/${method}`, "http://opencode.local")
    url.searchParams.set("location[directory]", directory.path)
    return Effect.promise(async () => {
      const response = await handler(
        new Request(url, {
          method: "POST",
          headers: { "content-type": "application/json", ...headers },
          body: JSON.stringify({ input }),
        }),
      )
      return { status: response.status, body: (await response.json()) as Record<string, any> }
    })
  }
  return { call }
})

const admin = { "x-verified-role": "marking-admin" }

it.live(
  "a connector starts at the deployment marking and only an admin may lower it",
  () =>
    Effect.gen(function* () {
      const { call } = yield* serve
      const start = yield* call("get", { connector: "gitlab" })
      expect(start.status).toBe(200)
      expect(start.body.output).toMatchObject({ marking: "CUI", allowed: ["CUI"] })

      const refused = yield* call("set", { connector: "gitlab", marking: "UNCLASSIFIED" })
      expect(refused.status).toBe(400)
      expect(refused.body.type).toBe("marking.requires_admin")
      expect((yield* call("get", { connector: "gitlab" })).body.output.marking).toBe("CUI")

      // A role sent under an untrusted header name is no admin.
      const spoofed = yield* call(
        "set",
        { connector: "gitlab", marking: "UNCLASSIFIED" },
        { "x-role": "marking-admin" },
      )
      expect(spoofed.status).toBe(400)

      expect((yield* call("get", { connector: "gitlab" }, admin)).body.output.allowed).toEqual(["CUI", "UNCLASSIFIED"])
      const lowered = yield* call("set", { connector: "gitlab", marking: "UNCLASSIFIED" }, admin)
      expect(lowered.status).toBe(200)
      expect(lowered.body.output).toMatchObject({ marking: "UNCLASSIFIED", previous: "CUI" })

      // Anyone may raise it again.
      expect((yield* call("set", { connector: "gitlab", marking: "CUI" })).body.output.marking).toBe("CUI")
    }),
  30_000,
)

it.live(
  "no admin role is configured, so nobody may lower a marking",
  () =>
    Effect.gen(function* () {
      delete process.env.BADGER_TRUSTED_ROLE_HEADER
      const { call } = yield* serve
      const refused = yield* call("set", { connector: "gitlab", marking: "UNCLASSIFIED" }, admin)
      expect(refused.status).toBe(400)
      expect(refused.body.type).toBe("marking.requires_admin")
    }),
  30_000,
)

it.live(
  "a marking the deployment does not allow is refused",
  () =>
    Effect.gen(function* () {
      const { call } = yield* serve
      const refused = yield* call("set", { connector: "gitlab", marking: "SECRET" }, admin)
      expect(refused.status).toBe(400)
      expect(refused.body.type).toBe("marking.not_allowed")
    }),
  30_000,
)
