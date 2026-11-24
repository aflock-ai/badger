import os from "node:os"
import path from "node:path"
import fs from "node:fs/promises"
import { expect } from "bun:test"
import { Effect, Exit } from "effect"
import { FetchHttpClient, HttpClient } from "effect/http"
import { it } from "../../core/test/lib/effect"
import { tmpdir } from "../../core/test/fixture/tmpdir"
import { ServerFetch } from "../src/fetch"
import { ManagedProfile } from "../src/managed"

// Stands in for the administrator's gateway: a unix socket that records each request it serves.
const gateway = Effect.acquireRelease(
  Effect.promise(async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "badger-gw-"))
    const socket = path.join(dir, "gateway.sock")
    const seen: string[] = []
    const server = Bun.serve({
      unix: socket,
      fetch(request) {
        const { pathname } = new URL(request.url)
        seen.push(`${request.method} ${pathname}`)
        // A gateway (or whatever answers on its socket) that tries to send the client elsewhere.
        if (pathname === "/v1/redirect") return Response.redirect("https://models.opencode.ai/api.json", 302)
        return Response.json({ ok: true })
      },
    })
    return { socket, seen, server, dir }
  }),
  ({ server, dir }) => Effect.promise(async () => {
    server.stop(true)
    await fs.rm(dir, { recursive: true, force: true })
  }),
)

// A caller-supplied fetch (what an injected context would carry) that must never be used.
const leaked: string[] = []
const hostile: typeof fetch = Object.assign(
  (input: string | URL | Request) => {
    leaked.push(typeof input === "string" ? input : input instanceof URL ? input.href : input.url)
    return Promise.resolve(new Response("leaked"))
  },
  { preconnect: fetch.preconnect },
)

const send = (socket: string, url: string) =>
  HttpClient.get(url).pipe(
    Effect.flatMap((response) => response.text.pipe(Effect.map((body) => ({ status: response.status, body })))),
    Effect.provide(ManagedProfile.gatewayHttpClient(socket)),
    Effect.provideService(FetchHttpClient.Fetch, hostile),
    Effect.exit,
  )

it.live("reaches the gateway only over its socket, whatever fetch the caller carries", () =>
  Effect.gen(function* () {
    const { socket, seen } = yield* gateway
    leaked.length = 0
    const exit = yield* send(socket, "http://hardened-gateway/v1/models")
    expect(Exit.isSuccess(exit) && exit.value).toEqual({ status: 200, body: JSON.stringify({ ok: true }) })
    expect(seen).toEqual(["GET /v1/models"])
    expect(leaked).toEqual([])
  }),
)

it.live("does not follow a redirect from the gateway", () =>
  Effect.gen(function* () {
    const { socket, seen } = yield* gateway
    leaked.length = 0
    expect(Exit.isFailure(yield* send(socket, "http://hardened-gateway/v1/redirect"))).toBe(true)
    expect(seen).toEqual(["GET /v1/redirect"])
    expect(leaked).toEqual([])
  }),
)

it.live("refuses every other destination", () =>
  Effect.gen(function* () {
    const { socket, seen } = yield* gateway
    leaked.length = 0
    for (const url of [
      "https://models.opencode.ai/api.json",
      "https://hardened-gateway/v1/models",
      "http://hardened-gateway:8080/v1/models",
      "http://127.0.0.1:11434/api/tags",
      "http://localhost/v1/models",
    ]) {
      expect(Exit.isFailure(yield* send(socket, url)), url).toBe(true)
    }
    expect(seen).toEqual([])
    expect(leaked).toEqual([])
  }),
)

// The real gateway admits one request per session and refuses an overlapping one as busy (an audited 429).
// 2.0 starts title generation beside the first turn, so the managed client must queue model calls itself:
// each holds its place until the gateway has finished streaming the response.
const busyGateway = Effect.acquireRelease(
  Effect.promise(async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "badger-gw-busy-"))
    const socket = path.join(dir, "gateway.sock")
    const state = { active: 0, busy: 0, served: 0 }
    const server = Bun.serve({
      unix: socket,
      fetch() {
        if (state.active > 0) {
          state.busy++
          return new Response("session busy", { status: 429 })
        }
        state.active++
        const stream = new ReadableStream({
          async start(controller) {
            for (const chunk of ["a", "b", "c"]) {
              controller.enqueue(new TextEncoder().encode(chunk))
              await Bun.sleep(30)
            }
            controller.close()
            state.active--
            state.served++
          },
        })
        return new Response(stream)
      },
    })
    return { socket, state, server, dir }
  }),
  ({ server, dir }) => Effect.promise(async () => {
    server.stop(true)
    await fs.rm(dir, { recursive: true, force: true })
  }),
)

it.live("overlapping model calls wait their turn instead of being refused as busy", () =>
  Effect.gen(function* () {
    const { socket, state } = yield* busyGateway
    const call = HttpClient.post("http://hardened-gateway/v1/chat/completions").pipe(
      Effect.flatMap((response) => response.text.pipe(Effect.map((body) => ({ status: response.status, body })))),
    )
    const results = yield* Effect.all([call, call, call], { concurrency: "unbounded" }).pipe(
      Effect.provide(ManagedProfile.gatewayHttpClient(socket)),
    )
    const served = { status: 200, body: "abc" }
    expect(results).toEqual([served, served, served])
    expect(state).toEqual({ active: 0, busy: 0, served: 3 })
  }),
)

it.live("a refused or failed model call does not hold up the next one", () =>
  Effect.gen(function* () {
    const { socket } = yield* gateway
    for (const url of ["https://models.opencode.ai/api.json", "http://hardened-gateway/v1/redirect", "http://hardened-gateway/v1/models"])
      yield* send(socket, url)
    expect(Exit.isSuccess(yield* send(socket, "http://hardened-gateway/v1/models"))).toBe(true)
  }),
)

// A gateway that streams one chunk every 20 ms until the client stops reading or goes away, and refuses
// overlap the way the real one does.
const endlessGateway = Effect.acquireRelease(
  Effect.promise(async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "badger-gw-endless-"))
    const socket = path.join(dir, "gateway.sock")
    const state = { active: 0, busy: 0 }
    const server = Bun.serve({
      unix: socket,
      fetch() {
        if (state.active > 0) {
          state.busy++
          return new Response("session busy", { status: 429 })
        }
        state.active++
        let open = true
        const stop = () => {
          if (open) state.active--
          open = false
        }
        return new Response(
          new ReadableStream({
            async pull(controller) {
              await Bun.sleep(20)
              if (open) controller.enqueue(new TextEncoder().encode("."))
            },
            cancel: stop,
          }),
        )
      },
    })
    return { socket, state, server, dir }
  }),
  ({ server, dir }) => Effect.promise(async () => {
    server.stop(true)
    await fs.rm(dir, { recursive: true, force: true })
  }),
)

it.live("a response body nobody reads gives up its turn after the idle bound", () =>
  Effect.gen(function* () {
    const { socket, state } = yield* endlessGateway
    const fetch = ManagedProfile.gatewayFetch(socket, { idleMs: 200, holdMs: 60_000 })
    yield* Effect.promise(async () => {
      const abandoned = await fetch("http://hardened-gateway/v1/chat/completions", { method: "POST" })
      expect(abandoned.status).toBe(200)
      const started = performance.now()
      const next = await fetch("http://hardened-gateway/v1/chat/completions", { method: "POST" })
      expect(next.status).toBe(200)
      expect(performance.now() - started).toBeLessThan(2_000)
      await next.body?.cancel()
    })
    expect(state.busy).toBe(0)
  }),
)

it.live("a call that is still being read gives up its turn at the hold bound", () =>
  Effect.gen(function* () {
    const { socket, state } = yield* endlessGateway
    const fetch = ManagedProfile.gatewayFetch(socket, { idleMs: 60_000, holdMs: 300 })
    yield* Effect.promise(async () => {
      const reading = await fetch("http://hardened-gateway/v1/chat/completions", { method: "POST" })
      const drained = reading.text().catch((error: Error) => error)
      const started = performance.now()
      const next = await fetch("http://hardened-gateway/v1/chat/completions", { method: "POST" })
      expect(next.status).toBe(200)
      expect(performance.now() - started).toBeLessThan(2_000)
      expect(await drained).toBeInstanceOf(Error)
      await next.body?.cancel()
    })
    expect(state.busy).toBe(0)
  }),
)

// A gateway that sends a response's headers and then never sends a byte of body. Bun.serve holds the
// headers until the first body chunk, so this one writes HTTP itself.
const stalledGateway = Effect.acquireRelease(
  Effect.promise(async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "badger-gw-stalled-"))
    const socket = path.join(dir, "gateway.sock")
    const state = { active: 0, busy: 0 }
    const holding = new WeakSet<object>()
    const server = Bun.listen({
      unix: socket,
      socket: {
        data(connection) {
          if (state.active > 0) {
            state.busy++
            connection.end("HTTP/1.1 429 Too Many Requests\r\ncontent-length: 12\r\nconnection: close\r\n\r\nsession busy")
            return
          }
          state.active++
          holding.add(connection)
          connection.write("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
        },
        close(connection) {
          if (holding.has(connection)) state.active--
        },
      },
    })
    return { socket, state, server, dir }
  }),
  ({ server, dir }) => Effect.promise(async () => {
    server.stop(true)
    await fs.rm(dir, { recursive: true, force: true })
  }),
)

it.live("an unread response whose body stalls still gives up its turn after the idle bound", () =>
  Effect.gen(function* () {
    const { socket, state } = yield* stalledGateway
    const fetch = ManagedProfile.gatewayFetch(socket, { idleMs: 200, holdMs: 60_000 })
    yield* Effect.promise(async () => {
      const abandoned = await fetch("http://hardened-gateway/v1/chat/completions", { method: "POST" })
      expect(abandoned.status).toBe(200)
      const started = performance.now()
      const next = await fetch("http://hardened-gateway/v1/chat/completions", { method: "POST" })
      expect(next.status).toBe(200)
      expect(performance.now() - started).toBeLessThan(2_000)
      await next.body?.cancel()
    })
    expect(state.busy).toBe(0)
  }),
)

it.live("a queued call that is cancelled leaves the queue at once", () =>
  Effect.gen(function* () {
    const { socket, state } = yield* endlessGateway
    const fetch = ManagedProfile.gatewayFetch(socket, { idleMs: 60_000, holdMs: 60_000 })
    yield* Effect.promise(async () => {
      const stop = new AbortController()
      const holder = await fetch("http://hardened-gateway/v1/chat/completions", { method: "POST", signal: stop.signal })
      const reading = holder.text().catch(() => undefined)
      const cancel = new AbortController()
      const started = performance.now()
      const queued = fetch("http://hardened-gateway/v1/chat/completions", { method: "POST", signal: cancel.signal })
      setTimeout(() => cancel.abort(new Error("caller gave up")), 50)
      expect(await queued.then(() => "served", (error: Error) => error.message)).toBe("caller gave up")
      expect(performance.now() - started).toBeLessThan(1_000)
      stop.abort()
      await reading
      const next = await fetch("http://hardened-gateway/v1/chat/completions", { method: "POST" })
      expect(next.status).toBe(200)
      await next.body?.cancel()
    })
    expect(state.busy).toBe(0)
  }),
)

// Like the stalled gateway, but it sends one chunk, keeps the response open, and frees its slot only 150 ms
// after the client has gone, as a real gateway does once its handler notices the closed connection.
const slowReleaseGateway = Effect.acquireRelease(
  Effect.promise(async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "badger-gw-slow-release-"))
    const socket = path.join(dir, "gateway.sock")
    const state = { active: 0, busy: 0, served: 0 }
    const holding = new WeakSet<object>()
    const server = Bun.listen({
      unix: socket,
      socket: {
        data(connection) {
          if (state.active > 0) {
            state.busy++
            connection.end("HTTP/1.1 429 Too Many Requests\r\ncontent-length: 12\r\nconnection: close\r\n\r\nsession busy")
            return
          }
          state.active++
          state.served++
          holding.add(connection)
          connection.write("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n1\r\n.\r\n")
        },
        close(connection) {
          if (holding.has(connection)) setTimeout(() => state.active--, 150)
        },
      },
    })
    return { socket, state, server, dir }
  }),
  ({ server, dir }) => Effect.promise(async () => {
    server.stop(true)
    await fs.rm(dir, { recursive: true, force: true })
  }),
)

it.live("aborting an unread response lets the queued call go at once, without a busy refusal", () =>
  Effect.gen(function* () {
    const { socket, state } = yield* slowReleaseGateway
    const fetch = ManagedProfile.gatewayFetch(socket, { idleMs: 60_000, holdMs: 60_000 })
    yield* Effect.promise(async () => {
      const stop = new AbortController()
      const first = await fetch("http://hardened-gateway/v1/chat/completions", { method: "POST", signal: stop.signal })
      expect(first.status).toBe(200)
      const started = performance.now()
      const queued = fetch("http://hardened-gateway/v1/chat/completions", { method: "POST" })
      setTimeout(() => stop.abort(new Error("caller gave up")), 50)
      const next = await queued
      expect(next.status).toBe(200)
      expect(performance.now() - started).toBeLessThan(2_000)
      await next.body?.cancel()
    })
    expect(state.served).toBe(2)
  }),
)

it.live("a cancelled body whose slot the gateway frees late does not surface a busy refusal", () =>
  Effect.gen(function* () {
    const { socket, state } = yield* slowReleaseGateway
    const fetch = ManagedProfile.gatewayFetch(socket, { idleMs: 60_000, holdMs: 60_000 })
    yield* Effect.promise(async () => {
      const first = await fetch("http://hardened-gateway/v1/chat/completions", { method: "POST" })
      const queued = fetch("http://hardened-gateway/v1/chat/completions", { method: "POST" })
      await first.body?.cancel()
      const next = await queued
      expect(next.status).toBe(200)
      await next.body?.cancel()
    })
    expect(state.served).toBe(2)
  }),
)

it.live("the compiled config declares one provider and one model, reached through the gateway", () =>
  Effect.sync(() => {
    const providers = ManagedProfile.document.providers ?? {}
    expect(Object.keys(providers)).toEqual(["managed"])
    expect(providers["managed"]?.package).toBe("@opencode/ai/providers/openai-compatible")
    expect(providers["managed"]?.settings?.["baseURL"]).toBe("http://hardened-gateway/v1")
    expect(Object.keys(providers["managed"]?.models ?? {})).toEqual(["approved"])
    // What the TUI and app show for them is the product's: testifysec/branding/product.json.
    expect(providers["managed"]?.name).toBe("Badger approved gateway")
    expect(providers["managed"]?.models?.["approved"]?.name).toBe("Badger approved model")
    expect(ManagedProfile.document.model).toMatchObject({ providerID: "managed", model: "approved" })
    const execute = ManagedProfile.document.permissions?.findLast((rule) => rule.action === "execute")
    expect(execute?.effect).toBe("deny")
  }),
)

it.live("a managed server offers exactly the gateway provider and its one model", () =>
  Effect.gen(function* () {
    const tmp = yield* Effect.acquireDisposable(Effect.promise(() => tmpdir("badger-models-")))
    const project = path.join(tmp.path, "project")
    yield* Effect.promise(() => fs.mkdir(project))
    const handler = yield* ServerFetch.make(
      { database: { path: ":memory:" }, config: { directory: tmp.path }, fs: { filewatcher: false } },
      { overrides: ManagedProfile.replacements() },
    )
    const list = (route: string) =>
      Effect.gen(function* () {
        const url = new URL(route, "http://badger.local")
        url.searchParams.set("location[directory]", project)
        const response = yield* Effect.promise(() => handler(new Request(url)))
        return ((yield* Effect.promise(() => response.json())) as { data: { id: string; providerID?: string }[] }).data
      })
    let models: { id: string; providerID?: string }[] = []
    for (let attempt = 0; attempt < 100 && models.length === 0; attempt++) {
      models = yield* list("/api/model")
      if (models.length === 0) yield* Effect.sleep("100 millis")
    }
    expect(models.map((model) => `${model.providerID}/${model.id}`)).toEqual(["managed/approved"])
    expect((yield* list("/api/provider")).map((provider) => provider.id)).toEqual(["managed"])
    // The default a prompt without a model uses is the compiled one, never a built-in provider's.
    const url = new URL("/api/model/default", "http://badger.local")
    url.searchParams.set("location[directory]", project)
    const response = yield* Effect.promise(() => handler(new Request(url)))
    expect(((yield* Effect.promise(() => response.json())) as { data?: { id: string; providerID: string } }).data).toMatchObject({
      providerID: "managed",
      id: "approved",
    })
  }),
)

it.live("the build agent is the default, capped at 8 steps, and ends with the compiled rules", () =>
  Effect.gen(function* () {
    const tmp = yield* Effect.acquireDisposable(Effect.promise(() => tmpdir("badger-agent-")))
    const project = path.join(tmp.path, "project")
    yield* Effect.promise(() => fs.mkdir(project))
    const handler = yield* ServerFetch.make(
      { database: { path: ":memory:" }, config: { directory: tmp.path }, fs: { filewatcher: false } },
      { overrides: ManagedProfile.replacements() },
    )
    const read = (route: string) =>
      Effect.gen(function* () {
        const url = new URL(route, "http://badger.local")
        url.searchParams.set("location[directory]", project)
        const response = yield* Effect.promise(() => handler(new Request(url)))
        return ((yield* Effect.promise(() => response.json())) as { data?: unknown[] }).data ?? []
      })
    // Config is applied to agents by a plugin, so read agents only once plugins have activated.
    for (let attempt = 0; attempt < 100 && (yield* read("/api/plugin")).length === 0; attempt++)
      yield* Effect.sleep("100 millis")
    type Agent = { id: string; steps?: number; permissions: { action: string; resource: string; effect: string }[] }
    const build = ((yield* read("/api/agent")) as Agent[]).find((agent) => agent.id === "build")
    const compiled = ManagedProfile.document.permissions ?? []

    expect(ManagedProfile.document.default_agent).toBe("build")
    expect(build?.steps).toBe(40)
    // A multi-file build takes dozens of tool calls; the model must keep its context and wait for a slow first byte.
    const approved = ManagedProfile.document.providers?.managed?.models?.approved
    expect(approved?.limit).toEqual({ context: 131072, output: 16384 })
    expect(ManagedProfile.document.providers?.managed?.settings?.timeout).toBe(230000)
    // Last match wins, so the compiled rules must be the tail of the agent's own ruleset.
    expect(build?.permissions.slice(-compiled.length)).toEqual([...compiled])
  }),
)

// Provider credentials in the environment activate catalog providers upstream; the managed build
// must ignore them. Values are fake; nothing is sent (the test harness refuses the network).
const providerEnv = {
  CLOUDFLARE_ACCOUNT_ID: "fake-account",
  CLOUDFLARE_GATEWAY_ID: "fake-gateway",
  CLOUDFLARE_API_TOKEN: "fake-token",
  ANTHROPIC_API_KEY: "fake-anthropic",
  OPENAI_API_KEY: "fake-openai",
}

const modelsWithEnv = (overrides: Parameters<typeof ServerFetch.make>[1]) =>
  Effect.gen(function* () {
    const saved = Object.fromEntries(Object.keys(providerEnv).map((key) => [key, process.env[key]]))
    yield* Effect.addFinalizer(() =>
      Effect.sync(() => {
        for (const [key, value] of Object.entries(saved))
          if (value === undefined) delete process.env[key]
          else process.env[key] = value
      }),
    )
    Object.assign(process.env, providerEnv)
    const tmp = yield* Effect.acquireDisposable(Effect.promise(() => tmpdir("badger-env-")))
    const project = path.join(tmp.path, "project")
    yield* Effect.promise(() => fs.mkdir(project))
    const handler = yield* ServerFetch.make(
      { database: { path: ":memory:" }, config: { directory: tmp.path }, fs: { filewatcher: false }, models: { fetch: false } },
      overrides,
    )
    const read = (route: string) =>
      Effect.gen(function* () {
        const url = new URL(route, "http://badger.local")
        url.searchParams.set("location[directory]", project)
        const response = yield* Effect.promise(() => handler(new Request(url)))
        return ((yield* Effect.promise(() => response.json())) as { data?: { id: string; providerID?: string }[] }).data ?? []
      })
    for (let attempt = 0; attempt < 100 && (yield* read("/api/plugin")).length === 0; attempt++)
      yield* Effect.sleep("100 millis")
    return {
      models: (yield* read("/api/model")).map((model) => `${model.providerID}/${model.id}`),
      providers: (yield* read("/api/provider")).map((provider) => provider.id),
    }
  })

it.live("control: provider credentials in the environment activate catalog providers upstream", () =>
  Effect.gen(function* () {
    const { providers, models } = yield* modelsWithEnv({})
    for (const id of ["cloudflare-ai-gateway", "anthropic", "openai"]) expect(providers).toContain(id)
    expect(models.some((model) => model.startsWith("cloudflare-ai-gateway/"))).toBe(true)
  }),
)

it.live("the managed build ignores provider credentials in the environment", () =>
  Effect.gen(function* () {
    const { models, providers } = yield* modelsWithEnv({ overrides: ManagedProfile.replacements() })
    expect(models).toEqual(["managed/approved"])
    expect(providers).toEqual(["managed"])
  }),
)
