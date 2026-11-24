import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { expect, test } from "bun:test"
import { Effect } from "effect"
import { tmpdir } from "../../core/test/fixture/tmpdir"
import { it } from "../../core/test/lib/effect"
import { ServerFetch } from "../src/fetch"
import { ManagedLimits } from "../src/managed-limits"
import { ManagedProfile } from "../src/managed"

const served = { steps: 80, context: 65536, output: 8192, timeout_seconds: 200 }

test("accepts exactly four positive integers or nulls, and nothing else", () => {
  expect(ManagedLimits.parse(JSON.stringify(served))).toEqual(served)
  const unset = { steps: null, context: null, output: null, timeout_seconds: null }
  expect(ManagedLimits.parse(JSON.stringify(unset))).toEqual(unset)
  for (const bad of [
    { ...served, model: "attacker/model" },
    { ...served, steps: "999" },
    { ...served, steps: 0 },
    { ...served, steps: -1 },
    { ...served, context: 1.5 },
    { steps: 80, context: 65536, output: 8192 },
    [served],
    null,
  ])
    expect(ManagedLimits.parse(JSON.stringify(bad))).toBeUndefined()
  expect(ManagedLimits.parse("steps=999")).toBeUndefined()
})

test("served values replace the compiled ones, within what the system can do", () => {
  expect(ManagedLimits.resolve(ManagedProfile.limits, undefined)).toBe(ManagedProfile.limits)
  expect(ManagedLimits.resolve(ManagedProfile.limits, { steps: null, context: null, output: null, timeout_seconds: null })).toEqual(
    ManagedProfile.limits,
  )
  expect(ManagedLimits.resolve(ManagedProfile.limits, served)).toEqual({ steps: 80, context: 65536, output: 8192, timeoutMs: 200_000 })
  // Technical limits, not policy: the 1 MiB request, the answer inside the window, the gateway's 600 s.
  expect(ManagedLimits.resolve(ManagedProfile.limits, { steps: 999, context: 1_000_000, output: 2_000_000, timeout_seconds: 900 })).toEqual({
    steps: 999,
    context: 262_144,
    output: 262_143,
    timeoutMs: 600_000,
  })
})

// Stands in for the gateway's socket, answering GET /v1/limits as `answer` says.
const gateway = (answer: (request: Request) => Response | Promise<Response>) =>
  Effect.acquireRelease(
    Effect.promise(async () => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), "badger-limits-"))
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

it.live("reads the limits once through the gateway socket", () =>
  Effect.gen(function* () {
    const { socket, seen } = yield* gateway(() => Response.json(served))
    expect(yield* Effect.promise(() => ManagedLimits.read(socket))).toEqual(served)
    expect(seen).toEqual(["GET /v1/limits"])
  }),
)

it.live("any failure to read them is none, so the compiled limits hold", () =>
  Effect.gen(function* () {
    const missing = yield* gateway(() => new Response("limits unavailable", { status: 404 }))
    expect(yield* Effect.promise(() => ManagedLimits.read(missing.socket))).toBeUndefined()
    const widened = yield* gateway(() => Response.json({ ...served, permissions: [{ action: "*", effect: "allow" }] }))
    expect(yield* Effect.promise(() => ManagedLimits.read(widened.socket))).toBeUndefined()
    // A gateway that never answers costs the start at most the deadline.
    const silent = yield* gateway(() => new Promise<Response>(() => {}))
    expect(yield* Effect.promise(() => ManagedLimits.read(silent.socket, 50))).toBeUndefined()
    expect(yield* Effect.promise(() => ManagedLimits.read(path.join(missing.dir, "absent.sock")))).toBeUndefined()
  }),
)

it.live("the served limits are the session's config, and a project's config still is not", () =>
  Effect.gen(function* () {
    const tmp = yield* Effect.acquireDisposable(Effect.promise(() => tmpdir("badger-limits-config-")))
    const project = path.join(tmp.path, "project")
    yield* Effect.promise(async () => {
      await fs.mkdir(project, { recursive: true })
      await fs.writeFile(path.join(project, "opencode.json"), JSON.stringify({ agents: { build: { steps: 999 } } }))
    })
    const handler = yield* ServerFetch.make(
      {
        app: { version: "managed-test" },
        database: { path: ":memory:" },
        config: { directory: path.join(tmp.path, "global") },
        fs: { filewatcher: false },
        models: { fetch: false },
      },
      { overrides: ManagedProfile.replacements({ limits: served }) },
    )
    const url = new URL("/api/config", "http://badger.local")
    url.searchParams.set("location[directory]", project)
    const entries = (yield* Effect.promise(() => handler(new Request(url)).then((r) => r.json()))) as Array<{
      info: typeof ManagedProfile.document
    }>
    expect(entries).toHaveLength(1)
    const info = entries[0]!.info
    expect(info.agents).toEqual({ build: { steps: 80 } })
    expect(info.providers?.managed?.settings?.timeout).toBe(200_000)
    expect(info.providers?.managed?.models?.approved?.limit).toEqual({ context: 65536, output: 8192 })
    // Everything else is the compiled document.
    expect(info.permissions).toEqual(ManagedProfile.document.permissions)
    expect(info.providers?.managed?.settings?.baseURL).toBe(ManagedProfile.document.providers?.managed?.settings?.baseURL)
  }),
)
