import fs from "node:fs/promises"
import path from "node:path"
import { expect } from "bun:test"
import { Effect } from "effect"
import type { LayerNode } from "@opencode/util/effect/layer-node"
import { tmpdir } from "../../core/test/fixture/tmpdir"
import { it } from "../../core/test/lib/effect"
import { ServerFetch } from "../src/fetch"
import { ManagedProfile } from "../src/managed"
import { ManagedFlow } from "../src/managed-flow"
import { RoutePolicy } from "../src/route-policy"

type Handler = (request: Request) => Promise<Response>

const workspace = Effect.fnUntraced(function* () {
  const tmp = yield* Effect.acquireDisposable(Effect.promise(() => tmpdir("badger-routes-")))
  const global = path.join(tmp.path, "global")
  const project = path.join(tmp.path, "project")
  yield* Effect.promise(async () => {
    await fs.mkdir(global, { recursive: true })
    await fs.mkdir(project, { recursive: true })
  })
  return { root: tmp.path, global, project }
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

const call = (handler: Handler, method: string, route: string, project: string, body?: unknown) => {
  const url = new URL(route, "http://badger.local")
  url.searchParams.set("location[directory]", project)
  return Effect.promise(() =>
    handler(
      new Request(url, {
        method,
        headers: body === undefined ? undefined : { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
    ),
  )
}

const json = (response: Response) =>
  Effect.promise(() => response.text().then((text) => (text ? (JSON.parse(text) as { _tag?: string }) : {})))

const exists = (file: string) => Effect.promise(() => fs.access(file).then(() => true, () => false))

// A spawned process may take a moment to write; poll before concluding it ran.
const appears = (file: string) =>
  Effect.gen(function* () {
    for (let attempt = 0; attempt < 50; attempt++) {
      if (yield* exists(file)) return true
      yield* Effect.sleep("100 millis")
    }
    return false
  })

const session = (handler: Handler, project: string) =>
  Effect.gen(function* () {
    const response = yield* call(handler, "POST", "/api/session", project, {})
    expect(response.status).toBe(200)
    const body = (yield* Effect.promise(() => response.json())) as { data: { id: string } }
    return body.data.id
  })

// Every route the managed profile refuses, with a request that would reach its handler.
const refused = (sessionID: string) =>
  [
    ["GET", "/api/credential"],
    ["POST", "/api/credential", {}],
    ["PATCH", "/api/credential/cred_x", {}],
    ["POST", "/api/credential/cred_x/activate"],
    ["DELETE", "/api/credential/cred_x"],
    ["POST", "/api/integration/openai/connect/key", {}],
    ["POST", "/api/integration/openai/connect/external", {}],
    ["POST", "/api/integration/openai/connect/oauth", {}],
    ["POST", "/api/integration/openai/connect/command", {}],
    ["PUT", "/api/experimental/mcp/x", {}],
    ["POST", "/api/experimental/mcp/x/connect"],
    ["POST", "/api/shell", {}],
    ["POST", `/api/session/${sessionID}/shell`, {}],
    ["POST", "/api/pty", {}],
    ["POST", "/api/pty/pty_x/connect-token"],
    ["GET", "/api/pty/pty_x/connect?ticket=x"],
    ["POST", `/api/experimental/session/${sessionID}/terminal`, {}],
    ["POST", "/api/experimental/persistent-pty/handoff"],
    ["POST", "/api/experimental/persistent-pty/pty_x/connect-token"],
    ["GET", "/api/experimental/persistent-pty/pty_x/connect"],
    ["POST", "/api/worktree", {}],
    ["POST", "/api/vcs/init", {}],
  ] as const

it.live("control: upstream routes every refused request to its handler", () =>
  Effect.gen(function* () {
    const { global, project } = yield* workspace()
    const handler = yield* boot(global, [])
    const sessionID = yield* session(handler, project)
    for (const [method, route, payload] of refused(sessionID)) {
      const response = yield* call(handler, method, route, project, payload)
      // An unknown route answers 404 with no body; a handler answers with anything else.
      const body = yield* Effect.promise(() => response.text())
      expect({ method, route, answered: response.status !== 404 || body !== "" }).toEqual({
        method,
        route,
        answered: true,
      })
      expect(body).not.toContain(RoutePolicy.tag)
    }
    const list = yield* call(handler, "GET", "/api/credential", project)
    expect(list.status).toBe(200)
  }),
)

it.live("refuses every listed route before it reaches a handler", () =>
  Effect.gen(function* () {
    const { global, project } = yield* workspace()
    const handler = yield* boot(global, ManagedProfile.replacements())
    const sessionID = yield* session(handler, project)
    for (const [method, route, payload] of refused(sessionID)) {
      const response = yield* call(handler, method, route, project, payload)
      expect({ method, route, status: response.status, tag: (yield* json(response))._tag }).toEqual({
        method,
        route,
        status: 404,
        tag: RoutePolicy.tag,
      })
    }
  }),
)

it.live("refuses path spellings the router would still match", () =>
  Effect.gen(function* () {
    const { global, project } = yield* workspace()
    const handler = yield* boot(global, ManagedProfile.replacements())
    for (const route of ["/api/credential/", "/api//credential", "/API/credential", "/api/%63redential"]) {
      const response = yield* call(handler, "GET", route, project)
      const tag = response.status === 404 ? (yield* json(response))._tag : undefined
      // Either the policy refuses it, or the router does not resolve it at all; never a handler.
      expect({ route, refused: response.status === 404 && (tag === RoutePolicy.tag || tag === undefined) }).toEqual({
        route,
        refused: true,
      })
    }
    const head = yield* call(handler, "HEAD", "/api/credential", project)
    expect(head.status).toBe(404)
  }),
)

it.live("leaves routes it does not list alone", () =>
  Effect.gen(function* () {
    const { global, project } = yield* workspace()
    const handler = yield* boot(global, ManagedProfile.replacements())
    const sessionID = yield* session(handler, project)
    const response = yield* call(handler, "GET", `/api/session/${sessionID}`, project)
    expect(response.status).toBe(200)
  }),
)

// Requests that start a process writing `marker` when the route is served.
const spawning = (handler: Handler, project: string, marker: string) =>
  Effect.gen(function* () {
    const write = (name: string) => `printf ran > ${JSON.stringify(`${marker}-${name}`)}`
    const sessionID = yield* session(handler, project)
    yield* call(handler, "POST", "/api/shell", project, { command: write("shell") })
    yield* call(handler, "POST", `/api/session/${sessionID}/shell`, project, { command: write("session-shell") })
    yield* call(handler, "POST", "/api/pty", project, { command: "/bin/sh", args: ["-c", write("pty")] })
    yield* call(handler, "PUT", "/api/experimental/mcp/x", project, {
      config: { type: "local", command: ["/bin/sh", "-c", write("mcp")] },
    })
    return ["shell", "session-shell", "pty", "mcp"].map((name) => `${marker}-${name}`)
  })

it.live("control: upstream spawns a process from each spawning route", () =>
  Effect.gen(function* () {
    const { root, global, project } = yield* workspace()
    const handler = yield* boot(global, [])
    for (const file of yield* spawning(handler, project, path.join(root, "ran")))
      expect({ file, ran: yield* appears(file) }).toEqual({ file, ran: true })
  }),
)

it.live("spawns no process from any spawning route", () =>
  Effect.gen(function* () {
    const { root, global, project } = yield* workspace()
    const handler = yield* boot(global, ManagedProfile.replacements())
    const files = yield* spawning(handler, project, path.join(root, "ran"))
    yield* Effect.sleep("1 second")
    for (const file of files) expect({ file, ran: yield* exists(file) }).toEqual({ file, ran: false })
  }),
)

// OPENCODE_PTY_BIN pointing at a script that records it was run.
const ptyBin = Effect.fnUntraced(function* (root: string) {
  const marker = path.join(root, "pty-bin-ran")
  const script = path.join(root, "pty-bin")
  yield* Effect.promise(() => fs.writeFile(script, `#!/bin/sh\nprintf ran > ${JSON.stringify(marker)}\n`, { mode: 0o755 }))
  const previous = process.env.OPENCODE_PTY_BIN
  yield* Effect.acquireRelease(
    Effect.sync(() => {
      process.env.OPENCODE_PTY_BIN = script
    }),
    () =>
      Effect.sync(() => {
        if (previous === undefined) delete process.env.OPENCODE_PTY_BIN
        else process.env.OPENCODE_PTY_BIN = previous
      }),
  )
  return marker
})

it.live("control: upstream persistent terminals run OPENCODE_PTY_BIN", () =>
  Effect.gen(function* () {
    const { root, global, project } = yield* workspace()
    const marker = yield* ptyBin(root)
    const handler = yield* boot(global, [])
    const sessionID = yield* session(handler, project)
    yield* call(handler, "POST", `/api/experimental/session/${sessionID}/terminal`, project, {
      args: [],
      title: "t",
      env: {},
    })
    expect(yield* appears(marker)).toBe(true)
  }),
)

it.live("persistent terminals are unavailable and never run OPENCODE_PTY_BIN, even with the routes open", () =>
  Effect.gen(function* () {
    const { root, global, project } = yield* workspace()
    const marker = yield* ptyBin(root)
    // Re-open every route, so the request reaches the replaced service itself.
    const handler = yield* boot(global, [
      ...ManagedProfile.replacements(),
      RoutePolicy.node.replace(RoutePolicy.layer),
    ])
    const sessionID = yield* session(handler, project)
    const create = yield* call(handler, "POST", `/api/experimental/session/${sessionID}/terminal`, project, {
      args: [],
      title: "t",
      env: {},
    })
    expect(create.ok).toBe(false)
    const list = yield* call(handler, "GET", `/api/experimental/session/${sessionID}/terminal`, project)
    expect(list.status).toBe(200)
    expect(yield* Effect.promise(() => list.json())).toEqual({ data: [] })
    yield* Effect.sleep("1 second")
    expect(yield* exists(marker)).toBe(false)
  }),
)

// The managed profile serves its connector flow's label (T3b): the banner's session part.
it.live("the managed profile reports its connector flow's label", () =>
  Effect.gen(function* () {
    const { global } = yield* workspace()
    const flow = ManagedFlow.make({ gateway: "SECRET", connectors: { jira: "CONFIDENTIAL" } })
    const handler = yield* boot(global, ManagedProfile.replacements({ flow }))
    const marking = () =>
      Effect.promise(() => handler(new Request("http://badger.local/api/marking")).then((r) => r.json() as Promise<{ label: unknown }>))
    expect((yield* marking()).label).toBeNull()
    flow.call({ server: "jira", tool: "search" })
    expect((yield* marking()).label).toBe("CONFIDENTIAL")
  }).pipe(Effect.scoped),
)
