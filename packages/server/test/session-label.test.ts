import { expect } from "bun:test"
import { Effect } from "effect"
import { it } from "../../core/test/lib/effect"
import { ServerFetch } from "../src/fetch"
import { ManagedFlow } from "../src/managed-flow"
import { SessionLabel } from "../src/session-label"

// The session label (T3b): a managed server reports its workspace label beside its deployment
// marking, and announces each raise on the event stream, so the app's banner shows the join of the
// two and reads it again when it rises.

const options = {
  app: { version: "test-version" },
  database: { path: ":memory:" },
  config: { project: false },
  models: { fetch: false },
  fs: { filewatcher: false },
  password: "secret",
} as const

const auth = { authorization: `Basic ${btoa("opencode:secret")}` }

const policy = { gateway: "SECRET", connectors: { jira: "CONFIDENTIAL", wiki: "SECRET" } }

const marking = (handler: (request: Request) => Promise<Response>) =>
  Effect.promise(async () => (await handler(new Request("http://opencode.local/api/marking", { headers: auth }))).json())

/** Reads the server's event stream frame by frame: `next(type)` is the data of the next event of that type. */
function events(response: Response) {
  const reader = response.body!.getReader()
  const decoder = new TextDecoder()
  let pending = ""
  return {
    async next(type: string): Promise<unknown> {
      while (true) {
        const boundary = pending.indexOf("\n\n")
        if (boundary !== -1) {
          const data = pending
            .slice(0, boundary)
            .split("\n")
            .find((line) => line.startsWith("data: "))
            ?.slice(6)
          pending = pending.slice(boundary + 2)
          const event = data ? JSON.parse(data) : undefined
          if (event?.type === type) return event.data
          continue
        }
        const chunk = await reader.read()
        if (chunk.done) throw new Error(`event stream closed before ${type}`)
        pending += decoder.decode(chunk.value, { stream: true })
      }
    },
    close: () => reader.cancel().catch(() => {}),
  }
}

it.live("a server without a connector flow reports no session label", () =>
  Effect.gen(function* () {
    const handler = yield* ServerFetch.make(options)
    expect((yield* marking(handler)).label).toBeNull()
  }).pipe(Effect.scoped),
)

it.live("a managed server reports its label once it rises above the lowest, as a banner", () =>
  Effect.gen(function* () {
    const flow = ManagedFlow.make(policy)
    const handler = yield* ServerFetch.make(options, { overrides: [SessionLabel.node.replace(SessionLabel.fromFlow(flow))] })
    // At the lowest label there is nothing to add to the deployment's marking.
    expect((yield* marking(handler)).label).toBeNull()
    expect(flow.call({ server: "jira", tool: "search" })).toBeUndefined()
    expect((yield* marking(handler)).label).toBe("CONFIDENTIAL")
    expect(flow.call({ server: "wiki", tool: "get_page" })).toBeUndefined()
    expect((yield* marking(handler)).label).toBe("SECRET")
  }).pipe(Effect.scoped),
)

it.live("each raise is announced on the event stream with the new label", () =>
  Effect.gen(function* () {
    const flow = ManagedFlow.make(policy)
    const handler = yield* ServerFetch.make(options, { overrides: [SessionLabel.node.replace(SessionLabel.fromFlow(flow))] })
    const response = yield* Effect.promise(() => handler(new Request("http://opencode.local/api/event", { headers: auth })))
    expect(response.status).toBe(200)
    const stream = events(response)
    // The first frame is sent once the stream is subscribed, so a raise after it is on the stream.
    yield* Effect.promise(() => stream.next("server.connected"))
    flow.call({ server: "jira", tool: "search" })
    expect(yield* Effect.promise(() => stream.next("marking.label.raised"))).toEqual({ label: "CONFIDENTIAL" })
    // A call that does not raise it announces nothing: the next event is the next raise.
    flow.call({ server: "jira", tool: "search" })
    flow.call({ server: "wiki", tool: "get_page" })
    expect(yield* Effect.promise(() => stream.next("marking.label.raised"))).toEqual({ label: "SECRET" })
    yield* Effect.promise(() => stream.close())
  }).pipe(Effect.scoped),
)
