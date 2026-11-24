import { expect } from "bun:test"
import { Effect } from "effect"
import { it } from "../../core/test/lib/effect"
import { ServerFetch } from "../src/fetch"
import { deployment, preset } from "@testifysec/marking"

// The scheme a server reports: its name, digest and deployment markings, lowest first.
const reported = (name: string) => {
  const s = preset(name)
  return { name: s.name, sha256: s.digest, levels: [...deployment(s).levels] }
}

const options = {
  app: { version: "test-version" },
  database: { path: ":memory:" },
  config: { project: false },
  models: { fetch: false },
  fs: { filewatcher: false },
  password: "secret",
} as const

const auth = { authorization: `Basic ${btoa("opencode:secret")}` }

// The deployment owns the marking: it comes from the server's environment, never from a request.
function withMarking(env: Record<string, string | undefined>) {
  return Effect.acquireRelease(
    Effect.sync(() => {
      const saved = {
        BADGER_DATA_MARKING: process.env.BADGER_DATA_MARKING,
        BADGER_ALLOWED_MARKINGS: process.env.BADGER_ALLOWED_MARKINGS,
        BADGER_MARKING_SCHEME: process.env.BADGER_MARKING_SCHEME,
      }
      for (const [key, value] of Object.entries(env)) {
        if (value === undefined) delete process.env[key]
        else process.env[key] = value
      }
      return saved
    }),
    (saved) =>
      Effect.sync(() => {
        for (const [key, value] of Object.entries(saved)) {
          if (value === undefined) delete process.env[key]
          else process.env[key] = value
        }
      }),
  )
}

const get = (handler: (request: Request) => Promise<Response>, headers: Record<string, string> = auth) =>
  Effect.promise(() => handler(new Request("http://opencode.local/api/marking", { headers })))

it.live("reports the deployment's data marking", () =>
  Effect.gen(function* () {
    yield* withMarking({ BADGER_DATA_MARKING: "CUI", BADGER_ALLOWED_MARKINGS: undefined })
    const handler = yield* ServerFetch.make(options)
    const response = yield* get(handler)
    expect(response.status).toBe(200)
    expect(yield* Effect.promise(() => response.json())).toEqual({
      marking: "CUI",
      classification: "UNCLASSIFIED",
      allowed: ["CUI"],
      scheme: reported("us-gov"),
      // No connector flow, so no workspace label (session-label.test.ts).
      label: null,
    })
  }).pipe(Effect.scoped),
)

it.live("reports no marking when the deployment sets none", () =>
  Effect.gen(function* () {
    yield* withMarking({ BADGER_DATA_MARKING: undefined, BADGER_ALLOWED_MARKINGS: undefined })
    const handler = yield* ServerFetch.make(options)
    const response = yield* get(handler)
    expect(response.status).toBe(200)
    expect(yield* Effect.promise(() => response.json())).toEqual({
      marking: null,
      classification: null,
      allowed: [],
      scheme: reported("us-gov"),
      // No connector flow, so no workspace label (session-label.test.ts).
      label: null,
    })
  }).pipe(Effect.scoped),
)

// The app orders and checks a server's marking with the scheme the server reports, so a deployment
// on another scheme is shown with its own markings, never refused for not being us-gov's.
it.live("reports the deployment's classification scheme with its markings", () =>
  Effect.gen(function* () {
    yield* withMarking({ BADGER_MARKING_SCHEME: "corporate", BADGER_DATA_MARKING: "CONFIDENTIAL", BADGER_ALLOWED_MARKINGS: undefined })
    const handler = yield* ServerFetch.make(options)
    const response = yield* get(handler)
    const body = yield* Effect.promise(() => response.json())
    expect(body.marking).toBe("CONFIDENTIAL")
    expect(body.scheme).toEqual(reported("corporate"))
    expect(body.scheme.levels).toContain("CONFIDENTIAL")
  }).pipe(Effect.scoped),
)

it.live("requires the server password", () =>
  Effect.gen(function* () {
    yield* withMarking({ BADGER_DATA_MARKING: "CUI", BADGER_ALLOWED_MARKINGS: undefined })
    const handler = yield* ServerFetch.make(options)
    expect((yield* get(handler, {})).status).toBe(401)
  }).pipe(Effect.scoped),
)
