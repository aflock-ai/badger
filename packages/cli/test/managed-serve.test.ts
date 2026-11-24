import { NodeFileSystem } from "@effect/platform-node"
import { Global } from "@opencode/util/global"
import { expect, test } from "bun:test"
import { Effect } from "effect"
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { ManagedServe } from "../src/managed-serve"
import { ServerConnection } from "../src/services/server-connection"

async function temp() {
  return fs.mkdtemp(path.join(os.tmpdir(), "badger-serve-"))
}

const issuer = "https://idp.example.invalid/realms/badger"
const audience = "badger-workspace"
const owner = "user-1234"
const edge = generateKeyPairSync("ec", { namedCurve: "P-256" })
const other = generateKeyPairSync("ec", { namedCurve: "P-256" })
const jwk = (key: KeyObject, kid: string) => ({ ...key.export({ format: "jwk" }), kid, alg: "ES256", use: "sig" })
const now = () => Math.floor(Date.now() / 1000)

/** A token as the identity provider signs it; `override` changes claims or the header. */
function token(key: KeyObject, claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}) {
  const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url")
  const signing = `${part({ alg: "ES256", kid: "edge-1", typ: "JWT", ...header })}.${part({
    iss: issuer,
    aud: [audience, "account"],
    sub: owner,
    exp: now() + 300,
    nbf: now() - 10,
    ...claims,
  })}`
  return `${signing}.${sign("sha256", Buffer.from(signing), { key, dsaEncoding: "ieee-p1363" }).toString("base64url")}`
}

async function contract(keys: unknown[] = [jwk(edge.publicKey, "edge-1")]) {
  const dir = await temp()
  const file = path.join(dir, "jwks.json")
  await fs.writeFile(file, JSON.stringify({ keys }))
  const env: NodeJS.ProcessEnv = {
    BADGER_SERVE_JWKS_FILE: file,
    BADGER_SERVE_ISSUER: issuer,
    BADGER_SERVE_AUDIENCE: audience,
    BADGER_SERVE_SUBJECT: owner,
  }
  return { dir, env }
}

const bearer = (value: string) => ({ authorization: `Bearer ${value}` })
const request = (headers: Record<string, string> = {}) => new Request("http://workspace.test/api/info", { headers })

test("only a current token for the owner, signed by a configured key, is authorized", async () => {
  const { dir, env } = await contract()
  try {
    const authorized = ManagedServe.authorizer(ManagedServe.settings(env))
    const exp = now() + 300
    // A good token is accepted until its expiry plus the 30 seconds of skew.
    expect(authorized(request(bearer(token(edge.privateKey, { exp }))))).toBe((exp + 30) * 1000)
    expect(authorized(request(bearer(token(edge.privateKey, { aud: audience }))))).toBeNumber()
    for (const [name, value] of [
      ["another key", token(other.privateKey)],
      ["another key under another kid", token(other.privateKey, {}, { kid: "edge-2" })],
      ["wrong audience", token(edge.privateKey, { aud: "account" })],
      ["wrong issuer", token(edge.privateKey, { iss: "https://idp.example.invalid/realms/other" })],
      ["another user", token(edge.privateKey, { sub: "user-5678" })],
      ["expired", token(edge.privateKey, { exp: now() - 120 })],
      ["no expiry", token(edge.privateKey, { exp: undefined })],
      ["not yet valid", token(edge.privateKey, { nbf: now() + 600 })],
      ["another algorithm", token(edge.privateKey, {}, { alg: "RS256" })],
      ["alg none", token(edge.privateKey, {}, { alg: "none" }).split(".").slice(0, 2).join(".") + "."],
      ["critical header", token(edge.privateKey, {}, { crit: ["x"] })],
      [
        "tampered claims",
        (() => {
          const [h, , sig] = token(edge.privateKey).split(".")
          const forged = Buffer.from(
            JSON.stringify({ iss: issuer, aud: audience, sub: owner, exp: now() + 9999 }),
          ).toString("base64url")
          return `${h}.${forged}.${sig}`
        })(),
      ],
      ["garbage", "a.b.c"],
    ] as const)
      expect([name, authorized(request(bearer(value)))]).toEqual([name, undefined])
    expect(authorized(request())).toBeUndefined()
    expect(authorized(request({ authorization: "Basic YmFkZ2VyOng=" }))).toBeUndefined()
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
})

// The workspace's own account can read everything the listener is configured with, so that must be
// public: a key file with private material is refused, and the contract is required in full.
test("the workspace holds nothing that mints a token", async () => {
  for (const keys of [[edge.privateKey.export({ format: "jwk" })], [{ ...jwk(edge.publicKey, "edge-1"), d: "x" }]]) {
    const { dir, env } = await contract(keys)
    try {
      expect(() => ManagedServe.settings(env)).toThrow("private key material")
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  }
  const { dir, env } = await contract()
  try {
    const settings = ManagedServe.settings({ ...env })
    for (const entry of settings.keys.values()) expect(entry.key.type).toBe("public")
    for (const name of [
      "BADGER_SERVE_JWKS_FILE",
      "BADGER_SERVE_ISSUER",
      "BADGER_SERVE_AUDIENCE",
      "BADGER_SERVE_SUBJECT",
    ])
      expect(() => ManagedServe.settings({ ...env, [name]: undefined })).toThrow("serve in this build needs")
    expect(() => ManagedServe.settings({ ...env, BADGER_SERVE_JWKS_FILE: path.join(dir, "absent") })).toThrow(
      "could not read",
    )
    // A key without kid or alg, or of the wrong type for its alg, is not a signing key.
    const { dir: d2, env: e2 } = await contract([{ ...jwk(edge.publicKey, "edge-1"), alg: "RS256" }])
    expect(() => ManagedServe.settings(e2)).toThrow("no usable signing key")
    await fs.rm(d2, { recursive: true, force: true })
    // The old password variables are removed, so no tool inherits them.
    const old: NodeJS.ProcessEnv = { ...env, OPENCODE_SERVER_PASSWORD: "x", OPENCODE_PASSWORD: "y" }
    ManagedServe.settings(old)
    expect(old.OPENCODE_SERVER_PASSWORD).toBeUndefined()
    expect(old.OPENCODE_PASSWORD).toBeUndefined()
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
})

test("--service, --stdio and --cors are refused", () => {
  expect(ManagedServe.refusedFlags({ service: false, stdio: false, cors: [] })).toBe(false)
  expect(ManagedServe.refusedFlags({ service: true, stdio: false, cors: [] })).toBe(true)
  expect(ManagedServe.refusedFlags({ service: false, stdio: true, cors: [] })).toBe(true)
  expect(ManagedServe.refusedFlags({ service: false, stdio: false, cors: ["https://elsewhere.test"] })).toBe(true)
})

test("the listener asks for credentials first, forwards the API without them, and serves the UI", async () => {
  const seen: Request[] = []
  const handle = ManagedServe.handler({
    authorized: (request) =>
      request.headers.get("authorization") === "Bearer good" ? Date.now() + 3_600_000 : undefined,
    server: {
      url: "http://in-process.invalid/",
      fetch: async (request) => (seen.push(request), new Response("api")),
    },
    files: { "index.html": "<html>", "assets/app.js": "js" },
  })
  const call = (pathname: string, init: RequestInit = {}, authorization = "Bearer good") =>
    handle(
      new Request("http://workspace.test" + pathname, { ...init, headers: { authorization, ...(init.headers ?? {}) } }),
    )

  for (const pathname of ["/", "/healthz", "/api/info", "/assets/app.js", "/openapi.json"]) {
    const response = await call(pathname, {}, "Bearer bad")
    expect(response.status).toBe(401)
  }
  expect(seen).toHaveLength(0)

  expect(await (await call("/healthz")).text()).toBe("ok\n")

  const posted = await call("/api/session?x=1", {
    method: "POST",
    body: "{}",
    headers: { "content-type": "application/json" },
  })
  expect(await posted.text()).toBe("api")
  expect(seen[0]!.url).toBe("http://in-process.invalid/api/session?x=1")
  expect(seen[0]!.method).toBe("POST")
  expect(seen[0]!.headers.get("authorization")).toBeNull()
  expect(seen[0]!.headers.get("content-type")).toBe("application/json")
  expect(await seen[0]!.text()).toBe("{}")

  for (const pathname of ["/api", "/auth/x", "/openapi.json"]) await call(pathname)
  expect(seen.map((request) => new URL(request.url).pathname)).toEqual([
    "/api/session",
    "/api",
    "/auth/x",
    "/openapi.json",
  ])

  const asset = await call("/assets/app.js")
  expect(await asset.text()).toBe("js")
  expect(asset.headers.get("x-content-type-options")).toBe("nosniff")
  const route = await call("/session/abc")
  expect(await route.text()).toBe("<html>")
  expect(route.headers.get("cache-control")).toBe("no-cache")
  expect(route.headers.get("content-security-policy")).toStartWith("default-src 'self'")
  expect(asset.headers.get("content-security-policy")).toStartWith("default-src 'self'")
  expect((await call("/assets/app.js", { method: "POST", body: "x" })).status).toBe(405)
})

// The UI's live updates are a server-sent event stream on /api/event: the same token, streamed
// through as it arrives. Terminals, the only WebSocket path, stay refused in this build.
test("the event stream needs the token and streams through the listener", async () => {
  const handle = ManagedServe.handler({
    authorized: (request) =>
      request.headers.get("authorization") === "Bearer good" ? Date.now() + 3_600_000 : undefined,
    server: {
      url: "http://in-process.invalid/",
      fetch: async () => {
        const body = new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("data: one\n\n"))
            controller.enqueue(new TextEncoder().encode("data: two\n\n"))
            controller.close()
          },
        })
        return new Response(body, { headers: { "content-type": "text/event-stream" } })
      },
    },
    files: {},
  })
  const open = (authorization: string) =>
    handle(new Request("http://workspace.test/api/event", { headers: { authorization, accept: "text/event-stream" } }))
  expect((await open("Bearer bad")).status).toBe(401)
  const stream = await open("Bearer good")
  expect(stream.headers.get("content-type")).toBe("text/event-stream")
  expect(await stream.text()).toBe("data: one\n\ndata: two\n\n")
})

// A long answer lasts only as long as the token that opened it: the event stream is cut when the
// token expires, and opening it again needs a token that is still good.
test("an event stream is closed when its token expires, and reopening needs a good token", async () => {
  const { dir, env } = await contract()
  try {
    const authorized = ManagedServe.authorizer(ManagedServe.settings(env))
    let opened = 0
    const handle = ManagedServe.handler({
      authorized,
      server: {
        url: "http://in-process.invalid/",
        fetch: async (request) => {
          opened++
          let timer: ReturnType<typeof setInterval> | undefined
          const body = new ReadableStream({
            start(controller) {
              timer = setInterval(() => controller.enqueue(new TextEncoder().encode("data: tick\n\n")), 50)
              request.signal.addEventListener("abort", () => clearInterval(timer))
            },
            cancel() {
              clearInterval(timer)
            },
          })
          return new Response(body, { headers: { "content-type": "text/event-stream" } })
        },
      },
      files: {},
    })
    const open = (value: string) =>
      handle(new Request("http://workspace.test/api/event", { headers: { authorization: `Bearer ${value}` } }))
    // Accepted for about two more seconds: exp is 28 s ago, within the 30 s of skew.
    const short = token(edge.privateKey, { exp: now() - 28 })
    const started = Date.now()
    const stream = await open(short)
    expect(stream.status).toBe(200)
    const text = await stream.text() // ends only when the listener cuts it
    const lasted = Date.now() - started
    expect(text).toContain("data: tick")
    expect(lasted).toBeGreaterThan(500)
    expect(lasted).toBeLessThan(5_000)
    // The same token again is refused and reaches nothing; a fresh one opens the stream.
    expect((await open(short)).status).toBe(401)
    expect(opened).toBe(1)
    const fresh = await open(token(edge.privateKey))
    expect(fresh.status).toBe(200)
    await fresh.body?.cancel()
    expect(opened).toBe(2)
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
}, 30_000)

// The listener is in front of the same in-process server the managed CLI runs, so the managed
// profile's route refusals hold through it: a credential route answers 404 as it does in-process.
test("the managed profile's refused routes stay refused through the listener", async () => {
  const root = await temp()
  try {
    const layer = Global.layerWith({
      config: path.join(root, "config"),
      state: path.join(root, "state"),
      data: path.join(root, "data"),
    })
    const statuses = await Effect.runPromise(
      Effect.gen(function* () {
        const resolved = yield* ServerConnection.resolve({ managed: true })
        const handle = ManagedServe.handler({
          authorized: () => Date.now() + 3_600_000,
          server: { url: resolved.endpoint.url, fetch: resolved.fetch! },
          files: {},
        })
        const status = (method: string, pathname: string) =>
          Effect.promise(() =>
            handle(
              new Request("http://workspace.test" + pathname, {
                method,
                headers: { "content-type": "application/json" },
                body: method === "GET" ? undefined : "{}",
              }),
            ).then((response) => response.status),
          )
        return {
          info: yield* status("GET", "/api/info"),
          credential: yield* status("GET", "/api/credential"),
          shell: yield* status("POST", "/api/shell"),
          pty: yield* status("POST", "/api/pty"),
        }
      }).pipe(Effect.provide(layer), Effect.provide(NodeFileSystem.layer), Effect.scoped),
    )
    expect(statuses).toEqual({ info: 200, credential: 404, shell: 404, pty: 404 })
  } finally {
    await fs.rm(root, { recursive: true, force: true })
  }
}, 30_000)

// The raise record (GET /managed/raise): the latest connector call refused at the raise ceiling, for
// the UI's "continue in a copy" and "cancel". It is the listener's own JSON, behind the same token,
// and no /managed path ever reaches the in-process server or falls through to the web UI.
test("the raise record is served as JSON behind the token, and /managed never falls through", async () => {
  let pending: { sessionID?: string; server: string; tool: string; level: string } | undefined
  const seen: Request[] = []
  const handle = ManagedServe.handler({
    authorized: (request) =>
      request.headers.get("authorization") === "Bearer good" ? Date.now() + 3_600_000 : undefined,
    server: { url: "http://in-process.invalid/", fetch: async (request) => (seen.push(request), new Response("api")) },
    files: { "index.html": "<html>" },
    raise: () => pending,
  })
  const call = (pathname: string, init: RequestInit = {}, authorization = "Bearer good") =>
    handle(new Request("http://workspace.test" + pathname, { ...init, headers: { authorization } }))
  const json = async (response: Response) => {
    expect(response.headers.get("content-type")).toStartWith("application/json")
    expect(response.headers.get("cache-control")).toBe("no-store")
    return response.json()
  }

  pending = { sessionID: "ses_a", server: "jira", tool: "jira_search", level: "CONFIDENTIAL" }
  expect((await call("/managed/raise", {}, "Bearer bad")).status).toBe(401)
  expect((await call("/managed/raise", {}, "")).status).toBe(401)

  const found = await call("/managed/raise")
  expect(found.status).toBe(200)
  expect(await json(found)).toEqual({ raise: pending })
  // Asked for its own session, the record is found; asked for another, it is not.
  expect(await json(await call("/managed/raise?session=ses_a"))).toEqual({ raise: pending })
  const other = await call("/managed/raise?session=ses_b")
  expect(other.status).toBe(404)
  expect(await json(other)).toEqual({ error: "no raise is pending" })

  pending = undefined
  const none = await call("/managed/raise")
  expect(none.status).toBe(404)
  expect(await json(none)).toEqual({ error: "no raise is pending" })

  const method = await call("/managed/raise", { method: "POST", body: "{}" })
  expect(method.status).toBe(405)
  expect(await json(method)).toEqual({ error: "method not allowed" })

  for (const pathname of ["/managed", "/managed/", "/managed/unknown", "/managed/raise/x", "/managed/../managed/x"]) {
    const response = await call(pathname)
    expect(response.status).toBe(404)
    expect(await json(response)).toEqual({ error: "not found" })
  }
  expect(seen).toHaveLength(0)
})

test("without a connector flow, the raise record is absent, not the web UI", async () => {
  const handle = ManagedServe.handler({
    authorized: () => Date.now() + 3_600_000,
    server: { url: "http://in-process.invalid/", fetch: async () => new Response("api") },
    files: { "index.html": "<html>" },
  })
  const response = await handle(
    new Request("http://workspace.test/managed/raise", { headers: { authorization: "Bearer x" } }),
  )
  expect(response.status).toBe(404)
  expect(await response.json()).toEqual({ error: "no raise is pending" })
})
