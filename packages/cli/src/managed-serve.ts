export * as ManagedServe from "./managed-serve"

import { constants, createPublicKey, verify, type KeyObject } from "node:crypto"
import { readFileSync } from "node:fs"
import { Effect } from "effect"
import { FSUtil } from "@opencode/util/fs-util"
import { load, type AssetMap } from "./app-assets"
import type { ManagedFlow } from "@opencode/server/managed-flow"
import { ManagedModels } from "@opencode/server/managed-models"
import { Managed, Refused } from "./managed"
import { ServerConnection } from "./services/server-connection"
import { WebUi } from "./services/web-ui"

/**
 * `serve` in the managed build, for a hosted workspace behind an authenticating edge
 * (testifysec/HARDENING.md, section 11). It reuses the in-process server the managed CLI already
 * runs (ManagedProfile replacements, RoutePolicy refusals, the gateway-socket-only HTTP client) and
 * puts one listener in front of it:
 *
 * - The listener binds only the address given with --hostname and --port; there is no default.
 * - Every request, UI or API, must carry `Authorization: Bearer <JWT>`: the identity provider's
 *   token for the signed-in user, which the edge forwards. It is checked against public keys only
 *   (a JWKS file), so nothing the workspace's own account can read mints a token: its issuer,
 *   audience and subject (the workspace's owner) must be the configured ones and it must be
 *   current. The agent's shell never sees the browser's requests, so it holds no token.
 * - There is no CORS, pairing, tunnel, service registration or terminal.
 */

/** The listener's settings, from the environment: the edge contract. */
export interface Settings {
  readonly keys: ReadonlyMap<string, { readonly alg: string; readonly key: KeyObject }>
  readonly issuer: string
  readonly audience: string
  readonly subject: string
}

/** Signature algorithms a key may use, and how node:crypto verifies each. */
const algorithms: Record<string, { readonly kty: string; readonly hash: string; readonly ieee?: boolean }> = {
  RS256: { kty: "RSA", hash: "sha256" },
  PS256: { kty: "RSA", hash: "sha256" },
  ES256: { kty: "EC", hash: "sha256", ieee: true },
  ES384: { kty: "EC", hash: "sha384", ieee: true },
}

/** JWK members that only a private key has. A key file holding one is refused outright. */
const privateMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]

/** Clock skew allowed on exp and nbf, in seconds. */
const skew = 30

/** Reads the edge contract once: BADGER_SERVE_JWKS_FILE, _ISSUER, _AUDIENCE and _SUBJECT. */
export function settings(env: NodeJS.ProcessEnv = process.env): Settings {
  delete env.OPENCODE_SERVER_PASSWORD
  delete env.OPENCODE_PASSWORD
  const file = env.BADGER_SERVE_JWKS_FILE
  const issuer = env.BADGER_SERVE_ISSUER
  const audience = env.BADGER_SERVE_AUDIENCE
  const subject = env.BADGER_SERVE_SUBJECT
  if (!file || !issuer || !audience || !subject)
    throw new Refused(
      "serve in this build needs BADGER_SERVE_JWKS_FILE, BADGER_SERVE_ISSUER, BADGER_SERVE_AUDIENCE and BADGER_SERVE_SUBJECT",
    )
  let jwks: { keys?: unknown }
  try {
    jwks = JSON.parse(readFileSync(file, "utf8"))
  } catch {
    throw new Refused("serve in this build could not read BADGER_SERVE_JWKS_FILE")
  }
  const keys = new Map<string, { alg: string; key: KeyObject }>()
  for (const jwk of Array.isArray(jwks.keys) ? jwks.keys : []) {
    if (!jwk || typeof jwk !== "object") throw new Refused("BADGER_SERVE_JWKS_FILE holds a key that is not an object")
    const value = jwk as Record<string, unknown>
    if (privateMembers.some((member) => Object.hasOwn(value, member)))
      throw new Refused("BADGER_SERVE_JWKS_FILE holds private key material; it must hold public keys only")
    if (value.use !== undefined && value.use !== "sig") continue
    const alg = typeof value.alg === "string" ? value.alg : undefined
    if (typeof value.kid !== "string" || !alg || algorithms[alg]?.kty !== value.kty) continue
    try {
      keys.set(value.kid, { alg, key: createPublicKey({ key: value as never, format: "jwk" }) })
    } catch {
      throw new Refused(`BADGER_SERVE_JWKS_FILE key ${value.kid} cannot be read`)
    }
  }
  if (keys.size === 0)
    throw new Refused("BADGER_SERVE_JWKS_FILE holds no usable signing key (kid, alg and kty required)")
  return { keys, issuer, audience, subject }
}

const segment = /^[A-Za-z0-9_-]+$/

function decode(part: string) {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>
}

/**
 * The instant (milliseconds since the epoch) a request's token stops being accepted, when it carries
 * a current token for the workspace's owner, signed by a configured key with that key's algorithm;
 * undefined otherwise. Anything malformed is refused.
 */
export function authorizer(settings: Settings, now = () => Date.now() / 1000) {
  return (request: Request): number | undefined => {
    const header = request.headers.get("authorization") ?? ""
    if (!header.startsWith("Bearer ") || header.length > 16384) return undefined
    const parts = header.slice("Bearer ".length).split(".")
    if (parts.length !== 3 || !parts.every((part) => segment.test(part))) return undefined
    try {
      const head = decode(parts[0]!)
      const claims = decode(parts[1]!)
      const entry = typeof head.kid === "string" ? settings.keys.get(head.kid) : undefined
      if (!entry || head.alg !== entry.alg || head.crit !== undefined) return undefined
      const algorithm = algorithms[entry.alg]!
      const signed = verify(
        algorithm.hash,
        Buffer.from(`${parts[0]}.${parts[1]}`),
        entry.alg === "PS256"
          ? { key: entry.key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }
          : algorithm.ieee
            ? { key: entry.key, dsaEncoding: "ieee-p1363" }
            : entry.key,
        Buffer.from(parts[2]!, "base64url"),
      )
      if (!signed) return undefined
      const time = now()
      const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
      const ok =
        claims.iss === settings.issuer &&
        audience.includes(settings.audience) &&
        claims.sub === settings.subject &&
        typeof claims.exp === "number" &&
        claims.exp + skew > time &&
        (claims.nbf === undefined || (typeof claims.nbf === "number" && claims.nbf - skew <= time))
      return ok ? ((claims.exp as number) + skew) * 1000 : undefined
    } catch {
      return undefined
    }
  }
}

/** Paths the in-process server answers; everything else is the web UI. */
export function api(pathname: string) {
  return (
    pathname === "/api" || pathname.startsWith("/api/") || pathname.startsWith("/auth/") || pathname === "/openapi.json"
  )
}

/** A JSON answer from the listener itself; never cached. */
function json(status: number, value: unknown) {
  return new Response(JSON.stringify(value) + "\n", {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff" },
  })
}

/**
 * The listener's own /managed routes. Only GET /managed/raise exists: the latest connector call
 * refused at the raise ceiling (`{"raise":{sessionID?,server,tool,level}}`), for the UI's "continue
 * in a copy" or "cancel"; `?session=<id>` asks for that session's. No raise, or none for that
 * session, is a 404. Every other /managed path is a JSON 404: none reaches the in-process server or
 * the web UI.
 */
function managed(url: URL, method: string, raise?: () => ManagedFlow.Raise | undefined) {
  if (url.pathname !== "/managed/raise") return json(404, { error: "not found" })
  if (method !== "GET" && method !== "HEAD") return json(405, { error: "method not allowed" })
  const record = raise?.()
  const session = url.searchParams.get("session")
  if (!record || (session !== null && record.sessionID !== session)) return json(404, { error: "no raise is pending" })
  return json(200, { raise: record })
}

/**
 * The listener's request handler. API paths go to the in-process server without the edge's
 * credentials; /managed paths are the listener's own (managed); other GET and HEAD requests get a
 * web UI asset, or index.html for a client route.
 */
export function handler(input: {
  /** When the request's token stops being accepted (ms since the epoch), or undefined if it is not. */
  readonly authorized: (request: Request) => number | undefined
  readonly server: { readonly url: string; readonly fetch: (request: Request) => Promise<Response> }
  readonly files: AssetMap
  readonly now?: () => number
  /** The connector flow's pending raise (ManagedFlow pendingRaise); absent without connectors. */
  readonly raise?: () => ManagedFlow.Raise | undefined
}) {
  const now = input.now ?? Date.now
  return async (request: Request): Promise<Response> => {
    const until = input.authorized(request)
    if (until === undefined) return new Response("unauthorized\n", { status: 401 })
    const url = new URL(request.url)
    if (url.pathname === "/healthz") return new Response("ok\n")
    if (url.pathname === "/managed" || url.pathname.startsWith("/managed/"))
      return managed(url, request.method, input.raise)
    if (api(url.pathname)) {
      const headers = new Headers(request.headers)
      headers.delete("authorization")
      // A response outlives its request only as long as the token does: the event stream, or any
      // other long answer, is cut when the token expires, and the client must sign in again.
      const expiry = AbortSignal.timeout(Math.max(0, until - now()))
      const signal = AbortSignal.any([request.signal, expiry])
      const response = await input.server.fetch(
        new Request(new URL(url.pathname + url.search, input.server.url), {
          method: request.method,
          headers,
          body: request.method === "GET" || request.method === "HEAD" ? undefined : await request.arrayBuffer(),
          signal,
        }),
      )
      return response.body ? new Response(bounded(response.body, signal), response) : response
    }
    if (request.method !== "GET" && request.method !== "HEAD") return new Response(null, { status: 405 })
    const key = url.pathname.replace(/^\//, "")
    const name = input.files[key] !== undefined ? key : "index.html"
    const file = input.files[name]
    if (file === undefined) return new Response(null, { status: 404 })
    const html = name === "index.html"
    return new Response(typeof file === "string" ? file : new Uint8Array(file), {
      headers: {
        "content-type": FSUtil.mimeType(name),
        "cache-control": html ? "no-cache" : "public, max-age=3600",
        // The same policy the upstream web UI sends (services/web-ui.ts).
        "content-security-policy": html
          ? WebUi.cspForHtml(typeof file === "string" ? file : Buffer.from(file).toString())
          : WebUi.csp(),
        "x-content-type-options": "nosniff",
      },
    })
  }
}

/** The body, ended when the signal aborts: the source is cancelled and the stream closes. */
function bounded(body: ReadableStream<Uint8Array>, signal: AbortSignal) {
  const reader = body.getReader()
  return new ReadableStream<Uint8Array>({
    start(controller) {
      const stop = () => {
        void reader.cancel().catch(() => {})
        try {
          controller.close()
        } catch {}
      }
      if (signal.aborted) return stop()
      signal.addEventListener("abort", stop, { once: true })
    },
    async pull(controller) {
      try {
        const { done, value } = await reader.read()
        if (done) controller.close()
        else controller.enqueue(value)
      } catch {
        try {
          controller.close()
        } catch {}
      }
    },
    cancel() {
      void reader.cancel().catch(() => {})
    },
  })
}

/** The flags `serve` refuses in this build. */
export function refusedFlags(input: {
  readonly service: boolean
  readonly stdio: boolean
  readonly cors: readonly string[]
}) {
  return input.service || input.stdio || input.cors.length > 0
}

export const run = Effect.fnUntraced(function* (input: { readonly hostname?: string; readonly port?: number }) {
  if (!input.hostname || input.port === undefined)
    return yield* Effect.fail(new Refused("serve in this build needs an explicit --hostname and --port"))
  const contract = yield* Effect.try({ try: () => settings(), catch: (error) => error as Refused })
  yield* Managed.requireGateway
  const server = yield* ServerConnection.resolve({})
  const assets = yield* load()
  const listener = Bun.serve({
    hostname: input.hostname,
    port: input.port,
    idleTimeout: 0,
    fetch: handler({
      authorized: authorizer(contract),
      server: { url: server.endpoint.url, fetch: server.fetch! },
      files: assets.files,
      raise: server.raise,
    }),
  })
  yield* Effect.addFinalizer(() => Effect.promise(() => listener.stop(true)))
  if (server.limits) {
    const values = server.limits.values
    console.log(
      `limits source=${server.limits.source} steps=${values.steps} context=${values.context} output=${values.output} timeout=${values.timeoutMs / 1000}s`,
    )
  }
  if (server.models) console.log(ManagedModels.summary(server.models.served))
  console.log(`managed server listening on http://${input.hostname}:${listener.port}`)
  return yield* Effect.never
})
