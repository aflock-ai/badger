import { Service, type Endpoint, type EnsureOptions } from "@opencode/client/effect/service"
import { ClientError, isUnauthorizedError, OpenCode } from "@opencode/client/promise"
import { OPENCODE_ARTIFACT, OPENCODE_CHANNEL, OPENCODE_VERSION } from "../version"
import type { Plugin } from "@opencode/plugin/effect/plugin"
import { EmbeddedHost } from "@opencode/sdk/host"
import { ManagedProfile } from "@opencode/server/managed"
import { ManagedLimits } from "@opencode/server/managed-limits"
import { ManagedModels } from "@opencode/server/managed-models"
import type { ManagedFlow } from "@opencode/server/managed-flow"
import type { LayerNode } from "@opencode/util/effect/layer-node"
import { Global } from "@opencode/util/global"
import path from "node:path"
import { Effect, Redacted } from "effect"
import { databasePath } from "../database-path"
import { Managed } from "../managed"
import { ManagedConnectorProfile } from "../managed-connectors"
import { Env } from "../env"
import { ServiceConfig } from "./service-config"
import { Standalone } from "./standalone"

export type Args = {
  readonly server?: string
  readonly standalone?: boolean
  /** Defaults to the compiled build; set only by tests. */
  readonly managed?: boolean
  /** Plugins compiled into the binary, registered on a managed build's in-process server. */
  readonly plugins?: ReadonlyArray<Plugin>
  readonly mismatch?: "replace" | "ignore" | "error"
  readonly onStart?: EnsureOptions["onStart"]
}

export type Resolved = {
  readonly endpoint: Endpoint
  readonly service?: ReturnType<typeof managedService>
  /** Set for an in-process server: every request goes through it, and `endpoint.url` is only a base URL. */
  readonly fetch?: typeof globalThis.fetch
  /** The managed build's connector flow: the latest call refused at the raise ceiling, if any. */
  readonly raise?: () => ManagedFlow.Raise | undefined
  /** The managed build's limits for this run, and whether the broker served them or they are the compiled ones. */
  readonly limits?: { readonly source: "broker" | "compiled"; readonly values: ManagedLimits.Limits }
  /** The managed build's models for this run: the gateway's allowlist, or none for the compiled one. */
  readonly models?: { readonly served?: ManagedModels.Served }
}

/** A client for a resolved server: over its fetch when it is in-process, else its URL. */
export function client(server: Resolved) {
  return OpenCode.make({ baseUrl: server.endpoint.url, headers: Service.headers(server.endpoint), fetch: server.fetch })
}

const resolved = (value: Resolved) => value

/**
 * Runs the server inside this process and reaches it through a fetch function: nothing listens,
 * there is no password to steal, and no background service is started or registered. The
 * replacements are the runtime profile, applied after the standard server set.
 */
export const inProcess = Effect.fn("cli.server-connection.in-process")(function* (input: {
  readonly overrides: LayerNode.Replacements
  /** Plugins compiled into this binary, registered on the host before it serves requests. */
  readonly plugins?: ReadonlyArray<Plugin>
}) {
  const global = yield* Global.Service
  const host = yield* EmbeddedHost.create(
    {
      app: { name: OPENCODE_ARTIFACT, version: OPENCODE_VERSION, channel: OPENCODE_CHANNEL },
      database: { path: databasePath(global.data) },
      plugins: input.plugins,
    },
    { overrides: input.overrides },
  )
  yield* Effect.addFinalizer(() => Effect.promise(() => host.close()))
  return resolved({ endpoint: { url: "http://in-process.invalid/" }, fetch: host.fetch })
})

export const resolve = Effect.fn("cli.server-connection.resolve")(function* (args: Args = {}) {
  if (args.managed ?? Managed.enabled) {
    yield* Managed.serverFlags(args, true)
    const admitted = yield* ManagedConnectorProfile.load()
    const flow = admitted && ManagedConnectorProfile.flow(admitted, path.join(Global.Path.state, "connector-flow.jsonl"))
    // The administrator's limits for this workspace's owner and the profile's models, once, at start; without
    // them the compiled ones. Neither takes the gateway's model slot, so they are read side by side.
    const socket = Managed.gatewaySocket ?? ManagedProfile.gatewaySocket
    const [served, allowed] = yield* Effect.promise(() => Promise.all([ManagedLimits.read(socket), ManagedModels.read(socket)]))
    const limits = { source: served ? ("broker" as const) : ("compiled" as const), values: ManagedLimits.resolve(ManagedProfile.limits, served) }
    const server = yield* inProcess({
      overrides: ManagedProfile.replacements({
        gatewaySocket: Managed.gatewaySocket,
        connectors: admitted?.connectors,
        flow,
        limits: served,
        models: allowed,
      }),
      plugins: ManagedConnectorProfile.plugins(admitted, flow, args.plugins),
    })
    return resolved({ ...server, limits, models: { served: allowed }, ...(flow ? { raise: () => flow.pendingRaise() } : {}) })
  }
  if (args.server !== undefined && args.standalone)
    return yield* Effect.fail(new Error("--server and --standalone cannot be combined"))
  if (args.server !== undefined) {
    const password = yield* Env.password
    const endpoint = {
      url: args.server,
      auth: password ? { type: "basic" as const, username: "opencode", password: Redacted.value(password) } : undefined,
    } satisfies Endpoint
    const client = OpenCode.make({ baseUrl: endpoint.url, headers: Service.headers(endpoint) })
    const health = yield* Effect.tryPromise({
      try: () => client.server.info({ signal: AbortSignal.timeout(5_000) }),
      catch: (cause) => connectError(endpoint, cause),
    })
    if (health.version !== OPENCODE_VERSION)
      process.stderr.write(
        `Warning: Server at ${endpoint.url} has version ${health.version}; this client is ${OPENCODE_VERSION}. Continuing anyway.\n`,
      )
    return resolved({ endpoint })
  }
  if (args.standalone || (yield* ServiceConfig.read()).disabled === true) {
    return resolved({ endpoint: yield* Standalone.start() })
  }

  const mismatch = args.mismatch ?? "ignore"
  const options = yield* ServiceConfig.options({ checkVersion: mismatch !== "ignore" })
  return resolved({
    endpoint: yield* resolveManaged({ ...options, onStart: args.onStart }, mismatch),
    service: managedService(options),
  })
})

function managedService(options: EnsureOptions) {
  const reconnectOptions = { ...options, version: undefined }
  return {
    reconnect: () => Service.ensure(reconnectOptions),
    restart: () =>
      Effect.gen(function* () {
        yield* Service.stop({ file: options.file, pty: "handoff" })
        yield* Service.ensure(reconnectOptions)
      }),
  }
}

export const shutdownPersistentPty = Effect.fn("cli.server-connection.shutdown-persistent-pty")(function* (
  options: EnsureOptions,
) {
  const endpoint = yield* Service.discover({ ...options, version: undefined })
  if (!endpoint) return
  const client = OpenCode.make({ baseUrl: endpoint.url, headers: Service.headers(endpoint) })
  yield* Effect.tryPromise(() => client.experimental.persistentPty.shutdown())
})

const resolveManaged = Effect.fnUntraced(function* (options: EnsureOptions, mismatch: NonNullable<Args["mismatch"]>) {
  if (mismatch === "replace") return yield* Service.ensure(options)
  if (mismatch === "ignore") return yield* Service.ensure({ ...options, version: undefined })

  const compatible = yield* Service.discover(options)
  if (compatible !== undefined) return compatible
  const existing = yield* Service.discover({ ...options, version: undefined })
  if (existing !== undefined)
    return yield* Effect.fail(new Error("Background server version does not match this client"))
  return yield* Service.ensure(options)
})

function connectError(endpoint: Endpoint, cause: unknown) {
  if (isUnauthorizedError(cause)) {
    return new Error(
      endpoint.auth === undefined
        ? `Server at ${endpoint.url} requires a password; set OPENCODE_PASSWORD`
        : `Server at ${endpoint.url} rejected the password`,
      { cause },
    )
  }
  if (cause instanceof ClientError && cause.reason === "Transport")
    return new Error(`Could not reach server at ${endpoint.url}`, { cause })
  return new Error(`Server at ${endpoint.url} did not provide a compatible V2 health response`, { cause })
}

export * as ServerConnection from "./server-connection"
