export * as ManagedProfile from "./managed"

import { Effect, Layer, Stream } from "effect"
import { FetchHttpClient, HttpClient } from "effect/http"
import { Config } from "@opencode/core/config"
import { ConfigPluginSource } from "@opencode/core/config/plugin/source"
import { Mcp } from "@opencode/core/mcp/index"
import { ModelsDev } from "@opencode/core/models-dev"
import { PersistentPty } from "@opencode/core/persistent-pty"
import { Pty } from "@opencode/core/pty"
import { Document, type Info } from "@opencode/schema/config"
import { Model } from "@opencode/schema/model"
import { Provider } from "@opencode/schema/provider"
import { makeLocationNode } from "@opencode/util/effect/app-node"
import { httpClient } from "@opencode/util/effect/app-node-platform"
import type { LayerNode } from "@opencode/util/effect/layer-node"
import product from "@testifysec/branding/product.json"
import { ManagedConnectors } from "./managed-connectors"
import { ManagedFlow } from "./managed-flow"
import { ManagedLimits } from "./managed-limits"
import { ManagedModels } from "./managed-models"
import { RoutePolicy } from "./route-policy"
import { SessionLabel } from "./session-label"

/**
 * The managed (Badger) runtime profile: service replacements compiled into the managed build,
 * applied after the standard server set the way `ServerWorkerd.replacements` is. Each entry
 * removes an authority upstream would otherwise take from the filesystem, the network or the
 * environment, so nothing outside the binary can widen what a managed session may do beyond the
 * compiled limits. The runtime inputs besides the signed profile's connectors are four integers and
 * a list of model IDs with display names, both read once at start through the gateway (design L6,
 * as amended 2026-11-03: several models, from a profile that may be unsigned for now).
 *
 * - Config is this one document. Project, global, system, `.claude`, wellknown, `OPENCODE_CONFIG*`
 *   and macOS managed preferences are never read, and it cannot be updated at runtime. Its steps,
 *   context, output and timeout are the administrator's for this workspace's owner when the model
 *   broker serves them at start (`ManagedLimits`): parsed strictly, exactly four integers, each
 *   clamped to what the system can do. They name no model, tool, path, permission or address, and
 *   the broker enforces output and spend on every call whatever the agent was told.
 * - Its models are the administrator's profile's when the gateway serves them at start
 *   (`ManagedModels`): at most 32, each an ID the gateway admits, a display name and optionally a
 *   context and output that can only lower the limits above; the gateway's default is the session's.
 *   The gateway admits a request only for a model in that profile, whatever the session sends, so
 *   the list widens what the user can pick, never what the gateway forwards. Unless the gateway
 *   serves a list, the one compiled model, `managed/approved`, is the session's.
 * - Plugins are the precompiled set only: no plugin-directory scan, npm install, or import from disk.
 *   Built-ins that reach the network or load code are switched off (`removed`), including the
 *   guarded OpenCode Console/Zen provider, which repository config cannot remove.
 * - The models.dev catalog is empty and never fetched or read from the on-disk cache: models come
 *   only from the compiled config and the gateway's allowlist.
 * - Terminals (Pty) cannot be opened, and persistent terminals are unavailable: their daemon is never
 *   resolved, so `OPENCODE_PTY_BIN` is never read.
 * - The HTTP routes that read or store credentials, add or connect MCP servers, or start a process
 *   (shell, terminals, worktrees, `git init`) are refused before routing (`refused`), so neither a
 *   socket client nor the in-process client reaches their handlers.
 * - Every HTTP request in the service graph goes to the administrator's model gateway over its unix
 *   socket, or is refused. The gateway holds provider credentials; this process holds none.
 */

/** Host the compiled provider addresses; requests to it go over the gateway socket. */
export const gatewayHost = "hardened-gateway"
/** Where the administrator mounts the gateway's socket. */
export const gatewaySocket = "/run/hardened-gateway/gateway.sock"

/**
 * The compiled limits: what the agent uses when the broker serves none (a broker that cannot be
 * reached, a provider that is not a broker, or nothing set in the portal).
 */
export const limits: ManagedLimits.Limits = {
  // A multi-file build is dozens of tool calls; at 8 the user had to type "continue" constantly (pilot, 2026-10-29).
  steps: 40,
  context: 131072,
  output: 16384,
  // Large prompts can take over 30 s to the first byte, and 16k output tokens take minutes. 230 s stays under the
  // broker's 240 s whole-call limit, so the agent sees a timeout it can retry rather than a 502.
  timeoutMs: 230000,
}

/** The compiled configuration: deny by default, then read, edit, shell and the Requirements read. Nothing else loads. */
export const document: Info = {
  model: { providerID: Provider.ID.make("managed"), model: Model.ID.make("approved") },
  default_agent: "build",
  agents: { build: { steps: limits.steps } },
  providers: {
    managed: {
      // Display names are the product's; the IDs (`managed/approved`) stay fixed.
      name: product.providerName,
      // Bundled native route: no npm install, no AI SDK, requests through the graph's HttpClient.
      package: "@opencode/ai/providers/openai-compatible",
      settings: { baseURL: `http://${gatewayHost}/v1`, timeout: limits.timeoutMs },
      models: {
        approved: {
          name: product.modelName,
          capabilities: { tools: true },
          limit: { context: limits.context, output: limits.output },
        },
      },
    },
  },
  update: "disable",
  share: "disabled",
  snapshots: false,
  lsp: false,
  formatter: false,
  permissions: [
    { action: "*", resource: "*", effect: "deny" },
    { action: "read", resource: "*", effect: "allow" },
    { action: "edit", resource: "*", effect: "allow" },
    { action: "shell", resource: "*", effect: "allow" },
    // Read-only, takes no arguments, and exists only in a launch the human signed in to Requirements.
    { action: "pushgate_requirements", resource: "*", effect: "allow" },
    { action: "external_directory", resource: "*", effect: "deny" },
    // Code Mode runs model-written programs with their own fetch; denied outright, not by `*` alone.
    { action: "execute", resource: "*", effect: "deny" },
  ],
}

/**
 * The compiled configuration with the connectors the administrator's signed profile admitted (one
 * local MCP server and its permission rules per entry, appended after the defaults), the limits
 * the broker served and the models the gateway allows. With none of them it is `document` unchanged.
 */
export function compile(
  connectors: readonly ManagedConnectors.Staged[] = [],
  served?: ManagedLimits.Served,
  allowed?: ManagedModels.Served,
): Info {
  const own = ManagedLimits.resolve(limits, served)
  const limited: Info =
    own === limits && !allowed
      ? document
      : {
          ...document,
          ...(allowed && { model: { providerID: Provider.ID.make("managed"), model: Model.ID.make(allowed.default) } }),
          agents: { build: { steps: own.steps } },
          providers: {
            managed: {
              ...document.providers!.managed!,
              settings: { ...document.providers!.managed!.settings, timeout: own.timeoutMs },
              models: allowed
                ? Object.fromEntries(allowed.models.map((entry) => [entry.id, model(entry, own)]))
                : {
                    approved: {
                      ...document.providers!.managed!.models!.approved!,
                      limit: { context: own.context, output: own.output },
                    },
                  },
            },
          },
        }
  if (!connectors.length) return limited
  return {
    ...limited,
    mcp: ManagedConnectors.servers(connectors),
    permissions: [...(document.permissions ?? []), ...ManagedConnectors.permissions(connectors)],
  }
}

/** One allowed model, its own context and output only lowering the agent's. */
function model(entry: ManagedModels.Entry, own: ManagedLimits.Limits) {
  const context = Math.min(entry.context ?? own.context, own.context)
  return {
    name: entry.name,
    capabilities: { tools: true },
    limit: { context, output: Math.min(entry.output ?? own.output, own.output, context - 1) },
  }
}

const configNode = (info: Info) =>
  makeLocationNode({
    service: Config.Service,
    layer: Layer.succeed(
      Config.Service,
      Config.Service.of({
        entries: () => Effect.succeed([new Document({ type: "document", info })]),
        compatibility: () => Effect.succeed({ claude: [], agents: [] }),
        changes: () => Stream.empty,
      }),
    ),
    deps: [],
  })

/**
 * Built-in plugins the managed build switches off: every model provider (the gateway provider is
 * declared in the compiled config), web search and fetch, the OpenCode Console/Zen provider, MCP,
 * wellknown remote config, background model warming and the browser.
 */
export const removed = [
  "opencode.provider.*",
  "opencode.websearch.*",
  "opencode.config.websearch",
  "opencode.tool.websearch",
  "opencode.tool.webfetch",
  "opencode.config.mcp",
  "opencode.mcp.codemode.defaults",
  "opencode.wellknown",
  "opencode.warming",
  "opencode.browser",
  // Connector markings come only from the signed profile; nobody sets one at runtime.
  "badger.connector-marking",
] as const

/**
 * The plugins switched off for a session. With admitted connectors the config MCP plugin stays on to
 * start them; it reads only the compiled document, so it starts nothing else.
 */
export function removedFor(connectors: readonly ManagedConnectors.Connector[] = []): readonly string[] {
  return connectors.length ? removed.filter((target) => target !== "opencode.config.mcp") : removed
}

const pluginSourceNode = (targets: readonly string[]) =>
  makeLocationNode({
    service: ConfigPluginSource.Service,
    layer: Layer.succeed(
      ConfigPluginSource.Service,
      ConfigPluginSource.Service.of({
        operations: () => Effect.succeed(targets.map((target) => ({ type: "remove" as const, target, trusted: true }))),
        changes: () => Stream.never,
      }),
    ),
    deps: [],
  })

const modelsLayer = Layer.succeed(
  ModelsDev.Service,
  ModelsDev.Service.of({ get: () => Effect.succeed([]), refresh: () => Effect.void }),
)

const nativeFetch = globalThis.fetch

/**
 * A fetch that reaches only `http://hardened-gateway/...`, over `socket`. Everything else is refused.
 *
 * Calls go one at a time. The gateway admits one request per session and refuses an overlapping one as
 * busy, and 2.0 generates a session's title beside its first turn; either call could be the one refused.
 * Each call keeps its turn until its response body has been read to the end, cancelled or failed. A body
 * nobody reads cannot hold the turn: after `idleMs` without a read, or `holdMs` in all, the call is
 * aborted and the next one goes.
 */
export function gatewayFetch(
  socket: string,
  {
    idleMs = 30_000,
    holdMs = 600_000,
    settleMs = 2_000,
    flow,
  }: { idleMs?: number; holdMs?: number; settleMs?: number; flow?: ManagedFlow.Flow } = {},
): typeof fetch {
  let queue: Promise<void> = Promise.resolve()
  // A caller that gives up while still queued leaves at once; its place passes straight through.
  const turn = (signal: AbortSignal) => {
    let release!: () => void
    const done = new Promise<void>((resolve) => (release = resolve))
    const ready = queue
    queue = queue.then(() => done)
    return new Promise<() => void>((resolve, reject) => {
      const leave = () => {
        release()
        reject(signal.reason)
      }
      if (signal.aborted) return leave()
      signal.addEventListener("abort", leave, { once: true })
      void ready.then(() => {
        signal.removeEventListener("abort", leave)
        if (signal.aborted) return leave()
        resolve(release)
      })
    })
  }
  // Set when a call ended early (cancelled, aborted, failed or timed out): its connection is closed, but the
  // gateway may not have freed its slot yet.
  let cutShort = false
  return Object.assign(
    async (input: string | URL | Request, init?: RequestInit) => {
      const request = new Request(input, init)
      const url = new URL(request.url)
      if (url.protocol !== "http:" || url.host !== gatewayHost)
        throw new Error(`the managed build reaches only its model gateway, not ${url.origin}`)
      const release = await turn(request.signal)
      // The high-water check, once this call holds its turn: a connector call that raised the label
      // while it waited counts. Nothing above the gateway's marking is sent.
      if (flow)
        try {
          flow.send(request.headers.get("x-opencode-session-id") ?? undefined)
        } catch (error) {
          release()
          throw error
        }
      const abort = new AbortController()
      let idle: ReturnType<typeof setTimeout> | undefined
      let reader: ReadableStreamDefaultReader<Uint8Array> | undefined
      let ended = false
      // Ends this call's turn. An early end first tears the call down, so the next one starts only after
      // this connection is closed.
      const end = async (early?: unknown) => {
        if (ended) return
        ended = true
        clearTimeout(idle)
        clearTimeout(hold)
        request.signal.removeEventListener("abort", onAbort)
        if (early !== undefined) {
          cutShort = true
          abort.abort(early)
          // Aborting the fetch does not reach a body already handed back; cancel that too.
          await reader?.cancel(early).catch(() => {})
        }
        release()
      }
      const onAbort = () => void end(request.signal.reason ?? new Error("model call aborted"))
      request.signal.addEventListener("abort", onAbort, { once: true })
      const hold = setTimeout(
        () => void end(new Error(`model call held the gateway for ${holdMs} ms; the next one may go`)),
        holdMs,
      )
      // Right after a call ended early, a busy refusal is that call's slot still being freed, not a second
      // caller: wait briefly and send again. In normal operation calls never overlap and this never runs.
      const send = async () => {
        const settled = Date.now() + settleMs
        for (let wait = 25; ; wait = Math.min(wait * 2, 400)) {
          const response = await nativeFetch(request.clone(), {
            unix: socket,
            redirect: "error",
            signal: AbortSignal.any([request.signal, abort.signal]),
          })
          if (response.status !== 429 || !cutShort || Date.now() >= settled) {
            cutShort = false
            return response
          }
          await response.body?.cancel().catch(() => {})
          await Bun.sleep(wait)
        }
      }
      const response = await send().catch(async (error) => {
        await end(error ?? new Error("model call failed"))
        throw error
      })
      if (!response.body) {
        await end()
        return response
      }
      reader = response.body.getReader()
      const waitForRead = () => {
        clearTimeout(idle)
        idle = setTimeout(
          () => void end(new Error(`model call body unread for ${idleMs} ms; the next one may go`)),
          idleMs,
        )
      }
      waitForRead()
      const body = new ReadableStream<Uint8Array>(
        {
          async pull(controller) {
            // A read in progress is activity, however slowly the gateway answers it.
            clearTimeout(idle)
            const next = await reader.read().catch(async (error) => {
              await end(error ?? new Error("model call body failed"))
              throw error
            })
            if (next.done) {
              await end()
              controller.close()
            } else {
              controller.enqueue(next.value)
              waitForRead()
            }
          },
          cancel: (reason) => end(reason ?? new Error("model call cancelled")),
        },
        // Read only when the caller reads: a speculative read would count as activity for a body nobody reads.
        { highWaterMark: 0 },
      )
      return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers })
    },
    { preconnect: () => {} },
  )
}

/**
 * The managed graph's HttpClient. It fixes the fetch on every request, so a FetchHttpClient.Fetch
 * provided by a caller's context cannot redirect it.
 */
export function gatewayHttpClient(socket: string, flow?: ManagedFlow.Flow) {
  const fetch = gatewayFetch(socket, { flow })
  return Layer.effect(
    HttpClient.HttpClient,
    Effect.map(HttpClient.HttpClient, (client) =>
      HttpClient.transform(client, (effect) => Effect.provideService(effect, FetchHttpClient.Fetch, fetch)),
    ),
  ).pipe(Layer.provide(FetchHttpClient.layer))
}

const unavailable = (what: string) => Effect.die(new Error(`${what} is unavailable in the managed profile`))

const ptyLayer = Layer.succeed(
  Pty.Service,
  Pty.Service.of({
    list: () => Effect.succeed([]),
    get: (ptyID) => Effect.fail(new Pty.NotFoundError({ ptyID })),
    create: () => unavailable("Pty.create"),
    update: (ptyID) => Effect.fail(new Pty.NotFoundError({ ptyID })),
    remove: (ptyID) => Effect.fail(new Pty.NotFoundError({ ptyID })),
    write: (ptyID) => Effect.fail(new Pty.NotFoundError({ ptyID })),
    attach: (ptyID) => Effect.fail(new Pty.NotFoundError({ ptyID })),
  }),
)

/**
 * Endpoints the managed build does not serve. Credentials live in the gateway, MCP servers come
 * only from the compiled config, and processes start only through the agent's permissioned tools.
 */
export const refused = [
  "credential.list",
  "credential.create",
  "credential.update",
  "credential.activate",
  "credential.remove",
  "integration.connect.key",
  "integration.connect.external",
  "integration.oauth.connect",
  "integration.command.connect",
  "mcp.add",
  "mcp.connect",
  "shell.create",
  "session.shell",
  "pty.create",
  "pty.connectToken",
  "pty.connect",
  "persistentPty.create",
  "persistentPty.handoff",
  "persistentPty.connectToken",
  "persistentPty.connect",
  "worktree.create",
  "vcs.init",
] as const

const routePolicyLayer = Layer.succeed(RoutePolicy.Service, RoutePolicy.Service.of({ refused }))

const ptyUnavailable = Effect.fail(
  new PersistentPty.UnavailableError({ message: "persistent terminals are unavailable in the managed profile" }),
)

const persistentPtyLayer = Layer.succeed(
  PersistentPty.Service,
  PersistentPty.Service.of({
    list: () => Effect.succeed([]),
    get: () => ptyUnavailable,
    create: () => ptyUnavailable,
    write: () => ptyUnavailable,
    resize: () => ptyUnavailable,
    control: () => ptyUnavailable,
    input: () => ptyUnavailable,
    snapshot: () => ptyUnavailable,
    read: () => Effect.succeed(null),
    remove: () => ptyUnavailable,
    shutdown: () => Effect.void,
    handoff: () => Effect.succeed(null),
    attach: () => ptyUnavailable,
  }),
)

/**
 * How the managed build runs its admitted connectors' MCP streams: the first prompt waits up to 20
 * seconds for them to connect, so it has their tools, and a stream that closes (a restarted or idle
 * connector pod, a connector that exited) is reopened with backoff, from 1 second up to 1 minute.
 */
export const connectorMcp = { startupWaitMs: 20_000, reconnect: { initialMs: 1_000, maxMs: 60_000 } } as const

export function replacements(
  options: {
    readonly gatewaySocket?: string
    readonly connectors?: readonly ManagedConnectors.Staged[]
    readonly flow?: ManagedFlow.Flow
    /** The limits the broker served at start (`ManagedLimits.read`); none keeps the compiled ones. */
    readonly limits?: ManagedLimits.Served
    /** The models the gateway allows (`ManagedModels.read`); none keeps the compiled `managed/approved`. */
    readonly models?: ManagedModels.Served
  } = {},
): LayerNode.Replacements {
  return [
    httpClient.replace(gatewayHttpClient(options.gatewaySocket ?? gatewaySocket, options.flow)),
    Config.node.replace(configNode(compile(options.connectors, options.limits, options.models))),
    ConfigPluginSource.node.replace(pluginSourceNode(removedFor(options.connectors))),
    ModelsDev.node.replace(modelsLayer),
    Pty.node.replace(ptyLayer),
    PersistentPty.node.replace(persistentPtyLayer),
    RoutePolicy.node.replace(routePolicyLayer),
    ...(options.connectors?.length ? [Mcp.node.replace(Mcp.configured(connectorMcp))] : []),
    // The workspace label the banner shows beside the deployment marking, announced on each raise.
    ...(options.flow ? [SessionLabel.node.replace(SessionLabel.fromFlow(options.flow))] : []),
  ]
}
