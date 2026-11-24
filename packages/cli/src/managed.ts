export * as Managed from "./managed"

import { connect } from "node:net"
import { Effect, Layer } from "effect"
import { ManagedModels } from "@opencode/server/managed-models"
import { Observability } from "@opencode/util/observability"
import type { Spec } from "./framework/spec"
import type { LazyHandler } from "./framework/runtime"
import { Updater as UpdaterService } from "./services/updater"

declare const TESTIFYSEC_MANAGED_WORKER: boolean
declare const TESTIFYSEC_FIXTURE_MODEL: boolean

/**
 * The managed (Badger) build, chosen at compile time. It runs the server in-process with
 * `ManagedProfile.replacements()`, never starts, finds or updates a background service, and
 * keeps only the commands that do work in a session. Nothing at runtime can turn it off.
 */
export const enabled = typeof TESTIFYSEC_MANAGED_WORKER !== "undefined" && TESTIFYSEC_MANAGED_WORKER

// A managed build sends no telemetry of its own: its exporter is not configured from OTEL_*. The variables stay in
// the environment, because the processes the agent starts belong to the user's project and may use them.
if (enabled) Observability.ignoreEnvironment()

/** Whether this is a UAT build with the fixture model compiled in (`build.ts --fixture-model`). Never in a release. */
export const fixtureModel = typeof TESTIFYSEC_FIXTURE_MODEL !== "undefined" && TESTIFYSEC_FIXTURE_MODEL

/** A command or flag this build does not offer. It is printed as its message alone, never as a crash. */
export class Refused extends Error {
  override name = "Refused"
}

/**
 * The model gateway's socket. Only a fixture-model UAT build points elsewhere: its synthetic model
 * listens where the build can create it. A release build compiles the branch out.
 */
// Tests the define directly, not `fixtureModel`: the bundler only folds the literal out of a release build this way.
export const gatewaySocket: string | undefined =
  typeof TESTIFYSEC_FIXTURE_MODEL !== "undefined" && TESTIFYSEC_FIXTURE_MODEL ? "/tmp/hardened-fixture-model.sock" : undefined

/**
 * Fails at once, with a message naming the socket, when the managed build's model gateway cannot be
 * reached: it is the only model route, and a session without it would only retry until stopped.
 * A build that is not managed has nothing to check.
 */
export const requireGateway: Effect.Effect<void, Error> = Effect.suspend(() => {
  if (!enabled) return Effect.void
  return Effect.gen(function* () {
    const { ManagedProfile } = yield* Effect.promise(() => import("@opencode/server/managed"))
    const socket = gatewaySocket ?? ManagedProfile.gatewaySocket
    yield* Effect.callback<void, Error>((resume) => {
      const unavailable = (reason: string) =>
        resume(Effect.fail(new Refused(`The model gateway is not available at ${socket} (${reason}). Ask your administrator to start it.`)))
      const probe = connect({ path: socket })
      const timer = setTimeout(() => (probe.destroy(), unavailable("no answer within 2s")), 2_000)
      probe.once("connect", () => (clearTimeout(timer), probe.end(), resume(Effect.void)))
      probe.once("error", (error: NodeJS.ErrnoException) => (clearTimeout(timer), unavailable(error.code ?? error.message)))
    })
  })
})

/**
 * Commands a managed build keeps. Everything else administers services, credentials or code.
 * `about` only prints the version and the upstream license, which every build must carry.
 * `serve` puts the in-process server behind an authenticating edge (managed-serve.ts).
 */
export const kept: ReadonlySet<string> = new Set(["about", "run", "mini", "models", "stats", "session", "serve"])

/**
 * Whether permissions are auto-approved. A managed build refuses the flags outright: what a
 * session may do comes from the compiled policy, not from how the command was started.
 */
export function permissionFlags(
  input: { readonly auto: boolean; readonly yolo: boolean; readonly dangerouslySkipPermissions: boolean },
  managed = enabled,
) {
  const requested = input.auto || input.yolo || input.dangerouslySkipPermissions
  if (managed && requested)
    return Effect.fail(new Refused("--auto, --yolo and --dangerously-skip-permissions are not available in this build"))
  return Effect.succeed(requested)
}

/**
 * Refuses `--server` and `--standalone`. A managed build reaches only the server it runs in-process; checked
 * before the gateway, so the caller hears about the flag rather than about a gateway it would never use.
 */
export function serverFlags(input: { readonly server?: string; readonly standalone?: boolean }, managed = enabled) {
  if (managed && (input.server !== undefined || input.standalone))
    return Effect.fail(new Refused("--server and --standalone are not available in this build"))
  return Effect.void
}

/** A managed build imports session data only from a local file: it fetches nothing on the caller's behalf. */
export function importSource(file: string, managed = enabled) {
  if (managed && /^https?:\/\//i.test(file))
    return Effect.fail(new Refused("Importing a session from a URL is not available in this build"))
  return Effect.void
}

/** The compiled profile's model, as `provider/model`: the session's when the gateway serves no allowlist. */
export const approvedModel = "managed/approved"

/**
 * Refuses, before anything else runs, a `--model` that is not a managed model. Which managed models
 * exist is the gateway's allowlist, read when the session starts; the server and the gateway refuse
 * one it does not list, but anything else the caller should hear about at once.
 */
export function modelFlag(model: string | undefined, managed = enabled) {
  if (managed && model !== undefined && !(model.startsWith("managed/") && ManagedModels.id.test(model.slice("managed/".length))))
    return Effect.fail(new Error(`Model "${model}" is not available in this build; it runs only the administrator's managed/ models`))
  return Effect.void
}

/** Replaces the handler of every command a managed build does not keep with one that refuses. */
export function gate(root: Spec.Any, handlers: ReadonlyArray<LazyHandler>, managed = enabled) {
  if (!managed) return handlers
  const refused = new Set<unknown>()
  const collect = (node: Spec.Any) => {
    refused.add(node.spec)
    for (const alias of node.aliases) refused.add(alias.spec)
    for (const child of Object.values(node.commands)) collect(child)
  }
  for (const [name, child] of Object.entries(root.commands)) if (!kept.has(name)) collect(child)
  const refuse = () =>
    Promise.resolve({
      default: () => Effect.fail(new Refused("This command is not available in this build")),
    })
  return handlers.map((handler) => (refused.has(handler.spec) ? { ...handler, load: refuse } : handler))
}

export const Updater = UpdaterService.Service

const noUpdates = () => Effect.fail(new Refused("Updates are managed by your administrator in this build"))

/** The managed build's updater: it never checks, downloads or installs anything. */
export const updaterLayer = Layer.succeed(
  UpdaterService.Service,
  UpdaterService.Service.of({
    run: () => Effect.succeed(undefined),
    check: () => Effect.succeed({ type: "unavailable", message: "Updates are managed by your administrator" }),
    apply: noUpdates,
    method: () => Effect.succeed(undefined),
    latest: noUpdates,
    upgrade: noUpdates,
    removal: () => undefined,
  }),
)
