export * as ManagedLimits from "./managed-limits"

import { Option, Schema } from "effect"

/**
 * The managed agent's four limits, which an administrator sets in the management portal per person
 * (testifysec/model-broker, quotas): steps per turn, the context the agent compacts at, the output it
 * asks for, and the provider timeout. The broker serves the workspace owner's values at
 * `GET /v1/limits` through the gateway; the server reads them once at start (`read`). They are the
 * agent's own settings, not controls: the broker enforces output and money on every call whatever
 * the agent was told (docs/design/planned/managed-agent-limits.md, L1 and L6).
 */
export interface Limits {
  readonly steps: number
  readonly context: number
  readonly output: number
  readonly timeoutMs: number
}

/**
 * Technical limits, not policy: what the system can serve whatever an administrator sets. The
 * gateway and the broker accept a 1 MiB request, about 262144 tokens; the gateway ends a call at
 * 600 s at most.
 */
export const technical = { context: 262_144, timeoutMs: 600_000 } as const

const count = Schema.NullOr(Schema.Number.check(Schema.isInt(), Schema.isGreaterThan(0)))

/** The broker's answer: exactly these four fields, each a positive integer or null (unset). */
const Served = Schema.fromJsonString(
  Schema.Struct({ steps: count, context: count, output: count, timeout_seconds: count }),
)

export type Served = typeof Served.Type

/** The served values, or none for anything but the exact shape: then the compiled values hold. */
export function parse(text: string): Served | undefined {
  return Option.getOrUndefined(Schema.decodeUnknownOption(Served)(text, { onExcessProperty: "error" }))
}

/** The served values over the compiled ones, each clamped to what the system can do. */
export function resolve(compiled: Limits, served: Served | undefined): Limits {
  if (!served) return compiled
  const context = Math.min(served.context ?? compiled.context, technical.context)
  return {
    steps: served.steps ?? compiled.steps,
    context,
    output: Math.min(served.output ?? compiled.output, context - 1),
    timeoutMs: Math.min(served.timeout_seconds === null ? compiled.timeoutMs : served.timeout_seconds * 1000, technical.timeoutMs),
  }
}

/**
 * Asks the gateway on `socket` for this workspace's limits, once, within `deadlineMs`. Any failure
 * (no gateway answer, a gateway or provider without the route, a malformed answer) is none.
 */
export async function read(socket: string, deadlineMs = 3_000): Promise<Served | undefined> {
  const response = await fetch("http://hardened-gateway/v1/limits", {
    unix: socket,
    redirect: "error",
    signal: AbortSignal.timeout(deadlineMs),
  }).catch(() => undefined)
  if (!response?.ok) return undefined
  return parse(await response.text().catch(() => ""))
}
