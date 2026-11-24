export * as ManagedModels from "./managed-models"

import { Option, Schema } from "effect"

/**
 * The models a managed session may choose among: the administrator's profile lists them, and the
 * gateway admits a request only for one of them (testifysec/gateway, unsigned profile). The gateway
 * serves that list and the default at `GET /v1/models`; the server reads it once at start (`read`).
 * Each entry is an ID, a display name, and optionally the model's own context and output, which can
 * only lower the agent's limits. Nothing here names an address, credential, tool or permission.
 */

/** As many models as the gateway allows in a profile. */
export const maxModels = 32
/** The largest answer read: 32 models at their longest fit well inside it. */
export const maxBytes = 16_384

/** The gateway's model ID grammar: also a key under `managed/`, so no slash or whitespace. */
export const id = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const name = /^[A-Za-z0-9][A-Za-z0-9 .,:_()/+-]{0,63}$/
const size = Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 1 << 24 }))

const Entry = Schema.Struct({
  id: Schema.String,
  name: Schema.String,
  context: Schema.optionalKey(size),
  output: Schema.optionalKey(size),
})

/** The gateway's answer: exactly `default` and `models`. */
const Served = Schema.fromJsonString(Schema.Struct({ default: Schema.String, models: Schema.Array(Entry) }))

export type Served = typeof Served.Type
export type Entry = Served["models"][number]

/**
 * The allowlist, or none for anything but the exact shape with 1 to 32 distinct well-formed models,
 * the default among them: then the compiled model holds.
 */
export function parse(text: string): Served | undefined {
  if (text.length > maxBytes) return undefined
  const served = Option.getOrUndefined(Schema.decodeUnknownOption(Served)(text, { onExcessProperty: "error" }))
  if (!served || served.models.length === 0 || served.models.length > maxModels) return undefined
  const ids = new Set(served.models.map((model) => model.id))
  if (ids.size !== served.models.length || !ids.has(served.default)) return undefined
  if (served.models.some((model) => !id.test(model.id) || !name.test(model.name))) return undefined
  return served
}

/**
 * Asks the gateway on `socket` for the allowlist, once, within `deadlineMs`. Any failure (no gateway
 * answer, a gateway with no profile allowlist, a malformed answer) is none.
 */
export async function read(socket: string, deadlineMs = 3_000): Promise<Served | undefined> {
  const signal = AbortSignal.timeout(deadlineMs)
  const response = await fetch("http://hardened-gateway/v1/models", { unix: socket, redirect: "error", signal }).catch(
    () => undefined,
  )
  if (!response?.ok || !response.body) return undefined
  // Read at most one byte past the limit, then stop: a longer answer is refused, not buffered.
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    while (length <= maxBytes) {
      const next = await reader.read()
      if (next.done) break
      chunks.push(next.value)
      length += next.value.byteLength
    }
  } catch {
    return undefined
  } finally {
    void reader.cancel().catch(() => {})
  }
  if (length > maxBytes) return undefined
  try {
    return parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)))
  } catch {
    return undefined
  }
}

/** The start log's line: where the session's models came from, its default and every ID. */
export function summary(served: Served | undefined) {
  if (!served) return "models source=compiled default=approved models=approved"
  return `models source=profile default=${served.default} models=${served.models.map((model) => model.id).join(",")}`
}
