import type { Bearer } from "./bearer"
import { strictJSON } from "./strict-json"
import { edge, platform, parseResponse, targetSchema, type Target, type Requirements } from "./schema"

export type Fetch = (url: string, init: RequestInit) => Promise<Response>
export async function requestJSON(url: string, init: RequestInit, signal: AbortSignal, send: Fetch = fetch) {
  const parsed = new URL(url)
  if (
    ![edge, platform].includes(parsed.origin) ||
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    parsed.protocol !== "https:"
  )
    throw new Error("requirements-origin")
  const response = await send(url, {
    ...init,
    redirect: "error",
    credentials: "omit",
    cache: "no-store",
    signal: AbortSignal.any([signal, AbortSignal.timeout(10_000)]),
  })
  if (response.redirected || (response.status >= 300 && response.status < 400)) throw new Error("requirements-redirect")
  const reader = response.body?.getReader()
  if (!reader) throw new Error("requirements-body")
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    while (true) {
      const part = await reader.read()
      if (part.done) break
      length += part.value.length
      if (length > 2 * 1024 * 1024) throw new Error("requirements-size")
      chunks.push(part.value)
    }
    // Older edge deployments return an unversioned 404 (often HTML).
    const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks))
    const body = (() => {
      try {
        return strictJSON(text)
      } catch {
        if (response.status === 404) return null
        throw new Error("requirements-json")
      }
    })()
    return { status: response.status, body }
  } finally {
    await reader.cancel().catch(() => {})
    reader.releaseLock()
  }
}

export async function readRequirements(
  target: Target,
  bearer: Bearer,
  signal: AbortSignal,
  send?: Fetch,
): Promise<Requirements> {
  try {
    targetSchema.parse(target)
    const query = new URLSearchParams(target).toString()
    if (query.length > 2048) throw new Error("requirements-query")
    const result = await requestJSON(
      `${edge}/api/requirements?${query}`,
      { headers: { Authorization: bearer.authorization(), Accept: "application/json" } },
      signal,
      send,
    )
    if (result.status === 404 && (!result.body || typeof result.body !== "object" || !("version" in result.body)))
      return { version: "pushgate.requirements.v1", state: "unsupported", code: "edge_api_unsupported" }
    const parsed = parseResponse(result.body, target, result.status)
    // A server that echoes the bearer in any field gets nothing displayed: once returned, a
    // response is serialized into the sidebar and model context, where the private field cannot help.
    if (strings(parsed).some((value) => bearer.redact(value) !== value)) throw new Error("requirements-echo")
    return parsed
  } catch {
    return { version: "pushgate.requirements.v1", state: "unavailable", code: "requirements_unavailable" }
  }
}

/** Every string inside a parsed JSON value, for checking a response for credential echoes. */
export function strings(value: unknown): string[] {
  if (typeof value === "string") return [value]
  if (Array.isArray(value)) return value.flatMap(strings)
  if (value && typeof value === "object") return Object.values(value).flatMap(strings)
  return []
}
