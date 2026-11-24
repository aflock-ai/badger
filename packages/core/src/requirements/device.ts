import z from "zod"
import { setTimeout } from "node:timers/promises"
import { numericID, platform, repo, scopes, uuid } from "./schema"
import { requestJSON, strings, type Fetch } from "./transport"
import { Bearer } from "./bearer"
import type { Selection as SavedSelection } from "./selection"

const bounded = z.string().max(1024)
const deviceSchema = z
  .object({
    device_code: bounded.min(1),
    user_code: z.string().regex(/^[A-Z0-9-]{4,32}$/),
    verification_uri: z.literal(`${platform}/auth/cli/device`),
    verification_uri_complete: bounded,
    expires_in: z.number().int().min(1).max(1800),
    interval: z.number().int().min(1).max(60),
  })
  .strict()
  .refine((d) => d.verification_uri_complete === `${platform}/auth/cli/device?user_code=${d.user_code}`)
const tokenSchema = z
  .object({
    access_token: z
      .string()
      .min(1)
      .max(16384)
      .regex(/^[\x21-\x7e]+$/),
    token_type: z.literal("Bearer"),
    expires_in: z
      .number()
      .int()
      .min(1)
      .max(365 * 86400),
    scope: bounded,
    tenant_id: uuid.optional(),
    tenant_name: bounded.optional(),
    user_id: uuid.optional(),
    email: bounded.optional(),
    name: bounded.optional(),
  })
  .strict()
  .refine((t) => t.scope.split(" ").sort().join(" ") === scopes.split(" ").sort().join(" "))
const catalogSchema = z
  .object({
    tenant_id: uuid,
    github_app_connected: z.boolean(),
    partial: z.boolean(),
    connect_url: bounded.optional(),
    repositories: z
      .array(
        z
          .object({
            id: repo,
            repository_id: numericID,
            full_name: bounded,
            clone_url: bounded,
            private: z.boolean(),
            installation_id: numericID,
            account_login: bounded,
            account_type: bounded,
          })
          .strict()
          .refine(
            (r) => r.id === `github.com/${r.full_name}` && r.clone_url === `https://github.com/${r.full_name}.git`,
          ),
      )
      .max(10000),
  })
  .strict()
export type Selection = { repo: string; repository_id: string }

/** Thrown by a `select` callback when the human declines to choose a repository. */
export class ConnectCancelled extends Error {}

// Fixed local sentences only. Server prose, URLs and schema input never reach these.
const reasons = {
  cancelled: "Connection cancelled.",
  "device-unavailable": "The platform sign-in service is unavailable.",
  "device-refused": "Sign-in was denied or refused in the browser.",
  "device-expired": "The sign-in code expired before it was approved.",
  "catalog-unavailable": "The platform repository catalog could not be read.",
  "catalog-incomplete": "The platform source-control integration is not connected, or no repositories are authorized.",
  "catalog-ambiguous": "The platform returned conflicting IDs for one repository.",
  "selection-refused": "No repository was selected before the sign-in expired.",
} as const

class Failure extends Error {
  constructor(readonly reason: keyof typeof reasons) {
    super(reason)
  }
}

// Always shown: a browser launch can report success without a visible window (SSH, headless),
// and the human should confirm the browser shows the same code (RFC 8628 section 5.4).
export function signInNotice(url: string, userCode: string) {
  return `Open this independent sign-in in your browser: ${url}\nConfirm the browser shows code ${userCode}.\n`
}

export interface Session {
  readonly selection: SavedSelection
  readonly bearer: Bearer
}

// Device sign-in for one TUI launch. The bearer stays in memory in the returned Session; only the
// non-secret selection may be saved (selection.ts). Neither refresh nor status can log in.
export async function connect(input: {
  directory: string
  signal: AbortSignal
  onCode: (url: string, userCode: string) => Promise<void>
  select: (repos: Selection[]) => Promise<number>
  send?: Fetch
  wait?: (ms: number) => Promise<void>
}): Promise<Session> {
  try {
    const post = (route: string, body: object) =>
      requestJSON(
        `${platform}/oauth/device/${route}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify(body),
        },
        input.signal,
        input.send,
      )
    const response = await post("code", { client_id: "badger-requirements", scope: scopes })
    if (response.status !== 200) throw new Failure("device-unavailable")
    const device = deviceSchema.parse(response.body)
    const deadline = Date.now() + device.expires_in * 1000
    await input.onCode(device.verification_uri_complete, device.user_code)
    let interval = device.interval * 1000
    while (Date.now() < deadline && !input.signal.aborted) {
      await (input.wait ? input.wait(interval) : setTimeout(interval, undefined, { signal: input.signal }))
      if (Date.now() >= deadline || input.signal.aborted) break
      const reply = await post("token", {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: device.device_code,
        client_id: "badger-requirements",
      })
      if (reply.status === 400) {
        const error = z.object({ error: bounded, error_description: bounded.optional() }).strict().parse(reply.body)
        if (error.error === "slow_down") {
          // RFC 8628 3.5: each slow_down adds five seconds for good. The code's expiry bounds the wait.
          interval += 5000
          continue
        }
        if (error.error === "authorization_pending") continue
        throw new Failure(error.error === "expired_token" ? "device-expired" : "device-refused")
      }
      if (reply.status !== 200) throw new Failure("device-unavailable")
      const token = tokenSchema.parse(reply.body)
      const expires = Date.now() + token.expires_in * 1000
      const catalog = await requestJSON(
        `${platform}/api/pushgate/repositories`,
        { headers: { Authorization: `Bearer ${token.access_token}`, Accept: "application/json" } },
        input.signal,
        input.send,
      )
      if (catalog.status !== 200) throw new Failure("catalog-unavailable")
      const list = catalogSchema.parse(catalog.body)
      // A catalog that echoes the bearer would carry it into the selection, and so onto disk.
      if (strings(list).some((value) => value.includes(token.access_token))) throw new Failure("catalog-unavailable")
      if (
        list.partial ||
        !list.github_app_connected ||
        list.repositories.length === 0 ||
        (token.tenant_id && token.tenant_id !== list.tenant_id)
      )
        throw new Failure("catalog-incomplete")
      const repos = list.repositories
        .map((r) => ({ repo: r.id, repository_id: r.repository_id }))
        .filter(
          (r, i, all) =>
            all.findIndex((other) => other.repo === r.repo && other.repository_id === r.repository_id) === i,
        )
      if (repos.some((r) => repos.some((other) => other.repo === r.repo && other.repository_id !== r.repository_id)))
        throw new Failure("catalog-ambiguous")
      const index = await input.select(repos)
      if (!Number.isInteger(index) || !repos[index] || input.signal.aborted || expires <= Date.now())
        throw new Failure("selection-refused")
      return {
        selection: { version: 1, enabled: true, directory: input.directory, ...repos[index] },
        bearer: new Bearer(token.access_token, expires),
      }
    }
    throw new Failure(input.signal.aborted ? "cancelled" : "device-expired")
  } catch (error) {
    // Never relay server prose, URLs, token/schema input, or an HTTP client's request dump.
    const reason =
      input.signal.aborted || error instanceof ConnectCancelled
        ? "cancelled"
        : error instanceof Failure
          ? error.reason
          : undefined
    throw new Error(
      reason
        ? `Requirements connection failed: ${reasons[reason]} No credential was saved.`
        : "Requirements connection failed. No credential was saved; retry independent sign-in from a terminal.",
    )
  }
}
