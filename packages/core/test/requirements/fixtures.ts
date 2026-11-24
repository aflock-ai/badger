import { Bearer } from "@opencode/core/requirements/bearer"
import type { Credentials } from "@opencode/core/requirements/monitor"
import type { Requirements } from "@opencode/core/requirements/schema"

export const target = {
  repo: "github.com/acme/project",
  repository_id: "123",
  commit: "a".repeat(40),
  ref: "refs/heads/main",
}
export const snapshot = {
  version: "pushgate.requirements.v1",
  state: "available",
  target,
  assignment_source: "connection_snapshot",
  applicability: "incomplete",
  connection: { generation: 3, created_at: "2026-09-01T00:00:00Z" },
  builtins: [{ id: "signed", mode: "block", availability: "supported" }],
  policies: [],
  last_decision: { state: "none", current_status: "unavailable" },
} satisfies Requirements


type Fields = { token: string; expires: number; directory: string; repo: string; repository_id: string }
export const defaults: Fields = {
  token: "dedicated",
  expires: 4_000_000_000_000,
  directory: "/work",
  repo: target.repo,
  repository_id: target.repository_id,
}

/** In-memory credentials as one TUI launch holds them: a new Bearer per sign-in. */
export function credentials(fields: Partial<Fields> = {}): Credentials & { fields: Fields } {
  const all = { ...defaults, ...fields }
  return {
    fields: all,
    selection: { version: 1, enabled: true, directory: all.directory, repo: all.repo, repository_id: all.repository_id },
    bearer: new Bearer(all.token, all.expires),
  }
}
