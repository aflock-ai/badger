import { execFile } from "node:child_process"
import { promisify } from "node:util"
import type { Selection } from "./device"

// Returns display-name hints only. Never return userinfo or an endpoint from local Git config.
export function remoteRepository(raw: string): string | undefined {
  if (raw.length > 8192 || /[\s\p{Cc}\p{Cf}\\?#]/u.test(raw)) return
  const scp = /^(?:[a-zA-Z0-9_-]+@)?(github\.com|pushgate\.dev):([^/].*)$/i.exec(raw)
  const source = scp ? `ssh://${scp[1]}/${scp[2]}` : raw
  const parts = /^(https?|ssh|git):\/\/(?:[^/]*@)?(github\.com|pushgate\.dev)(?::([0-9]+))?\/(.*)$/i.exec(source)
  if (!parts) return
  const url = URL.parse(source)
  if (!url || !["github.com", "pushgate.dev"].includes(url.hostname.toLowerCase())) return
  const port = { "https:": "443", "http:": "80", "ssh:": "22", "git:": "9418" }[url.protocol]
  if (parts[3] && parts[3] !== port) return
  // Validate the raw path, not URL.pathname: URL parsing normalizes dot segments.
  const route = parts[4]!.replace(/\/$/, "").replace(/\.git$/, "")
  const match = (
    url.hostname.toLowerCase() === "github.com"
      ? /^([a-zA-Z0-9-]+)\/([a-zA-Z0-9_.-]+)$/
      : /^(?:gh|(?:r\/)?github\.com)\/([a-zA-Z0-9-]+)\/([a-zA-Z0-9_.-]+)$/
  ).exec(route)
  if (!match || [".", ".."].includes(match[2]!)) return
  return `github.com/${match[1]}/${match[2]}`.toLowerCase()
}

export async function repositoryPrompt(directory: string, repos: Selection[]) {
  const initialValue = await (async () => {
    // Ambient Git overrides must not redirect --directory or emit credential-bearing traces.
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")))
    const git = async (...args: string[]) =>
      (await promisify(execFile)("git", args, { cwd: directory, env, timeout: 2000, maxBuffer: 256 * 1024 })).stdout
    if ((await git("rev-parse", "--is-inside-work-tree")) !== "true\n") return
    const names = (await git("remote")).split("\n").filter(Boolean)
    if (names.length > 64) return
    const hints = new Set<string>()
    for (const name of names) {
      for (const mode of [[], ["--push"]]) {
        const output = await git("remote", "get-url", "--all", ...mode, "--", name)
        for (const raw of output.split("\n")) {
          const hint = remoteRepository(raw)
          if (hint) hints.add(hint)
        }
      }
    }
    const matches = repos.flatMap((repo, index) => (hints.has(repo.repo.toLowerCase()) ? [index] : []))
    return matches.length === 1 ? matches[0] : undefined
  })().catch(() => undefined) // Git errors can contain raw remotes; never relay them.
  return {
    message:
      initialValue === undefined
        ? "Select the platform repository for this directory (no unique Git suggestion)"
        : "Confirm the platform repository for this directory (Git suggestion only, not identity or authorization)",
    options: repos.map((r, value) => ({ value, label: `${r.repo} (#${r.repository_id})` })),
    initialValue,
  }
}
