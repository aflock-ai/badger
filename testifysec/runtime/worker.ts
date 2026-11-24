import { mkdirSync } from "node:fs"
import { strictJSON } from "../managed/strict-json"
import { Branding } from "../branding/product"

declare const TESTIFYSEC_FIXTURE_MODEL: boolean

// This is the untrusted OpenCode worker, never the signing/admission authority.
// The broker creates its OS boundary before starting this compiled entrypoint.
try {
  if (process.platform !== "linux" || process.cwd() !== "/workspace" || Bun.argv.length !== 2)
    throw new Error("worker requires the managed Linux execution boundary")
  const chunks: Uint8Array[] = []
  let length = 0
  for await (const chunk of Bun.stdin.stream()) {
    length += chunk.byteLength
    if (length > 128 * 1024) throw new Error("prompt too large")
    chunks.push(chunk)
  }
  const input = strictJSON(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)))
  if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).sort().join(",") !== "profileDigest,prompt,schema")
    throw new Error("invalid prompt request")
  const request = input as Record<string, unknown>
  if (request.schema !== "testifysec.hardened-opencode.prompt/v1" || typeof request.prompt !== "string" ||
      !request.prompt.trim() || request.prompt.length > 64000 || typeof request.profileDigest !== "string" ||
      !/^[a-f0-9]{64}$/.test(request.profileDigest)) throw new Error("invalid prompt request")

  for (const key of Object.keys(process.env)) delete process.env[key]
  Object.assign(process.env, {
    PATH: "/toolpack/bin:/usr/bin:/bin", HOME: "/tmp/hardened/home", SHELL: "/bin/sh", LANG: "C.UTF-8", TMPDIR: "/tmp",
    XDG_CONFIG_HOME: "/tmp/hardened/config", XDG_DATA_HOME: "/tmp/hardened/data",
    XDG_CACHE_HOME: "/tmp/hardened/cache", XDG_STATE_HOME: "/tmp/hardened/state",
    OPENCODE_DB: "/tmp/hardened/session.db", OPENCODE_DISABLE_MODELS_FETCH: "1",
    OPENCODE_DISABLE_AUTOUPDATE: "1", OPENCODE_DISABLE_PRUNE: "1", OPENCODE_DISABLE_FFF: "1",
    OPENCODE_EXPERIMENTAL_DISABLE_FILEWATCHER: "1", OPENCODE_DISABLE_PROJECT_CONFIG: "1", OPENCODE_PURE: "1",
  })
  mkdirSync("/tmp/hardened/home", { recursive: true })
  if (TESTIFYSEC_FIXTURE_MODEL) {
    const { serveFixture } = await import("./fixture-model")
    serveFixture()
  }
  process.stdout.write(JSON.stringify({ type: "managed_worker_start", profileDigest: request.profileDigest,
    product: Branding.name, scope: "untrusted-worker", fixtureModel: TESTIFYSEC_FIXTURE_MODEL }) + "\n")
  // Fixed arguments: prompt text cannot select serve/PTY/MCP/auth/upgrade/attach.
  process.argv = [process.execPath, Branding.command, "run", "--format", "json", "--model", "managed/approved", "--agent", "build", "--", request.prompt]
  // The 2.0 CLI entry. The managed build runs its server in-process with the managed profile.
  await import("../../packages/cli/src/index")
} catch {
  process.stderr.write("managed worker unavailable\n")
  process.exitCode = 1
}
