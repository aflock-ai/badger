import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { inspect } from "node:util"
import { Bearer } from "@opencode/core/requirements/bearer"
import { connect } from "@opencode/core/requirements/device"
import {
  legacyCredentialFile,
  loadSelection,
  removeLegacyCredential,
  saveSelection,
  selectionFile,
} from "@opencode/core/requirements/selection"
import { platform } from "@opencode/core/requirements/schema"

// A token shape no other test data contains, so a scan for it cannot match by accident.
const token = "pgr_custody_probe_7f3c1e9a2b4d6f8a0c2e4f6a8b0d2f4a"

const device = {
  device_code: "dc-1",
  user_code: "ABCD-1234",
  verification_uri: `${platform}/auth/cli/device`,
  verification_uri_complete: `${platform}/auth/cli/device?user_code=ABCD-1234`,
  expires_in: 600,
  interval: 1,
}
const catalog = {
  tenant_id: "11111111-1111-4111-8111-111111111111",
  github_app_connected: true,
  partial: false,
  repositories: [
    {
      id: "github.com/acme/widgets",
      repository_id: "42",
      full_name: "acme/widgets",
      clone_url: "https://github.com/acme/widgets.git",
      private: true,
      installation_id: "7",
      account_login: "acme",
      account_type: "Organization",
    },
  ],
}

function reply(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })
}

function platformFake() {
  const seen: { url: string; authorization: string | null }[] = []
  const send = async (url: string, init: RequestInit) => {
    seen.push({ url, authorization: new Headers(init.headers).get("authorization") })
    if (url.endsWith("/oauth/device/code")) return reply(200, device)
    if (url.endsWith("/oauth/device/token"))
      return reply(200, {
        access_token: token,
        token_type: "Bearer",
        expires_in: 3600,
        scope: "pushgate:policy-read pushgate:repo-read",
      })
    if (url.endsWith("/api/pushgate/repositories")) return reply(200, catalog)
    return reply(404, {})
  }
  return { send, seen }
}

let root: string
let saved: Record<string, string | undefined>
const xdg = ["HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "TMPDIR"] as const

beforeEach(async () => {
  root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "requirements-custody-")))
  saved = Object.fromEntries(xdg.map((key) => [key, process.env[key]]))
  for (const key of xdg) {
    const dir = path.join(root, key.toLowerCase())
    await fs.mkdir(dir, { recursive: true, mode: 0o700 })
    process.env[key] = dir
  }
})

afterEach(async () => {
  for (const key of xdg) {
    if (saved[key] === undefined) delete process.env[key]
    else process.env[key] = saved[key]
  }
  await fs.rm(root, { recursive: true, force: true })
})

// Every path a test writes must be inside its temp root, never the real home.
function inRoot(file: string) {
  if (!file.startsWith(root + path.sep)) throw new Error(`test path escaped its temp root: ${file}`)
  return file
}

async function filesUnder(dir: string): Promise<string[]> {
  const out: string[] = []
  for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) out.push(...(await filesUnder(full)))
    else out.push(full)
  }
  return out
}

describe("Requirements custody: the bearer lives in memory only", () => {
  test("a full sign-in and saved selection write the bearer nowhere on disk", async () => {
    const platformApi = platformFake()
    const directory = path.join(root, "work")
    await fs.mkdir(directory)
    const env = { ...process.env }
    const session = await connect({
      directory,
      signal: new AbortController().signal,
      onCode: async () => {},
      select: async () => 0,
      send: platformApi.send,
      wait: async () => {},
    })
    await saveSelection(session.selection, inRoot(selectionFile(env, directory)))

    expect(session.bearer.expired).toBe(false)
    // The bearer was used for the catalog: the fake saw it as a header and nowhere else.
    expect(platformApi.seen.filter((s) => s.authorization === `Bearer ${token}`).map((s) => s.url)).toEqual([
      `${platform}/api/pushgate/repositories`,
    ])

    const files = await filesUnder(root)
    expect(files).toContain(selectionFile(env, directory))
    for (const file of files) expect(await fs.readFile(file, "utf8"), file).not.toContain(token)
  })

  test("the bearer does not serialize, print or reach the environment", async () => {
    const session = await connect({
      directory: root,
      signal: new AbortController().signal,
      onCode: async () => {},
      select: async () => 0,
      send: platformFake().send,
      wait: async () => {},
    })
    expect(JSON.stringify(session)).not.toContain(token)
    expect(inspect(session, { depth: 10, showHidden: true })).not.toContain(token)
    expect(String(session.bearer)).not.toContain(token)
    expect(Object.values(process.env).some((value) => value?.includes(token))).toBe(false)
    expect(Object.keys(session.bearer)).toEqual(["expires"])
  })

  test("the saved selection is non-secret and a credential-bearing file is refused", async () => {
    const file = inRoot(selectionFile(process.env, root))
    await saveSelection(
      { version: 1, enabled: true, directory: root, repo: "github.com/acme/widgets", repository_id: "42" },
      file,
    )
    const loaded = await loadSelection(file)
    expect(loaded).toEqual({
      version: 1,
      enabled: true,
      directory: root,
      repo: "github.com/acme/widgets",
      repository_id: "42",
    })
    expect(Object.keys(JSON.parse(await fs.readFile(file, "utf8"))).sort()).toEqual([
      "directory",
      "enabled",
      "repo",
      "repository_id",
      "version",
    ])
    expect((await fs.stat(file)).mode & 0o777).toBe(0o600)

    // A selection carrying a token (the 1.x file shape) is never accepted.
    await fs.writeFile(file, JSON.stringify({ ...loaded, token }), { mode: 0o600 })
    await expect(loadSelection(file)).rejects.toThrow()
    await expect(saveSelection({ ...loaded, token }, file)).rejects.toThrow()
  })

  test("a 1.x credential file is deleted, not read", async () => {
    const legacy = inRoot(legacyCredentialFile(process.env))
    await fs.mkdir(path.dirname(legacy), { recursive: true, mode: 0o700 })
    await fs.writeFile(legacy, JSON.stringify({ version: 1, token }), { mode: 0o600 })
    expect(await removeLegacyCredential(legacy)).toBe(true)
    await expect(fs.lstat(legacy)).rejects.toThrow()
    expect(await removeLegacyCredential(legacy)).toBe(false)
  })

  test("selection files that are symlinks or readable by others are refused", async () => {
    const file = inRoot(selectionFile(process.env, root))
    const value = { version: 1, enabled: true, directory: root, repo: "github.com/acme/widgets", repository_id: "42" }
    await saveSelection(value, file)
    await fs.chmod(file, 0o644)
    await expect(loadSelection(file)).rejects.toThrow()
    await fs.rm(file)
    const target = path.join(root, "elsewhere.json")
    await fs.writeFile(target, JSON.stringify(value), { mode: 0o600 })
    await fs.symlink(target, file)
    await expect(loadSelection(file)).rejects.toThrow()
  })

  test("an expired bearer reports expired and refuses to authorize", () => {
    const bearer = new Bearer(token, Date.now() - 1)
    expect(bearer.expired).toBe(true)
    expect(() => bearer.authorization()).toThrow()
  })
})

test("a catalog that echoes the bearer is refused before selection, so it is never saved", async () => {
  const platformApi = platformFake()
  const echoing = {
    ...catalog,
    repositories: [
      {
        ...catalog.repositories[0],
        id: `github.com/acme/${token}`,
        full_name: `acme/${token}`,
        clone_url: `https://github.com/acme/${token}.git`,
      },
    ],
  }
  let offered = false
  const send = async (url: string, init: RequestInit) =>
    url.endsWith("/api/pushgate/repositories")
      ? new Response(JSON.stringify(echoing), { status: 200, headers: { "content-type": "application/json" } })
      : platformApi.send(url, init)
  const error = await connect({
    directory: root,
    signal: new AbortController().signal,
    onCode: async () => {},
    select: async () => {
      offered = true
      return 0
    },
    send,
    wait: async () => {},
  }).catch((e: Error) => e)
  expect(error).toBeInstanceOf(Error)
  expect((error as Error).message).not.toContain(token)
  expect(offered).toBe(false)
  for (const file of await filesUnder(root)) expect(await fs.readFile(file, "utf8"), file).not.toContain(token)
})
