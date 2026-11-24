import { afterEach, beforeEach, expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { launch, optOut } from "@opencode/core/requirements/launch"
import { platform } from "@opencode/core/requirements/schema"
import {
  legacyCredentialFile,
  loadSelection,
  saveSelection,
  selectionFile,
} from "@opencode/core/requirements/selection"

const token = "pgr_launch_probe_3d5f7a9c1e2b4d6f8a0c2e4f6a8b0d2f"
const entry = (name: string, repository_id: string) => ({
  id: `github.com/acme/${name}`,
  repository_id,
  full_name: `acme/${name}`,
  clone_url: `https://github.com/acme/${name}.git`,
  private: true,
  installation_id: "7",
  account_login: "acme",
  account_type: "Organization",
})

function platformFake(repositories = [entry("widgets", "42"), entry("gadgets", "43")]) {
  const seen: string[] = []
  const send = async (url: string) => {
    seen.push(url)
    const json = (body: unknown) => Response.json(body)
    if (url.endsWith("/oauth/device/code"))
      return json({
        device_code: "dc-1",
        user_code: "ABCD-1234",
        verification_uri: `${platform}/auth/cli/device`,
        verification_uri_complete: `${platform}/auth/cli/device?user_code=ABCD-1234`,
        expires_in: 600,
        interval: 1,
      })
    if (url.endsWith("/oauth/device/token"))
      return json({
        access_token: token,
        token_type: "Bearer",
        expires_in: 3600,
        scope: "pushgate:repo-read pushgate:policy-read",
      })
    if (url.endsWith("/api/pushgate/repositories"))
      return json({
        tenant_id: "11111111-1111-4111-8111-111111111111",
        github_app_connected: true,
        partial: false,
        repositories,
      })
    return new Response("{}", { status: 404 })
  }
  return { send, seen }
}

let root: string
let environment: Record<string, string>
let directory: string

beforeEach(async () => {
  root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "requirements-launch-")))
  environment = { HOME: root, XDG_CONFIG_HOME: path.join(root, "config") }
  directory = path.join(root, "work")
  await fs.mkdir(directory)
})

afterEach(() => fs.rm(root, { recursive: true, force: true }))

const run = (options: {
  optIn?: boolean
  send: ReturnType<typeof platformFake>["send"]
  choose?: () => Promise<number>
}) => {
  const notices: string[] = []
  const result = launch({
    directory,
    environment,
    optIn: options.optIn ?? false,
    signal: new AbortController().signal,
    notify: (text) => notices.push(text),
    choose: options.choose ?? (async () => 1),
    send: options.send,
    wait: async () => {},
  })
  return { notices, result }
}

test("a directory that never opted in starts without Requirements and no network", async () => {
  const api = platformFake()
  expect(await run({ send: api.send }).result).toBeUndefined()
  expect(api.seen).toEqual([])
})

test("opting in signs in, saves only the chosen repository, and holds the bearer in memory", async () => {
  const api = platformFake()
  const { notices, result } = run({ optIn: true, send: api.send })
  const holder = await result
  expect(notices.join("")).toContain("ABCD-1234")
  expect(holder?.get()?.selection.repo).toBe("github.com/acme/gadgets")
  expect(await loadSelection(selectionFile(environment, directory))).toEqual({
    version: 1,
    enabled: true,
    directory,
    repo: "github.com/acme/gadgets",
    repository_id: "43",
  })
  const text = await fs.readFile(selectionFile(environment, directory), "utf8")
  expect(text).not.toContain(token)
})

test("an opted-in directory signs in at each start and reuses its saved repository without asking", async () => {
  await saveSelection(
    { version: 1, enabled: true, directory, repo: "github.com/acme/widgets", repository_id: "42" },
    selectionFile(environment, directory),
  )
  const api = platformFake()
  let asked = false
  const holder = await run({
    send: api.send,
    choose: async () => {
      asked = true
      return 1
    },
  }).result
  expect(asked).toBe(false)
  expect(holder?.get()?.selection).toMatchObject({ repo: "github.com/acme/widgets", repository_id: "42" })
  expect(api.seen.some((url) => url.endsWith("/oauth/device/code"))).toBe(true)
})

test("a saved repository the catalog no longer authorizes starts without Requirements and says why", async () => {
  await saveSelection(
    { version: 1, enabled: true, directory, repo: "github.com/acme/widgets", repository_id: "42" },
    selectionFile(environment, directory),
  )
  const { notices, result } = run({ send: platformFake([entry("gadgets", "43")]).send })
  expect(await result).toBeUndefined()
  expect(notices.at(-1)).toContain("no longer authorized")
})

test("a failed sign-in starts without Requirements, with the fixed reason and no saved selection", async () => {
  const { notices, result } = run({ optIn: true, send: async () => Response.json({}, { status: 503 }) })
  expect(await result).toBeUndefined()
  expect(notices.at(-1)).toContain("sign-in service is unavailable")
  expect(await loadSelection(selectionFile(environment, directory))).toBeUndefined()
})

test("opting out removes this directory's selection, so the next launch starts without Requirements", async () => {
  await saveSelection(
    { version: 1, enabled: true, directory, repo: "github.com/acme/widgets", repository_id: "42" },
    selectionFile(environment, directory),
  )
  expect(await optOut({ directory, environment })).toBe(true)
  expect(await loadSelection(selectionFile(environment, directory))).toBeUndefined()
  const api = platformFake()
  expect(await run({ send: api.send }).result).toBeUndefined()
  expect(api.seen).toEqual([])
})

const choice = (dir: string, id = "42") =>
  ({ version: 1, enabled: true, directory: dir, repo: "github.com/acme/widgets", repository_id: id }) as const

test("opting out with no choice for this directory has nothing to remove", async () => {
  expect(await optOut({ directory, environment })).toBe(false)
})

test("concurrent opt-ins and opt-outs across directories never lose or touch another directory's choice", async () => {
  const dirs = await Promise.all(
    Array.from({ length: 30 }, async (_, index) => {
      const dir = path.join(root, `project-${index}`)
      await fs.mkdir(dir)
      return dir
    }),
  )
  // A third opt in, a third opt out, a third keep the choice they had; all at once.
  for (const dir of dirs.slice(10)) await saveSelection(choice(dir), selectionFile(environment, dir))
  await Promise.all(
    dirs.map((dir, index) => {
      if (index < 10)
        return launch({
          directory: dir,
          environment,
          optIn: true,
          signal: new AbortController().signal,
          notify: () => {},
          choose: async () => 0,
          send: platformFake().send,
          wait: async () => {},
        })
      if (index < 20) return optOut({ directory: dir, environment })
      return loadSelection(selectionFile(environment, dir))
    }),
  )
  const left = await Promise.all(dirs.map((dir) => loadSelection(selectionFile(environment, dir))))
  expect(
    left.map((value, index) => (index < 10 ? value?.repository_id : index < 20 ? value : value?.directory)),
  ).toEqual([...Array(10).fill("42"), ...Array(10).fill(undefined), ...dirs.slice(20)])
})

test("opting out also deletes a 1.x on-disk bearer, unread", async () => {
  const legacy = legacyCredentialFile(environment)
  await fs.mkdir(path.dirname(legacy), { recursive: true, mode: 0o700 })
  await fs.writeFile(legacy, "pgr_legacy_plaintext_bearer", { mode: 0o600 })
  expect(await optOut({ directory, environment })).toBe(false)
  expect(await fs.stat(legacy).catch(() => undefined)).toBeUndefined()
})
