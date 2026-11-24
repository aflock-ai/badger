import { expect, test } from "bun:test"
import { execFile } from "node:child_process"
import { promisify } from "node:util"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { remoteRepository, repositoryPrompt } from "@opencode/core/requirements/remote"
import { connect } from "@opencode/core/requirements/device"
import { platform, scopes } from "@opencode/core/requirements/schema"

const repos = [
  { repo: "github.com/acme/other", repository_id: "321" },
  { repo: "github.com/acme/project", repository_id: "123" },
]

test("remote parser returns only a normalized repository hint, never URL credentials", () => {
  for (const url of [
    "https://github.com/acme/project.git",
    "http://github.com/acme/project",
    "git://github.com/acme/project.git",
    "git@github.com:acme/project.git",
    "ssh://git@github.com/acme/project.git",
    "ssh://git@github.com:22/acme/project.git",
    "https://user:synthetic-secret@github.com/ACME/Project.git/",
    "https://x:synthetic-secret@pushgate.dev/gh/acme/project.git",
    "https://pushgate.dev/github.com/acme/project.git",
    "https://pushgate.dev/r/github.com/acme/project.git",
    "git@pushgate.dev:gh/acme/project.git",
    "ssh://git@pushgate.dev/github.com/acme/project",
  ])
    expect(remoteRepository(url)).toBe("github.com/acme/project")
})

test("remote parser refuses spoofed hosts, unsafe paths and malformed inputs without exceptions", () => {
  for (const url of [
    "https://github.com.evil.test/acme/project.git",
    "https://github.com@evil.test/acme/project.git",
    "https://evil.test/github.com/acme/project.git",
    "https://pushgate.dev.evil.test/gh/acme/project.git",
    "https://github%2ecom/acme/project.git",
    "https://github.com./acme/project.git",
    "https://github.com:9999/acme/project.git",
    "https://github.com/acme/../acme/project.git",
    "https://github.com/acme/%70roject.git",
    "https://github.com/acme/project.git/extra",
    "https://github.com/acme/project.git?token=synthetic-secret",
    "https://github.com/acme/project.git#secret",
    "https://github.com\\@evil.test/acme/project.git",
    "https://github.com/acme/project.git\n",
    "https://pushgate.dev/acme/project.git",
    "https://pushgate.dev/r/evil.test/acme/project.git",
    "file:///github.com/acme/project.git",
    "ext::arbitrary-command",
    "/local/acme/project",
    "not a URL synthetic-secret",
  ])
    expect(remoteRepository(url)).toBeUndefined()
})

test("connect still requires selection and keeps the catalog ID when the human overrides the hint", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "badger-selection-"))
  const git = (...args: string[]) => promisify(execFile)("git", args, { cwd: directory })
  try {
    await git("init", "-q")
    await git("remote", "add", "origin", "https://x:remote-secret@pushgate.dev/gh/acme/project.git")
    const requests: string[] = []
    let selections = 0
    const saved = await connect({
      directory,
      signal: new AbortController().signal,
      onCode: async () => {},
      wait: async () => {},
      select: async (catalog) => {
        selections++
        const prompt = await repositoryPrompt(directory, catalog)
        expect(prompt.initialValue).toBe(1)
        // The human can choose a different catalog entry; the hint cannot override that choice.
        return prompt.options[0]!.value
      },
      send: async (url, init) => {
        requests.push(url)
        expect(JSON.stringify(init)).not.toContain("remote-secret")
        if (url.endsWith("/code"))
          return Response.json({
            device_code: "device-secret",
            user_code: "ABCD-EFGH",
            verification_uri: `${platform}/auth/cli/device`,
            verification_uri_complete: `${platform}/auth/cli/device?user_code=ABCD-EFGH`,
            expires_in: 600,
            interval: 1,
          })
        if (url.endsWith("/token"))
          return Response.json({
            access_token: "independent-token",
            token_type: "Bearer",
            expires_in: 3600,
            scope: scopes,
          })
        return Response.json({
          tenant_id: "11111111-1111-4111-8111-111111111111",
          github_app_connected: true,
          partial: false,
          repositories: repos.map((r) => ({
            id: r.repo,
            repository_id: r.repository_id,
            full_name: r.repo.slice("github.com/".length),
            clone_url: `https://${r.repo}.git`,
            private: true,
            installation_id: "456",
            account_login: "acme",
            account_type: "Organization",
          })),
        })
      },
    })
    expect(selections).toBe(1)
    expect(saved.selection.repo).toBe(repos[0]!.repo)
    expect(saved.selection.repository_id).toBe("321")
    expect(saved.selection.directory).toBe(directory)
    expect(saved.bearer.authorization()).toBe("Bearer independent-token")
    expect(requests).toEqual([
      `${platform}/oauth/device/code`,
      `${platform}/oauth/device/token`,
      `${platform}/api/pushgate/repositories`,
    ])
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})

test("directory-scoped local discovery suggests only unique authorized matches and never changes remotes", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "badger-hint-"))
  const git = (...args: string[]) => promisify(execFile)("git", args, { cwd: directory })
  try {
    expect((await repositoryPrompt(directory, repos)).initialValue).toBeUndefined()
    await git("init", "--initial-branch=main")
    expect((await repositoryPrompt(directory, repos)).initialValue).toBeUndefined()
    await git("remote", "add", "origin", "https://user:synthetic-secret@github.com/acme/project.git")
    await git("remote", "set-url", "--push", "origin", "https://x:synthetic-secret@pushgate.dev/gh/acme/project.git")
    const before = await git("config", "--local", "--list")
    const prompt = await repositoryPrompt(directory, repos)
    expect(prompt.initialValue).toBe(1)
    expect(prompt.options[1]).toEqual({ value: 1, label: "github.com/acme/project (#123)" })
    expect(JSON.stringify(prompt)).not.toContain("synthetic-secret")
    expect((await git("config", "--local", "--list")).stdout === before.stdout).toBe(true)
    expect((await repositoryPrompt(directory, [repos[0]!])).initialValue).toBeUndefined()
    await git("remote", "add", "upstream", "git@github.com:acme/other.git")
    await git("config", "branch.main.remote", "origin")
    expect((await repositoryPrompt(directory, repos)).initialValue).toBeUndefined()
    await git("remote", "remove", "upstream")
    await git("remote", "set-url", "--push", "origin", "https://pushgate.dev/github.com/acme/other.git")
    expect((await repositoryPrompt(directory, repos)).initialValue).toBeUndefined()
    await git("remote", "set-url", "--push", "origin", "https://pushgate.dev/github.com/acme/project.git")
    await git("worktree", "add", "--orphan", "-b", "hint-worktree", path.join(directory, "linked"))
    expect((await repositoryPrompt(path.join(directory, "linked"), repos)).initialValue).toBe(1)
    expect((await repositoryPrompt(path.join(directory, "missing"), repos)).initialValue).toBeUndefined()
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})
