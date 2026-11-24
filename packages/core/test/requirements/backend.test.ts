import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { execFile } from "node:child_process"
import { promisify } from "node:util"
import { watchRequirements, requirementsSource, project, gitTarget } from "@opencode/core/requirements/monitor"
import type { Projection } from "@opencode/core/requirements/projection"
import { credentials, snapshot, target } from "./fixtures"

const credential = credentials()

// A throwaway repository on a named branch: CI checks out a detached merge commit, so the
// test never reads this checkout's own HEAD.
async function scratchRepository() {
  const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "requirements-git-")))
  const repository = path.join(dir, "repo")
  const git = (args: string[]) => promisify(execFile)("git", args, { cwd: dir })
  await git(["init", "-q", "--initial-branch=main", repository])
  await git(["-C", repository, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "init"])
  return { dir, repository, git }
}

test("real Git Unicode-whitespace refs are refused, never silently changed to another branch", async () => {
  const { dir, repository, git } = await scratchRepository()
  try {
    await git(["-C", repository, "branch", "topic", "HEAD"])
    for (const whitespace of ["\u00a0", "\u2003"]) {
      const ref = `refs/heads/topic${whitespace}`
      await git(["-C", repository, "branch", `topic${whitespace}`, "HEAD"])
      await git(["-C", repository, "symbolic-ref", "HEAD", ref])
      expect((await git(["-C", repository, "symbolic-ref", "HEAD"])).stdout).toBe(`${ref}\n`)
      const selected = credentials({ directory: repository })
      let requests = 0
      const states: Projection[] = []
      const monitor = watchRequirements(
        {
          store: async () => selected,
          current: (s) => gitTarget(repository, s.selection),
          read: async () => {
            requests++
            return snapshot
          },
        },
        (value) => states.push(value),
      )
      try {
        await monitor.tick()
        expect(states.at(-1)?.state).toBe("unavailable")
        expect(requests).toBe(0)
      } finally {
        monitor.stop()
      }
    }
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
})

test("target changes abort in-flight reads; stale completion cannot repopulate; cleanup stops work", async () => {
  let current = target
  const pending: { signal: AbortSignal; finish: (value: typeof snapshot) => void }[] = []
  const states: Projection[] = []
  const monitor = watchRequirements(
    {
      store: async () => credential,
      current: async () => current,
      read: (_target, _token, signal) => new Promise((finish) => pending.push({ signal, finish })),
    },
    (s) => states.push(s),
    { interval: 100_000 },
  )
  await monitor.tick()
  expect(pending.length).toBe(1)
  current = { ...target, commit: "b".repeat(40) }
  await monitor.tick()
  expect(pending[0].signal.aborted).toBe(true)
  pending[0].finish(snapshot)
  await Promise.resolve()
  expect(states.at(-1)?.state).toBe("loading")
  pending[1].finish({ ...snapshot, target: current })
  await new Promise((resolve) => setTimeout(resolve, 0))
  expect(states.at(-1)?.state).toBe("available")
  monitor.stop()
  expect(pending[1].signal.aborted).toBe(true)
  const count = states.length
  await monitor.tick()
  expect(states.length).toBe(count)
})

test("disabled store has no git helpers or traffic; absent credential clears state", async () => {
  let calls = 0
  const states: Projection[] = []
  const monitor = watchRequirements(
    {
      store: async () => undefined,
      current: async () => {
        calls++
        return target
      },
      read: async () => {
        calls++
        return snapshot
      },
    },
    (s) => states.push(s),
  )
  await monitor.tick()
  monitor.stop()
  expect(calls).toBe(0)
  expect(states.at(-1)?.state).toBe("disabled")
})

test("local projection deduplicates subscribers, remote projection never runs git or network", async () => {
  let calls = 0
  const deps = {
    store: async () => credential,
    current: async () => target,
    read: async () => {
      calls++
      return snapshot
    },
  }
  const source = await requirementsSource("/work", () => credential, deps)
  const context = { session: "one", directory: "/work" }
  const stop = source!.subscribe(context, () => {})
  const stop2 = source!.subscribe(context, () => {})
  await new Promise((resolve) => setTimeout(resolve, 0))
  expect(calls).toBe(1)
  stop()
  stop2()
  const states: Projection[] = []
  const remote = await requirementsSource(undefined, () => credential, deps)
  remote!.subscribe(context, (s) => states.push(s))()
  expect(states.at(-1)?.state).toBe("unsupported")
  expect(calls).toBe(1)
  expect(await requirementsSource("/work", () => undefined, { ...deps, store: async () => undefined })).toBeUndefined()
})

test("historical decisions and unsummarized constraints cannot claim current satisfaction", () => {
  const view = project({
    ...snapshot,
    last_decision: {
      state: "historical",
      current_status: "unavailable",
      assignment_match: "custom_releases_only",
      created_at: "2026-09-01T00:00:00Z",
      verdict: "accepted",
      checks: [{ name: "\x1b[31mtest\u202e", result: "pass", detail: "not current" }],
    },
  } as Parameters<typeof project>[0])
  expect(view.lines.join("\n")).toContain("historical")
  expect(view.lines.join("\n")).toContain("Current status: unknown")
  expect(view.lines.join("\n")).toContain("signer constraints, Rego, timestamps, dependencies, expiry")
  expect(view.details.join("\n")).not.toMatch(/[\x1b\u202e]/)
})

test("backend reads real Git HEAD/ref and refuses another worktree", async () => {
  const { dir, repository } = await scratchRepository()
  try {
    const current = await gitTarget(repository, credentials({ directory: repository }).selection)
    expect(current.commit).toMatch(/^[0-9a-f]{40}$/)
    expect(current.ref).toBe("refs/heads/main")
    expect(current.repo).toBe(target.repo)
    await expect(gitTarget(repository, credential.selection)).rejects.toThrow("requirements-worktree")
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
})

test("expiry and removal atomically clear a prior success without more feature traffic", async () => {
  let saved: ReturnType<typeof credentials> | undefined = credential
  let calls = 0
  const states: Projection[] = []
  const monitor = watchRequirements(
    {
      store: async () => saved,
      current: async () => target,
      read: async () => {
        calls++
        return snapshot
      },
    },
    (s) => states.push(s),
  )
  await monitor.tick()
  await new Promise((resolve) => setTimeout(resolve, 0))
  expect(states.at(-1)?.state).toBe("available")
  saved = credentials({ expires: 1 })
  await monitor.tick()
  expect(states.at(-1)?.state).toBe("signin")
  expect(states.at(-1)?.details).toEqual([])
  saved = undefined
  await monitor.tick()
  expect(states.at(-1)?.state).toBe("disabled")
  expect(calls).toBe(1)
  monitor.stop()
})
