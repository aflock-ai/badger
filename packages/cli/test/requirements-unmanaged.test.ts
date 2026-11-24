import { expect, test } from "bun:test"
import { Effect, Option } from "effect"
import { Requirements } from "../src/requirements"

// Ported from 1.x testifysec/requirements/launch.test.ts: a build that is not managed has no Requirements.
// Source runs are not managed, so neither flag may sign in, prompt, or touch the selection file.
test("a build that is not managed has no Requirements, whatever the flag says", async () => {
  const fetches: unknown[] = []
  const original = globalThis.fetch
  globalThis.fetch = Object.assign(
    (...args: unknown[]) => (fetches.push(args), Promise.reject(new Error("no network"))),
    {
      preconnect: () => {},
    },
  ) as typeof fetch
  try {
    for (const requested of [Option.none(), Option.some(true), Option.some(false)])
      expect(await Effect.runPromise(Requirements.start(requested))).toEqual({ server: [], tui: [] })
  } finally {
    globalThis.fetch = original
  }
  expect(fetches).toEqual([])
})
