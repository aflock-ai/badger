import { expect, setSystemTime, test } from "bun:test"
import { requirementsSource, watchRequirements } from "@opencode/core/requirements/monitor"
import type { Projection } from "@opencode/core/requirements/projection"
import type { Requirements } from "@opencode/core/requirements/schema"
import { credentials, snapshot, target } from "./fixtures"

const credential = credentials()
const settle = () => new Promise<void>((resolve) => setImmediate(resolve))

test("30-second refresh keeps the snapshot, emits only changed projections, and clears failures", async () => {
  setSystemTime(1_000_000)
  const states: Projection[] = []
  const pending: ReturnType<typeof Promise.withResolvers<Requirements>>[] = []
  const monitor = watchRequirements(
    {
      store: async () => credential,
      current: async () => target,
      read: () => {
        const reply = Promise.withResolvers<Requirements>()
        pending.push(reply)
        return reply.promise
      },
    },
    (value) => states.push(value),
    { interval: 100_000 },
  )
  try {
    await monitor.tick()
    pending[0].resolve(snapshot)
    await settle()
    expect(states.map((value) => value.state)).toEqual(["loading", "available"])
    setSystemTime(1_029_999)
    await monitor.tick()
    expect(pending).toHaveLength(1)
    for (let i = 1; i <= 3; i++) {
      setSystemTime(1_000_000 + i * 30_000)
      await monitor.tick()
      expect(pending).toHaveLength(i + 1)
      expect(states).toHaveLength(2)
      pending[i].resolve(structuredClone(snapshot))
      await settle()
      expect(states).toHaveLength(2)
    }
    setSystemTime(1_120_000)
    await monitor.tick()
    pending[4].resolve({
      ...snapshot,
      connection: { ...snapshot.connection, generation: snapshot.connection.generation + 1 },
    })
    await settle()
    expect(states).toHaveLength(3)
    expect(states.at(-1)?.details).not.toEqual(states[1].details)
    setSystemTime(1_150_000)
    await monitor.tick()
    pending[5].reject(new Error("offline"))
    await settle()
    expect(states.at(-1)).toEqual({ state: "unavailable", lines: ["Requirements unavailable."], details: [] })
  } finally {
    monitor.stop()
    setSystemTime()
  }
})

test("scope and credential changes invalidate immediately and abort late background results", async () => {
  for (const field of ["commit", "ref", "repo", "repository_id", "token", "directory", "expires"] as const) {
    let current = target
    let saved = credentials()
    const states: Projection[] = []
    const pending: { signal: AbortSignal; reply: ReturnType<typeof Promise.withResolvers<Requirements>> }[] = []
    const monitor = watchRequirements(
      {
        store: async () => saved,
        current: async () => current,
        read: (_target, _token, signal) => {
          const reply = Promise.withResolvers<Requirements>()
          pending.push({ signal, reply })
          return reply.promise
        },
      },
      (value) => states.push(value),
      { interval: 100_000, refresh: 0 },
    )
    try {
      await monitor.tick()
      pending[0].reply.resolve(snapshot)
      await settle()
      await monitor.tick()
      expect(states.at(-1)?.state).toBe("available")
      if (field === "commit" || field === "ref")
        current = { ...target, [field]: field === "commit" ? "b".repeat(40) : "refs/heads/other" }
      else
        saved = credentials({
          ...saved.fields,
          [field]: field === "expires" ? saved.fields.expires - 1 : `${saved.fields[field]}-other`,
        })
      await monitor.tick()
      expect(states.at(-1)).toEqual({
        state: "loading",
        lines: ["Reading requirements; current status unknown."],
        details: [],
      })
      expect(pending[1].signal.aborted).toBe(true)
      const count = states.length
      pending[1].reply.resolve(snapshot)
      await settle()
      expect(states).toHaveLength(count)
      monitor.stop()
      expect(pending[2].signal.aborted).toBe(true)
      pending[2].reply.resolve({ ...snapshot, target: current })
      await settle()
      await monitor.tick()
      expect(states).toHaveLength(count)
      expect(pending).toHaveLength(3)
    } finally {
      monitor.stop()
    }
  }
})

test("subscribers get no duplicate initial loading; tool reads fetch fresh and final unsubscribe aborts", async () => {
  let calls = 0
  const signals: AbortSignal[] = []
  const source = await requirementsSource("/work", () => credential, {
    store: async () => credential,
    current: async () => target,
    read: async (_target, _token, signal) => {
      signals.push(signal)
      calls++
      if (calls > 1) throw new Error("offline")
      return snapshot
    },
  })
  const context = { session: "one", directory: "/work" }
  const states: Projection[] = []
  const stop = source!.subscribe(context, (value) => states.push(value))
  const stop2 = source!.subscribe(context, () => {})
  try {
    await settle()
    expect(states.map((value) => value.state)).toEqual(["loading", "available"])
    expect((await source!.read(context, new AbortController().signal)).state).toBe("unavailable")
    expect(calls).toBe(2)
    stop()
    expect(signals[0].aborted).toBe(false)
    stop2()
    expect(signals[0].aborted).toBe(true)
  } finally {
    stop()
    stop2()
  }
})
