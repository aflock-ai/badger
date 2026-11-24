import { expect, test } from "bun:test"
import { CredentialHolder } from "@opencode/core/requirements/holder"
import { requirementsSource, watchRequirements } from "@opencode/core/requirements/monitor"
import { credentials, snapshot, target } from "./fixtures"

test("the holder tells listeners about sign-in, sign-out and expiry, and stops when unsubscribed", async () => {
  const holder = new CredentialHolder()
  let events = 0
  const unsubscribe = holder.subscribe(() => events++)
  const first = credentials()
  holder.set(first)
  expect(holder.get()).toBe(first)
  holder.set(first)
  expect(events).toBe(1)
  holder.set(undefined)
  expect(events).toBe(2)
  holder.set(credentials({ expires: Date.now() + 20 }))
  const expired = Promise.withResolvers<void>()
  holder.subscribe(() => expired.resolve())
  await expired.promise
  expect(holder.get()?.bearer.expired).toBe(true)
  unsubscribe()
  const before = events
  holder.set(undefined)
  expect(events).toBe(before)
})

test("a change between the recheck after Git and the read it allows starts no read", async () => {
  const holder = new CredentialHolder()
  const original = credentials()
  holder.set(original)
  let stores = 0
  let reads = 0
  const states: string[] = []
  const monitor = watchRequirements(
    {
      // The second store read is the recheck after the Git check. It reads the old credential,
      // then sign-out lands before the monitor resumes: only the change event can catch that.
      store: async () => {
        const value = holder.get()
        if (++stores === 2) holder.set(undefined)
        return value
      },
      current: async () => target,
      read: async () => {
        reads++
        return snapshot
      },
      changes: holder.subscribe,
    },
    (value) => states.push(value.state),
    { interval: 100_000, watch: 100_000 },
  )
  await monitor.tick()
  for (let turn = 0; turn < 20; turn++) await new Promise<void>((resolve) => setImmediate(resolve))
  monitor.stop()
  expect(reads).toBe(0)
  expect(states).not.toContain("available")
})

test("requirementsSource over a holder hears its sign-out without being told to", async () => {
  const holder = new CredentialHolder()
  const original = credentials()
  holder.set(original)
  let reads = 0
  const source = await requirementsSource("/work", holder, {
    // A store that still answers with the old credential: only the holder's event can stop the read.
    store: async () => original,
    // Sign-out lands while the Git check runs; this source was given no `changes`.
    current: async () => {
      holder.set(undefined)
      return target
    },
    read: async () => {
      reads++
      return snapshot
    },
  })
  const result = await source!.read({ session: "one", directory: "/work" }, new AbortController().signal)
  expect(reads).toBe(0)
  expect(result.state).not.toBe("available")
})
