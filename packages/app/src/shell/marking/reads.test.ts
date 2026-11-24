import { expect, test } from "bun:test"
import { MarkingReads } from "./reads"

/** A read whose answer the test chooses, and when. */
function reads() {
  const pending: { key: string; resolve: (marking: string | null) => void; reject: () => void }[] = []

  const controller = MarkingReads.make(
    (key) =>
      new Promise<string | null>((resolve, reject) => pending.push({ key, resolve, reject: () => reject(new Error("x")) })),
    () => {},
  )

  return { controller, pending }
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 0))

test("a server that reconnects with a higher marking shows the new marking", async () => {
  const { controller, pending } = reads()
  controller.sync([{ key: "a", live: true }])
  pending.shift()!.resolve("UNCLASSIFIED")
  await settle()
  expect(controller.marking([{ key: "a", live: true }])).toEqual({ type: "marking", marking: "UNCLASSIFIED" })

  // The server restarts: its connection drops, then comes back with CUI.
  controller.sync([{ key: "a", live: false }])
  expect(controller.marking([{ key: "a", live: false }])).toEqual({ type: "loading" })
  controller.sync([{ key: "a", live: true }])
  expect(pending).toHaveLength(1)
  pending.shift()!.resolve("CUI")
  await settle()
  expect(controller.marking([{ key: "a", live: true }])).toEqual({ type: "marking", marking: "CUI" })
})

test("a server removed or unhealthy is read again when it returns", async () => {
  const { controller, pending } = reads()
  controller.sync([{ key: "a", live: true }])
  pending.shift()!.resolve("UNCLASSIFIED")
  await settle()
  controller.sync([])
  expect(controller.marking([])).toEqual({ type: "none" })
  controller.sync([{ key: "a", live: true }])
  expect(pending).toHaveLength(1)
  pending.shift()!.resolve("CUI")
  await settle()
  expect(controller.marking([{ key: "a", live: true }])).toEqual({ type: "marking", marking: "CUI" })
})

test("a read from before a reconnect cannot overwrite the newer one", async () => {
  const { controller, pending } = reads()
  controller.sync([{ key: "a", live: true }])
  const stale = pending.shift()!
  controller.sync([{ key: "a", live: false }])
  controller.sync([{ key: "a", live: true }])
  pending.shift()!.resolve("CUI")
  stale.resolve("UNCLASSIFIED")
  await settle()
  expect(controller.marking([{ key: "a", live: true }])).toEqual({ type: "marking", marking: "CUI" })
})

test("a failed read is unavailable, and a live server keeps its read until it changes", async () => {
  const { controller, pending } = reads()
  controller.sync([{ key: "a", live: true }])
  pending.shift()!.reject()
  await settle()
  expect(controller.marking([{ key: "a", live: true }])).toEqual({ type: "unavailable" })
  controller.sync([{ key: "a", live: true }])
  expect(pending).toHaveLength(0)
})

test("a server reporting a marking the app does not know is unavailable, and it is logged", async () => {
  const warned: unknown[][] = []
  const warn = console.warn
  console.warn = (...args: unknown[]) => void warned.push(args)
  try {
    const { controller, pending } = reads()
    controller.sync([{ key: "a", live: true }])
    pending.shift()!.resolve("SECRET")
    await settle()
    expect(controller.marking([{ key: "a", live: true }])).toEqual({ type: "unavailable" })
    expect(warned).toHaveLength(1)
    expect(String(warned[0]![0])).toContain("unknown")
    expect(warned[0]).toContain("a")
  } finally {
    console.warn = warn
  }
})

test("a read carries the server's scheme into the banner", async () => {
  const corporate = { name: "corporate", sha256: "sha256:corporate", levels: ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] }
  const controller = MarkingReads.make(async () => ({ marking: "INTERNAL", scheme: corporate }), () => {})
  controller.sync([{ key: "a", live: true }])
  await settle()
  expect(controller.marking([{ key: "a", live: true }])).toEqual({ type: "marking", marking: "INTERNAL" })
})
