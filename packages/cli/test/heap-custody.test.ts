import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { Effect } from "effect"
import { MemoryCustody } from "@opencode/util/memory-custody"
import { Heap } from "../src/heap"

test("no heap snapshot is written once the process held a secret", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "heap-custody-"))
  try {
    MemoryCustody.restrict("Requirements bearer")
    const file = path.join(dir, "probe.heapsnapshot")
    await Effect.runPromise(Heap.snapshot(file))
    await expect(fs.lstat(file)).rejects.toThrow()
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
})

test("a secret taken while the v8 module loads still stops the snapshot", async () => {
  // A fresh process: the flag is one-way, and the earlier test already set it in this one.
  const script = `
    import { Effect } from "effect"
    import { MemoryCustody } from "@opencode/util/memory-custody"
    import { Heap } from ${JSON.stringify(path.join(import.meta.dir, "../src/heap.ts"))}
    let wrote = false
    // Restriction lands after the pre-check passed and before the writer runs.
    const load = async () => {
      MemoryCustody.restrict("Requirements bearer taken mid-load")
      return { writeHeapSnapshot: (target) => { wrote = true; return target } }
    }
    await Effect.runPromise(Heap.snapshot("/nonexistent/race.heapsnapshot", load))
    console.log(JSON.stringify({ restricted: MemoryCustody.restricted(), wrote }))
  `
  const child = Bun.spawn([process.execPath, "-e", script], { cwd: import.meta.dir, stdout: "pipe", stderr: "pipe" })
  const out = (await new Response(child.stdout).text()).trim().split("\n").at(-1)
  expect(await child.exited).toBe(0)
  expect(JSON.parse(out!)).toEqual({ restricted: true, wrote: false })
})
