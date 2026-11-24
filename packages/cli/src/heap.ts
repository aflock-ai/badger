import { Global } from "@opencode/util/global"
import { MemoryCustody } from "@opencode/util/memory-custody"
import { Effect, Queue } from "effect"
import path from "node:path"

export const listen = Effect.gen(function* () {
  const global = yield* Global.Service
  if (process.platform === "win32") return
  const signals = yield* Queue.dropping<void>(1)
  yield* Effect.acquireRelease(
    Effect.sync(() => {
      const handler = () => Queue.offerUnsafe(signals, undefined)
      process.on("SIGUSR1", handler)
      return handler
    }),
    (handler) => Effect.sync(() => process.off("SIGUSR1", handler)),
  )
  yield* Queue.take(signals).pipe(
    Effect.andThen(
      Effect.suspend(() => {
        const file = path.join(
          global.log,
          `heap-${process.pid}-${new Date().toISOString().replace(/[:.]/g, "")}.heapsnapshot`,
        )
        return snapshot(file)
      }),
    ),
    Effect.forever,
    Effect.forkScoped({ startImmediately: true }),
  )
})

/** Writes a heap snapshot, unless this process has held a secret that must never reach disk. */
export const snapshot = (
  file: string,
  load: () => Promise<{ writeHeapSnapshot: (file: string) => string }> = () => import("node:v8"),
) =>
  Effect.gen(function* () {
    const refused = Effect.logWarning("heap snapshot refused: this process holds a secret", {
      reason: MemoryCustody.why(),
    })
    if (MemoryCustody.restricted()) return yield* refused
    yield* Effect.logInfo("writing heap snapshot", { path: file })
    const { writeHeapSnapshot } = yield* Effect.tryPromise(load)
    // Again in the same synchronous step as the write: a secret may have arrived while v8 loaded.
    const written = yield* Effect.try(() => (MemoryCustody.restricted() ? false : (writeHeapSnapshot(file), true)))
    if (!written) return yield* refused
    yield* Effect.logInfo("heap snapshot written", { path: file })
  }).pipe(Effect.catchCause((cause) => Effect.logError("failed to write heap snapshot", { path: file, cause })))

export * as Heap from "./heap"
