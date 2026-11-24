import { describe, expect, test } from "bun:test"
import { chmod, stat, writeFile } from "node:fs/promises"
import path from "path"
import { Effect, Layer } from "effect"
import { Database } from "@opencode/core/database/database"
import { Global } from "@opencode/util/global"
import { tmpdir } from "./fixture/tmpdir"

// Read while the connection is open: SQLite may remove the sidecars on close.
const openModes = (filename: string) =>
  Effect.runPromise(
    Effect.gen(function* () {
      yield* Layer.build(Database.layer({ path: filename }))
      return yield* Effect.promise(() =>
        Promise.all(["", "-wal", "-shm"].map(async (suffix) => (await stat(filename + suffix)).mode & 0o777)),
      )
    }).pipe(Effect.scoped, Effect.provideService(Global.Service, Global.make({ data: path.dirname(filename) }))),
  )

describe.skipIf(process.platform === "win32")("Database file permissions", () => {
  test("creates the database and sidecars readable only by the owner", async () => {
    await using tmp = await tmpdir()

    expect(await openModes(path.join(tmp.path, "opencode.db"))).toEqual([0o600, 0o600, 0o600])
  })

  test("tightens an existing database and sidecars", async () => {
    await using tmp = await tmpdir()
    const filename = path.join(tmp.path, "opencode.db")
    await Promise.all(
      ["", "-wal", "-shm"].map(async (suffix) => {
        await writeFile(filename + suffix, "")
        await chmod(filename + suffix, 0o644)
      }),
    )

    expect(await openModes(filename)).toEqual([0o600, 0o600, 0o600])
  })
})

describe.skipIf(process.platform === "win32")("Database open", () => {
  // A replacement server opens the database while the server it replaces is still closing it. The
  // busy timeout must apply to the very first statement, or opening fails on that brief lock.
  test("waits for another process's lock instead of failing", async () => {
    await using tmp = await tmpdir()
    const filename = path.join(tmp.path, "opencode.db")
    await openModes(filename)
    const holder = Bun.spawn(
      [process.execPath, path.join(import.meta.dir, "fixture/sqlite-lock-holder.ts"), filename, "500"],
      {
        stdout: "pipe",
      },
    )
    await holder.stdout.getReader().read()

    expect(await openModes(filename)).toEqual([0o600, 0o600, 0o600])
    expect(await holder.exited).toBe(0)
  })
})
