export * as ConnectorMarking from "./connector-marking.js"

import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises"
import path from "node:path"
import { Global } from "@opencode/util/global"
import { SecurityMarking } from "@opencode/util/security-marking"
import { deployment, type Scheme } from "@testifysec/marking"

// Other Badger processes may share the state file, so every decision reads it fresh and writes
// hold SQLite's write lock on a companion database. The operating system owns that lock: it is
// held for as long as the writer lives, however long that is, and released the instant the
// writer exits or crashes, so there is no owner to record and no stale lock to take over.
// node:sqlite is missing from the Bun this repo pins, so each runtime uses its own driver.
async function locked<T>(lock: string, run: () => Promise<T>): Promise<T> {
  await mkdir(path.dirname(lock), { recursive: true, mode: 0o700 })
  const db = process.versions.bun
    ? new (await import("bun:sqlite")).Database(lock)
    : new (await import("node:sqlite")).DatabaseSync(lock)
  try {
    await chmod(lock, 0o600)
    // No busy timeout: a synchronous wait would stall this process's event loop, and with it
    // any writer in this same process that holds the lock.
    db.exec("PRAGMA busy_timeout = 0")
    for (let attempt = 0; ; attempt++) {
      try {
        db.exec("BEGIN IMMEDIATE")
        break
      } catch (error) {
        // SQLITE_BUSY: Bun reports it as errno, node:sqlite as errcode.
        const busy =
          error &&
          typeof error === "object" &&
          (("errno" in error && error.errno === 5) || ("errcode" in error && error.errcode === 5))
        if (!busy) throw error
        if (attempt === 500) throw new Error("Connector marking state is locked")
      }
      await new Promise((resolve) => setTimeout(resolve, 10))
    }
    try {
      return await run()
    } finally {
      db.exec("ROLLBACK")
    }
  } finally {
    db.close()
  }
}

// The envelope's version key, which is therefore never a connector's name.
const envelope = "connector-markings"

const isObject = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value)

// The state file is the plain map {connector: marking} for us-gov, the scheme of every deployment
// before schemes existed, and {"connector-markings": 2, "scheme": <digest>, "markings": {...}} for any
// other. A file written under one scheme is refused under another: its markings have no place there.
export function store(
  file = path.join(Global.Path.state, "connector-markings.json"),
  policy = SecurityMarking.policy,
  scheme: () => Scheme = () => SecurityMarking.scheme(),
) {
  const markings = () => deployment(scheme())
  const read = () =>
    readFile(file, "utf8")
      .then((text) => {
        const parsed: unknown = JSON.parse(text)
        if (!isObject(parsed)) throw new Error("Invalid connector marking state")
        // Any file naming a version is an envelope and must be a whole, valid one: read as the plain
        // map, a malformed envelope would drop its scheme pin and its selections.
        const pinned = Object.hasOwn(parsed, envelope)
        if (pinned && (parsed[envelope] !== 2 || typeof parsed.scheme !== "string" || !isObject(parsed.markings)))
          throw new Error("Invalid connector marking state")
        if (!markings().owns(pinned ? parsed.scheme : undefined))
          throw new Error("Connector markings were stored under another marking scheme")
        return new Map<string, unknown>(Object.entries(pinned ? (parsed.markings as Record<string, unknown>) : parsed))
      })
      .catch((error: unknown) => {
        if (error && typeof error === "object" && "code" in error && error.code === "ENOENT")
          return new Map<string, unknown>()
        throw error
      })
  // Only a marking admin may choose a marking below the deployment's or below the connector's
  // current one (SecurityMarking.markingAdmin).
  const view = (values: Map<string, unknown>, connector: string, access: { mayLower: boolean }) => {
    const configured = policy()
    const d = markings()
    const selected = values.get(connector)
    // A stored entry that is not an allowed marking reads as the most restrictive marking.
    const marking =
      selected === undefined
        ? configured.marking
        : typeof selected === "string" && configured.allowed.includes(selected)
          ? selected
          : d.levels[d.levels.length - 1]
    const floor = (value: string) =>
      d.lowers(value, configured.marking) || (marking !== null && d.lowers(value, marking))
    return {
      ...configured,
      allowed: configured.allowed.filter((value) => access.mayLower || !floor(value)),
      marking,
      // The connector's own marking's classification, which under some schemes differs by level.
      classification: marking === null ? configured.classification : d.stamp(marking).classification,
    }
  }
  const get = async (connector: string, access = { mayLower: false }) => view(await read(), connector, access)
  let writing: Promise<unknown> = Promise.resolve()
  const set = (connector: string, marking: string, access = { mayLower: false }) => {
    const result = writing.then(() =>
      locked(file + ".lock", async () => {
        if (connector === envelope) throw new Error(`${JSON.stringify(envelope)} is a reserved name, not a connector`)
        if (!policy().allowed.includes(marking)) throw new Error("Marking is not enabled for this deployment")
        const values = await read()
        const before = view(values, connector, { mayLower: false })
        if (!access.mayLower && !before.allowed.includes(marking))
          throw new Error("Lowering a data marking requires an admin role")
        const next = new Map(values).set(connector, marking)
        const d = markings()
        const map = Object.fromEntries(next)
        const body = d.owns(undefined) ? map : { [envelope]: 2, scheme: d.scheme.digest, markings: map }
        await writeFile(file + ".tmp", JSON.stringify(body), { mode: 0o600 })
        await rename(file + ".tmp", file)
        return { ...view(next, connector, access), previous: before.marking }
      }),
    )
    writing = result.catch(() => {})
    return result
  }
  return { get, set }
}

let shared: ReturnType<typeof store> | undefined
export function current() {
  return (shared ??= store())
}
