export * as ManagedFlow from "./managed-flow"

import { dlopen } from "bun:ffi"
import { closeSync, fsyncSync, fstatSync, ftruncateSync, openSync, readFileSync, writeFileSync } from "node:fs"
import path from "node:path"
import { bottom, dominates, format, join, NoBanner, parse, type Marking } from "@testifysec/marking"

/**
 * The high-water check for enclave service connectors (testifysec/CONNECTORS.md, "Session
 * high-water and flow checks"). A connector's classification is the one its administrator set in
 * the signed profile, and nothing is read from the content it returns.
 *
 * There is one label per Badger state directory, as the connector pod keeps one per workspace:
 * the join of the markings of every connector this state directory has ever called. Sessions,
 * subagents, forks and resumes all share it, so no lineage has to be tracked. A call to a
 * connector, read or write, needs that connector's marking to dominate the label: a write would
 * put content there, and a read's arguments (a search query) would too. No write down. A send to
 * the model gateway needs the gateway's accredited marking to dominate the label, which the gateway
 * ceiling (admission refuses a connector above the gateway) already guarantees.
 *
 * The label rises when a call is allowed, before the connector runs, and never goes down: a call
 * that is then cancelled or declined still raises it, which over-labels and never under-labels.
 * Every refusal, and every decision at or into a label above the lowest, is appended to the audit
 * file and flushed to disk, and a transfer whose decision cannot be written is refused. At start the label is rebuilt as the
 * join of every allowed call the file records; a file that cannot be read stops the start. One
 * process owns the file at a time, so no other process's calls go unseen. Only an administrator
 * resets the label, by removing the state directory.
 */

export interface Policy {
  /** The marking the model gateway is accredited for. */
  readonly gateway: string
  /** Each admitted connector's marking, set by the administrator in the signed profile. */
  readonly connectors: Readonly<Record<string, string>>
  /**
   * The highest label this workspace may reach (BADGER_RAISE_CEILING), set by the workspace
   * controller that created it. A call that would lift the label above it is not run here: the user
   * is offered a copy of the workspace at the higher level instead. Unset (laptop builds): no ceiling.
   */
  readonly ceiling?: string
}

/** A call refused at the ceiling, for the app to offer "continue in a copy" or "cancel". */
export interface Raise {
  readonly sessionID?: string
  readonly server: string
  readonly tool: string
  /** The level the copy would need. */
  readonly level: string
}

export interface Decision {
  readonly time: string
  /** The session that asked, for the record only: the label is shared by every session. */
  readonly sessionID?: string
  readonly sink: string
  readonly label: string
  readonly accredited: string
  readonly allowed: boolean
  readonly tool?: string
}

export class Refused extends Error {
  override name = "Refused"
}

/** Decisions kept in memory; the audit file has them all. */
const keptDecisions = 256

export function make(policy: Policy, options: { readonly audit?: string } = {}) {
  const gateway = parse(policy.gateway)
  const connectors = new Map(Object.entries(policy.connectors).map(([name, value]) => [name, parse(value)]))
  const ceiling = policy.ceiling === undefined ? undefined : parse(policy.ceiling)
  const decisions: Decision[] = []
  let label: Marking = bottom
  let pending: Raise | undefined
  const listeners = new Set<(label: string) => void>()

  // One process owns the audit file at a time; then the label is the join of every allowed call it
  // records. Any error reading it but a missing file stops the start.
  const release = options.audit ? own(options.audit) : () => {}
  if (options.audit) {
    const audit = options.audit
    const fail = (what: string, cause: unknown) => {
      release()
      return new Error(`${what} cannot be read, so this state directory's classification is unknown`, { cause })
    }
    let recorded = ""
    try {
      recorded = readFileSync(audit, "utf8")
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw fail(audit, error)
    }
    for (const [index, line] of recorded.split("\n").entries()) {
      if (line.trim() === "") continue
      try {
        const entry = JSON.parse(line) as Decision
        if (typeof entry.sink !== "string" || typeof entry.allowed !== "boolean") throw new Error("not a decision")
        if (entry.allowed && entry.sink.startsWith("connector:")) label = join(label, parse(entry.accredited))
      } catch (error) {
        throw fail(`${audit} line ${index + 1}`, error)
      }
    }
  }

  // The directory is flushed once, after the file's first write, so the file itself survives a crash.
  let directorySynced = false
  let stopped = false
  /** Records a decision and flushes it to disk; false when that fails. */
  const decide = (decision: Omit<Decision, "time">) => {
    const entry = { time: new Date().toISOString(), ...decision }
    // The audit file keeps every decision; memory keeps the latest few for a running server.
    decisions.push(entry)
    if (decisions.length > keptDecisions) decisions.splice(0, decisions.length - keptDecisions)
    if (!options.audit) return true
    // After a failed write the record may hold part of a line, so nothing more is written or
    // allowed until a restart reads it (and stops if it cannot).
    if (stopped) return false
    try {
      const fd = openSync(options.audit, "a", 0o600)
      try {
        const size = fstatSync(fd).size
        try {
          // The whole record or a failure: writeFileSync on a descriptor repeats short writes.
          writeFileSync(fd, JSON.stringify(entry) + "\n")
          fsyncSync(fd)
        } catch (error) {
          // Undo a partial record where possible, so a restart reads only whole lines.
          try {
            ftruncateSync(fd, size)
            fsyncSync(fd)
          } catch {}
          throw error
        }
      } finally {
        closeSync(fd)
      }
      if (!directorySynced) {
        const dir = openSync(path.dirname(options.audit), "r")
        try {
          fsyncSync(dir)
        } finally {
          closeSync(dir)
        }
        directorySynced = true
      }
      return true
    } catch {
      stopped = true
      return false
    }
  }
  const unrecorded = "its decision could not be written to the audit record"
  /**
   * Checks one transfer; the refusal message, or undefined when allowed. `next` is the label once
   * it is allowed: a call that lifts the label off the lowest is recorded too.
   */
  const check = (
    decision: Omit<Decision, "time" | "label" | "accredited" | "allowed">,
    accredited: Marking,
    next: Marking = label,
  ) => {
    // After a failed write nothing is allowed, at the lowest label too, until a restart.
    if (stopped) return unrecorded
    const allowed = dominates(accredited, label)
    const above = !dominates(bottom, next)
    const recorded = (!allowed || above) && decide({ ...decision, label: format(label), accredited: format(accredited), allowed })
    if (allowed && (recorded || !above)) return undefined
    return allowed ? unrecorded : `this workspace holds ${format(label)} content and ${decision.sink} is accredited for ${format(accredited)}`
  }

  return {
    decisions: decisions as readonly Decision[],
    /** Gives up ownership of the audit file (also done when the process exits). */
    close: release,
    /** The current label of this state directory. */
    label: () => label,
    /** The latest call refused at the ceiling, if any: what the app offers to continue in a copy. */
    pendingRaise: () => pending,
    /** Checks a request to the model gateway: refused unless the gateway's marking dominates the label. */
    send: (sessionID?: string) => {
      const refusal = check({ ...(sessionID ? { sessionID } : {}), sink: "gateway" }, gateway)
      if (refusal) throw new Refused(`The request was not sent: ${refusal}.`)
    },
    /**
     * Checks a call to a connector, read or write, and raises the label to the connector's marking
     * when it is allowed. Returns the refusal message, or undefined when the connector's marking
     * dominates the label. A tool of another server is not checked.
     */
    call: (input: { readonly sessionID?: string; readonly server: string; readonly tool: string }) => {
      const accredited = connectors.get(input.server)
      if (!accredited) return undefined
      const decision = { ...(input.sessionID ? { sessionID: input.sessionID } : {}), sink: `connector:${input.server}`, tool: input.tool }
      // A label no banner prints (controlled unclassified with FGI, AEA or non-IC groups) is refused.
      let next: Marking
      try {
        next = join(label, accredited)
      } catch (error) {
        if (!(error instanceof NoBanner)) throw error
        decide({ ...decision, label: format(label), accredited: format(accredited), allowed: false })
        return `${input.tool} was refused: ${error.message}.`
      }
      // Above the ceiling the call is not run here, and the label does not move: the controller's
      // connector gateway would refuse it too. The user continues in a copy, or cancels.
      if (ceiling && !dominates(ceiling, next)) {
        const refused = { ...decision, label: format(label), accredited: format(accredited), allowed: false }
        if (stopped || !decide(refused)) return `${input.tool} was refused: ${unrecorded}.`
        const level = format(next)
        pending = { ...(input.sessionID ? { sessionID: input.sessionID } : {}), server: input.server, tool: input.tool, level }
        return `This read is ${level}. Continue in a ${level} copy of this workspace, or cancel. (${input.tool} was not run.)`
      }
      const refusal = check(decision, accredited, next)
      if (refusal === unrecorded) return `${input.tool} was refused: ${refusal}.`
      if (refusal)
        return `${input.tool} was refused: ${refusal}, and its arguments would carry that content there (no write down). An administrator resets the label by removing the Badger state directory.`
      const rose = !dominates(label, next)
      label = next
      // Announced after the label moved: a listener only shows it, and cannot change the decision.
      if (rose)
        for (const listener of listeners)
          try {
            listener(format(next))
          } catch {}
      return undefined
    },
    /**
     * Calls `listener` with the new label, as a banner, each time a call raises it. Returns the
     * function that stops it.
     */
    subscribe: (listener: (label: string) => void) => {
      listeners.add(listener)
      return () => void listeners.delete(listener)
    },
  }
}

export type Flow = ReturnType<typeof make>

/**
 * Takes the audit file for this process with a kernel lock (flock) on `<audit>.lock`, held on an
 * open descriptor until the process exits or `close` runs. The kernel drops it when the process
 * dies, so there is no stale lock to judge, and it holds across processes and PID namespaces that
 * share the file, so two containers on one state directory cannot both own it. A lock that cannot
 * be taken, for any reason, stops the start: two owners would each miss the other's calls.
 */
function own(audit: string) {
  const lock = `${audit}.lock`
  const fd = openSync(lock, "a", 0o600)
  if (flock()(fd, LOCK_EX | LOCK_NB) !== 0) {
    closeSync(fd)
    throw new Error(`${audit} is in use by another process; one process at a time keeps this workspace's classification`)
  }
  let held = true
  const release = () => {
    if (!held) return
    held = false
    process.off("exit", release)
    // Closing the descriptor drops the lock; the lock file stays, empty, for the next owner.
    closeSync(fd)
  }
  process.on("exit", release)
  return release
}

const LOCK_EX = 2
const LOCK_NB = 4
let flockFn: ((fd: number, operation: number) => number) | undefined
/** libc's flock(2), loaded once. */
function flock() {
  if (flockFn) return flockFn
  const library =
    process.platform === "darwin" ? "/usr/lib/libSystem.B.dylib" : process.platform === "linux" ? "libc.so.6" : undefined
  if (!library) throw new Error(`the audit file cannot be locked on ${process.platform}`)
  const { symbols } = dlopen(library, { flock: { args: ["i32", "i32"], returns: "i32" } })
  flockFn = (fd, operation) => symbols.flock(fd, operation) as number
  return flockFn
}
