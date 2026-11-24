import path from "node:path"
import os from "node:os"
import fs from "node:fs/promises"
import { constants } from "node:fs"
import { spawn } from "node:child_process"
import { randomBytes } from "node:crypto"
import { assets } from "./assets"
import { strictJSON } from "../managed/strict-json"
import { nativeTarget, validateAssets, type NativeRole } from "./native-assets"
import type { EnrollmentRequest, AttestationRequest } from "./request"

export type NativeEvent = Readonly<Record<string, unknown>> & { schema: "testifysec.hardened-code.command-event/v1", event: string }
type Requests = { enroll: EnrollmentRequest, attest: AttestationRequest }
const sha = (bytes: Uint8Array) => new Bun.CryptoHasher("sha256").update(bytes).digest("hex")
async function within<T>(promise: Promise<T>, ms: number): Promise<T | undefined> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try { return await Promise.race([promise, new Promise<undefined>(resolve => { timer = setTimeout(() => resolve(undefined), ms) })]) }
  finally { if (timer) clearTimeout(timer) }
}
export class NativeCommandError extends Error {
  constructor(readonly code: string) { super("Native command unavailable: " + code); this.name = "NativeCommandError" }
}

function requestBytes(role: NativeRole, request: unknown) {
  let nodes = 0
  function plain(value: unknown, depth = 0): void {
    if (++nodes > 2048 || depth > 16) throw new NativeCommandError("request-bounds")
    if (value === null || typeof value === "boolean") return
    if (typeof value === "string") {
      if (value.length > 16384 || !value.isWellFormed()) throw new NativeCommandError("request-encoding")
      return
    }
    if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return
    if (!value || typeof value !== "object" || (Object.getPrototypeOf(value) !== Object.prototype && !Array.isArray(value))) throw new NativeCommandError("request-type")
    if (Array.isArray(value) && value.length > 1024) throw new NativeCommandError("request-bounds")
    const descriptors = Object.getOwnPropertyDescriptors(value)
    // oxlint-disable-next-line no-restricted-globals -- genuine reflection: bound and check every own key, symbols included, of an untrusted request
    if (Reflect.ownKeys(descriptors).length > 1024) throw new NativeCommandError("request-bounds")
    // oxlint-disable-next-line no-restricted-globals -- genuine reflection, as above
    for (const key of Reflect.ownKeys(descriptors)) {
      if (Array.isArray(value) && key === "length") continue
      const descriptor = descriptors[key as string]
      if (typeof key !== "string" || !descriptor.enumerable || !("value" in descriptor)) throw new NativeCommandError("request-accessor")
      plain(descriptor.value, depth + 1)
    }
  }
  plain(request)
  const bytes = Buffer.from(JSON.stringify(request))
  if (bytes.length > 16384) throw new NativeCommandError("request-bounds")
  const value = strictJSON(bytes.toString()) as Record<string, unknown>
  if (!value || Array.isArray(value) || value.schema !== `testifysec.hardened-code.${role}/v1` ||
      typeof value.stateDirectory !== "string" || !path.isAbsolute(value.stateDirectory) ||
      !["platform", "local-self-signed"].includes(String(value.trustMode))) throw new NativeCommandError("request-role")
  return { bytes, value }
}

async function materialize(bytes: Uint8Array, expected: string) {
  // Ignore TMPDIR/HOME. This follows the packaging layer's Unix custody scope:
  // other users cannot replace a fresh owner-only child of a root sticky /tmp.
  const parent = await fs.realpath("/tmp")
  const root = await fs.open(parent, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  let directory: string | undefined
  let directoryHandle: Awaited<ReturnType<typeof fs.open>> | undefined
  let created = false
  let own: Awaited<ReturnType<typeof root.stat>> | undefined
  async function release(remove: boolean) {
    try {
      if (remove) {
        // Never remove a failed mkdir target, or a pathname whose original
        // opened directory identity was not established.
        if (!created || !directory || !own) throw new NativeCommandError("cleanup-incomplete")
        const current = await fs.lstat(directory)
        if (!current.isDirectory() || current.dev !== own.dev || current.ino !== own.ino) throw new NativeCommandError("cleanup-custody")
        await fs.rm(directory, { recursive: true })
      }
    } finally { try { await directoryHandle?.close() } finally { await root.close() } }
  }
  try {
    const stat = await root.stat()
    if (!stat.isDirectory() || (stat.uid !== 0 && stat.uid !== process.getuid!()) ||
      ((stat.mode & 0o022) !== 0 && (stat.uid !== 0 || (stat.mode & 0o1000) === 0))) throw new NativeCommandError("temporary-directory-custody")
    directory = path.join(parent, "aflock-command-" + randomBytes(24).toString("hex"))
    await fs.mkdir(directory, { mode: 0o700 })
    created = true
    directoryHandle = await fs.open(directory, constants.O_RDONLY | constants.O_NOFOLLOW)
    const candidate = await directoryHandle.stat()
    if (!candidate.isDirectory() || candidate.uid !== process.getuid!() || (candidate.mode & 0o777) !== 0o700) throw new NativeCommandError("temporary-directory-custody")
    own = candidate
    const executable = path.join(directory, "command")
    const file = await fs.open(executable, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o500)
    try { await file.writeFile(bytes); await file.sync() } finally { await file.close() }
    const check = await fs.open(executable, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    try {
      const stat = await check.stat()
      if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid!() || stat.size !== bytes.length || (stat.mode & 0o777) !== 0o500 || sha(await check.readFile()) !== expected) throw new NativeCommandError("materialized-integrity")
    } finally { await check.close() }
    return { directory, executable, cleanup: () => release(true), retain: () => release(false) }
  } catch (error) {
    await release(created && own !== undefined)
    if (created && !own) throw new NativeCommandError("cleanup-incomplete")
    throw error
  }
}

export async function runNative<R extends NativeRole>(role: R, request: Requests[R], onEvent: (event: NativeEvent) => void, options: { signal?: AbortSignal } = {}) {
  if (role !== "enroll" && role !== "attest") throw new NativeCommandError("unknown-role")
  // Node/Bun filesystem APIs cannot reproduce the native Windows ACL/ancestor
  // and suspended Job Object contract. Cross-builds must refuse, not weaken it.
  if (process.platform !== "darwin" && process.platform !== "linux") throw new NativeCommandError("platform-not-qualified")
  if (typeof onEvent !== "function") throw new NativeCommandError("event-handler")
  const input = requestBytes(role, request)
  const arch = process.arch === "x64" ? "amd64" : process.arch
  const selected = validateAssets(assets, process.platform, arch, false).find(asset => asset.role === role)
  if (!selected) throw new NativeCommandError("helper-not-bundled")
  if (!selected.file.startsWith("/$bunfs/")) throw new NativeCommandError("embedded-asset-required")
  const content = Bun.file(selected.file)
  if (content.size !== selected.size) throw new NativeCommandError("embedded-integrity")
  const bytes = await content.bytes()
  if (bytes.length !== selected.size || sha(bytes) !== selected.sha256) throw new NativeCommandError("embedded-integrity")
  nativeTarget(bytes, process.platform, arch)
  if (options.signal?.aborted) throw new NativeCommandError("cancelled")
  const payload = await materialize(bytes, selected.sha256)
  let failure: NativeCommandError | undefined
  let child: ReturnType<typeof spawn> | undefined
  let ownedPid: number | undefined
  let killTimer: ReturnType<typeof setTimeout> | undefined
  let deadline: ReturnType<typeof setTimeout> | undefined
  let events = 0
  let terminal: string | undefined
  let exited: Promise<number> | undefined
  let drained: Promise<boolean> | undefined
  let exitObserved = false
  let cleanupReady = false
  const kill = (signal: NodeJS.Signals) => {
    if (ownedPid === undefined) return
    try { process.kill(-ownedPid, signal) } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw new NativeCommandError("process-cleanup") }
  }
  const stop = (code: string) => {
    if (failure) return
    failure = new NativeCommandError(code)
    // A group containing only an exiting process can transiently refuse TERM
    // on macOS. Never infer cleanup from this best-effort request: observed
    // child exit, final group termination and bounded pipe drain remain required.
    try { kill("SIGTERM") } catch { /* verified after child exit below */ }
    killTimer = setTimeout(() => { try { kill("SIGKILL") } catch { /* final cleanup must still succeed */ } }, 1000)
  }
  const cancel = () => stop("cancelled")
  process.on("SIGINT", cancel); process.on("SIGTERM", cancel); options.signal?.addEventListener("abort", cancel, { once: true })
  try {
    if (failure || options.signal?.aborted) throw new NativeCommandError("cancelled")
    const env: Record<string, string> = { PATH: "/usr/bin:/bin", HOME: payload.directory, TMPDIR: payload.directory, LANG: "C" }
    if (input.value.trustMode === "platform") env.CILOCK_STATE_DIR = path.join(String(input.value.stateDirectory), "platform")
    child = spawn(payload.executable, [role], { cwd: payload.directory, env, detached: true, stdio: ["pipe", "pipe", "pipe"] })
    // Capture only the original positive PID; never derive a new signal target
    // from mutable child state after an await.
    if (Number.isSafeInteger(child.pid) && child.pid! > 1) ownedPid = child.pid
    exited = new Promise<number>(resolve => {
      child!.once("error", () => { stop("spawn-refused"); if (ownedPid === undefined) { exitObserved = true; resolve(2) } })
      child!.once("exit", (code, signal) => { exitObserved = true; resolve(code ?? 128 + (signal ? os.constants.signals[signal] : 0)) })
    })
    deadline = setTimeout(() => stop("deadline"), selected.timeoutSeconds * 1000)
    child.stdin!.on("error", () => stop("request-write"))
    child.stdin!.end(input.bytes)
    const output = (async () => {
      let total = 0, pending = Buffer.alloc(0)
      try {
        for await (const data of child!.stdout!) {
          total += data.length
          if (total > 128 * 1024) throw new Error("output limit")
          pending = Buffer.concat([pending, data])
          while (pending.includes(10)) {
            const end = pending.indexOf(10)
            if (end === 0 || end > 16384 || ++events > 128) throw new Error("event bounds")
            const event = strictJSON(new TextDecoder("utf-8", { fatal: true }).decode(pending.subarray(0, end))) as NativeEvent
            pending = pending.subarray(end + 1)
            if (!event || typeof event !== "object" || Array.isArray(event) || event.schema !== "testifysec.hardened-code.command-event/v1" ||
                !(role === "enroll" ? ["ceremony", "enrolled", "progress", "error"] : ["attested", "progress", "error"]).includes(event.event) || terminal) throw new Error("event schema")
            if (["enrolled", "attested", "error"].includes(event.event)) terminal = event.event
            // The frontend renders an exact public field allowlist; neither
            // raw stdout nor stderr is printed by this runner.
            const result = onEvent(event) as unknown
            if (result && typeof result === "object" && "then" in result) { void Promise.resolve(result).catch(() => {}); throw new Error("synchronous event handler required") }
          }
          if (pending.length > 16384) throw new Error("event line limit")
        }
        if (pending.length) throw new Error("truncated event")
      } catch { stop("event-refused") }
    })()
    const errors = (async () => {
      let total = 0
      try { for await (const data of child!.stderr!) { total += data.length; if (total > 16384) { stop("stderr-limit"); break } } }
      catch { stop("stderr-read") }
    })()
    drained = Promise.all([output, errors]).then(() => true)
    const exitCode = await within(exited, selected.timeoutSeconds * 1000 + 5000)
    if (exitCode === undefined) { stop("process-drain-deadline"); throw failure }
    kill("SIGKILL")
    if (!await within(drained, 2000)) throw new NativeCommandError("output-drain-deadline")
    cleanupReady = true
    if (failure) throw failure
    if (exitCode === 0 && terminal !== (role === "enroll" ? "enrolled" : "attested")) throw new NativeCommandError("missing-result")
    return { exitCode, events }
  } finally {
    if (deadline) clearTimeout(deadline)
    if (killTimer) clearTimeout(killTimer)
    process.off("SIGINT", cancel); process.off("SIGTERM", cancel); options.signal?.removeEventListener("abort", cancel)
    try {
      if (child && !cleanupReady) {
        // Cancellation is not proof of termination. Even exceptional paths
        // must observe native exit and completed pipe readers before deletion.
        try { kill("SIGKILL") } catch { /* require a successful final kill below */ }
        if (!exitObserved && exited) await within(exited, 2000)
        if (exitObserved) {
          let groupStopped = false
          try { kill("SIGKILL"); groupStopped = true } catch { /* retain payload */ }
          const pipesDrained = drained ? await within(drained, 2000) : false
          cleanupReady = groupStopped && pipesDrained === true
        }
      }
    } finally {
      child?.stdin?.destroy(); child?.stdout?.destroy(); child?.stderr?.destroy()
      if (!child || cleanupReady) await payload.cleanup()
      else { await payload.retain(); throw new NativeCommandError("cleanup-incomplete") }
    }
  }
}
