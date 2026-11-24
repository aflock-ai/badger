export * as Shell from "./shell.js"

import path from "path"
import { Context, Deferred, Duration, Effect, Fiber, Latch, Layer, Schema, Schedule, Stream } from "effect"
import { ChildProcess } from "effect/process"
import { produce } from "immer"
import { Shell } from "@opencode/schema/shell"
import { AppProcess } from "@opencode/util/process"
import { CrossSpawnSpawner } from "@opencode/util/cross-spawn-spawner"
import { makeGlobalNode, makeLocationNode } from "@opencode/util/effect/app-node"
import { FSUtil } from "@opencode/util/fs-util"
import { Bus } from "./bus.js"
import { Environment } from "./environment/index.js"
import { FileRetention } from "./file-retention.js"
import { Location } from "./location.js"
import { Global } from "@opencode/util/global"
import { ShellSelect } from "./shell/select.js"
import type { ShellCreateBefore } from "@opencode/plugin/effect/shell"
import { PluginHooks } from "./plugin/hooks.js"
import { SessionEnvironment } from "./session/environment.js"
import { SessionSchema } from "./session/schema.js"
import { Config } from "./config.js"
import { ToolOutputRedaction } from "./tool-output-redaction.js"
import { ToolOutput } from "./tool-output.js"
import { ShellResult } from "./shell/result.js"

export class NotFoundError extends Schema.TaggedError<NotFoundError>()("Shell.NotFoundError", {
  id: Shell.ID,
}) {}

// Keep recent exited processes observable in memory, including their file-backed output.
// The process-local cap complements the time-based sweep, which also cleans files left by restarts.
const EXITED_LIMIT = 25
export const RETENTION = Duration.days(7)
export const DIRECTORY = "shell"

type Info = Shell.Info
type CreateInput = Shell.CreateInput & {
  shell?: string
}

// The most raw output held in memory per shell. Past it the raw copy is dropped and pages come from the
// redacted file. Each read redacts the whole raw output (text() is linear), so this also bounds that.
const RAW_LIMIT = 1024 * 1024

type Active = {
  // Immutable snapshot; lifecycle updates replace it via immer `produce`.
  info: Info
  file: string
  size: number
  newlines: number
  // The raw output, held in memory only and never written to disk, while it fits in RAW_LIMIT. Reads are
  // served from text() of all of it, not page by page, so a page boundary cannot separate a credential
  // from its label, and nothing the redacted file had to withhold is lost to a reader during the
  // session. Once it is evicted or the process ends, pages come from the file. `redacted` caches the
  // redaction for the raw size it was computed at.
  raw?: { chunks: Buffer[]; size: number; redacted?: { at: number; bytes: Buffer; newlines: number } }
  // Set when the raw copy is evicted: its redaction at that moment, and how far the file had got. Reads
  // keep one cursor space across the switch: the frozen bytes first, then the file from that offset.
  frozen?: { bytes: Buffer; newlines: number; fileOffset: number; fileNewlines: number }
  // What each stream has written to the file since its raw lines last reached the in-memory copy (the
  // copy waits until the stream settles). A read that continues into the file after eviction starts past
  // it, so the frozen bytes end with it instead; this includes a withheld marker.
  ahead?: () => string
  // Resolves with the terminal Info once the command exits, times out, or is killed. A wait
  // started after termination resolves immediately from the already-completed deferred.
  done: Deferred.Deferred<Info, NotFoundError>
  timeoutFiber?: Fiber.Fiber<void>
  timeout?: (duration: number) => Effect.Effect<void>
}

// Drops the raw copy, keeping its redaction so cursors already handed out still point at the same bytes.
function evict(command: Active) {
  const redacted = redactedRaw(command)
  if (!redacted) return
  // Redacted lines already in the file but not yet in the raw copy (a stream that has not settled, or one
  // that withholds, with its marker) follow it, so nothing is lost or shown twice where reads continue into
  // the file. They may come after lines the other stream wrote later; each stream keeps its own order.
  const ahead = command.ahead?.() ?? ""
  const tail = ahead && (redacted.bytes.length > 0 && redacted.bytes.at(-1) !== 10 ? "\n" : "") + ahead
  command.frozen = {
    bytes: Buffer.concat([redacted.bytes, Buffer.from(tail)]),
    newlines: redacted.newlines + (tail.match(/\n/g)?.length ?? 0),
    fileOffset: command.size,
    fileNewlines: command.newlines,
  }
  command.raw = undefined
}

// text() of the whole raw output, computed again only when more output has arrived.
function redactedRaw(command: Active) {
  const raw = command.raw
  if (!raw) return undefined
  if (raw.redacted?.at !== raw.size) {
    const bytes = Buffer.from(ToolOutputRedaction.text(Buffer.concat(raw.chunks).toString("utf8")))
    let newlines = 0
    for (let index = bytes.indexOf(10); index !== -1; index = bytes.indexOf(10, index + 1)) newlines++
    raw.redacted = { at: raw.size, bytes, newlines }
  }
  return raw.redacted
}

/**
 * Location-owned non-interactive shell command process service.
 *
 * Each `create` spawns one shell command, captures combined stdout/stderr to a
 * file, and returns an ID. Clients poll `get` for status and `output` for
 * file-backed output by cursor. No session, message, or permission state lives
 * here; callers (e.g. `ShellTool`) own that association and store the shell ID.
 */
export interface Interface {
  readonly create: <E = never, R = never>(
    input: CreateInput,
    before?: (input: ShellCreateBefore) => Effect.Effect<void, E, R>,
  ) => Effect.Effect<Shell.Info, E | AppProcess.AppProcessError, R>
  // Currently running commands only; exited shells are retained for get/output but excluded here.
  readonly list: () => Effect.Effect<Shell.Info[]>
  readonly get: (id: Shell.ID) => Effect.Effect<Shell.Info, NotFoundError>
  // Resolves once the command reaches a terminal status, returning its final Info. Fails with
  // NotFoundError if the command is unknown or is removed before it terminates.
  readonly wait: (id: Shell.ID) => Effect.Effect<Shell.Info, NotFoundError>
  // A known shell's terminal state and bounded tail. Missing capture remains distinct from its exit status.
  readonly result: (started: Shell.Info) => Effect.Effect<ShellResult.Result>
  // Replaces the running command's timeout from now; zero clears it.
  readonly timeout: (id: Shell.ID, duration: number) => Effect.Effect<Shell.Info, NotFoundError>
  readonly output: (id: Shell.ID, input?: Shell.OutputInput) => Effect.Effect<Shell.Output, NotFoundError>
  readonly remove: (id: Shell.ID) => Effect.Effect<void, NotFoundError>
}

export class Service extends Context.Service<Service, Interface>()("@opencode/Shell") {}

export const cleanup = Effect.fn("Shell.cleanup")(function* () {
  const fs = yield* FSUtil.Service
  const global = yield* Global.Service
  const directory = path.join(global.data, DIRECTORY)
  const projects = yield* fs.readDirectoryEntries(directory).pipe(
    Effect.map((entries) => entries.filter((entry) => entry.type === "directory")),
    Effect.orElseSucceed(() => []),
  )
  const files = yield* Effect.forEach(
    projects,
    (project) =>
      fs.readDirectoryEntries(path.join(directory, project.name)).pipe(
        Effect.map((entries) =>
          entries.flatMap((entry) =>
            entry.type === "file" && /^sh_[0-9a-f]{12}.*\.out$/.test(entry.name)
              ? [path.join(directory, project.name, entry.name)]
              : [],
          ),
        ),
        Effect.orElseSucceed(() => []),
      ),
    { concurrency: 8 },
  )
  yield* FileRetention.cleanup(fs, files.flat(), RETENTION)
})

const cleanupLayer = Layer.effectDiscard(
  cleanup().pipe(Effect.repeat(Schedule.spaced(Duration.hours(1))), Effect.forkScoped),
)

const cleanupNode = makeGlobalNode({
  name: "shell-output-cleanup",
  layer: cleanupLayer,
  deps: [FSUtil.node, Global.node],
})

const layer = () =>
  Layer.effect(
    Service,
    Effect.gen(function* () {
      const bus = yield* Bus.Service
      const location = yield* Location.Service
      const global = yield* Global.Service
      const shell = yield* ShellSelect.Service
      const environment = yield* Environment.Service
      const hooks = yield* PluginHooks.Service
      const environments = yield* SessionEnvironment.Service
      const config = yield* Config.Service
      const context = yield* Effect.context()
      const runFork = Effect.runForkWith(context)
      const commands = new Map<Shell.ID, Active>()
      const exitOrder: Shell.ID[] = []

      const outputDir = path.join(global.data, DIRECTORY, location.project.id)
      const { mkdir, unlink } = yield* Effect.promise(() => import("fs/promises"))
      const { createWriteStream, createReadStream } = yield* Effect.promise(() => import("fs"))
      yield* Effect.promise(() => mkdir(outputDir, { recursive: true }))

      yield* Effect.addFinalizer(() =>
        Effect.gen(function* () {
          for (const command of commands.values()) {
            if (command.timeoutFiber) yield* Fiber.interrupt(command.timeoutFiber)
            // Teardown interrupts pending commands; it is not a terminal command failure.
            yield* Deferred.interrupt(command.done)
          }
          commands.clear()
          exitOrder.length = 0
        }),
      )

      const require = Effect.fnUntraced(function* (id: Shell.ID) {
        const command = commands.get(id)
        if (!command) return yield* new NotFoundError({ id })
        return command
      })

      const removeCommand = Effect.fnUntraced(function* (id: Shell.ID) {
        const command = commands.get(id)
        const index = exitOrder.indexOf(id)
        if (index !== -1) exitOrder.splice(index, 1)
        if (!command) return
        commands.delete(id)
        if (command.timeoutFiber) yield* Fiber.interrupt(command.timeoutFiber)
        // Unblock any wait still pending when the command is removed before it terminated.
        yield* Deferred.fail(command.done, new NotFoundError({ id }))
        yield* Effect.promise(() => unlink(command.file).catch(() => {}))
        yield* bus.publish(Shell.Event.Deleted, { id })
      })

      const remove = Effect.fn("Shell.remove")(function* (id: Shell.ID) {
        yield* require(id)
        yield* removeCommand(id)
      })

      const list = Effect.fn("Shell.list")(function* () {
        return Array.from(commands.values())
          .filter((command) => command.info.status === "running")
          .map((command) => command.info)
      })

      const get = Effect.fn("Shell.get")(function* (id: Shell.ID) {
        return (yield* require(id)).info
      })

      const wait = Effect.fn("Shell.wait")(function* (id: Shell.ID) {
        return yield* Deferred.await((yield* require(id)).done)
      })

      const timeout = Effect.fn("Shell.timeout")(function* (id: Shell.ID, duration: number) {
        const command = yield* require(id)
        if (command.info.status !== "running" || !command.timeout) return command.info
        yield* command.timeout(duration)
        return command.info
      })

      const output = Effect.fnUntraced(function* (id: Shell.ID, input?: Shell.OutputInput) {
        const command = yield* require(id)
        const cursor = input?.cursor ?? 0
        const limit = input?.limit ?? 65536
        // Cursors and size count bytes of the redacted raw output while it is in memory, file bytes after.
        const redacted = redactedRaw(command)
        if (redacted) {
          const size = redacted.bytes.length
          if (cursor >= size) return { output: "", cursor: size, size, truncated: false }
          const start = Math.max(0, cursor)
          const page = redacted.bytes.subarray(start, start + limit)
          return { output: page.toString("utf8"), cursor: start + page.length, size, truncated: false }
        }
        // After eviction: the frozen bytes, then the file from where it was at eviction.
        const frozen = command.frozen
        const before = frozen?.bytes.length ?? 0
        const fileStart = frozen?.fileOffset ?? 0
        const size = before + command.size - fileStart
        if (cursor >= size) return { output: "", cursor: size, size, truncated: false }
        const start = Math.max(0, cursor)
        // A page that starts in the frozen bytes continues into the file, so it is as full as asked.
        const kept = frozen && start < before ? frozen.bytes.subarray(start, start + limit) : Buffer.alloc(0)
        const fileAt = fileStart + Math.max(0, start - before)
        const length = Math.max(0, Math.min(limit - kept.length, command.size - fileAt))
        const buffer = Buffer.alloc(length)
        const bytesRead =
          length === 0
            ? 0
            : yield* Effect.promise(
                () =>
                  new Promise<number>((resolve) => {
                    const stream = createReadStream(command.file, { start: fileAt, end: fileAt + length - 1 })
                    let offset = 0
                    stream.on("data", (chunk: string | Buffer) => {
                      const bytes = Buffer.from(chunk)
                      bytes.copy(buffer, offset)
                      offset += bytes.length
                    })
                    stream.on("end", () => resolve(offset))
                    stream.on("error", () => resolve(0))
                  }),
              )
        return {
          // The file is redacted line by line as it is written; each file page is redacted whole again
          // on the way out, the authority for what any client or the model reads. The frozen bytes are
          // already redacted.
          output: kept.toString("utf8") + ToolOutputRedaction.text(buffer.subarray(0, bytesRead).toString("utf8")),
          cursor: start + kept.length + bytesRead,
          size,
          truncated: false,
        }
      })

      const result = Effect.fn("Shell.result")(function* (started: Shell.Info) {
        const info = yield* wait(started.id).pipe(
          Effect.catchTag("Shell.NotFoundError", () =>
            Effect.succeed({ ...started, status: "killed" as const, time: { ...started.time, completed: Date.now() } }),
          ),
        )
        const capture = yield* Effect.gen(function* () {
          const limits = Config.latest(yield* config.entries(), "tool_output")
          const maxLines = limits?.max_lines ?? ToolOutput.MAX_LINES
          const maxBytes = limits?.max_bytes ?? ToolOutput.MAX_BYTES
          const latest = yield* output(info.id, { cursor: Number.MAX_SAFE_INTEGER })
          const page = yield* output(info.id, { cursor: Math.max(0, latest.size - maxBytes), limit: maxBytes })
          const lines = page.output.split("\n")
          if (page.output.endsWith("\n")) lines.pop()
          const truncated = latest.size > maxBytes || lines.length > maxLines
          const text = lines.length > maxLines ? lines.slice(-maxLines).join("\n") : page.output
          const active = yield* require(info.id)
          const newlines =
            redactedRaw(active)?.newlines ??
            (active.frozen ? active.frozen.newlines + active.newlines - active.frozen.fileNewlines : active.newlines)
          const total = newlines + (page.output.endsWith("\n") ? 0 : 1)
          const shown = Math.min(lines.length, maxLines)
          const notice = truncated
            ? `\n\n[showing lines ${total - shown + 1}-${total} of ${total}; full output saved to ${info.file}]`
            : ""
          return { output: `${text || "(no output)"}${notice}`, truncated }
        }).pipe(Effect.catchTag("Shell.NotFoundError", () => Effect.succeed(undefined)))
        return { info, capture }
      })

      const create = Effect.fn("Shell.create")(function* <E = never, R = never>(
        input: CreateInput,
        before?: (input: ShellCreateBefore) => Effect.Effect<void, E, R>,
      ) {
        const sessionID = input.metadata?.sessionID
        const baseEnv =
          location.workspaceID !== undefined
            ? undefined
            : ((Schema.is(SessionSchema.ID)(sessionID) ? yield* environments.get(sessionID) : undefined) ?? process.env)
        const invocation: ShellCreateBefore = {
          command: input.command,
          cwd: input.cwd ?? location.directory,
          timeout: input.timeout ?? 0,
          shell: input.shell ?? (yield* shell.resolve({ priority: "config" })),
          env: {
            ...baseEnv,
            TERM: "xterm-256color",
            OPENCODE_TERMINAL: "1",
          },
        }
        yield* hooks.trigger("shell", "create.before", invocation)
        if (before) yield* before(invocation)

        const id = Shell.ID.ascending()
        const args = ShellSelect.args(invocation.shell, invocation.command)
        const file = path.join(outputDir, `${id}.out`)

        const info: Info = {
          id,
          status: "running",
          command: invocation.command,
          cwd: invocation.cwd,
          shell: invocation.shell,
          file,
          metadata: input.metadata ?? {},
          time: { started: Date.now() },
        }

        // Spawn through the Environment and stream combined output to the file. The handle is scope-bound, so
        // the managing fiber keeps its scope open until the command terminates (it awaits `done` at the
        // end). `create` returns once `ready` resolves with the registered command.
        const ready = Deferred.makeUnsafe<Active, AppProcess.AppProcessError>()
        runFork(
          Effect.scoped(
            Effect.gen(function* () {
              const handle = yield* environment.spawner
                .spawn(
                  ChildProcess.make(invocation.shell, args, {
                    cwd: invocation.cwd,
                    env: invocation.env,
                    stdin: "ignore",
                    detached: process.platform !== "win32",
                    forceKillAfter: Duration.seconds(3),
                  }),
                )
                .pipe(
                  Effect.mapError((cause) => new AppProcess.AppProcessError({ command: invocation.command, cause })),
                )
              const command: Active = {
                info: produce(info, (draft) => {
                  draft.pid = handle.pid
                }),
                file,
                size: 0,
                newlines: 0,
                raw: { chunks: [], size: 0 },
                done: Deferred.makeUnsafe<Info, NotFoundError>(),
              }
              commands.set(id, command)

              const stream = createWriteStream(file)
              const outputDone = Latch.makeUnsafe()
              let midLine = false
              const write = (text: string) => {
                if (!text) return
                // Only a stream's final, unterminated line leaves the file mid-line; end it before more
                // output so the two streams' lines never join.
                const chunk = Buffer.from(midLine ? "\n" + text : text)
                midLine = !text.endsWith("\n")
                stream.write(chunk)
                command.size += chunk.length
                // Count while streaming so truncation notices never rescan the output file.
                for (let index = chunk.indexOf(10); index !== -1; index = chunk.indexOf(10, index + 1))
                  command.newlines++
              }
              // The raw copy in memory takes complete lines the same way, so its lines never join either.
              let rawMidLine = false
              const keep = (text: string) => {
                const raw = command.raw
                if (!text || !raw) return
                const chunk = Buffer.from(rawMidLine ? "\n" + text : text)
                rawMidLine = !text.endsWith("\n")
                if (raw.size + chunk.length > RAW_LIMIT) {
                  evict(command)
                  return
                }
                raw.chunks.push(chunk)
                raw.size += chunk.length
              }
              // The model is told to read this file, so it holds only redacted output. stdout and stderr
              // are redacted separately, line by line; a line is written once complete, so no prefix of a
              // credential reaches the file. A read failure drops the unfinished line instead of writing it.
              const streams: Array<() => string> = []
              command.ahead = () => streams.map((ahead) => ahead()).join("")
              const redacted = (source: Stream.Stream<Uint8Array, unknown>) => {
                const decoder = new TextDecoder()
                const lines = ToolOutputRedaction.stream()
                // Complete raw lines wait in `staged` until the stream is settled: every complete line it has
                // been given has been emitted as it reads in the whole output. A line it holds (it ends inside
                // a decoded terminal sequence), withholds, or has not finished because a removed sequence
                // swallowed its raw newline was never checked against what follows, so showing it early could
                // expose a credential whose end has not arrived ("https://alice:pw%1b]0;x\n%07@host"). Lines
                // are not matched one for one: removing a sequence changes how many there are. At the end of
                // the stream everything is released, and the whole output is redacted together. Only the new
                // text is searched for a newline, and nothing accumulates once the raw copy is gone. The raw
                // copy is updated before the file, so a chunk that evicts it is still read from the file after
                // the frozen bytes.
                let staged = ""
                let unfinished = ""
                let ahead = ""
                streams.push(() => ahead)
                const take = (text: string) => {
                  const out = lines.push(text)
                  if (command.raw) {
                    const end = text.lastIndexOf("\n") + 1
                    if (end === 0) unfinished += text
                    else {
                      staged += unfinished + text.slice(0, end)
                      unfinished = text.slice(end)
                    }
                    const settled = lines.settled()
                    if (settled) {
                      keep(staged)
                      staged = ""
                      ahead = ""
                    }
                    // Raw text that could not fit is not held while it grows.
                    if (command.raw && staged.length + unfinished.length > RAW_LIMIT) evict(command)
                    // Counted only while the copy exists: after eviction, `out` is read from the file.
                    if (command.raw && !settled) ahead += out
                  }
                  if (!command.raw) {
                    staged = ""
                    unfinished = ""
                    ahead = ""
                  }
                  write(out)
                }
                return source.pipe(
                  Stream.runForEach((chunk: Uint8Array) =>
                    Effect.sync(() => take(decoder.decode(chunk, { stream: true }))),
                  ),
                  Effect.andThen(
                    Effect.sync(() => {
                      const last = decoder.decode()
                      const out = lines.push(last) + lines.finish()
                      // The raw tail joins the copy only if it closes every terminal sequence it opened; one left
                      // open would swallow the other stream's lines that follow it in the copy ("\x1b]0;title"
                      // before "fatal: ...\x07"). Otherwise the stream's redacted lines take its place, as in
                      // the file.
                      const tail = staged + unfinished + last
                      keep(ToolOutputRedaction.closed(tail) ? tail : ahead + out)
                      ahead = ""
                      write(out)
                    }),
                  ),
                  // A read failure drops the raw lines not yet released, but what the file already holds for
                  // them (redacted, with a withheld marker) is put in the copy, so reads still show it.
                  Effect.catch(() =>
                    Effect.sync(() => {
                      keep(ahead)
                      ahead = ""
                      staged = ""
                      unfinished = ""
                    }),
                  ),
                )
              }
              const pump = Effect.all([redacted(handle.stdout), redacted(handle.stderr)], {
                concurrency: "unbounded",
                discard: true,
              })
              runFork(
                Effect.gen(function* () {
                  yield* pump
                  yield* Effect.promise(
                    () =>
                      new Promise<void>((resolve) => {
                        stream.end(() => resolve())
                      }),
                  )
                  yield* outputDone.open
                }),
              )
              yield* Effect.promise(
                () =>
                  new Promise<void>((resolve) => {
                    stream.once("open", () => resolve())
                    stream.once("error", () => resolve())
                  }),
              )

              const finish = (status: Info["status"], exit?: number, beforeWait = Effect.void, signal?: string) =>
                Effect.gen(function* () {
                  if (command.info.status !== "running") return
                  command.info = produce(command.info, (draft) => {
                    draft.status = status
                    if (exit !== undefined) draft.exit = exit
                    if (signal !== undefined) draft.signal = signal
                    draft.time.completed = Date.now()
                  })
                  yield* beforeWait
                  yield* outputDone.await
                  // Resolve waiters with the terminal Info before any retention eviction, so an evicted
                  // command still reports success rather than the removal NotFoundError. This runs before
                  // the timeout-fiber interrupt below, which on the timeout path would otherwise cancel
                  // this very fiber (finish is invoked by the timeout fiber) before waiters are resolved.
                  yield* Deferred.succeed(command.done, command.info)
                  yield* bus.publish(Shell.Event.Exited, {
                    id,
                    ...(exit !== undefined ? { exit } : {}),
                    status,
                  })
                  exitOrder.push(id)
                  while (exitOrder.length > EXITED_LIMIT) {
                    const oldest = exitOrder[0]
                    if (!oldest) break
                    yield* removeCommand(oldest)
                  }
                  // Keep exited history data-only. Interrupt last because finish may run on the timeout fiber.
                  const timeoutFiber = command.timeoutFiber
                  command.timeout = undefined
                  command.timeoutFiber = undefined
                  if (timeoutFiber) yield* Fiber.interrupt(timeoutFiber)
                })

              command.timeout = (duration) =>
                Effect.gen(function* () {
                  if (command.timeoutFiber) yield* Fiber.interrupt(command.timeoutFiber)
                  command.timeoutFiber = undefined
                  if (duration === 0 || command.info.status !== "running") return
                  command.timeoutFiber = runFork(
                    Effect.sleep(Duration.millis(duration)).pipe(
                      Effect.flatMap(() =>
                        finish(
                          "timeout",
                          undefined,
                          handle.kill({ forceKillAfter: Duration.seconds(3) }).pipe(Effect.catch(() => Effect.void)),
                        ),
                      ),
                    ),
                  )
                })

              yield* command.timeout(invocation.timeout)

              runFork(
                handle.exitCode.pipe(
                  Effect.flatMap((code) => finish("exited", code)),
                  Effect.catch((error) =>
                    finish(
                      "exited",
                      undefined,
                      Effect.void,
                      error.cause instanceof CrossSpawnSpawner.KilledBySignal ? error.cause.signal : undefined,
                    ),
                  ),
                ),
              )

              yield* bus.publish(Shell.Event.Created, { info })
              yield* Deferred.succeed(ready, command)
              // Hold the handle's scope open until the command terminates; closing it earlier would
              // release (kill) the process before its exit is observed.
              yield* Deferred.await(command.done).pipe(Effect.catch(() => Effect.void))
            }),
          ).pipe(Effect.catchTag("AppProcessError", (error) => Deferred.fail(ready, error))),
        )

        const command = yield* Deferred.await(ready)
        return command.info
      })

      return Service.of({ create, list, get, wait, result, timeout, output, remove })
    }),
  )

export const node = makeLocationNode({
  service: Service,
  layer: layer(),
  deps: [
    Bus.node,
    Location.node,
    Global.node,
    ShellSelect.node,
    Environment.node,
    PluginHooks.node,
    SessionEnvironment.node,
    Config.node,
    cleanupNode,
  ],
})
