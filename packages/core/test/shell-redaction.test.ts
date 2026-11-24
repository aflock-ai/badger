import { expect } from "bun:test"
import { Cause, Deferred, Effect, Layer, Queue, Sink, Stream } from "effect"
import { systemError, type PlatformError } from "effect/PlatformError"
import { ChildProcessSpawner } from "effect/process"
import { ExitCode, makeHandle, ProcessId } from "effect/process/ChildProcessSpawner"
import { readFile } from "node:fs/promises"
import { AppNodeBuilder } from "@opencode/core/effect/app-node-builder"
import { Config } from "@opencode/core/config"
import { Environment } from "@opencode/core/environment/index"
import { Location } from "@opencode/core/location"
import { Shell } from "@opencode/core/shell"
import { ToolOutputRedaction } from "@opencode/core/tool-output-redaction"
import { Global } from "@opencode/util/global"
import { hostEnvironmentLayer } from "./fixture/environment"
import { tempGlobalLayer } from "./fixture/global"
import { tempLocationLayer } from "./fixture/location"
import { it } from "./lib/effect"

// Invented credentials only.
const token = "ghp_" + "B".repeat(36)
const password = "synthetic-password-123456"

// A Shell service whose one process emits whatever the test feeds into its stdout and stderr queues.
const harness = <A>(
  body: (feed: {
    stdout: Queue.Queue<Uint8Array, Cause.Done | PlatformError>
    stderr: Queue.Queue<Uint8Array, Cause.Done | PlatformError>
    exited: Deferred.Deferred<ExitCode>
    bytes: (text: string) => Uint8Array
  }) => Effect.Effect<A, unknown, Shell.Service>,
) =>
  Effect.gen(function* () {
    const stdout = yield* Queue.unbounded<Uint8Array, Cause.Done | PlatformError>()
    const stderr = yield* Queue.unbounded<Uint8Array, Cause.Done | PlatformError>()
    const exited = yield* Deferred.make<ExitCode>()
    const bytes = (text: string) => new TextEncoder().encode(text)
    const environment = Layer.effect(
      Environment.Service,
      Effect.gen(function* () {
        const host = yield* Environment.Service
        return Environment.Service.of({
          ...host,
          spawner: ChildProcessSpawner.make(() =>
            Effect.succeed(
              makeHandle({
                pid: ProcessId(1),
                exitCode: Deferred.await(exited),
                isRunning: Deferred.isDone(exited).pipe(Effect.map((done) => !done)),
                kill: () => Deferred.succeed(exited, ExitCode(0)).pipe(Effect.asVoid),
                stdin: Sink.drain,
                stdout: Stream.fromQueue(stdout),
                stderr: Stream.fromQueue(stderr),
                // Raw merged output: reading it instead of the separate streams leaks.
                all: Stream.succeed(bytes(`${token} ${password}\n`)),
                getInputFd: () => Sink.drain,
                getOutputFd: () => Stream.empty,
                unref: Effect.succeed(Effect.void),
              }),
            ),
          ),
        })
      }),
    ).pipe(Layer.provide(hostEnvironmentLayer))

    yield* body({ stdout, stderr, exited, bytes }).pipe(
      Effect.provide(
        AppNodeBuilder.build(Shell.node, [
          Location.node.replace(tempLocationLayer),
          Global.node.replace(tempGlobalLayer),
          Config.node.replace(Config.testLayer()),
          Environment.node.replace(environment),
        ]),
      ),
    )
  })

it.live("the shell output file never holds a credential, even mid-stream", () =>
  harness(({ stdout, stderr, exited, bytes }) =>
    Effect.gen(function* () {
      const shell = yield* Shell.Service
      const info = yield* shell.create({ shell: "sh", command: "leaky", timeout: 0 })
      const file = () => Effect.promise(() => readFile(info.file, "utf8").catch(() => ""))
      const settle = Effect.promise(() => Bun.sleep(30))

      // A token split across chunks: no prefix of it may reach the file before its line ends.
      yield* Queue.offer(stdout, bytes(`clone ${token.slice(0, 10)}`))
      yield* settle
      expect(yield* file()).not.toContain("ghp_")
      yield* Queue.offer(stdout, bytes(`${token.slice(10)} done\n`))
      yield* Queue.offer(stderr, bytes(`fatal: https://alice:${password}@example.test/repo.git\n`))
      // An unterminated last line with a credential is redacted at EOF, not dropped raw.
      yield* Queue.offer(stdout, bytes(`Bearer%1b]0;x\n%07 ${password}-osc\n`))
      yield* Queue.offer(stdout, bytes(`Authorization: Bearer ${password}`))
      // An overlong line withholds the rest of stderr from the file, with one visible marker so the cut
      // is not silent.
      yield* Queue.offer(stderr, bytes(`Bearer%1b]0;${"x".repeat(70_000)}\ntitle07\n%07 ${password}-late\n`))
      yield* Queue.offer(stderr, bytes("withheld tail\n"))
      yield* Queue.end(stdout)
      yield* Queue.end(stderr)
      yield* Deferred.succeed(exited, ExitCode(0))

      const result = yield* shell.result(info)
      const written = yield* file()
      for (const visible of [written, result.capture?.output ?? ""]) {
        expect(visible).not.toContain(token)
        expect(visible).not.toContain(password)
        expect(visible).toContain("clone [redacted] done")
        expect(visible).toContain("fatal: https://[redacted]@example.test/repo.git")
        expect(visible).toContain("Authorization: [redacted]")
        // A stream's unterminated last line is never glued onto the other stream's output.
        expect(visible).not.toMatch(/\[redacted\]fatal/)
      }
      // The file withholds everything after the overlong line behind one marker; reads during the session
      // come from the raw output in memory, redacted whole, so they keep the later lines.
      expect(written).toContain(ToolOutputRedaction.withheldMarker)
      expect(written).not.toContain("withheld tail")
      expect(result.capture?.output).not.toContain(ToolOutputRedaction.withheldMarker)
      expect(result.capture?.output).toContain("withheld tail")
      // Reads are redacted whole, so a credential the per-line write path cannot see (an encoded OSC
      // sequence spanning a raw newline) is still gone from every page a client or the model reads.
      expect((yield* shell.output(info.id, { cursor: 0 })).output).not.toContain(password)
    }),
  ),
)

it.live("past the in-memory limit, later output is read from the redacted file", () =>
  harness(({ stdout, stderr, exited, bytes }) =>
    Effect.gen(function* () {
      const shell = yield* Shell.Service
      const info = yield* shell.create({ shell: "sh", command: "big", timeout: 0 })
      const settle = Effect.promise(() => Bun.sleep(30))
      yield* Queue.offer(stdout, bytes(`fatal: https://alice:${password}@example.test/r\n`))
      yield* Queue.offer(stdout, bytes(`${"y".repeat(50_000)}\nkept in memory\n`))
      yield* settle
      // More than the 1 MiB kept in memory, in ordinary lines.
      for (let line = 0; line < 20; line++) yield* Queue.offer(stderr, bytes(`${"z".repeat(60_000)}\n`))
      yield* settle
      yield* Queue.offer(stdout, bytes("stdout after eviction\n"))
      yield* Queue.offer(stderr, bytes(`stderr after eviction https://bob:${password}@example.test/s\n`))
      yield* Queue.end(stdout)
      yield* Queue.end(stderr)
      yield* Deferred.succeed(exited, ExitCode(0))
      yield* shell.wait(info.id).pipe(Effect.orDie)
      let page = ""
      for (let cursor = 0; ; ) {
        const next = yield* shell.output(info.id, { cursor, limit: 4 * 1024 * 1024 })
        if (next.output === "") break
        page += next.output
        cursor = next.cursor
      }
      // What was in memory at eviction stays readable; after it, the file's redacted lines.
      expect(page).toContain("kept in memory")
      expect(page).toContain("fatal: https://[redacted]@example.test/r")
      expect(page).toContain("stderr after eviction https://[redacted]@example.test/s")
      expect(page).toContain("stdout after eviction")
      expect(page).not.toContain(password)
    }),
  ),
)

it.live("a cursor handed out before eviction reads on without skipping", () =>
  harness(({ stdout, stderr, exited, bytes }) =>
    Effect.gen(function* () {
      const shell = yield* Shell.Service
      const info = yield* shell.create({ shell: "sh", command: "paged", timeout: 0 })
      yield* Queue.offer(stdout, bytes(`head\n${"y".repeat(50_000)}\nmid\n`))
      const settle = Effect.promise(() => Bun.sleep(30))
      yield* settle
      const first = yield* shell.output(info.id, { cursor: 0, limit: 10 })
      expect(first.output).toBe("head\nyyyyy")
      // More than the 1 MiB kept in memory evicts the raw copy.
      for (let line = 0; line < 20; line++) yield* Queue.offer(stderr, bytes(`z${line} ${"z".repeat(60_000)}\n`))
      yield* settle
      yield* Queue.end(stdout)
      yield* Queue.end(stderr)
      yield* Deferred.succeed(exited, ExitCode(0))
      yield* shell.wait(info.id).pipe(Effect.orDie)
      let read = first.output
      for (let cursor = first.cursor; ; ) {
        const page = yield* shell.output(info.id, { cursor, limit: 100_000 })
        if (page.output === "") break
        read += page.output
        cursor = page.cursor
      }
      expect(read.startsWith(`head\n${"y".repeat(50_000)}\nmid\n`)).toBe(true)
      for (let line = 0; line < 20; line++) expect(read).toContain(`z${line} `)
    }),
  ),
)

it.live("evicting mid-withhold shows the withheld marker exactly once across the switch", () =>
  harness(({ stdout, stderr, exited, bytes }) =>
    Effect.gen(function* () {
      const shell = yield* Shell.Service
      const info = yield* shell.create({ shell: "sh", command: "withholding", timeout: 0 })
      const settle = Effect.promise(() => Bun.sleep(30))
      // stdout withholds from its overlong line on, so its lines never reach the in-memory copy; what it
      // wrote to the file before that (and the marker) is kept across the switch.
      yield* Queue.offer(stdout, bytes(`head\n${"y".repeat(70_000)}\nheld back\n`))
      yield* settle
      const first = yield* shell.output(info.id, { cursor: 0, limit: 5 })
      for (let line = 0; line < 20; line++) yield* Queue.offer(stderr, bytes(`z${line} ${"z".repeat(60_000)}\n`))
      yield* settle
      yield* Queue.offer(stdout, bytes("stdout after eviction\n"))
      yield* Queue.offer(stderr, bytes("stderr after eviction\n"))
      yield* Queue.end(stdout)
      yield* Queue.end(stderr)
      yield* Deferred.succeed(exited, ExitCode(0))
      yield* shell.wait(info.id).pipe(Effect.orDie)
      let read = first.output
      for (let cursor = first.cursor; ; ) {
        const page = yield* shell.output(info.id, { cursor, limit: 100_000 })
        if (page.output === "") break
        read += page.output
        cursor = page.cursor
      }
      // stdout's released lines follow what stderr had already put in the copy; each stream keeps its order.
      expect(read.split("head\n").length - 1).toBe(1)
      expect(read.indexOf("head\n")).toBeLessThan(read.indexOf(ToolOutputRedaction.withheldMarker))
      expect(read).not.toContain("held back")
      expect(read.split(ToolOutputRedaction.withheldMarker).length - 1).toBe(1)
      expect(read.indexOf(ToolOutputRedaction.withheldMarker)).toBeLessThan(read.indexOf("stderr after eviction"))
      expect(read).not.toContain("stdout after eviction")
    }),
  ),
)

it.live("the result's tail page spans the switch from the kept bytes into the file", () =>
  harness(({ stdout, stderr, exited, bytes }) =>
    Effect.gen(function* () {
      const shell = yield* Shell.Service
      const info = yield* shell.create({ shell: "sh", command: "ends-after-eviction", timeout: 0 })
      const settle = Effect.promise(() => Bun.sleep(30))
      // Just under the 1 MiB kept in memory, then a 30 kB line that evicts it, so less than one 50 kB tail
      // page sits in the file and the result's last page starts in the kept bytes.
      for (let line = 0; line < 17; line++) yield* Queue.offer(stdout, bytes(`${"z".repeat(60_000)}\n`))
      yield* settle
      yield* Queue.offer(stdout, bytes(`${"w".repeat(30_000)}\n`))
      yield* settle
      yield* Queue.offer(stderr, bytes(`fatal: final error https://alice:${password}@example.test/r\n`))
      yield* Queue.end(stdout)
      yield* Queue.end(stderr)
      yield* Deferred.succeed(exited, ExitCode(0))
      const result = yield* shell.result(info)
      expect(result.capture?.output).toContain("fatal: final error https://[redacted]@example.test/r")
      expect(result.capture?.output).not.toContain(password)
    }),
  ),
)

it.live("a read between chunks shows no line the stream is still holding", () =>
  harness(({ stdout, stderr, exited, bytes }) =>
    Effect.gen(function* () {
      const shell = yield* Shell.Service
      const info = yield* shell.create({ shell: "sh", command: "held", timeout: 0 })
      const settle = Effect.promise(() => Bun.sleep(30))
      const read = () => shell.output(info.id, { cursor: 0 }).pipe(Effect.map((page) => page.output))
      // An encoded OSC title whose terminator follows a raw newline: the redactor reads the two raw
      // lines as one, so no read may show the first without the "@host" that marks it a credential.
      yield* Queue.offer(stdout, bytes("before\nhttps://alice:q7v9z2k6m8p4%1b]0;x\n"))
      yield* settle
      expect(yield* read()).not.toContain("q7v9z2k6m8p4")
      // Long enough that the redactor reads the held lines again and emits them as one.
      yield* Queue.offer(stdout, bytes(`%07@example.test/${"r".repeat(100)}\n`))
      yield* settle
      expect(yield* read()).not.toContain("q7v9z2k6m8p4")
      // A raw ESC sequence swallowing a raw newline, split across chunks the same way.
      yield* Queue.offer(stdout, bytes("https://bob:w3x8c5n1t6\x1b]0;x\n"))
      yield* settle
      expect(yield* read()).not.toContain("w3x8c5n1t6")
      yield* Queue.offer(stdout, bytes(`\x07@example.test/${"s".repeat(100)}\n`))
      yield* settle
      expect(yield* read()).not.toContain("w3x8c5n1t6")
      yield* Queue.end(stdout)
      yield* Queue.end(stderr)
      yield* Deferred.succeed(exited, ExitCode(0))
      const result = yield* shell.result(info)
      expect(result.capture?.output).not.toContain("q7v9z2k6m8p4")
      const done = yield* read()
      expect(done).toContain("before\n")
      expect(done).not.toContain("q7v9z2k6m8p4")
      expect(done).not.toContain("w3x8c5n1t6")
    }),
  ),
)

it.live("a stream that fails keeps what the file already shows for it", () =>
  harness(({ stdout, stderr, exited, bytes }) =>
    Effect.gen(function* () {
      const shell = yield* Shell.Service
      const info = yield* shell.create({ shell: "sh", command: "failing", timeout: 0 })
      const settle = Effect.promise(() => Bun.sleep(30))
      // stdout withholds from its overlong line on, so nothing of it is in the raw copy yet.
      yield* Queue.offer(stdout, bytes(`head\n${"y".repeat(70_000)}\nheld back\n`))
      yield* settle
      yield* Queue.fail(
        stdout,
        systemError({ _tag: "Unknown", module: "Test", method: "read", description: "read failed" }),
      )
      yield* Queue.end(stderr)
      yield* Deferred.succeed(exited, ExitCode(0))
      const result = yield* shell.result(info)
      const read = (yield* shell.output(info.id, { cursor: 0 })).output
      for (const output of [read, result.capture?.output ?? ""]) {
        expect(output).toContain("head\n")
        expect(output).toContain(ToolOutputRedaction.withheldMarker)
        expect(output).not.toContain("held back")
      }
    }),
  ),
)

it.live("a terminal sequence left open at one stream's end does not swallow the other stream", () =>
  harness(({ stdout, stderr, exited, bytes }) =>
    Effect.gen(function* () {
      const shell = yield* Shell.Service
      const info = yield* shell.create({ shell: "sh", command: "open title", timeout: 0 })
      const settle = Effect.promise(() => Bun.sleep(30))
      yield* Queue.offer(stdout, bytes("out\n\x1b]0;title"))
      yield* Queue.end(stdout)
      yield* settle
      yield* Queue.offer(stderr, bytes("fatal: deployment failed\x07\n"))
      yield* Queue.end(stderr)
      yield* Deferred.succeed(exited, ExitCode(0))
      const result = yield* shell.result(info)
      const read = (yield* shell.output(info.id, { cursor: 0 })).output
      for (const output of [read, result.capture?.output ?? ""]) {
        expect(output).toContain("out\n")
        expect(output).toContain("fatal: deployment failed")
        expect(output).not.toContain("title")
      }
    }),
  ),
)

it.live("an encoded terminal sequence left open at one stream's end does not swallow the other stream", () =>
  harness(({ stdout, stderr, exited, bytes }) =>
    Effect.gen(function* () {
      const shell = yield* Shell.Service
      const info = yield* shell.create({ shell: "sh", command: "open encoded title", timeout: 0 })
      const settle = Effect.promise(() => Bun.sleep(30))
      yield* Queue.offer(stdout, bytes("out\n%1b]0;title"))
      yield* Queue.end(stdout)
      yield* settle
      yield* Queue.offer(stderr, bytes("fatal: deployment failed%07\n"))
      yield* Queue.end(stderr)
      yield* Deferred.succeed(exited, ExitCode(0))
      yield* shell.result(info)
      const read = (yield* shell.output(info.id, { cursor: 0 })).output
      expect(read).toContain("out\n")
      expect(read).toContain("fatal: deployment failed")
    }),
  ),
)
