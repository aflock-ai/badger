import { expect, test } from "bun:test"
import { Effect, Layer, Schedule, Stream } from "effect"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { Bus } from "@opencode/core/bus"
import { Config } from "@opencode/core/config"
import { ConfigMcpPlugin } from "@opencode/core/config/plugin/mcp"
import { Credential } from "@opencode/core/credential"
import { Form } from "@opencode/core/form"
import { Integration } from "@opencode/core/integration"
import { Location } from "@opencode/core/location"
import { ManagedPolicy } from "@opencode/core/managed-policy"
import { Mcp } from "@opencode/core/mcp/index"
import { AbsolutePath } from "@opencode/core/schema"
import { State } from "@opencode/core/state"
import { Document, Info } from "@opencode/schema/config"
import { ConfigMCP } from "@opencode/schema/config/mcp"
import { ID } from "@opencode/schema/event"
import { hostEnvironmentLayer } from "./fixture/environment"
import { location } from "./fixture/location"

// One configured server, "lifecycle", on the real Mcp layer with the given options.
function mcpTestLayer(server: typeof ConfigMCP.Server.Type, options?: Mcp.Options) {
  const unused = () => Effect.die("unused integration service")
  return Layer.effectDiscard(
    Effect.gen(function* () {
      const bus = yield* Bus.Service
      yield* State.batch(ConfigMcpPlugin.register(bus.subscribe()))
    }),
  ).pipe(
    Layer.provideMerge(Mcp.layer(options)),
    Layer.provideMerge(Form.layer),
    Layer.provide(
      Layer.mergeAll(
        ManagedPolicy.layer,
        Config.testLayer([
          new Document({
            type: "document",
            info: new Info({ mcp: new ConfigMCP.Info({ servers: { lifecycle: server } }) }),
          }),
        ]),
        Layer.succeed(
          Location.Service,
          Location.Service.of(location({ directory: AbsolutePath.make(import.meta.dir) })),
        ),
        Layer.mock(Bus.Service, {
          subscribe: () => Stream.never,
          publish: (definition, data) => Effect.succeed({ id: ID.create(), type: definition.type, data } as never),
        }),
        Layer.mock(Integration.Service, {
          revision: () => 0,
          connection: {
            active: unused,
            resolve: unused,
            key: unused,
            external: unused,
            activate: unused,
            update: unused,
            remove: unused,
            status: unused,
          },
          oauth: { connect: unused, status: unused, complete: unused, cancel: unused },
          command: { connect: unused, status: unused, cancel: unused },
        }),
        Layer.mock(Credential.Service, {}),
        hostEnvironmentLayer,
      ),
    ),
  )
}

// The managed build's connector options (packages/server/src/managed.ts, connectorMcp): the first
// tools() read waits for the servers' first connection attempts, and a closed stream is reopened.
const fixture = path.join(import.meta.dir, "fixture/mcp-lifecycle.ts")

async function startsFile() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-lifecycle-"))
  return { dir, file: path.join(dir, "starts") }
}
const count = async (file: string) =>
  (await fs.readFile(file, "utf8").catch(() => "")).split("\n").filter(Boolean).length

const local = (env: Record<string, string>) =>
  new ConfigMCP.Local({ type: "local", command: [process.execPath, fixture], environment: env })

test("with a startup wait, the first read includes a server that is still starting", async () => {
  const { dir, file } = await startsFile()
  try {
    const names = await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const mcp = yield* Mcp.Service
          return (yield* mcp.tools()).map((tool) => tool.name)
        }).pipe(
          Effect.provide(mcpTestLayer(local({ MCP_START_FILE: file, MCP_SLOW_MS: "500" }), { startupWaitMs: 10_000 })),
        ),
      ),
    )
    expect(names).toEqual(["lookup"])
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
}, 30_000)

test("without the option, a read does not wait (upstream behaviour)", async () => {
  const { dir, file } = await startsFile()
  try {
    const names = await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const mcp = yield* Mcp.Service
          return (yield* mcp.tools()).map((tool) => tool.name)
        }).pipe(Effect.provide(mcpTestLayer(local({ MCP_START_FILE: file, MCP_SLOW_MS: "1500" })))),
      ),
    )
    expect(names).toEqual([])
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
}, 30_000)

test("the wait is bounded: a server that has not started in time is left out", async () => {
  const { dir, file } = await startsFile()
  try {
    const { names, waited } = await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const mcp = yield* Mcp.Service
          const started = Date.now()
          const names = (yield* mcp.tools()).map((tool) => tool.name)
          return { names, waited: Date.now() - started }
        }).pipe(
          Effect.provide(mcpTestLayer(local({ MCP_START_FILE: file, MCP_SLOW_MS: "4000" }), { startupWaitMs: 300 })),
        ),
      ),
    )
    expect(names).toEqual([])
    expect(waited).toBeLessThan(2_000)
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
}, 30_000)

test("a server whose stream closes is restarted with backoff and its tools come back", async () => {
  const { dir, file } = await startsFile()
  try {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const mcp = yield* Mcp.Service
          expect((yield* mcp.tools()).map((tool) => tool.name)).toEqual(["lookup"])
          // The process exits after 300 ms; under reconnect it is started again.
          yield* Effect.promise(() => count(file)).pipe(
            Effect.filterOrFail((n) => n >= 3),
            Effect.retry({ times: 200, schedule: Schedule.spaced("50 millis") }),
          )
          const status = yield* mcp.servers().pipe(
            Effect.map((servers) => servers[0]?.status.status),
            Effect.filterOrFail((s) => s === "connected"),
            Effect.retry({ times: 200, schedule: Schedule.spaced("10 millis") }),
          )
          expect(status).toBe("connected")
        }).pipe(
          Effect.provide(
            mcpTestLayer(local({ MCP_START_FILE: file, MCP_EXIT_AFTER_MS: "300" }), {
              startupWaitMs: 10_000,
              reconnect: { initialMs: 50, maxMs: 200 },
            }),
          ),
        ),
      ),
    )
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
}, 30_000)

test("a disconnected server is not restarted", async () => {
  const { dir, file } = await startsFile()
  try {
    const before = await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const mcp = yield* Mcp.Service
          yield* mcp.disconnect("lifecycle")
          const n = yield* Effect.promise(() => count(file))
          yield* Effect.sleep("600 millis")
          return {
            n,
            after: yield* Effect.promise(() => count(file)),
            status: (yield* mcp.servers())[0]?.status.status,
          }
        }).pipe(
          Effect.provide(
            mcpTestLayer(local({ MCP_START_FILE: file }), {
              startupWaitMs: 10_000,
              reconnect: { initialMs: 50, maxMs: 100 },
            }),
          ),
        ),
      ),
    )
    expect(before.after).toBe(before.n)
    expect(before.status).toBe("disabled")
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
}, 30_000)

test("a server disconnected while a restart is pending is not started again", async () => {
  const { dir, file } = await startsFile()
  try {
    const result = await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const mcp = yield* Mcp.Service
          expect((yield* mcp.tools()).map((tool) => tool.name)).toEqual(["lookup"])
          // The process exits after 200 ms; the restart is then pending for 1 s.
          yield* mcp.servers().pipe(
            Effect.map((servers) => servers[0]?.status.status),
            Effect.filterOrFail((s) => s === "failed"),
            Effect.retry({ times: 200, schedule: Schedule.spaced("10 millis") }),
          )
          yield* mcp.disconnect("lifecycle")
          const n = yield* Effect.promise(() => count(file))
          yield* Effect.sleep("1600 millis")
          return {
            n,
            after: yield* Effect.promise(() => count(file)),
            status: (yield* mcp.servers())[0]?.status.status,
          }
        }).pipe(
          Effect.provide(
            mcpTestLayer(local({ MCP_START_FILE: file, MCP_EXIT_AFTER_MS: "200" }), {
              startupWaitMs: 10_000,
              reconnect: { initialMs: 1_000, maxMs: 1_000 },
            }),
          ),
        ),
      ),
    )
    expect(result.n).toBe(1)
    expect(result.after).toBe(1)
    expect(result.status).toBe("disabled")
  } finally {
    await fs.rm(dir, { recursive: true, force: true })
  }
}, 30_000)
