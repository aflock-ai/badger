import { expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { Effect, Schema } from "effect"
import { ConnectorMarking } from "../../src/connector-marking"
import { ConnectorTools } from "../../src/plugin/connector-tools"

const policy = () => ({ marking: "UNCLASSIFIED", classification: "UNCLASSIFIED", allowed: ["UNCLASSIFIED", "CUI"] })
const context = { sessionID: "s", agent: "a", messageID: "m", id: "c", progress: () => Effect.void } as never

// A minimal host: RPC registration always succeeds, and the tool editor stores tools by name.
function fakeHost() {
  const tools = new Map<string, any>()
  const editor = {
    list: () => [...tools.values()],
    get: (id: string) => tools.get(id),
    namespace: () => {},
    add: (tool: any) => tools.set(tool.name, { ...tool, id: tool.name }),
    update: (id: string, update: (tool: any) => void) => {
      const tool = tools.get(id)
      if (tool) update(tool)
    },
    remove: (id: string) => tools.delete(id),
  }
  const host = {
    rpc: Object.assign(() => ({}), { register: () => Effect.succeed({}) }),
    tool: { transform: (callback: (input: any) => void) => Effect.sync(() => callback(editor)) },
  } as any
  return { host, tools }
}

async function withStore(run: (store: ReturnType<typeof ConnectorMarking.store>, file: string) => Promise<void>) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "connector-tools-"))
  const file = path.join(dir, "markings.json")
  try {
    await run(ConnectorMarking.store(file, policy), file)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

const define = (id: string) => ({ id, methods: {}, events: {} }) as never
const tool = (name: string, content: string) => ({
  name,
  description: name,
  input: Schema.Unknown,
  execute: () => Effect.succeed({ content }),
})

test("with several connectors, a plugin's tool results carry the strictest marking", () =>
  withStore(async (store) => {
    const { host, tools } = fakeHost()
    const scoped = ConnectorTools.scope(host, store)
    await Effect.runPromise(scoped.rpc.register(define("jira"), {} as never) as never)
    await Effect.runPromise(scoped.rpc.register(define("gitlab"), {} as never) as never)
    await Effect.runPromise(scoped.tool.transform((editor) => editor.add(tool("search", "x"))) as never)
    await store.set("gitlab", "CUI")
    const result = await Effect.runPromise(tools.get("search").execute(null, context) as never)
    expect((result as any).metadata.connectorMarking).toEqual({
      connector: "gitlab",
      marking: "CUI",
      classification: "UNCLASSIFIED",
    })
  }))

test("a connector tool stays gated when its own plugin swaps its execute", () =>
  withStore(async (store) => {
    const { host, tools } = fakeHost()
    const scoped = ConnectorTools.scope(host, store)
    await Effect.runPromise(scoped.rpc.register(define("gitlab"), {} as never) as never)
    await Effect.runPromise(
      scoped.tool.transform((editor) => {
        editor.add(tool("search", "first"))
        editor.update("search", (current) => {
          current.execute = () => Effect.succeed({ content: "swapped" })
        })
      }) as never,
    )
    const result = await Effect.runPromise(tools.get("search").execute(null, context) as never)
    expect(result).toMatchObject({ content: "swapped", metadata: { connectorMarking: { connector: "gitlab" } } })
  }))

// Plugins share one tool registry, so another plugin's update must not lift a connector's gate.
test("another plugin cannot swap a connector tool's execute to remove its gate", () =>
  withStore(async (store, file) => {
    const { host, tools } = fakeHost()
    const connector = ConnectorTools.scope(host, store)
    const other = ConnectorTools.scope(host, store)
    await Effect.runPromise(connector.rpc.register(define("gitlab"), {} as never) as never)
    await Effect.runPromise(connector.tool.transform((editor) => editor.add(tool("search", "data"))) as never)
    let ran = 0
    await Effect.runPromise(
      other.tool.transform((editor) =>
        editor.update("search", (current) => {
          current.execute = () => Effect.sync(() => ({ content: `stolen ${++ran}` }))
        }),
      ) as never,
    )
    // Still marked by its connector.
    const result = await Effect.runPromise(tools.get("search").execute(null, context) as never)
    expect(result).toMatchObject({ metadata: { connectorMarking: { connector: "gitlab" } } })
    // Still refused, without running, when the marking cannot be read.
    await Bun.write(file, "{not json")
    const failed = await Effect.runPromise(Effect.flip(tools.get("search").execute(null, context)) as never)
    expect((failed as any)._tag).toBe("Tool.Error")
    expect(ran).toBe(1)
  }))

async function withPolicy(
  configured: () => { marking: string | null; classification: string | null; allowed: string[] },
  run: (store: ReturnType<typeof ConnectorMarking.store>) => Promise<void>,
) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "connector-tools-"))
  try {
    await run(ConnectorMarking.store(path.join(dir, "markings.json"), configured))
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

// Markings are in force (the deployment allows some) but none applies to the connector: its
// output would leave unmarked, so it is refused before the tool runs.
test("a connector tool is refused before it runs when markings are in force but it has none", () =>
  withPolicy(
    () => ({ marking: null, classification: null, allowed: ["UNCLASSIFIED", "CUI"] }),
    async (store) => {
      const { host, tools } = fakeHost()
      const scoped = ConnectorTools.scope(host, store)
      await Effect.runPromise(scoped.rpc.register(define("gitlab"), {} as never) as never)
      let ran = 0
      await Effect.runPromise(
        scoped.tool.transform((editor) =>
          editor.add({ ...tool("search", "x"), execute: () => Effect.sync(() => ({ content: `ran ${++ran}` })) }),
        ) as never,
      )
      const failed = await Effect.runPromise(Effect.flip(tools.get("search").execute(null, context)) as never)
      expect((failed as any)._tag).toBe("Tool.Error")
      expect(ran).toBe(0)
    },
  ))

// A deployment that configures no marking at all has nothing to carry: connector tools run unmarked.
test("with no marking configured, a connector tool runs and its result is unmarked", () =>
  withPolicy(
    () => ({ marking: null, classification: null, allowed: [] }),
    async (store) => {
      const { host, tools } = fakeHost()
      const scoped = ConnectorTools.scope(host, store)
      await Effect.runPromise(scoped.rpc.register(define("gitlab"), {} as never) as never)
      await Effect.runPromise(scoped.tool.transform((editor) => editor.add(tool("search", "x"))) as never)
      const result = await Effect.runPromise(tools.get("search").execute(null, context) as never)
      expect(result).toEqual({ content: "x" })
    },
  ))

// A managed build requires a marking: with none configured, connector data is refused, not let out unmarked.
test("in a managed build a connector tool with no marking is refused before it runs", () =>
  withPolicy(
    () => ({ marking: null, classification: null, allowed: [] }),
    async (store) => {
      const { host, tools } = fakeHost()
      const scoped = ConnectorTools.scope(host, store, { requireMarking: true })
      await Effect.runPromise(scoped.rpc.register(define("gitlab"), {} as never) as never)
      let ran = 0
      await Effect.runPromise(
        scoped.tool.transform((editor) =>
          editor.add({ ...tool("search", "x"), execute: () => Effect.sync(() => ({ content: `ran ${++ran}` })) }),
        ) as never,
      )
      const failed = await Effect.runPromise(Effect.flip(tools.get("search").execute(null, context)) as never)
      expect((failed as any)._tag).toBe("Tool.Error")
      expect(ran).toBe(0)
    },
  ))
