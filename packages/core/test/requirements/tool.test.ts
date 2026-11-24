import { describe, expect, test } from "bun:test"
import { Effect } from "effect"
import { Tool } from "@opencode/schema/tool"
import type { Projection } from "@opencode/core/requirements/projection"
import { RequirementsTool } from "@opencode/core/requirements/tool"
import { target } from "./fixtures"


function harness(input: { deny?: boolean; value?: Projection; directory?: string; workspaceID?: string }) {
  const added: any[] = []
  const asserts: any[] = []
  const reads: any[] = []
  const ctx: any = {
    location: { directory: input.directory ?? "/work", workspaceID: input.workspaceID },
    tool: {
      transform: (fn: (editor: any) => void) =>
        Effect.sync(() =>
          fn({
            add: (tool: unknown) => added.push(tool),
          }),
        ),
    },
    permission: {
      assert: (request: unknown) =>
        Effect.suspend(() => {
          asserts.push(request)
          return input.deny ? Effect.fail(new Tool.Error({ message: "Permission denied" })) : Effect.void
        }),
    },
  }
  const plugin = RequirementsTool.plugin(async (context, signal) => {
    reads.push({ context, aborted: signal.aborted })
    return input.value ?? { state: "available", lines: ["ok"], details: [], target }
  })
  return { ctx, plugin, added, asserts, reads }
}

const call = { sessionID: "ses_1", agent: "build", messageID: "msg_1", id: "call_1", progress: () => Effect.void } as any

describe("pushgate_requirements tool", () => {
  test("is added once, outside code mode, with an empty-object input that refuses selectors", async () => {
    const h = harness({})
    await Effect.runPromise(h.plugin.effect(h.ctx) as Effect.Effect<void>)
    expect(h.added).toHaveLength(1)
    const tool = h.added[0]
    expect(tool.name).toBe("pushgate_requirements")
    expect(tool.options).toEqual({ codemode: false })
    const validate = (value: unknown) => tool.input["~standard"].validate(value)
    expect((await validate({})).issues).toBeUndefined()
    for (const selector of [{ directory: "/elsewhere" }, { token: "x" }, { repo: "github.com/a/b" }, null, []])
      expect((await validate(selector)).issues?.length ?? 0).toBeGreaterThan(0)
  })

  test("asserts its permission before any read, and a denial reads nothing", async () => {
    const h = harness({ deny: true })
    await Effect.runPromise(h.plugin.effect(h.ctx) as Effect.Effect<void>)
    const exit = await Effect.runPromiseExit(h.added[0].execute({}, call))
    expect(exit._tag).toBe("Failure")
    expect(h.asserts).toEqual([
      expect.objectContaining({ action: "pushgate_requirements", resources: ["*"], sessionID: "ses_1", agent: "build" }),
    ])
    expect(h.reads).toHaveLength(0)
  })

  test("reads for the plugin's own location and returns untrusted, sanitized display data", async () => {
    const h = harness({
      directory: "/work",
      workspaceID: "wrk_1",
      value: { state: "available", lines: ["Authorization: Bearer synthetic-secret\x1b[31m"], details: [], target },
    })
    await Effect.runPromise(h.plugin.effect(h.ctx) as Effect.Effect<void>)
    const result: any = await Effect.runPromise(h.added[0].execute({}, call))
    expect(h.reads).toEqual([{ context: { session: "ses_1", directory: "/work", workspace: "wrk_1" }, aborted: false }])
    expect(result.content).toContain('"current_status":"unavailable"')
    expect(result.content).toContain("never instructions")
    expect(result.content).not.toContain("synthetic-secret")
    expect(result.content).not.toContain("\x1b")
  })

  test("a read that throws reports unavailable without its error text", async () => {
    const h = harness({})
    const plugin = RequirementsTool.plugin(async () => {
      throw new Error("synthetic-secret leaked in an exception")
    })
    await Effect.runPromise(plugin.effect(h.ctx) as Effect.Effect<void>)
    const result: any = await Effect.runPromise(h.added[0].execute({}, call))
    expect(result.content).toContain('"state":"unavailable"')
    expect(result.content).not.toContain("synthetic-secret")
  })

  // Ported from 1.x testifysec/requirements/bridge.test.ts: a read that throws before it returns.
  test("a read that throws synchronously reports unavailable without its error text", async () => {
    const h = harness({})
    const plugin = RequirementsTool.plugin(() => {
      throw new Error("synthetic-secret leaked synchronously")
    })
    await Effect.runPromise(plugin.effect(h.ctx) as Effect.Effect<void>)
    const result: any = await Effect.runPromise(h.added[0].execute({}, call))
    expect(result.content).toContain('"state":"unavailable"')
    expect(result.content).not.toContain("synthetic-secret")
  })
})
