import { expect, test } from "bun:test"
import { Effect } from "effect"
import { ManagedFlow } from "@opencode/server/managed-flow"
import { ManagedConnectorProfile } from "../src/managed-connectors"

// The plugin's hooks, captured from a stand-in plugin context.
function hooks() {
  const flow = ManagedFlow.make({ gateway: "SECRET", connectors: { confluence: "SECRET", jira: "CONFIDENTIAL" } })
  const registered: Record<string, (event: any) => Effect.Effect<unknown>> = {}
  const hook = (domain: string) => (name: string, fn: (event: any) => Effect.Effect<unknown>) =>
    Effect.sync(() => void (registered[`${domain}.${name}`] = fn))
  const plugin = ManagedConnectorProfile.flowPlugin(flow, ["confluence", "jira"])
  Effect.runSync(plugin.effect({ tool: { hook: hook("tool") }, permission: { hook: hook("permission") } } as any) as any)
  const evaluate = (action: string, effect = "allow") => {
    const event = { sessionID: "ses_a", action, resources: ["*"], effect, message: undefined as string | undefined }
    Effect.runSync(registered["permission.evaluate"]!(event))
    return event
  }
  return { flow, evaluate, registered }
}

test("a call to a higher connector raises the label, and a lower connector's call is then refused", () => {
  const { flow, evaluate } = hooks()
  expect(evaluate("jira_jira_search").effect).toBe("allow")
  expect(evaluate("confluence_confluence_get_page").effect).toBe("allow")
  expect(flow.label().level).toBe(3) // SECRET
  const refused = evaluate("jira_jira_search")
  expect(refused.effect).toBe("deny")
  expect(refused.message).toContain("no write down")
  expect(evaluate("confluence_confluence_search").effect).toBe("allow")
  expect(evaluate("read").effect).toBe("allow")
})

test("nothing is read from tool output: the plugin registers no result hook", () => {
  const { registered } = hooks()
  expect(Object.keys(registered)).toEqual(["permission.evaluate"])
})

test("a call that will ask the user raises the label even if it is then cancelled: intended", () => {
  const { flow, evaluate } = hooks()
  expect(evaluate("confluence_confluence_get_page", "ask").effect).toBe("ask")
  expect(flow.label().level).toBe(3) // SECRET, whatever the user answers
})

test("a call already denied is left alone and does not raise the label", () => {
  const { flow, evaluate } = hooks()
  expect(evaluate("confluence_confluence_get_page", "deny").effect).toBe("deny")
  expect(flow.label().level).toBe(0) // UNCLASSIFIED
})

test("after the signed profile expires, every connector call is refused", () => {
  const flow = ManagedFlow.make({ gateway: "SECRET", connectors: { confluence: "SECRET", jira: "CONFIDENTIAL" } })
  let now = Date.parse("2026-01-01T00:00:00Z")
  const registered: Record<string, (event: any) => Effect.Effect<unknown>> = {}
  const hook = (domain: string) => (name: string, fn: (event: any) => Effect.Effect<unknown>) =>
    Effect.sync(() => void (registered[`${domain}.${name}`] = fn))
  const plugin = ManagedConnectorProfile.flowPlugin(flow, ["confluence", "jira"], new Date("2026-01-02T00:00:00Z"), () => now)
  Effect.runSync(plugin.effect({ tool: { hook: hook("tool") }, permission: { hook: hook("permission") } } as any) as any)
  const evaluate = (action: string) => {
    const event = { sessionID: "ses_a", action, resources: ["*"], effect: "allow", message: undefined as string | undefined }
    Effect.runSync(registered["permission.evaluate"]!(event))
    return event
  }
  expect(evaluate("jira_jira_search").effect).toBe("allow")
  now = Date.parse("2026-01-02T00:00:00Z")
  const refused = evaluate("jira_jira_search")
  expect(refused.effect).toBe("deny")
  expect(refused.message).toContain("the signed profile expired at 2026-01-02T00:00:00.000Z")
  // Tools of other servers are not the profile's to refuse.
  expect(evaluate("read").effect).toBe("allow")
})

test("connector names that could be confused with their tools are refused", () => {
  const flow = ManagedFlow.make({ gateway: "SECRET", connectors: { jira: "CONFIDENTIAL", jira_jira: "SECRET" } })
  expect(() => ManagedConnectorProfile.flowPlugin(flow, ["jira", "jira_jira"])).toThrow("cannot be told apart")
  expect(() => ManagedConnectorProfile.flowPlugin(flow, ["jira", "jira_low"])).toThrow("cannot be told apart")
})

test("a tool is matched to the connector its action names, never to a longer lookalike", () => {
  const { evaluate } = hooks()
  evaluate("confluence_confluence_get_page")
  // jira_jira_search is jira's search; it is checked against jira, not some "jira_jira".
  expect(evaluate("jira_jira_search").effect).toBe("deny")
  expect(evaluate("jiraX_search").effect).toBe("allow")
})

// BADGER_RAISE_CEILING is set by the workspace controller. Set but empty is not "no ceiling": it
// stops the start, so a misrendered value can never switch the warning off.
test("an empty raise ceiling stops the start; only an unset one means none", () => {
  const admitted = {
    gateway: { classification: "SECRET" },
    connectors: [{ name: "jira", classification: "CONFIDENTIAL" }],
  } as unknown as Parameters<typeof ManagedConnectorProfile.flow>[0]
  expect(() => ManagedConnectorProfile.flow(admitted, undefined, "")).toThrow()
  expect(() => ManagedConnectorProfile.flow(admitted, undefined, "NOT A MARKING")).toThrow()
  const none = ManagedConnectorProfile.flow(admitted, undefined, undefined)
  expect(none.call({ server: "jira", tool: "jira_search" })).toBeUndefined()
  const ceiled = ManagedConnectorProfile.flow(admitted, undefined, "UNCLASSIFIED")
  expect(ceiled.call({ server: "jira", tool: "jira_search" })).toContain("Continue in a CONFIDENTIAL copy")
})
