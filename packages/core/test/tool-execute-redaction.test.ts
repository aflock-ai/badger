import { describe, expect } from "bun:test"
import { Agent } from "@opencode/core/agent"
import { AppNodeBuilder } from "@opencode/core/effect/app-node-builder"
import { PluginHooks } from "@opencode/core/plugin/hooks"
import { Session } from "@opencode/core/session"
import { SessionMessage } from "@opencode/core/session/message"
import { Tool } from "@opencode/core/tool"
import { Shell } from "@opencode/schema/shell"
import type { Info } from "@opencode/schema/tool"
import { LayerNode } from "@opencode/util/effect/layer-node"
import { Effect, Schema } from "effect"
import { inspect } from "node:util"
import { testEffect } from "./lib/effect"

// Invented credentials only.
const token = "ghp_" + "A".repeat(36)
const url = "https://alice:synthetic-password-123456@example.test/repo.git"

const it = testEffect(AppNodeBuilder.build(LayerNode.group([Tool.node, PluginHooks.node])))
const progress: unknown[] = []
const call = (name: string): Parameters<Tool.Snapshot["execute"]>[0] => ({
  sessionID: Session.ID.make("ses_redaction"),
  agent: Agent.ID.make("build"),
  messageID: SessionMessage.ID.make("msg_redaction"),
  progress: (update) => Effect.sync(() => void progress.push(update)),
  call: { type: "tool-call", id: `call-${name}`, name, input: {} },
})

const leaky: Info = {
  name: "leaky",
  description: "Returns credentials",
  input: Schema.Struct({}),
  output: Schema.Struct({ remote: Schema.String }),
  execute: (_, context) =>
    context
      .progress({ note: `cloning ${url}` })
      .pipe(Effect.as({ output: { remote: url }, content: `token ${token}`, metadata: { [token]: url } })),
}
const failing: Info = {
  name: "failing",
  description: "Fails with credentials",
  input: Schema.Struct({}),
  execute: () =>
    Effect.fail(new Tool.Error({ message: `push to ${url} failed`, metadata: { header: `Bearer ${token}` } })),
}

const control = new Error("declined by the user")
const controlled: Info = {
  name: "controlled",
  description: "Fails with a clean control error",
  input: Schema.Struct({}),
  execute: () => Effect.fail(new Tool.Error({ message: "declined", error: control })),
}
const credentialCause = new Error(`push to ${url} failed`)
const leakyCause: Info = {
  name: "leaky_cause",
  description: "Fails with a cause that holds a credential",
  input: Schema.Struct({}),
  execute: () => Effect.fail(new Tool.Error({ message: "push failed", error: credentialCause })),
}

const shellID = Shell.ID.create()
// Progress arrives in pieces: a URL whose "@host" has not arrived yet does not look like a credential.
const partial: Info = {
  name: "partial",
  description: "Publishes partial progress",
  input: Schema.Struct({}),
  execute: (_, context) =>
    Effect.gen(function* () {
      yield* context.progress({ shellID, status: "running" })
      yield* context.progress({ text: "cloning https://alice:synthetic-password-123456" })
      yield* context.progress({
        toolCalls: [{ id: "call_1", name: "git_push", status: "running", output: "remote: sk-" }],
      })
      return { content: "ok" }
    }),
}

const keyed: Info = {
  name: "keyed",
  description: "Publishes a credential as a progress key",
  input: Schema.Struct({}),
  execute: (_, context) => context.progress({ [token]: true, status: "running" }).pipe(Effect.as({ content: "ok" })),
}
// Credentials past what util.inspect prints: array index 100, depth 10, and after 10,000 characters.
const deep: Record<string, unknown> = {}
let cursor = deep
for (let depth = 0; depth < 10; depth++) cursor = (cursor.next = {}) as Record<string, unknown>
cursor.secret = url
const hiddenCauses = [
  { items: [...Array.from({ length: 100 }, () => "ok"), url] },
  deep,
  { log: "x".repeat(20_000) + " " + url },
]
const hidden = (index: number): Info => ({
  name: `hidden_${index}`,
  description: "Fails with a credential beyond inspect limits",
  input: Schema.Struct({}),
  execute: () => Effect.fail(new Tool.Error({ message: "failed", error: hiddenCauses[index] })),
})

// 20,000 nested arrays: well under 50 KiB of JSON, far past any stack a recursive walk could use.
let nestedValue: unknown = url
for (let depth = 0; depth < 20_000; depth++) nestedValue = [nestedValue]
const nestedOutput: Info = {
  name: "nested_output",
  description: "Returns and publishes deeply nested data",
  input: Schema.Struct({}),
  output: Schema.Struct({ nested: Schema.Unknown }),
  execute: (_, context) =>
    context
      .progress({ toolCalls: nestedValue as unknown[] })
      .pipe(Effect.as({ output: { nested: nestedValue }, metadata: { nested: nestedValue }, content: "ok" })),
}
const nestedCause: Info = {
  name: "nested_cause",
  description: "Fails with a deeply nested cause",
  input: Schema.Struct({}),
  execute: () => Effect.fail(new Tool.Error({ message: "failed", error: { nested: nestedValue } })),
}

// Each piece looks harmless; together they are a credential URL.
const split: Info = {
  name: "split",
  description: "Publishes a URL split across fields and updates",
  input: Schema.Struct({}),
  execute: (_, context) =>
    Effect.gen(function* () {
      yield* context.progress({ chunk: "https://alice:", part: "synthetic-password-123456" })
      yield* context.progress({ chunk: "@example.test" })
      return { content: "ok" }
    }),
}
const mapCause: Info = {
  name: "map_cause",
  description: "Fails with credentials inside a Map and a Set",
  input: Schema.Struct({}),
  execute: () =>
    Effect.fail(
      new Tool.Error({
        message: "failed",
        error: { headers: new Map([["Authorization", `Bearer ${token}`]]), seen: new Set([url]) },
      }),
    ),
}

// Error subclasses whose prototype serializes a credential captured in a closure.
const captured = `Bearer ${token}`
class JsonLeak extends Error {
  toJSON() {
    return { header: captured }
  }
}
class InspectLeak extends Error {
  [inspect.custom]() {
    return captured
  }
}
class GetterLeak extends Error {
  get header() {
    return captured
  }
}
class DataLeak extends Error {}
;(DataLeak.prototype as unknown as Record<string, string>).header = captured
class KeyLeak extends Error {}
;(KeyLeak.prototype as unknown as Record<string, boolean>)[token] = true
const leakyPrototypes = [
  new JsonLeak("x"),
  new InspectLeak("x"),
  new GetterLeak("x"),
  new DataLeak("x"),
  new KeyLeak("x"),
]
const prototypeCause = (index: number): Info => ({
  name: `prototype_${index}`,
  description: "Fails with an error whose prototype leaks",
  input: Schema.Struct({}),
  execute: () => Effect.fail(new Tool.Error({ message: "failed", error: leakyPrototypes[index] })),
})

// Fragments in fields whose values look like identifiers: together they spell a token.
const fragments: Info = {
  name: "fragments",
  description: "Publishes a token split across identifier-like fields",
  input: Schema.Struct({}),
  execute: (_, context) =>
    context
      .progress({
        id: "gh",
        status: "p_" + "A".repeat(36),
        stage: "ghp",
        provider: "AAAA",
        tool: "x",
        constructor: token,
        toString: token,
      })
      .pipe(Effect.as({ content: "ok" })),
}

// Reports a clean descriptor, but an ordinary read returns the credential.
const proxied = new Proxy(new Error("failed"), {
  // oxlint-disable-next-line no-restricted-globals -- genuine reflection: a Proxy trap forwarding to its target
  get: (target, key, receiver) => (key === "message" ? captured : Reflect.get(target, key, receiver)),
})
const proxyCause: Info = {
  name: "proxy_cause",
  description: "Fails with a Proxy cause",
  input: Schema.Struct({}),
  execute: () => Effect.fail(new Tool.Error({ message: "failed", error: proxied })),
}
const blockCause = [
  { type: "text", text: "https://alice:" },
  { type: "text", text: "password@example.test" },
]
const blockSplitCause: Info = {
  name: "block_split_cause",
  description: "Fails with a cause whose text blocks join into a URL credential",
  input: Schema.Struct({}),
  execute: () => Effect.fail(new Tool.Error({ message: "failed", error: blockCause })),
}
const providerSplit: Info = {
  name: "provider_split",
  description: "Splits a key across provider progress updates",
  input: Schema.Struct({}),
  execute: (_, context) =>
    Effect.gen(function* () {
      yield* context.progress({ provider: "sk-" })
      yield* context.progress({ provider: "a".repeat(16) })
      return { content: "ok" }
    }),
}

const keySplit: Info = {
  name: "key_split",
  description: "Splits a token across progress keys",
  input: Schema.Struct({}),
  execute: (_, context) =>
    Effect.gen(function* () {
      yield* context.progress({ ghp_: true })
      yield* context.progress({ ["A".repeat(36)]: true })
      return { content: "ok" }
    }),
}

class LeakyArray extends Array {
  toJSON() {
    return captured
  }
}
const arraySubclass: Info = {
  name: "array_subclass",
  description: "Publishes an Array subclass that serializes a credential",
  input: Schema.Struct({}),
  execute: (_, context) =>
    context.progress({ toolCalls: LeakyArray.from([{ status: "running" }]) as any }).pipe(Effect.as({ content: "ok" })),
}

const add = (service: Tool.Interface) =>
  service.transform((editor) => {
    editor.add({ ...leaky, options: { codemode: false } })
    editor.add({ ...failing, options: { codemode: false } })
    editor.add({ ...controlled, options: { codemode: false } })
    editor.add({ ...leakyCause, options: { codemode: false } })
    editor.add({ ...partial, options: { codemode: false } })
    editor.add({ ...keyed, options: { codemode: false } })
    editor.add({ ...split, options: { codemode: false } })
    editor.add({ ...fragments, options: { codemode: false } })
    editor.add({ ...proxyCause, options: { codemode: false } })
    editor.add({ ...blockSplitCause, options: { codemode: false } })
    editor.add({ ...providerSplit, options: { codemode: false } })
    editor.add({ ...keySplit, options: { codemode: false } })
    editor.add({ ...arraySubclass, options: { codemode: false } })
    editor.add({ ...mapCause, options: { codemode: false } })
    leakyPrototypes.forEach((_, index) => editor.add({ ...prototypeCause(index), options: { codemode: false } }))
    hiddenCauses.forEach((_, index) => editor.add({ ...hidden(index), options: { codemode: false } }))
    editor.add({ ...nestedOutput, options: { codemode: false } })
    editor.add({ ...nestedCause, options: { codemode: false } })
  })

describe("tool execution redaction", () => {
  it.effect("redacts results, metadata and progress before anyone sees them", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      const hooks = yield* PluginHooks.Service
      yield* add(service)
      const seenByHook: unknown[] = []
      yield* hooks.register("tool", "execute.after", (event) =>
        Effect.sync(() => {
          seenByHook.push(structuredClone(event.status === "completed" ? event.result : event.error))
        }),
      )
      progress.length = 0
      const result = yield* (yield* service.snapshot()).execute(call("leaky"))
      const visible = JSON.stringify([result, progress, seenByHook])
      expect(visible).not.toContain(token)
      expect(visible).not.toContain("synthetic-password-123456")
      expect(visible).toContain("https://[redacted]@example.test/repo.git")
    }),
  )

  it.effect("an after-hook cannot reintroduce a credential", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      const hooks = yield* PluginHooks.Service
      yield* add(service)
      yield* hooks.register("tool", "execute.after", (event) =>
        Effect.sync(() => {
          if (event.status === "completed") event.result = { content: `hooked ${token}` }
        }),
      )
      const result = yield* (yield* service.snapshot()).execute(call("leaky"))
      expect(JSON.stringify(result)).not.toContain(token)
    }),
  )

  it.effect("redacts tool errors, keeping the error type", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      const error = yield* (yield* service.snapshot()).execute(call("failing")).pipe(Effect.flip)
      expect(error).toBeInstanceOf(Tool.Error)
      const visible = JSON.stringify({ message: error.message, metadata: error.metadata })
      expect(visible).not.toContain("synthetic-password-123456")
      expect(visible).not.toContain(token)
      expect(error.message).toBe("push to https://[redacted]@example.test/repo.git failed")
    }),
  )

  it.effect("keeps a clean error cause by identity, so control errors still match", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      const error = yield* (yield* service.snapshot()).execute(call("controlled")).pipe(Effect.flip)
      expect(error.error).toBe(control)
    }),
  )

  it.effect("replaces a cause that holds a credential with a redacted copy of the same type", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      const error = yield* (yield* service.snapshot()).execute(call("leaky_cause")).pipe(Effect.flip)
      expect(error.error).not.toBe(credentialCause)
      expect(error.error).toBeInstanceOf(Error)
      expect((error.error as Error).message).toBe("push to https://[redacted]@example.test/repo.git failed")
    }),
  )

  it.effect("progress publishes identifiers and status only; free text waits for the result", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      progress.length = 0
      yield* (yield* service.snapshot()).execute(call("partial"))
      expect(JSON.stringify(progress)).not.toContain("synthetic-password")
      expect(JSON.stringify(progress)).not.toContain("sk-")
      expect(progress[0]).toEqual({ shellID, status: "running" })
      expect(progress[2]).toEqual({ toolCalls: [{ status: "running" }] })
    }),
  )

  it.effect("a credential used as a progress key is not published", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      progress.length = 0
      yield* (yield* service.snapshot()).execute(call("keyed"))
      expect(JSON.stringify(progress)).not.toContain(token)
      expect(progress[0]).toEqual({ status: "running" })
    }),
  )

  it.effect("a credential beyond inspect limits in an error cause is still redacted", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      for (const [index, cause] of hiddenCauses.entries()) {
        const error = yield* (yield* service.snapshot()).execute(call(`hidden_${index}`)).pipe(Effect.flip)
        expect(error.error).not.toBe(cause)
        expect(JSON.stringify(error.error)).not.toContain("synthetic-password-123456")
      }
    }),
  )

  it.effect("free text never reaches progress, however it is split", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      progress.length = 0
      yield* (yield* service.snapshot()).execute(call("split"))
      expect(JSON.stringify(progress)).not.toContain("synthetic-password")
      expect(JSON.stringify(progress)).not.toContain("alice")
    }),
  )

  it.effect("a credential inside a Map or Set in an error cause is not passed on", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      const error = yield* (yield* service.snapshot()).execute(call("map_cause")).pipe(Effect.flip)
      // Full dump, Map and Set contents included, with no truncation.
      const dump = inspect(error.error, {
        depth: Infinity,
        maxArrayLength: Infinity,
        maxStringLength: Infinity,
        showHidden: true,
      })
      expect(dump).not.toContain("synthetic-password")
      expect(dump).not.toContain(token)
    }),
  )

  it.effect("an error whose prototype serializes a credential is replaced, prototype and all", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      for (const [index, cause] of leakyPrototypes.entries()) {
        const error = yield* (yield* service.snapshot()).execute(call(`prototype_${index}`)).pipe(Effect.flip)
        expect(error.error).not.toBe(cause)
        expect(error.error).toBeInstanceOf(Error)
        const copy = error.error as object
        // Bun's inspect prints errors from their stack and ignores showHidden, so list own keys too.
        const shown = [
          JSON.stringify(copy),
          inspect(copy, { showHidden: true, depth: Infinity }),
          String((copy as any).header),
          // oxlint-disable-next-line no-restricted-globals -- genuine reflection: every own key, symbols and non-enumerables included
          Reflect.ownKeys(copy)
            .map((key) => `${String(key)}=${String(Object.getOwnPropertyDescriptor(copy, key)?.value)}`)
            .join(" "),
        ]
        for (const text of shown) expect(text).not.toContain(token)
      }
    }),
  )

  it.effect("an after-hook cannot smuggle a credential through a toJSON function", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      const hooks = yield* PluginHooks.Service
      yield* add(service)
      yield* hooks.register("tool", "execute.after", (event) =>
        Effect.sync(() => {
          if (event.status === "completed")
            event.result = { content: "ok", metadata: { toJSON: () => ({ header: captured }) } as any }
        }),
      )
      const result = yield* (yield* service.snapshot()).execute(call("leaky"))
      expect(JSON.stringify(result)).not.toContain(token)
    }),
  )

  it.effect("a result field read through a getter is redacted from a single read", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      const hooks = yield* PluginHooks.Service
      yield* add(service)
      yield* hooks.register("tool", "execute.after", (event) =>
        Effect.sync(() => {
          if (event.status !== "completed") return
          let reads = 0
          event.result = {
            content: "ok",
            get metadata() {
              return reads++ === 0 ? { authorization: captured } : undefined
            },
          } as any
        }),
      )
      const result = yield* (yield* service.snapshot()).execute(call("leaky"))
      expect(inspect(result, { showHidden: true, depth: Infinity, getters: true })).not.toContain(token)
    }),
  )

  it.effect("progress strings pass only when they meet their field's real contract", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      progress.length = 0
      yield* (yield* service.snapshot()).execute(call("fragments"))
      expect(progress).toEqual([{}])
    }),
  )

  it.effect("an untrusted error prototype is detached from the copy", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      for (const [index, cause] of leakyPrototypes.entries()) {
        const error = yield* (yield* service.snapshot()).execute(call(`prototype_${index}`)).pipe(Effect.flip)
        expect(Object.getPrototypeOf(error.error)).not.toBe(Object.getPrototypeOf(cause))
        expect((Object.getPrototypeOf(error.error) as any).header).toBeUndefined()
      }
    }),
  )

  it.effect("a provider field cannot carry pieces of a key", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      progress.length = 0
      yield* (yield* service.snapshot()).execute(call("provider_split"))
      expect(progress).toEqual([{}, {}])
    }),
  )

  it.effect("a Proxy cause is never kept by identity", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      const error = yield* (yield* service.snapshot()).execute(call("proxy_cause")).pipe(Effect.flip)
      expect(error.error).not.toBe(proxied)
      expect(String((error.error as Error).message)).not.toContain(token)
    }),
  )

  it.effect("a credential split across text blocks of an error cause is redacted", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      const error = yield* (yield* service.snapshot()).execute(call("block_split_cause")).pipe(Effect.flip)
      expect(error.error).not.toBe(blockCause)
      expect(JSON.stringify(error.error)).not.toContain("password")
    }),
  )

  it.effect("deeply nested output, progress and causes fail closed instead of overflowing the stack", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      progress.length = 0
      const result = yield* (yield* service.snapshot()).execute(call("nested_output"))
      const visible = JSON.stringify([result, progress])
      expect(visible).toContain("[too deep]")
      expect(visible).not.toContain("synthetic-password-123456")
      const error = yield* (yield* service.snapshot()).execute(call("nested_cause")).pipe(Effect.flip)
      expect(error).toBeInstanceOf(Tool.Error)
      expect(JSON.stringify(error.error)).toContain("[too deep]")
      expect(JSON.stringify(error.error)).not.toContain("synthetic-password-123456")
    }),
  )

  it.effect("progress keys are known fields only", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      progress.length = 0
      yield* (yield* service.snapshot()).execute(call("key_split"))
      expect(progress).toEqual([{}, {}])
    }),
  )

  it.effect("progress arrays are rebuilt as plain arrays", () =>
    Effect.gen(function* () {
      const service = yield* Tool.Service
      yield* add(service)
      progress.length = 0
      yield* (yield* service.snapshot()).execute(call("array_subclass"))
      expect(JSON.stringify(progress)).not.toContain(token)
      expect(Object.getPrototypeOf((progress[0] as any).toolCalls)).toBe(Array.prototype)
    }),
  )
})
