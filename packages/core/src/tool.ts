export * as Tool from "./tool.js"
export { CallID, Content, Error, FileContent, TextContent } from "@opencode/schema/tool"
export type { Context, Metadata, Namespace, Options, Result } from "@opencode/schema/tool"

import { ToolDefinition, type ToolCall } from "@opencode/ai"
import { Tool } from "@opencode/schema/tool"
import { Context, Effect, Layer, Result, Schema, SchemaIssue, Types } from "effect"
import { types } from "node:util"
import { makeLocationNode } from "@opencode/util/effect/app-node"
import type { Agent } from "./agent.js"
import { CodeModeCatalog } from "./codemode/catalog.js"
import { CodeModeTool } from "./codemode/tool.js"
import { Image } from "./image.js"
import { Permission } from "./permission.js"
import { PluginHooks } from "./plugin/hooks.js"
import { SessionMessage } from "./session/message.js"
import { SessionSchema } from "./session/schema.js"
import { State } from "./state.js"
import { ToolOutputRedaction } from "./tool-output-redaction.js"
import { definition, effectiveName, execute, normalizedName, normalizeContent } from "./tool/runtime.js"
import { Wildcard } from "./util/wildcard.js"

// Each field is read exactly once and that snapshot is what gets redacted and returned: a getter
// cannot hand a credential to a copy and something else to the check. Nothing else is carried over.
function redactResult<T extends Tool.Result>(result: T): T {
  const { output, content, metadata } = result
  return {
    ...(output === undefined ? {} : { output: ToolOutputRedaction.value(output) }),
    ...(content === undefined ? {} : { content: ToolOutputRedaction.value(content) }),
    ...(metadata === undefined ? {} : { metadata: ToolOutputRedaction.value(metadata) }),
  } as T
}

// Progress arrives in pieces, and pieces of a credential (a URL or token split across fields or
// updates) are not recognizable on their own. So progress carries no free text: numbers, booleans,
// and strings only in fields with a fixed contract, checked against it: generated session and shell
// IDs and the status vocabulary. Every other string waits for the final result, redacted whole.
// This guards output that tools pass along; it is not a sandbox against tool code itself.
const generatedID = (prefix: string) => new RegExp(`^${prefix}_[0-9a-f]{12}[0-9A-Za-z]{14}$`)
const sessionID = generatedID("ses")
// A Map, so a field such as "constructor" never resolves to something inherited.
const contracts = new Map<string, (text: string) => boolean>([
  ["sessionID", (text) => sessionID.test(text)],
  ["sessionId", (text) => sessionID.test(text)],
  ["shellID", (text) => generatedID("sh").test(text)],
  ["status", (text) => text === "running" || text === "completed" || text === "error"],
])
// Progress keys are the fields tools actually publish; any other key, whatever its value, is dropped.
const progressFields = new Set(["sessionID", "sessionId", "shellID", "status", "toolCalls"])
function progressSafe(update: unknown, field?: string, depth = 0): any {
  if (typeof update === "number" || typeof update === "boolean" || update === null) return update
  // Progress past the depth any tool publishes is dropped, not walked (see ToolOutputRedaction.maxDepth).
  if (depth > ToolOutputRedaction.maxDepth) return undefined
  if (typeof update === "string")
    return field !== undefined && contracts.get(field)?.(update) === true ? update : undefined
  // Array.from always builds a plain Array, so a subclass's inherited toJSON cannot come along.
  if (Array.isArray(update))
    return Array.from(update, (item) => progressSafe(item, undefined, depth + 1)).filter((item) => item !== undefined)
  if (update && typeof update === "object")
    return Object.fromEntries(
      Object.entries(update)
        .filter(([key]) => progressFields.has(key))
        .map(([key, item]) => [key, progressSafe(item, key, depth + 1)])
        .filter(([, item]) => item !== undefined),
    )
  return undefined
}

// Errors the runner and plan mode match by class, whose prototypes are this codebase's own code.
ToolOutputRedaction.trust(Permission.BlockedError)

// A cause with nothing to redact is kept by identity: permission and control errors are matched
// downstream by identity and type. Only a cause that holds a credential, or anything that could hide
// one from this check (an accessor, a function, a container other than a plain object or array such as
// a Map, or an error whose prototype could serialize hidden data), is replaced with a redacted copy.
function redactCause(cause: unknown) {
  return clean(cause) ? cause : ToolOutputRedaction.error(cause)
}

const plain = (item: object) => {
  const proto = Object.getPrototypeOf(item)
  if (proto === null || proto === Object.prototype || proto === Array.prototype) return true
  return item instanceof Error && ToolOutputRedaction.safePrototype(item)
}

// Every string reachable through own properties, symbol and non-enumerable keys included.
function clean(item: unknown, seen = new WeakSet<object>(), depth = 0): boolean {
  if (typeof item === "string") return ToolOutputRedaction.text(item) === item
  if (typeof item === "symbol") return clean(item.description ?? "", seen, depth)
  if (typeof item === "function") return false
  if (!item || typeof item !== "object") return true
  // Too deep to check is not clean: the cause goes to the depth-limited redacted copy instead.
  if (depth > ToolOutputRedaction.maxDepth) return false
  if (seen.has(item)) return true
  seen.add(item)
  // A Proxy can answer the descriptor checks below differently from an ordinary read.
  if (types.isProxy(item)) return false
  if (!plain(item)) return false
  if (Array.isArray(item) && !ToolOutputRedaction.textBlocksClean(item)) return false
  // oxlint-disable-next-line no-restricted-globals -- genuine reflection: every own key, symbols and non-enumerables included
  for (const key of Reflect.ownKeys(item)) {
    if (!clean(key, seen, depth)) return false
    const descriptor = Object.getOwnPropertyDescriptor(item, key)!
    if (!("value" in descriptor) || !clean(descriptor.value, seen, depth + 1)) return false
  }
  return true
}

function redactError(error: Tool.Error) {
  return new Tool.Error({
    message: ToolOutputRedaction.text(error.message),
    ...(error.error === undefined ? {} : { error: redactCause(error.error) }),
    ...(error.metadata === undefined ? {} : { metadata: ToolOutputRedaction.value(error.metadata) }),
  })
}

export class RegistrationError extends Schema.TaggedError<RegistrationError>()("Tool.RegistrationError", {
  name: Schema.String,
  message: Schema.String,
}) {}

export interface Editor {
  readonly list: () => readonly (Tool.Info & { readonly id: string })[]
  readonly get: (id: string) => (Tool.Info & { readonly id: string }) | undefined
  readonly namespace: (namespace: Tool.Namespace) => void
  readonly add: (tool: Tool.Info) => void
  readonly update: (id: string, update: (tool: Types.Mutable<Tool.Info>) => void) => void
  readonly remove: (id: string) => void
}

type Data = {
  tools: Map<string, Tool.Info & { readonly id: string }>
  namespaces: Map<string, Tool.Namespace>
  errors: { kind: "tool" | "namespace"; name: string; namespace?: string; error: RegistrationError }[]
}

export interface Interface extends State.Transformable<Editor> {
  readonly list: () => Effect.Effect<ReadonlyArray<Tool.Info & { readonly id: string }>>
  readonly snapshot: (permissions?: Permission.Ruleset) => Effect.Effect<Snapshot>
}

/** A local execution result after hooks and content normalization. */
export interface NormalizedResult extends Tool.Result {
  readonly content: ReadonlyArray<Tool.Content>
}

export interface Snapshot {
  readonly definitions: ReadonlyArray<ToolDefinition>
  readonly codeModeCatalog?: CodeModeCatalog.Inventory
  readonly execute: (input: {
    readonly sessionID: SessionSchema.ID
    readonly agent: Agent.ID
    readonly messageID: SessionMessage.ID
    readonly call: ToolCall
    readonly progress?: (update: Tool.Metadata) => Effect.Effect<void>
    /** Surviving request definitions, keyed by the names advertised after session context hooks. */
    readonly definitions?: ReadonlyMap<string, ToolDefinition>
  }) => Effect.Effect<NormalizedResult, Tool.Error>
}

export class Service extends Context.Service<Service, Interface>()("@opencode/Tool") {}

const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const hooks = yield* PluginHooks.Service
    const image = yield* Image.Service

    type NormalizedItem = Tool.Content | "decode" | "size"
    const normalizeImages = Effect.fnUntraced(function* (content: ReadonlyArray<Tool.Content>) {
      const normalized = yield* Effect.forEach(content, (item): Effect.Effect<NormalizedItem> => {
        if (item.type !== "file" || !item.mime.startsWith("image/")) return Effect.succeed(item)
        const base64 = /^data:[^,]*;base64,(.*)$/s.exec(item.uri)?.[1]
        if (base64 === undefined) return Effect.succeed(item)
        const resource = item.name ?? `${item.mime} tool output`
        return image.normalize(resource, { uri: resource, content: base64, encoding: "base64", mime: item.mime }).pipe(
          Effect.map((result) => ({
            ...item,
            uri: `data:${result.mime};base64,${result.content}`,
            mime: result.mime,
          })),
          Effect.catchTag("Image.ResizerUnavailableError", () => Effect.succeed(item)),
          Effect.catchTag("Image.DecodeError", () => Effect.succeed("decode" as const)),
          Effect.catchTag("Image.SizeError", () => Effect.succeed("size" as const)),
        )
      })
      const note = (reason: "decode" | "size", text: string) => {
        const count = normalized.filter((item) => item === reason).length
        if (count === 0) return []
        return [{ type: "text" as const, text: `[${count} image${count === 1 ? "" : "s"} omitted: ${text}]` }]
      }
      return [
        ...normalized.filter((item) => typeof item !== "string"),
        ...note("decode", "could not be decoded."),
        ...note("size", "could not be resized below the image size limit."),
      ]
    })

    const beforeExecute = (name: string, input: unknown, context: Tool.Context) =>
      hooks.trigger("tool", "execute.before", {
        tool: name,
        sessionID: context.sessionID,
        agent: context.agent,
        messageID: context.messageID,
        id: context.id,
        input,
      })

    const executeTool = Effect.fn("Tool.execute")(function* (
      tool: Tool.Info,
      name: string,
      input: unknown,
      context: Tool.Context,
    ) {
      // Credentials in tool output are redacted before any observer (progress, plugin hooks, the
      // runner, storage) sees them; inputs are never changed. See testifysec/TOOL-OUTPUT-REDACTION.md.
      const redacting = {
        ...context,
        progress: (update: Tool.Metadata) => context.progress(progressSafe(update)),
      }
      const execution = yield* execute(tool, input, redacting).pipe(
        Effect.map((value) => ({ value: redactResult(value) })),
        Effect.catchTag("Tool.Error", (failure) => Effect.succeed({ failure: redactError(failure) })),
      )
      const base = {
        tool: name,
        sessionID: context.sessionID,
        agent: context.agent,
        messageID: context.messageID,
        id: context.id,
        input,
      }
      if ("failure" in execution) {
        const afterEvent: PluginHooks.Domains["tool"]["execute.after"] = {
          ...base,
          status: "error",
          error: execution.failure,
        }
        yield* hooks.trigger("tool", "execute.after", afterEvent)
        return yield* redactError(afterEvent.error)
      }
      const afterEvent: PluginHooks.Domains["tool"]["execute.after"] = {
        ...base,
        status: "completed",
        result: {
          ...(execution.value.output === undefined ? {} : { output: execution.value.output }),
          content: execution.value.content,
          ...(execution.value.metadata === undefined ? {} : { metadata: execution.value.metadata }),
        },
      }
      yield* hooks.trigger("tool", "execute.after", afterEvent)
      // Again after the hook, so a plugin cannot reintroduce what was removed.
      const after = redactResult(afterEvent.result)
      const afterContent = yield* normalizeImages(normalizeContent(after.content, after.output))
      return {
        ...(after.output === undefined ? {} : { output: after.output }),
        content: afterContent,
        ...(after.metadata === undefined ? {} : { metadata: after.metadata }),
      }
    })

    let catalog: { data: Data; names: string; value: CodeModeCatalog.Inventory } | undefined
    const state = State.create<Data, Editor>({
      name: "tool",
      initial: () => ({
        tools: new Map(),
        namespaces: new Map(),
        errors: [],
      }),
      editor: (editor) => ({
        list: () => Array.from(editor.tools.values()),
        get: (id) => editor.tools.get(id),
        namespace: (namespace) => {
          const error = namespaceError(namespace.name)
          if (error) {
            editor.errors.push({ kind: "namespace", name: namespace.name, namespace: namespace.name, error })
            return
          }
          editor.namespaces.set(namespace.name, { ...namespace })
        },
        add: (tool) => {
          const error = registrationError(tool)
          if (error) {
            editor.errors.push({ kind: "tool", name: tool.name, namespace: tool.options?.namespace, error })
            return
          }
          const id = effectiveName(tool)
          editor.tools.set(id, { ...tool, id, options: tool.options && { ...tool.options } })
        },
        update: (id, update) => {
          const current = editor.tools.get(id)
          if (!current) return
          const tool = { ...current, options: current.options && { ...current.options } }
          update(tool)
          tool.name = current.name
          tool.id = id
          if (tool.options?.namespace !== current.options?.namespace)
            tool.options = { ...tool.options, namespace: current.options?.namespace }
          const error = registrationError(tool)
          if (error) {
            editor.errors.push({ kind: "tool", name: tool.name, namespace: tool.options?.namespace, error })
            return
          }
          editor.tools.set(id, tool)
        },
        remove: (id) => {
          editor.tools.delete(id)
        },
      }),
      notify: (value) => {
        catalog = undefined
        return Effect.forEach(
          value.errors,
          ({ kind, name, namespace, error }) =>
            Effect.logError(`Skipping invalid ${kind} registration`, {
              name,
              namespace,
              error: error.message,
            }),
          { discard: true },
        )
      },
    })

    return Service.of({
      transform: state.transform,
      reload: state.reload,
      list: () => Effect.sync(() => Array.from(state.get().tools.values())),
      snapshot: Effect.fn("Tool.snapshot")((permissions) =>
        Effect.sync(() => {
          const data = state.get()
          const active = new Map<string, Tool.Info>()
          const rules = permissions ?? []
          for (const [name, tool] of data.tools) {
            if (whollyDisabled(tool.options?.permission ?? name, rules)) continue
            active.set(name, tool)
          }
          const direct = new Map(Array.from(active).filter(([, tool]) => tool.options?.codemode === false))
          const codeModeTools = new Map(Array.from(active).filter(([, tool]) => tool.options?.codemode !== false))
          const namespaces = data.namespaces
          const codeModeInventory = { tools: codeModeTools, namespaces }
          const codeModeEnabled = !whollyDisabled("execute", rules)
          const codeModeTool = codeModeEnabled
            ? CodeModeTool.create(codeModeInventory, (name, tool, input, context) =>
                beforeExecute(name, input, context).pipe(
                  Effect.flatMap((event) => executeTool(tool, name, event.input, context)),
                ),
              )
            : undefined
          const names = Array.from(codeModeTools.keys()).join("\0")
          // Discovery is immutable for a registry revision and visible tool set. Keep request
          // definitions/executors fresh, but share the much larger rendered catalog across steps.
          const codeModeCatalog = !codeModeEnabled
            ? undefined
            : catalog?.data === data && catalog.names === names
              ? catalog.value
              : CodeModeTool.catalog(codeModeInventory)
          if (codeModeCatalog) catalog = { data, names, value: codeModeCatalog }
          return {
            ...(codeModeCatalog === undefined ? {} : { codeModeCatalog }),
            definitions: [
              ...Array.from(direct)
                .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
                .map(([, tool]) => definition(tool)),
              ...(codeModeTool ? [definition(codeModeTool)] : []),
            ],
            execute: Effect.fnUntraced(function* (input: Parameters<Snapshot["execute"]>[0]) {
              const context: Tool.Context = {
                sessionID: input.sessionID,
                agent: input.agent,
                messageID: input.messageID,
                id: Tool.CallID.make(input.call.id),
                progress: input.progress ?? (() => Effect.void),
              }
              const event = yield* beforeExecute(input.call.name, input.call.input, context)
              const requested = input.definitions?.get(event.tool)
              // Preserve session context removal and alias resolution, now after the repair hook.
              if (!requested && input.definitions && (direct.has(event.tool) || codeModeTool?.name === event.tool))
                return yield* new Tool.Error({ message: `Tool is not available for this request: ${event.tool}` })
              const name = requested?.name ?? event.tool
              if (name === "execute" && codeModeTool)
                return yield* executeTool(codeModeTool, name, event.input, context)
              const tool = direct.get(name)
              if (tool) return yield* executeTool(tool, name, event.input, context)
              return yield* new Tool.Error({
                message: `No tool named "${name}" is currently available. Please use a tool from the available tool list.`,
              })
            }),
          }
        }),
      ),
    })
  }),
)

const whollyDisabled = (action: string, rules: Permission.Ruleset) => {
  const rule = rules.findLast((rule) => Wildcard.match(action, rule.action))
  return rule?.resource === "*" && rule.effect === "deny"
}

const formatSchemaIssue = SchemaIssue.makeFormatterDefault()

function schemaMakeError(error: unknown) {
  if (error instanceof Error && SchemaIssue.isIssue(error.cause)) return formatSchemaIssue(error.cause)
  return error instanceof Error ? error.message : String(error)
}

function registrationError(tool: Tool.Info) {
  const namespace = tool.options?.namespace
  if (namespace !== undefined) {
    const error = namespaceError(namespace)
    if (error) return error
  }
  const name = normalizedName(tool)
  if (!/^[A-Za-z0-9_-]+$/.test(name)) return new RegistrationError({ name, message: `Invalid tool name: ${name}` })
  const id = effectiveName(tool)
  if (tool.options?.codemode === false && id === "execute")
    return new RegistrationError({ name: id, message: 'Tool name "execute" is reserved for CodeMode' })
  const result = Result.try({
    try: () => ToolDefinition.make(definition(tool)),
    catch: (error) =>
      new RegistrationError({ name: id, message: `Invalid tool definition ${id}: ${schemaMakeError(error)}` }),
  })
  return Result.isFailure(result) ? result.failure : undefined
}

function namespaceError(name: string) {
  if (name.split(".").every((segment) => /^[A-Za-z0-9_-]+$/.test(segment))) return
  return new RegistrationError({ name, message: `Invalid tool namespace: ${JSON.stringify(name)}` })
}

export const node = makeLocationNode({
  service: Service,
  layer,
  deps: [PluginHooks.node, Image.node],
})
