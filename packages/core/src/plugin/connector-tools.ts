export * as ConnectorTools from "./connector-tools.js"

import type { Plugin } from "@opencode/plugin/effect"
import { Tool } from "@opencode/schema/tool"
import { SecurityMarking } from "@opencode/util/security-marking"
import { Effect } from "effect"
import { ConnectorMarking } from "../connector-marking.js"

type Execute = Tool.Info["execute"]

// Every gated execute, mapped to its connector's wrap. Plugins share one tool registry and any of
// them may update any tool, so this is process-wide: whoever replaces a connector tool's execute,
// the replacement is gated by the connector that owns the tool.
const owners = new WeakMap<Execute, (execute: Execute) => Execute>()

/**
 * Scopes the shared plugin host to one plugin so its tool results carry its connectors' data
 * marking. A connector is a plugin RPC, and the plugin that registers the RPC is the plugin whose
 * tools speak for it: the RPC ids this plugin registers are its connectors. Before one of its tools
 * runs, the marking is read fresh (so a raise applies to later results); if it cannot be read the
 * tool is refused before it runs, as connector actions are. The result's metadata gets
 * `connectorMarking`. A plugin that registers no RPC is not a connector and is left alone.
 */
export function scope(
  host: Pick<Plugin.Context, "rpc" | "tool">,
  store: ReturnType<typeof ConnectorMarking.store>,
  // A managed build always requires a marking; others only when markings are in force.
  options: { readonly requireMarking?: boolean } = { requireMarking: SecurityMarking.build.managed },
): Pick<Plugin.Context, "rpc" | "tool"> {
  const connectors = new Set<string>()

  const marking = Effect.fn("ConnectorTools.marking")(function* () {
    const views = yield* Effect.forEach([...connectors], (connector) =>
      Effect.tryPromise(() => store.get(connector)).pipe(Effect.map((view) => ({ connector, ...view }))),
    ).pipe(Effect.mapError(() => new Tool.Error({ message: "The connector's data marking cannot be read" })))
    // No marking for a connector while one is required (a managed build) or markings are in force
    // (the deployment allows some): its output would leave unmarked, so refuse. Only a build that is
    // not managed and configures no marking at all has nothing to carry.
    if (views.some((view) => view.marking === null && (options.requireMarking || view.allowed.length > 0)))
      return yield* new Tool.Error({ message: "The connector has no data marking" })
    // With several connectors, the strictest marking applies to the plugin's results.
    return views.reduce<(typeof views)[number] | undefined>(
      (strictest, view) =>
        strictest === undefined ||
        (view.marking !== null && SecurityMarking.lowers(strictest.marking ?? "", view.marking))
          ? view
          : strictest,
      undefined,
    )
  })

  const wrap = (execute: Execute): Execute => {
    const gated: Execute = (input, context) =>
      Effect.gen(function* () {
        if (connectors.size === 0) return yield* execute(input, context)
        const view = yield* marking()
        const result = yield* execute(input, context)
        if (!view?.marking) return result
        return {
          ...result,
          metadata: {
            ...result.metadata,
            connectorMarking: { connector: view.connector, marking: view.marking, classification: view.classification },
          },
        }
      })
    owners.set(gated, wrap)
    return gated
  }

  return {
    rpc: Object.assign((definition: Parameters<Plugin.Context["rpc"]>[0]) => host.rpc(definition), host.rpc, {
      register: ((definition, handlers) =>
        host.rpc
          .register(definition, handlers)
          .pipe(
            Effect.tap(() => Effect.sync(() => connectors.add(definition.id))),
          )) as Plugin.Context["rpc"]["register"],
    }) as Plugin.Context["rpc"],
    tool: {
      ...host.tool,
      transform: (callback) =>
        host.tool.transform((editor) =>
          callback({
            ...editor,
            list: editor.list,
            get: editor.get,
            namespace: editor.namespace,
            remove: editor.remove,
            add: (tool) => editor.add({ ...tool, execute: wrap(tool.execute as Execute) } as typeof tool),
            update: (id, update) =>
              editor.update(id, (tool) => {
                const owner = owners.get(tool.execute)
                const before = tool.execute
                update(tool)
                // A connector tool stays gated whichever plugin swaps its execute.
                if (owner && tool.execute !== before) tool.execute = owner(tool.execute)
              }),
          }),
        ),
    },
  }
}
