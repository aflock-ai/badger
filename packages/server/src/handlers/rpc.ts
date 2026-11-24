import { ConnectorMarking } from "@opencode/core/connector-marking"
import { ConnectorMarkingPlugin } from "@opencode/core/plugin/connector-marking"
import { Rpc } from "@opencode/core/rpc"
import { Plugin } from "@opencode/core/plugin"
import { RpcError, RpcInternalError } from "@opencode/protocol/errors"
import { Global } from "@opencode/util/global"
import { Effect } from "effect"
import { HttpApiBuilder } from "effect/http-api"
import path from "node:path"
import { Api } from "../api"

// The caller's role comes only from the header the deployment names as trusted. Set
// BADGER_TRUSTED_ROLE_HEADER only behind a proxy that strips callers' copies of that header and
// sets it from a verified identity; unset, no call carries a role.
export function callerRole(headers: Readonly<Record<string, string | undefined>>, env = process.env) {
  const name = env.BADGER_TRUSTED_ROLE_HEADER?.trim().toLowerCase()
  return (name ? headers[name]?.trim() : undefined) || undefined
}

export const RpcHandler = HttpApiBuilder.group(Api, "server.rpc", (handlers) =>
  Effect.gen(function* () {
    const markings = ConnectorMarking.store(path.join((yield* Global.Service).state, "connector-markings.json"))
    return handlers.handle("rpc.call", ({ params, payload, request }) =>
      Effect.gen(function* () {
        yield* Plugin.awaitActivation
        const rpc = yield* Rpc.Service
        const role = callerRole(request.headers)
        // Every connector action is logged with its connector's data marking, and refused when that
        // marking cannot be read. The marking RPC itself is exempt so an admin can still repair it.
        if (params.rpcID !== ConnectorMarkingPlugin.Definition.id) {
          const marking = yield* Effect.tryPromise(() => markings.get(params.rpcID)).pipe(
            Effect.mapError(
              (): Rpc.Failure => ({
                type: "rpc.marking_unavailable",
                message: "The connector's data marking cannot be read",
              }),
            ),
          )
          yield* Effect.logInfo("connector action", {
            connector: params.rpcID,
            method: params.method,
            connector_marking: marking.marking,
            role,
          })
        }
        const output = yield* rpc.call(params.rpcID, params.method, payload.input, role === undefined ? {} : { role })
        return output === undefined ? {} : { output }
      }).pipe(
        Effect.mapError((error) =>
          error.type === "rpc.invalid_output" || error.type === "rpc.internal"
            ? new RpcInternalError({ type: error.type, message: error.message })
            : new RpcError({
                type: error.type,
                message: error.message,
                ...(error.data === undefined ? {} : { data: error.data }),
              }),
        ),
        // Defects outside handler execution are still logged, never echoed to the client.
        Effect.catchDefect((defect) =>
          Effect.logError("rpc call failed", { rpc: params.rpcID, method: params.method, defect }).pipe(
            Effect.andThen(Effect.fail(new RpcInternalError({ type: "rpc.internal", message: "RPC call failed" }))),
          ),
        ),
      ),
    )
  }),
)
