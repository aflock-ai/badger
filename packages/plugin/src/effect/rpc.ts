import type { RpcApi } from "@opencode/client/effect/api"
export type { RpcClient } from "@opencode/client/effect/api"
import type { Rpc } from "@opencode/schema/rpc"
import type { Effect, Scope } from "effect"
import type { Registration } from "./registration.js"

/**
 * Who made an RPC call. `role` is set only from the request header the deployment names as
 * trusted (BADGER_TRUSTED_ROLE_HEADER), which a fronting proxy sets from a verified identity.
 * In-process calls and calls without that header carry no role.
 */
export interface RpcCaller {
  readonly role?: string
}

export interface RpcCallContext<M extends Rpc.Method> {
  readonly error: Rpc.ErrorFactory<M>
  readonly caller: RpcCaller
}

export type RpcHandlers<D extends Rpc.Definition> = {
  readonly [Name in keyof D["methods"]]: (
    input: Rpc.Output<D["methods"][Name]["input"]>,
    context: RpcCallContext<D["methods"][Name]>,
  ) => Effect.Effect<Rpc.HandlerOutput<D["methods"][Name]["output"]>, Rpc.HandlerError<D["methods"][Name]>>
}

export interface RpcRegistration<D extends Rpc.Definition> extends Registration {
  readonly events: {
    readonly emit: (...args: Rpc.EventInput<D>) => Effect.Effect<void, unknown>
  }
}

export interface RpcDomain extends RpcApi<Rpc.SystemError, never, unknown> {
  readonly register: <const D extends Rpc.Definition>(
    definition: D,
    handlers: RpcHandlers<NoInfer<D>>,
  ) => Effect.Effect<RpcRegistration<D>, unknown, Scope.Scope>
}
