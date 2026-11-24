export * as RoutePolicy from "./route-policy"

import { Context, Effect, Layer } from "effect"
import { FindMyWay, HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/http"
import { makeGlobalNode } from "@opencode/util/effect/app-node"
import { Api } from "./api"

/**
 * Endpoints a runtime profile takes off the HTTP surface. Refusal happens in front of routing, so
 * a refused endpoint's handler never runs, whether the request comes over a socket or in process.
 */
export interface Interface {
  /** Endpoint names, as declared in the API (`credential.list`, `shell.create`, ...). */
  readonly refused: ReadonlyArray<string>
}

export class Service extends Context.Service<Service, Interface>()("@opencode/ServerRoutePolicy") {}

/** Upstream: every endpoint is served. */
export const layer = Layer.succeed(Service, Service.of({ refused: [] }))

export const node = makeGlobalNode({ service: Service, layer, deps: [] })

/** The `_tag` of a refused request's error body, shaped like the API's own errors. */
export const tag = "RouteNotAvailableError"

const endpoints = new Map(
  Object.values(Api.groups).flatMap((group) =>
    // Keyed by declared name; an endpoint value's own `name` is its class name.
    Object.entries(group.endpoints).map(([name, endpoint]) => [name, endpoint] as const),
  ),
)

/**
 * Global router middleware enforcing the policy. Refused endpoints are matched with a router built
 * from the same configuration as the API's, so any spelling that reaches a handler is refused too.
 */
export const middleware = HttpRouter.middleware(
  Effect.gen(function* () {
    const policy = yield* Service
    const router = FindMyWay.make<string>(yield* HttpRouter.RouterConfig)
    for (const name of policy.refused) {
      const endpoint = endpoints.get(name)
      if (!endpoint) return yield* Effect.die(new Error(`route policy names an unknown endpoint: ${name}`))
      router.on(endpoint.method, endpoint.path as FindMyWay.PathInput, name)
    }
    return (effect) =>
      Effect.flatMap(HttpServerRequest.HttpServerRequest, (request) => {
        const match =
          router.find(request.method, request.url) ??
          (request.method === "HEAD" ? router.find("GET", request.url) : undefined)
        if (!match) return effect
        return Effect.succeed(
          HttpServerResponse.jsonUnsafe(
            { _tag: tag, message: `${match.handler} is not available in this build` },
            { status: 404 },
          ),
        )
      })
  }),
  { global: true },
)
