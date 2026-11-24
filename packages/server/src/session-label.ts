export * as SessionLabel from "./session-label"

import { Context, Effect, Layer } from "effect"
import { bottom, dominates, format } from "@testifysec/marking"
import { Bus } from "@opencode/core/bus"
import { MarkingEvent } from "@opencode/schema/marking-event"
import { makeGlobalNode } from "@opencode/util/effect/app-node"
import type { ManagedFlow } from "./managed-flow"

/**
 * This workspace's label (design 5.5): the join of every connector this state directory has
 * called, kept by the managed build's connector flow. The server reports it beside the deployment
 * marking (GET /api/marking), and announces each raise on the event stream (marking.label.raised),
 * so the app's banner shows the join of the two and reads it again when it rises.
 */
export interface Interface {
  /** The label as a banner, or null while it is at the lowest (nothing to add) or there is no flow. */
  readonly current: () => string | null
}

export class Service extends Context.Service<Service, Interface>()("@opencode/ServerSessionLabel") {}

/** Upstream: no connector flow, so no label. */
export const layer = Layer.succeed(Service, Service.of({ current: () => null }))

export const node = makeGlobalNode({ service: Service, layer, deps: [] })

/** The managed build's: the flow's label, and an event on the bus each time a call raises it. */
export function fromFlow(flow: ManagedFlow.Flow) {
  return makeGlobalNode({
    service: Service,
    deps: [Bus.node],
    layer: Layer.effect(
      Service,
      Effect.gen(function* () {
        const bus = yield* Bus.Service
        const stop = flow.subscribe((label) => void Effect.runFork(bus.publish(MarkingEvent.LabelRaised, { label })))
        yield* Effect.addFinalizer(() => Effect.sync(stop))
        return Service.of({
          current: () => {
            const label = flow.label()
            return dominates(bottom, label) ? null : format(label)
          },
        })
      }),
    ),
  })
}
