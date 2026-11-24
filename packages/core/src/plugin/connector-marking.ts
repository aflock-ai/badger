export * as ConnectorMarkingPlugin from "./connector-marking.js"

import { define } from "@opencode/plugin/effect/plugin"
import { Rpc } from "@opencode/schema/rpc"
import { Global } from "@opencode/util/global"
import { SecurityMarking } from "@opencode/util/security-marking"
import { Effect, Schema } from "effect"
import path from "node:path"
import { ConnectorMarking } from "../connector-marking.js"

const View = Schema.Struct({
  marking: Schema.NullOr(Schema.String),
  classification: Schema.NullOr(Schema.String),
  allowed: Schema.Array(Schema.String),
})
const Problem = Schema.Struct({})
const errors = {
  "marking.unavailable": Problem,
  "marking.not_allowed": Problem,
  "marking.requires_admin": Problem,
}

/** A connector is a plugin RPC; its id is the connector id. */
export const Definition = Rpc.define({
  id: "connector-marking",
  methods: {
    get: { input: Schema.Struct({ connector: Schema.String }), output: View, errors },
    set: {
      input: Schema.Struct({ connector: Schema.String, marking: Schema.String }),
      output: Schema.Struct({ ...View.fields, previous: Schema.NullOr(Schema.String) }),
      errors,
    },
  },
  events: {},
})

// Lowering a marking is decontrol: only a caller whose verified role (RpcCaller) is one of the
// deployment's BADGER_MARKING_ADMIN_ROLES may do it. Unconfigured means nobody may.
function mayLower(role: string | undefined) {
  const header = process.env.BADGER_TRUSTED_ROLE_HEADER?.trim().toLowerCase()
  return role !== undefined && header !== undefined && header !== "" && SecurityMarking.markingAdmin({ [header]: role })
}

export const Plugin = define({
  id: "badger.connector-marking",
  effect: Effect.fn(function* (ctx) {
    const global = yield* Global.Service
    const store = ConnectorMarking.store(path.join(global.state, "connector-markings.json"))
    yield* ctx.rpc
      .register(Definition, {
        get: ({ connector }, call) =>
          Effect.tryPromise({
            try: () => store.get(connector, { mayLower: mayLower(call.caller.role) }),
            catch: () => call.error("marking.unavailable", "Could not read the connector's data marking", {}),
          }),
        set: ({ connector, marking }, call) =>
          Effect.gen(function* () {
            const admin = yield* Effect.try({
              try: () => mayLower(call.caller.role),
              catch: () => call.error("marking.unavailable", "Marking administration is misconfigured", {}),
            })
            const result = yield* Effect.tryPromise({
              try: () => store.set(connector, marking, { mayLower: admin }),
              catch: (error) => {
                const message = error instanceof Error ? error.message : ""
                if (message.includes("not enabled"))
                  return call.error("marking.not_allowed", "That data marking is not enabled for this deployment", {})
                if (message.includes("requires an admin"))
                  return call.error("marking.requires_admin", "Lowering a data marking requires a marking admin", {})
                return call.error("marking.unavailable", "Could not save the connector's data marking", {})
              },
            })
            yield* Effect.logInfo("connector marking changed", {
              connector,
              previous: result.previous,
              connector_marking: result.marking,
              marking_admin: admin,
            })
            return result
          }),
      })
      .pipe(Effect.orDie)
  }),
})
