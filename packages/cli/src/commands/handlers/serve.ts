import { Effect, Option } from "effect"
import { Commands } from "../commands"
import { Runtime } from "../../framework/runtime"
import { ServerProcess } from "../../server-process"
import { Managed } from "../../managed"
import { ManagedServe } from "../../managed-serve"

export default Runtime.handler(
  Commands.commands.serve,
  Effect.fnUntraced(function* (input) {
    // The managed build serves its in-process server behind an edge (testifysec/HARDENING.md, section 11).
    if (Managed.enabled) {
      if (ManagedServe.refusedFlags(input))
        return yield* Effect.fail(new Managed.Refused("--service, --stdio and --cors are not available in this build"))
      return yield* Effect.scoped(
        ManagedServe.run({ hostname: Option.getOrUndefined(input.hostname), port: Option.getOrUndefined(input.port) }),
      )
    }
    if (input.service && input.stdio) return yield* Effect.fail(new Error("--service and --stdio cannot be combined"))
    return yield* ServerProcess.run({
      mode: input.service ? "service" : input.stdio ? "stdio" : "default",
      hostname: Option.getOrUndefined(input.hostname),
      port: Option.getOrUndefined(input.port),
      cors: input.cors.length > 0 ? input.cors : undefined,
    })
  }),
)
