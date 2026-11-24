import { Effect, Option } from "effect"
import { Commands } from "../commands"
import { Runtime } from "../../framework/runtime"
import { Managed } from "../../managed"
import { Requirements } from "../../requirements"
import { ServerConnection } from "../../services/server-connection"

export default Runtime.handler(Commands.commands.run, (input) =>
  Effect.gen(function* () {
    const auto = yield* Managed.permissionFlags(input)
    yield* Managed.modelFlag(Option.getOrUndefined(input.model))
    yield* Managed.serverFlags({ server: Option.getOrUndefined(input.server), standalone: input.standalone })
    yield* Managed.requireGateway
    const { runNonInteractive } = yield* Effect.promise(() => import("../../run/run"))
    const separator = process.argv.indexOf("--", 2)
    const server = yield* ServerConnection.resolve({
      server: Option.getOrUndefined(input.server),
      standalone: input.standalone,
      plugins: (yield* Requirements.start(input.requirements)).server,
    })
    yield* Effect.promise(() =>
      runNonInteractive({
        server,
        message: [...input.message, ...(separator === -1 ? [] : process.argv.slice(separator + 1))],
        continue: input.continue,
        session: Option.getOrUndefined(input.session),
        fork: input.fork,
        model: Option.getOrUndefined(input.model),
        agent: Option.getOrUndefined(input.agent),
        format: input.format,
        file: [...input.file],
        title: Option.getOrUndefined(input.title),
        thinking: input.thinking,
        auto,
      }),
    )
  }),
)
