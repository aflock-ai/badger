import { Effect, Option } from "effect"
import { Runtime } from "../../framework/runtime"
import { Commands } from "../commands"

export default Runtime.handler(
  Commands.commands.enroll,
  Effect.fn("cli.enroll")(function* (input) {
    const { enroll } = yield* Effect.promise(() => import("../../../../../testifysec/commands/cli"))
    yield* Effect.tryPromise({
      try: () =>
        enroll({
          trustMode: Option.getOrUndefined(input.trustMode),
          settings: Option.getOrUndefined(input.settings),
          platform: Option.getOrUndefined(input.platform),
          stateDir: Option.getOrUndefined(input.stateDir),
          name: Option.getOrUndefined(input.name),
          repository: Option.getOrUndefined(input.repository),
          ttlSeconds: Option.getOrUndefined(input.ttlSeconds),
          browser: input.browser,
          json: input.json,
        }),
      catch: (error) => error,
    })
  }),
)
