import { Effect, Option } from "effect"
import { Runtime } from "../../framework/runtime"
import { Commands } from "../commands"

export default Runtime.handler(
  Commands.commands.attest,
  Effect.fn("cli.attest")(function* (input) {
    const { attest } = yield* Effect.promise(() => import("../../../../../testifysec/commands/cli"))
    yield* Effect.tryPromise({
      try: () =>
        attest({
          trustMode: Option.getOrUndefined(input.trustMode),
          settings: Option.getOrUndefined(input.settings),
          platform: Option.getOrUndefined(input.platform),
          stateDir: Option.getOrUndefined(input.stateDir),
          session: Option.getOrUndefined(input.session),
          json: input.json,
        }),
      catch: (error) => error,
    })
  }),
)
