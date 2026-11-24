import { SecurityMarking } from "@opencode/util/security-marking"
import { Effect } from "effect"
import { EOL } from "node:os"
import { CliBrand } from "../../brand"
import { Runtime } from "../../framework/runtime"
import { Managed } from "../../managed"
import { OPENCODE_VERSION } from "../../version"
import { Commands } from "../commands"

// A managed build also states the data marking in force, so an operator can check the binary's
// compiled policy (SecurityMarking.policy) from outside it.
export function markingLine() {
  const { marking } = SecurityMarking.policy()
  return marking ? `Data marking: ${marking}` : "Data marking: none (connector data is refused)"
}

export default Runtime.handler(
  Commands.commands.about,
  Effect.fn("cli.about")(function* () {
    process.stdout.write(CliBrand.about(OPENCODE_VERSION) + EOL)
    if (Managed.enabled) process.stdout.write(markingLine() + EOL)
  }),
)
