export * as ManagedRequirements from "./requirements"

import { ConnectCancelled, type Selection } from "@opencode/core/requirements/device"
import { launch, optOut } from "@opencode/core/requirements/launch"
import { requirementsSource } from "@opencode/core/requirements/monitor"
import { repositoryPrompt } from "@opencode/core/requirements/remote"
import { RequirementsTool } from "@opencode/core/requirements/tool"
import type { Plugin } from "@opencode/plugin/effect/plugin"
import type { RequirementsSource } from "@opencode/core/requirements/projection"

export { ConnectCancelled, optOut, repositoryPrompt }

/**
 * Requirements for one managed launch: the read tool as plugins for its in-process server, and the
 * credential-free source a sidebar subscribes to. The bearer lives in a holder in this process
 * only: the server runs in-process, so nothing else can reach it, and it ends with the launch.
 * Nothing is returned when the directory has not opted in or sign-in fails.
 */
export async function start(input: {
  readonly directory: string
  readonly environment: Record<string, string | undefined>
  readonly optIn: boolean
  readonly notify: (text: string) => void
  readonly choose: (directory: string, repos: Selection[]) => Promise<number>
}): Promise<{ readonly plugins: ReadonlyArray<Plugin>; readonly source?: RequirementsSource }> {
  const holder = await launch({ ...input, signal: new AbortController().signal })
  if (!holder) return { plugins: [] }
  const source = await requirementsSource(input.directory, holder)
  return source ? { plugins: [RequirementsTool.plugin(source.read)], source } : { plugins: [] }
}
