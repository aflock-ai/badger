export * as Requirements from "./requirements"

import { isCancel, select } from "@clack/prompts"
import type { Plugin } from "@opencode/plugin/effect/plugin"
import type { Plugin as TuiPlugin } from "@opencode/plugin/tui"
import { Effect, Option } from "effect"
import { Managed } from "./managed"

/**
 * Requirements for this launch: the read tool for the in-process server and, for the TUI, its
 * sidebar section. Only a managed build has it, and only for an opted-in directory.
 */
export const start = (
  requested: Option.Option<boolean>,
): Effect.Effect<{ readonly server: ReadonlyArray<Plugin>; readonly tui: ReadonlyArray<TuiPlugin.Definition> }> =>
  Effect.promise(async () => {
    if (!Managed.enabled) return { server: [], tui: [] }
    // Loaded only here, so a build that is not managed folds Requirements out with the branch.
    const { ManagedRequirements } = await import("@opencode/server/requirements")
    const directory = process.cwd()
    if (Option.contains(requested, false)) {
      const removed = await ManagedRequirements.optOut({ directory, environment: process.env })
      process.stderr.write(
        removed
          ? "Requirements: this directory is opted out; later launches here will not sign in.\n"
          : "Requirements: this directory was not opted in.\n",
      )
      return { server: [], tui: [] }
    }
    const started = await ManagedRequirements.start({
      directory,
      environment: process.env,
      optIn: Option.contains(requested, true),
      notify: (text) => process.stderr.write(text),
      choose: async (directory, repos) => {
        if (!process.stdin.isTTY || !process.stdout.isTTY) throw new ManagedRequirements.ConnectCancelled()
        const choice = await select(await ManagedRequirements.repositoryPrompt(directory, repos))
        if (isCancel(choice)) throw new ManagedRequirements.ConnectCancelled()
        return choice
      },
    })
    if (!started.source) return { server: started.plugins, tui: [] }
    const { requirementsSidebar } = await import("@opencode/tui/feature-plugins/sidebar/requirements")
    return { server: started.plugins, tui: [requirementsSidebar(started.source)] }
  })
