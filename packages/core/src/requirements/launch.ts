import fs from "node:fs/promises"
import { ConnectCancelled, connect, signInNotice, type Selection } from "./device"
import { CredentialHolder } from "./holder"
import {
  legacyCredentialFile,
  loadSelection,
  removeLegacyCredential,
  removeSelection,
  saveSelection,
  selectionFile,
} from "./selection"
import type { Fetch } from "./transport"

/**
 * Requirements for one managed launch. A directory that opted in signs in again at every start,
 * because the bearer is never stored; only the opt-in and the chosen repository are. A launch
 * asked to opt in signs in and asks for the repository. Anything else starts without Requirements
 * after one local file check. Failure is reported in a fixed sentence and never stops the launch.
 */
export async function launch(input: {
  directory: string
  environment: Record<string, string | undefined>
  /** Sign in and choose this directory's repository now, saving the choice. */
  optIn: boolean
  signal: AbortSignal
  notify: (text: string) => void
  /** Asks the human for one of the authorized repositories; only used when opting in. */
  choose: (directory: string, repos: Selection[]) => Promise<number>
  send?: Fetch
  wait?: (ms: number) => Promise<void>
}): Promise<CredentialHolder | undefined> {
  let missing = false
  try {
    await removeLegacyCredential(legacyCredentialFile(input.environment))
    const file = selectionFile(input.environment, await fs.realpath(input.directory))
    const saved = await loadSelection(file)
    const opted = saved?.directory === input.directory ? saved : undefined
    if (!opted && !input.optIn) return undefined
    const session = await connect({
      directory: input.directory,
      signal: input.signal,
      send: input.send,
      wait: input.wait,
      onCode: async (url, code) => input.notify(signInNotice(url, code)),
      select: async (repos) => {
        if (input.optIn) return input.choose(input.directory, repos)
        // The saved choice, by its immutable ID; a catalog that no longer authorizes it gets no default.
        const index = repos.findIndex((r) => r.repo === opted!.repo && r.repository_id === opted!.repository_id)
        missing = index < 0
        if (missing) throw new ConnectCancelled()
        return index
      },
    })
    if (input.optIn) await saveSelection(session.selection, file)
    const holder = new CredentialHolder()
    holder.set({ selection: session.selection, bearer: session.bearer })
    return holder
  } catch (error) {
    input.notify(
      missing
        ? "Requirements: the saved repository is no longer authorized for you. Start with --requirements to choose again.\n"
        : `${error instanceof Error && error.message.startsWith("Requirements") ? error.message : "Requirements unavailable; starting without it."}\n`,
    )
    return undefined
  }
}

/** Removes this directory's opt-in, if it has one. Returns whether there was one to remove. */
export async function optOut(input: { directory: string; environment: Record<string, string | undefined> }) {
  // Every Requirements entry point clears a 1.x on-disk bearer, unread, opting out included.
  await removeLegacyCredential(legacyCredentialFile(input.environment))
  const file = selectionFile(input.environment, await fs.realpath(input.directory))
  const saved = await loadSelection(file).catch(() => undefined)
  await removeSelection(file)
  return saved !== undefined
}
