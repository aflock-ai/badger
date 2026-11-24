type Key = { providerID: string; modelID: string }

/**
 * The model the composer uses: one the user or agent picked, else the configured one, else a recent
 * one, else the first connected. A configured model that is not available yields none, so the prompt
 * is refused instead of silently going to some other model.
 */
export function chooseModel<T extends Key>(
  input: {
    readonly picked: readonly (T | undefined)[]
    readonly configured?: T
    readonly recent?: T
    readonly first?: T
  },
  valid: (model: T) => boolean,
): T | undefined {
  const picked = input.picked.find((item): item is T => !!item && valid(item))
  if (picked) return picked
  if (input.configured) return valid(input.configured) ? input.configured : undefined
  return [input.recent, input.first].find((item): item is T => !!item && valid(item))
}
