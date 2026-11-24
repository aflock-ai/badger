import type { Credentials } from "./monitor"

// Timers longer than this fire at once, so a far expiry is reached in steps.
const longest = 2 ** 31 - 1

/**
 * Where one launch keeps its Requirements credential. Listeners hear every sign-in, sign-out and
 * expiry as it happens, so a monitor cycle under the old credential stops at once.
 */
export class CredentialHolder {
  #current: Credentials | undefined
  #expiry: ReturnType<typeof setTimeout> | undefined
  readonly #listeners = new Set<() => void>()

  readonly get = () => this.#current

  set(next: Credentials | undefined) {
    if (next === this.#current) return
    clearTimeout(this.#expiry)
    this.#expiry = undefined
    this.#current = next
    if (next) this.#watch(next)
    this.#emit()
  }

  readonly subscribe = (listener: () => void) => {
    this.#listeners.add(listener)
    return () => void this.#listeners.delete(listener)
  }

  #watch(held: Credentials) {
    const left = held.bearer.expires - Date.now()
    this.#expiry = setTimeout(
      () => {
        if (this.#current !== held) return
        if (held.bearer.expired) return this.#emit()
        this.#watch(held)
      },
      Math.min(Math.max(left, 0), longest),
    )
    this.#expiry.unref?.()
  }

  #emit() {
    for (const listener of [...this.#listeners]) listener()
  }
}
