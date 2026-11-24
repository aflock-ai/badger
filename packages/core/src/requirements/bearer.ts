import { MemoryCustody } from "@opencode/util/memory-custody"

// The Requirements read bearer, held in memory for one TUI launch and never persisted. The token
// is a private field: it does not serialize, print, or appear in Object.keys, so it cannot leak
// through JSON, logs, util.inspect, or a structured clone. Only the transport reads it.
export class Bearer {
  readonly #token: string
  readonly expires: number

  constructor(token: string, expires: number) {
    // Before the token is held: no built-in heap snapshot may write this process's memory to disk.
    MemoryCustody.restrict("Requirements bearer")
    this.#token = token
    this.expires = expires
  }

  get expired() {
    return this.expires <= Date.now()
  }

  authorization() {
    if (this.expired) throw new Error("requirements-bearer-expired")
    return `Bearer ${this.#token}`
  }

  /** Removes literal echoes of this bearer from text a server returned. */
  redact(text: string) {
    return text.replaceAll(this.#token, "[redacted]")
  }

  toJSON() {
    return { expires: this.expires }
  }

  toString() {
    return "[Requirements bearer]"
  }

  [Symbol.for("nodejs.util.inspect.custom")]() {
    return `Bearer { expires: ${this.expires} }`
  }
}
