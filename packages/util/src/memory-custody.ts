export * as MemoryCustody from "./memory-custody.js"

// Set once a process holds a secret in memory that must never reach disk (the Requirements read
// bearer). Built-in memory diagnostics check it before writing. One-way: dropping the secret does
// not re-enable them, since a released value can stay in memory. This stops this program's own
// dumps; it is not protection from a debugger, an OS core dump, or another same-user process.
let reason: string | undefined

export function restrict(why: string) {
  reason ??= why
}

export function restricted() {
  return reason !== undefined
}

export function why() {
  return reason
}
