import { ToolOutputRedaction } from "../tool-output-redaction"
// The local UI boundary carries display data only, never credentials or policy bytes.
export type Projection = {
  state: "disabled" | "loading" | "signin" | "unsupported" | "unavailable" | "disconnected" | "available"
  lines: readonly string[]
  details: readonly string[]
  target?: Readonly<{ repo: string; repository_id: string; commit: string; ref: string }>
}
export type RequirementsContext = { session: string; directory: string; workspace?: string }
export type RequirementsSource = {
  subscribe(context: RequirementsContext, emit: (value: Projection) => void): () => void
}

/**
 * Display-safe plain text: the tool-output redactor in display mode (tool-output-redaction.ts), after
 * the caller's own secret, on one line. `secret` removes one exact credential (the launch's bearer).
 * It runs on the raw text and on the shown line (the redactor's output with controls as spaces), and a
 * line where that credential only appears once control, invisible or escape characters are deleted
 * was split on purpose, so it is withheld whole.
 */
export function plain(value: string, secret: (text: string) => string = (text) => text) {
  const whole = secret(value)
  const bare = whole
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, "")
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, "")
  if (secret(bare) !== bare) return "[redacted]"
  // Controls become spaces before the last check, so it sees the line as shown.
  return secret(ToolOutputRedaction.text(whole, { display: true }).replace(/[\p{Cc}\p{Zl}\p{Zp}]/gu, " "))
}
