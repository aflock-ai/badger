export * as CrashReport from "./crash-report"

import { Brand } from "../brand"
import { describeOS, describeTerminal } from "./system"

/**
 * What the crash screen copies. An upstream build copies a pre-filled issue link for the
 * upstream tracker. A managed build copies plain text for the administrator: a stack trace can
 * name internal paths, so it is never turned into a link to a public site.
 */
export function make(input: { message: string; stack: string; version: string }) {
  if (Brand.enabled)
    return {
      text: [
        `${Brand.name} ${Brand.displayVersion(input.version)} crashed`,
        `OS: ${describeOS()}`,
        `Terminal: ${describeTerminal()}`,
        `Error: ${input.message}`,
        "",
        input.stack,
      ].join("\n"),
      hint: "Copy the report and send it to your administrator.",
      copied: "Report copied. Send it to your administrator.",
    }
  return {
    text: issueURL(input.message, input.stack, input.version).toString(),
    hint: "Copy the report and open a GitHub issue to help us fix this.",
    copied: "Report copied — paste it into a new GitHub issue.",
  }
}

function issueURL(message: string, stack: string, version: string) {
  // Field keys match the ids in .github/ISSUE_TEMPLATE/bug-report.yml so the issue
  // form opens pre-filled. Populating os/terminal/reproduce keeps the report past
  // the contributing-guidelines compliance check, which pushes for system info.
  const url = new URL("https://github.com/anomalyco/opencode/issues/new?template=bug-report.yml")
  url.searchParams.set("title", `TUI crash: ${message}`)
  url.searchParams.set("opencode-version", version)
  url.searchParams.set("os", describeOS())
  url.searchParams.set("terminal", describeTerminal())
  url.searchParams.set(
    "reproduce",
    "Reported automatically from the OpenCode crash screen. If you can, describe what you were doing when it crashed.",
  )

  // Budget the stack against the fully URL-encoded length (not the raw length) so
  // the final link stays under GitHub's practical limit; flag truncation so a
  // clipped trace is obvious. searchParams.set handles encoding without throwing,
  // so measuring url.toString() is both correct and safe on any input.
  const MAX_URL_LENGTH = 6000
  const marker = "\n… (truncated)"
  const head = `The OpenCode TUI crashed with an unexpected error.\n\n**Error:** ${message}\n\n**Stack trace:**\n`
  const setBody = (body: string) => url.searchParams.set("description", head + "```\n" + body + "\n```")

  setBody(stack)
  if (url.toString().length <= MAX_URL_LENGTH) return url

  // Largest raw stack prefix whose encoded URL (with the marker) still fits.
  let lo = 0
  let hi = stack.length
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2)
    setBody(stack.slice(0, mid) + marker)
    if (url.toString().length <= MAX_URL_LENGTH) lo = mid
    else hi = mid - 1
  }
  setBody(stack.slice(0, lo) + marker)
  return url
}
