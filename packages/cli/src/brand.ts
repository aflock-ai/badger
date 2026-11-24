export * as CliBrand from "./brand"

import { Branding } from "@testifysec/branding/product"

declare const OPENCODE_CLI_NAME: string | undefined

// Display only: what the command line calls the product. A managed build sets HARDENED_BUILD at
// compile time; an upstream build keeps OpenCode's text. This grants no authority.
export const name =
  typeof OPENCODE_CLI_NAME === "string" ? OPENCODE_CLI_NAME : Branding.enabled ? Branding.command : "opencode"
export const description = `${Branding.enabled ? Branding.displayName : "OpenCode"} command line interface`
export const directory = `Directory to start ${Branding.enabled ? Branding.shortName : "OpenCode"} in`

/** `--version`: the product version, with the OpenCode release it is built on. */
export function version(upstream: string) {
  return Branding.enabled ? `${Branding.displayVersion(upstream)} (OpenCode ${upstream})` : upstream
}

export const aboutDescription = `about ${Branding.name} and upstream licenses`

/** `about`: the version lines followed by OpenCode's license, in every build. */
export function about(upstream: string) {
  return Branding.about(upstream)
}

/** Whether `enroll` and `attest` exist. As in 1.x, only a branded build has them. */
export const attestation = Branding.enabled
