export * as Brand from "./brand"

import { Branding } from "@testifysec/branding/product"

// Display only: the product name the TUI shows. A managed build sets HARDENED_BUILD at compile
// time; an upstream build keeps OpenCode's text. This grants no authority.
export const enabled = Branding.enabled
export const name = Branding.enabled ? Branding.displayName : "OpenCode"
export const shortName = Branding.shortName
export const wordmark = Branding.wordmark
export const displayVersion = Branding.displayVersion
export const resume = Branding.resumeCommand

/** Terminal and window title: the product alone, or the product and what is open. */
export function title(subject?: string) {
  if (!subject) return name
  return `${Branding.enabled ? name : "OC"} | ${subject}`
}
