/// <reference path="./assets.d.ts" />
import product from "./product.json"
import upstreamLicense from "../../LICENSE" with { type: "text" }
import markSvg from "./badger-mark.svg" with { type: "text" }

declare const HARDENED_BUILD: boolean
declare const HARDENED_VERSION: string
declare const HARDENED_PREVIEW: boolean

// Display only. This compile-time switch grants no execution or signing authority.
export const enabled = typeof HARDENED_BUILD !== "undefined" && HARDENED_BUILD
export const preview = enabled && typeof HARDENED_PREVIEW !== "undefined" && HARDENED_PREVIEW
export const name = enabled ? product.name : "OpenCode"
export const shortName = enabled ? product.shortName : "OpenCode"
export const displayName = preview ? `${name} Preview` : name
export const command = enabled ? product.command : "opencode"
export const status = preview ? "Development preview" : ""
export const wordmark = [product.name, ...(preview ? [status] : [])]
export const tuiLogo = { left: ["", "", ""], right: [product.shortName.toUpperCase(), status, ""] }
export const wordmarkSvg = markSvg
export const providerName = enabled ? product.providerName : "Approved gateway"
export const modelName = enabled ? product.modelName : "Approved model"

// UI version only: never use product display metadata as the session database identity.
export function displayVersion(upstream: string) {
  return enabled ? (typeof HARDENED_VERSION === "string" ? HARDENED_VERSION : "development") : upstream
}

export function version(value: string) {
  return enabled ? `${displayName} ${displayVersion(value)}\nOpenCode ${value}\n${product.attribution}` : value
}

export function about(value: string) {
  return `${version(value)}\n\n${upstreamLicense}`
}

// Display only. Quote the actual executable so a copied binary can be resumed
// without an installed PATH command. No shell command is executed here.
export function resumeCommand(sessionID: string, mini = false) {
  if (!enabled) return `opencode${mini ? " --mini" : ""} -s ${sessionID}`
  const quote = (value: string) => process.platform === "win32"
    ? "'" + value.replaceAll("'", "''") + "'"
    : "'" + value.replaceAll("'", "'\\''") + "'"
  const invocation = `${process.platform === "win32" ? "& " : ""}${quote(process.execPath)}${mini ? " --mini" : ""} -s ${quote(sessionID)}`
  if (!preview) return invocation
  // Only storage locations are displayed, never provider credentials or arbitrary
  // environment. A privately launched preview must find the same session store.
  const storage = ["HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"]
    .flatMap((key) => process.env[key] === undefined ? [] : [[key, process.env[key]!] as const])
  if (process.platform === "win32") return `& { Set-Location -LiteralPath ${quote(process.cwd())} -ErrorAction Stop; ${storage.map(([key, value]) => `$env:${key}=${quote(value)}; `).join("")}${invocation} }`
  return `cd ${quote(process.cwd())} && env ${storage.map(([key, value]) => `${key}=${quote(value)}`).join(" ")} ${invocation}`
}

export { product }
export * as Branding from "./product"
