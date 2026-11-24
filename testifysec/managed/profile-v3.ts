import { parse as parseMarking } from "../marking/marking"
import { admitProfile, envelopeJSON, provisionedTrust, type SignerCertificate } from "./profile"
import { strictJSON } from "./strict-json"

// Profile v3 adds the enclave service connectors the administrator turns on and the marking the
// model gateway is accredited for (testifysec/CONNECTORS.md, Admission). Every other field follows
// the v1 rules. Admission validates each entry; the managed runtime starts exactly these
// connectors and nothing else.
export const payloadTypeV3 = "application/vnd.testifysec.hardened-opencode.profile.v3+json"

/**
 * The connectors a release ships, and the settings each accepts beyond the shared ones (a plugin
 * outside this list follows the connector pod's rules below). A value is
 * passed only as `--<flag>=<value>`; `values` restricts a flag to a fixed set.
 */
export const catalog: Readonly<Record<string, Readonly<Record<string, { readonly values?: readonly string[] }>>>> = {
  jira: { "marking-field": {}, "marking-label-prefix": {} },
  confluence: { "label-prefix": {} },
  gitlab: { auth: { values: ["private-token", "bearer"] }, "marking-prefix": {} },
}

const maxConnectors = 16

/**
 * A connector outside the catalog is a plugin served by the connector pod (cmd/conngw), admitted
 * under any name the pod accepts for a connector (its `name` rule), with flags the pod would pass to
 * the plugin (internal/launch `FlagName`, not `Reserved`) other than `notice`, which the managed
 * command line sets itself. testdata/connector-names.json beside cmd/conngw holds the corpus both
 * sides test. No such name holds an underscore, so a tool's action still names its connector.
 */
const pluginName = /^[a-z][a-z0-9-]{0,31}$/
const pluginFlag = /^[a-z][a-z0-9-]{0,31}$/
const reservedFlags = new Set(["base-url", "token-file", "classification", "ca-file", "enable-writes", "insecure-loopback-http", "manifest", "notice"])

function record(input: unknown, keys: string[], error = "invalid-schema") {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error(error)
  const value = input as Record<string, unknown>
  if (Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) throw new Error(error)
  return value
}

function marking(value: unknown) {
  if (typeof value !== "string") throw new Error("invalid-classification")
  try {
    parseMarking(value)
  } catch {
    throw new Error("invalid-classification")
  }
  return value
}

/** An absolute path with no relative segment, control character or trailing slash. */
function absolute(value: unknown) {
  if (
    typeof value !== "string" ||
    value.length > 1024 ||
    !value.startsWith("/") ||
    value.endsWith("/") ||
    /[\x00-\x1f\x7f\\]/.test(value) ||
    value.split("/").some((part, i) => i > 0 && (part === "" || part === "." || part === ".."))
  )
    throw new Error("invalid-connector-path")
  return value
}

/** An https URL with a host and nothing a connector would have to ignore: no credentials, query or fragment. */
function baseURL(value: unknown) {
  if (typeof value !== "string" || value.length > 2048 || /[\x00-\x20\x7f\\]/.test(value)) throw new Error("invalid-connector-url")
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new Error("invalid-connector-url")
  }
  if (url.protocol !== "https:" || !url.hostname || url.username || url.password || url.search || url.hash || value.includes("?") || value.includes("#"))
    throw new Error("invalid-connector-url")
  return value
}

const flagValue = /^[A-Za-z0-9][A-Za-z0-9 _.:\/-]{0,127}$/
/** The part of a permission key after `<connector>_`. */
const permissionTool = /^[a-z0-9_]*\*?$/

/**
 * An administrator's notice: one line printed under the top banner and over the bottom one, such as
 * a statement that test data is not really marked. It is never part of a banner, and it is printed
 * outside the untrusted-content block, so it is plain text (testifysec/CONNECTORS.md).
 */
const noticeText = /^[A-Za-z0-9 .,;:()'/-]{1,160}$/

function connector(input: unknown) {
  const keys = ["name", "binarySha256", "baseUrl", "tokenPath", "caPath", "writes", "classification", "flags", "permissions"]
  // `notice` is optional; every other key is required.
  const value = record(input, input && typeof input === "object" && Object.hasOwn(input, "notice") ? [...keys, "notice"] : keys)
  if (value.notice !== undefined && (typeof value.notice !== "string" || !noticeText.test(value.notice)))
    throw new Error("invalid-connector-notice")
  const name = value.name
  if (typeof name !== "string" || !pluginName.test(name)) throw new Error("unknown-connector")
  const listed = Object.hasOwn(catalog, name) ? catalog[name] : undefined
  if (typeof value.binarySha256 !== "string" || !/^[0-9a-f]{64}$/.test(value.binarySha256)) throw new Error("invalid-connector-pin")
  if (typeof value.writes !== "boolean") throw new Error("invalid-schema")
  const flags = value.flags
  if (!flags || typeof flags !== "object" || Array.isArray(flags)) throw new Error("invalid-schema")
  for (const [flag, setting] of Object.entries(flags)) {
    const known = listed
      ? (Object.hasOwn(listed, flag) ? listed[flag] : undefined)
      : (pluginFlag.test(flag) && !reservedFlags.has(flag) ? {} : undefined)
    if (!known || typeof setting !== "string" || !flagValue.test(setting) || (known.values && !known.values.includes(setting)))
      throw new Error("invalid-connector-flag")
  }
  const permissions = value.permissions
  if (!permissions || typeof permissions !== "object" || Array.isArray(permissions)) throw new Error("invalid-schema")
  // An entry grants or limits its own tools only: every key names this connector's prefix.
  for (const [tool, effect] of Object.entries(permissions))
    if (!tool.startsWith(name + "_") || tool.length > 128 || !permissionTool.test(tool.slice(name.length + 1)) ||
      !["allow", "ask", "deny"].includes(effect as string))
      throw new Error("invalid-connector-permission")
  return Object.freeze({
    name,
    binarySha256: value.binarySha256,
    baseUrl: baseURL(value.baseUrl),
    tokenPath: absolute(value.tokenPath),
    caPath: value.caPath === null ? null : absolute(value.caPath),
    writes: value.writes,
    classification: marking(value.classification),
    flags: Object.freeze({ ...(flags as Record<string, string>) }),
    permissions: Object.freeze({ ...(permissions as Record<string, "allow" | "ask" | "deny">) }),
    ...(value.notice === undefined ? {} : { notice: value.notice as string }),
  })
}

export type Connector = ReturnType<typeof connector>

function connectors(input: unknown) {
  if (!Array.isArray(input) || input.length > maxConnectors) throw new Error("invalid-schema")
  const admitted = input.map(connector)
  if (new Set(admitted.map((entry) => entry.name)).size !== admitted.length) throw new Error("duplicate-connector")
  return Object.freeze(admitted)
}

function gateway(input: unknown) {
  const value = record(input, ["classification"])
  return Object.freeze({ classification: marking(value.classification) })
}

export function provisionedTrustV3(input: unknown) {
  const value = record(input, ["schemaVersion", "publicKeys", "threshold", "tenantId", "deploymentId", "profileId", "minimumSequence"], "invalid-trust")
  if (value.schemaVersion !== 3) throw new Error("unsupported-trust-version")
  return provisionedTrust({ ...value, schemaVersion: 1 })
}

export function admitProfileV3(bytes: Uint8Array, trust: ReturnType<typeof provisionedTrustV3>, now: number,
  signers: SignerCertificate[] = []) {
  if (!bytes.byteLength || bytes.byteLength > 256 * 1024) throw new Error("invalid-profile-size")
  const value = record(strictJSON(new TextDecoder("utf-8", { fatal: true }).decode(bytes)), [
    "schemaVersion", "profileId", "tenantId", "deploymentId", "sequence", "notBefore", "expiresAt", "controls", "gateway", "connectors",
  ])
  if (value.schemaVersion !== 3) throw new Error("unsupported-profile-version")
  const selected = { gateway: gateway(value.gateway), connectors: connectors(value.connectors) }
  // The unchanged v1 rules for everything else. This view is never signed or verified.
  const { gateway: _, connectors: __, ...common } = value
  const profile = admitProfile(new TextEncoder().encode(JSON.stringify({ ...common, schemaVersion: 1 })), trust, now, signers)
  return { ...profile, ...selected }
}

export function envelopeJSONV3(bytes: Uint8Array) {
  const value = record(strictJSON(new TextDecoder("utf-8", { fatal: true }).decode(bytes)), ["payloadType", "payload", "signatures"])
  if (value.payloadType !== payloadTypeV3) throw new Error("unsupported-profile-type")
  const envelope = envelopeJSON(new TextEncoder().encode(JSON.stringify({
    ...value, payloadType: "application/vnd.testifysec.hardened-opencode.profile.v1+json",
  })))
  return { ...envelope, payloadType: payloadTypeV3 }
}

/**
 * Validates the `gateway` and `connectors` of an admitted v3 profile again, for a consumer that
 * reads them from the native verifier's output rather than from the signed payload.
 */
export function admittedV3(profile: unknown) {
  if (!profile || typeof profile !== "object" || Array.isArray(profile)) throw new Error("invalid-schema")
  const value = profile as Record<string, unknown>
  return { gateway: gateway(value.gateway), connectors: connectors(value.connectors) }
}
