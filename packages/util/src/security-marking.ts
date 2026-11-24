export * as SecurityMarking from "./security-marking.js"

import {
  deployment as deploymentOf,
  formatIn,
  joinIn,
  loadScheme,
  parseIn,
  preset,
  presetNames,
  type Deployment,
  type Scheme,
} from "@testifysec/marking"

export const reserved: ReadonlySet<string> = new Set([
  "deployment_marking",
  "marking_source",
  "classification",
  "control_marking",
  "marking_scheme",
])

declare const TESTIFYSEC_MANAGED_WORKER: boolean
declare const TESTIFYSEC_DATA_MARKING: string
declare const TESTIFYSEC_ALLOWED_MARKINGS: string
declare const TESTIFYSEC_MARKING_SCHEME: string

/** A scheme a build was compiled with: a preset by name, or a scheme file's text. */
export type CompiledScheme = { readonly preset: string } | { readonly file: string; readonly raw: string }

/**
 * The marking policy a build was compiled with (`build.ts --managed --data-marking --allowed-markings
 * --marking-scheme`). A build compiled without a scheme uses us-gov.
 */
export interface Build {
  readonly managed: boolean
  readonly marking: string | null
  readonly allowed: readonly string[]
  readonly scheme?: CompiledScheme | null
}

export const build: Build = {
  managed: typeof TESTIFYSEC_MANAGED_WORKER !== "undefined" && TESTIFYSEC_MANAGED_WORKER,
  marking: typeof TESTIFYSEC_DATA_MARKING !== "undefined" && TESTIFYSEC_DATA_MARKING ? TESTIFYSEC_DATA_MARKING : null,
  allowed:
    typeof TESTIFYSEC_ALLOWED_MARKINGS !== "undefined" && TESTIFYSEC_ALLOWED_MARKINGS
      ? (JSON.parse(TESTIFYSEC_ALLOWED_MARKINGS) as string[])
      : [],
  scheme:
    typeof TESTIFYSEC_MARKING_SCHEME !== "undefined" && TESTIFYSEC_MARKING_SCHEME
      ? (JSON.parse(TESTIFYSEC_MARKING_SCHEME) as CompiledScheme)
      : null,
}

function fromCompiled(compiled: CompiledScheme): Scheme {
  return "preset" in compiled ? preset(compiled.preset) : loadScheme(compiled.file, compiled.raw)
}

/**
 * The deployment's classification scheme. A managed build uses the scheme it was compiled with
 * (us-gov when none), and the environment may only assert that scheme's digest
 * (BADGER_MARKING_SCHEME_SHA256), never name another. Other builds read BADGER_MARKING_SCHEME: a
 * built-in preset's name, or else the absolute path of a scheme file, which must be pinned to its
 * digest. Unset is
 * us-gov, the scheme of every deployment before schemes existed.
 */
export function scheme(env: Record<string, string | undefined> = processEnv(), compiled: Build = build): Scheme {
  const name = env.BADGER_MARKING_SCHEME?.trim() || undefined
  const pin = env.BADGER_MARKING_SCHEME_SHA256?.trim() || undefined
  let s: Scheme
  if (compiled.managed) {
    if (name !== undefined) throw new Error("A managed build uses the marking scheme it was compiled with")
    s = compiled.scheme ? fromCompiled(compiled.scheme) : preset("us-gov")
  } else if (name === undefined || presetNames.includes(name)) {
    s = preset(name ?? "us-gov")
  } else {
    // Only a built-in preset's name is a preset; anything else is a file, on this platform's terms.
    if (!process.getBuiltinModule("node:path").isAbsolute(name))
      throw new Error("BADGER_MARKING_SCHEME must be a preset or an absolute path")
    if (pin === undefined) throw new Error("A marking scheme file must be pinned by BADGER_MARKING_SCHEME_SHA256")
    const fs = process.getBuiltinModule("node:fs")
    s = loadScheme(name, fs.readFileSync(name, "utf8"))
  }
  if (pin !== undefined && pin !== s.digest)
    throw new Error(`The marking scheme digest is ${s.digest}, not the pinned ${pin}`)
  return s
}

// The app's renderer imports this module too, and a browser has no process.
const processEnv = (): Record<string, string | undefined> =>
  (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env ?? {}

const deployments = new Map<string, Deployment>()
function deploymentFor(env: Record<string, string | undefined>, compiled: Build): Deployment {
  const s = scheme(env, compiled)
  let d = deployments.get(s.digest)
  if (!d) deployments.set(s.digest, (d = deploymentOf(s)))
  return d
}

/** This process's scheme as a server reports it: name, digest and deployment markings, lowest first. */
export function report(env: Record<string, string | undefined> = processEnv(), compiled: Build = build) {
  return reportOf(deploymentFor(env, compiled))
}

/** Every built-in preset as a server on it reports it: a client checks a claimed preset against these. */
export function presetReports() {
  return presetNames.map((name) => reportOf(deploymentOf(preset(name))))
}

function reportOf(d: Deployment) {
  return { name: d.scheme.name, sha256: d.scheme.digest, levels: [...d.levels] }
}

/** A scheme as a server reports it (report, presetReports). */
export type Report = { readonly name: string; readonly sha256: string; readonly levels: readonly string[] }

/**
 * The join of `banners` (a deployment marking, a workspace label) under the scheme a server
 * reported, as a banner. Only a scheme this process holds the table for can join: its own, or a
 * built-in preset, reported exactly. Anything else, an empty list, a banner that does not parse, or
 * a join no banner prints throws, so a caller shows the marking as unavailable, never a lower one.
 */
export function joinReported(
  reported: Report,
  banners: readonly string[],
  env: Record<string, string | undefined> = processEnv(),
  compiled: Build = build,
): string {
  const held = [deploymentFor(env, compiled), ...presetNames.map((name) => deploymentOf(preset(name)))]
  const d = held.find((candidate) => sameReport(reportOf(candidate), reported))
  if (!d) throw new Error(`The marking scheme ${reported.name} is not one this app holds`)
  if (banners.length === 0) throw new Error("Nothing to join")
  const s = d.scheme
  return formatIn(s, banners.map((banner) => parseIn(s, banner)).reduce((a, b) => joinIn(s, a, b)))
}

function sameReport(a: Report, b: Report) {
  return (
    a.sha256 === b.sha256 &&
    a.name === b.name &&
    a.levels.length === b.levels.length &&
    a.levels.every((level, i) => level === b.levels[i])
  )
}

/** This process's deployment markings, lowest first. */
export function levels(env: Record<string, string | undefined> = processEnv(), compiled: Build = build): readonly string[] {
  return deploymentFor(env, compiled).levels
}

/** True when `marking` is one of the deployment markings, so it has a place in their order. */
export function known(marking: string, env: Record<string, string | undefined> = processEnv(), compiled: Build = build) {
  return deploymentFor(env, compiled).levels.includes(marking)
}

/**
 * Deployment-owned values; repository config and prompts cannot change this policy.
 *
 * A managed build's policy is the one it was compiled with, and the environment may only tighten
 * it: raise the marking, or narrow the markings that may be chosen. It can never lower or unset
 * the marking or add a choice. A managed build compiled without a marking has none, whatever the
 * environment says, and its connector data is refused. Other builds read the environment only.
 */
export function policy(env: Record<string, string | undefined> = processEnv(), compiled: Build = build) {
  const d = deploymentFor(env, compiled)
  const order = d.levels
  const configured = fromEnv(env, d)
  if (!compiled.managed) return configured
  if (compiled.marking === null) return { marking: null, classification: null, allowed: [] as string[] }
  // A marking the build does not allow is a misconfiguration, never a way to enable it.
  if (configured.marking !== null && !compiled.allowed.includes(configured.marking))
    throw new Error("Invalid deployment marking configuration")
  const marking =
    configured.marking !== null && order.indexOf(configured.marking) > order.indexOf(compiled.marking)
      ? configured.marking
      : compiled.marking
  // The environment can narrow the build's choices, never add one. An env allowlist that leaves out
  // the marking in force is a misconfiguration; widening it back would override the restriction.
  if (env.BADGER_ALLOWED_MARKINGS && !configured.allowed.includes(marking))
    throw new Error("Invalid deployment marking configuration")
  const allowed = compiled.allowed
    .filter((value) => !env.BADGER_ALLOWED_MARKINGS || configured.allowed.includes(value))
    .sort((a, b) => order.indexOf(a) - order.indexOf(b))
  return { marking, classification: d.stamp(marking).classification, allowed }
}

function fromEnv(env: Record<string, string | undefined>, d: Deployment) {
  const marking = env.BADGER_DATA_MARKING?.trim() || null
  const raw: unknown = env.BADGER_ALLOWED_MARKINGS ? JSON.parse(env.BADGER_ALLOWED_MARKINGS) : marking ? [marking] : []
  if (
    !Array.isArray(raw) ||
    raw.length > 32 ||
    raw.some((value) => typeof value !== "string" || !valid(value) || !d.levels.includes(value)) ||
    (marking !== null && (!valid(marking) || !raw.includes(marking)))
  )
    throw new Error("Invalid deployment marking configuration")
  return { marking, classification: marking ? d.stamp(marking).classification : null, allowed: [...new Set(raw as string[])] }
}

function valid(value: string) {
  return value.length > 0 && value.length <= 160 && value === value.trim() && !/[\x00-\x1f\x7f]/.test(value)
}

/** Stamp new records, or preserve a stored record's marking when editing other metadata. */
export function metadata<V>(
  input?: Readonly<Record<string, V>>,
  original?: Readonly<Record<string, unknown>>,
  env: Record<string, string | undefined> = processEnv(),
): Record<string, V | string> | undefined {
  const fields: Record<string, V | string> = unreserved(input)
  const d = deploymentFor(env, build)
  if (original) {
    // An edit keeps the record's own marking; its reserved fields are rebuilt from that value.
    const kept = own(original, d)
    if (kept !== undefined) Object.assign(fields, d.stamp(kept))
    return fields
  }
  const value = policy(env).marking
  if (value) Object.assign(fields, d.stamp(value))
  return Object.keys(fields).length ? fields : undefined
}

/**
 * A stored record's marking, when it is one of this deployment's. A record stamped under another
 * scheme is refused: its marking has no place in this scheme's order, and dropping or replacing it
 * would relabel the record without a migration.
 */
function own(original: Readonly<Record<string, unknown>>, d: Deployment): string | undefined {
  const kept = original.deployment_marking
  if (kept === undefined && original.marking_scheme === undefined) return undefined
  if (!d.owns(original.marking_scheme)) throw new Error("This record was marked under another marking scheme")
  return typeof kept === "string" && d.levels.includes(kept) ? kept : undefined
}

function unreserved<V>(input: Readonly<Record<string, V>> | undefined): Record<string, V> {
  return Object.fromEntries(Object.entries(input ?? {}).filter(([key]) => !reserved.has(key)))
}

/**
 * True when `marking` sits below the deployment marking; lowering the controlled marking is
 * decontrol. A marking outside the order is refused: it has no place to compare from, and reading
 * it as the lowest would let it show, or be stored, under a lower one.
 */
export function lowers(
  marking: string,
  deployment: string | null,
  env: Record<string, string | undefined> = processEnv(),
  compiled: Build = build,
) {
  return deploymentFor(env, compiled).lowers(marking, deployment)
}

/**
 * Metadata for a new record derived from `original` (a fork). Only the original's marking value
 * is taken from history, and only when it is a known marking not below the current deployment
 * marking; otherwise the current marking applies. Every reserved field is rebuilt from that
 * value, because older records stored client-supplied metadata as-is.
 */
export function inherit<V>(
  input: Readonly<Record<string, V>> | undefined,
  original: Readonly<Record<string, unknown>>,
  env: Record<string, string | undefined> = processEnv(),
): Record<string, V | string> | undefined {
  const fields: Record<string, V | string> = unreserved(input)
  const d = deploymentFor(env, build)
  const inherited = own(original, d)
  const current = policy(env).marking
  const value = inherited !== undefined && !d.lowers(inherited, current) ? inherited : current
  if (value) Object.assign(fields, d.stamp(value))
  return Object.keys(fields).length ? fields : undefined
}

/**
 * True when the request carries a marking-admin role in the header the deployment names.
 * Set BADGER_TRUSTED_ROLE_HEADER only behind a proxy that removes caller copies of that
 * header and sets it from a verified identity. Unset means nobody may lower a marking.
 */
export function markingAdmin(
  headers: Record<string, string | undefined>,
  env: Record<string, string | undefined> = processEnv(),
) {
  const header = env.BADGER_TRUSTED_ROLE_HEADER?.trim().toLowerCase()
  const roles: unknown = env.BADGER_MARKING_ADMIN_ROLES ? JSON.parse(env.BADGER_MARKING_ADMIN_ROLES) : []
  if (!Array.isArray(roles) || roles.some((role) => typeof role !== "string"))
    throw new Error("Invalid marking admin configuration")
  const role = header ? headers[header] : undefined
  return role !== undefined && roles.includes(role)
}
