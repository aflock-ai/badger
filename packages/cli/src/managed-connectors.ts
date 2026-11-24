export * as ManagedConnectorProfile from "./managed-connectors"

import { spawn } from "node:child_process"
import { createHash } from "node:crypto"
import { chmod, copyFile, readdir, readFile, writeFile } from "node:fs/promises"
import path from "node:path"
import { Effect } from "effect"
import { define, type Plugin } from "@opencode/plugin/effect/plugin"
import { ManagedConnectors } from "@opencode/server/managed-connectors"
import { ManagedFlow } from "@opencode/server/managed-flow"
import { Global } from "@opencode/util/global"
import { admittedV3 } from "../../../testifysec/managed/profile-v3"
import { dominates, parse } from "../../../testifysec/marking/marking"
import { Refused } from "./managed"

declare const TESTIFYSEC_CONNECTOR_ADMISSION_SHA256: string
declare const TESTIFYSEC_CONNECTOR_PATHS: string

/**
 * The digest of the native admission verifier (testifysec/managed, profile v3) a build was compiled
 * to trust, or "" when the build admits no connectors. Nothing at runtime can set it.
 */
export const admissionSha256: string =
  typeof TESTIFYSEC_CONNECTOR_ADMISSION_SHA256 !== "undefined" ? TESTIFYSEC_CONNECTOR_ADMISSION_SHA256 : ""

/** Where the release and the administrator put what admission reads. */
export interface Paths {
  /** The native verifier, beside this executable with its Rookery library. */
  readonly admission: string
  /** The administrator's signed profile envelope. */
  readonly envelope: string
  /** The release's connector binaries, one file per connector name. */
  readonly release: string
  /**
   * Where the checked verifier and connectors are copied to run: under the badger state
   * directory, never the system temp directory, which a hardened worker may mount noexec.
   */
  readonly state: string
}

/**
 * Where the broker provisions them for a managed worker: the verifier bundle and connector binaries
 * on the read-only /toolpack mount, the envelope on a broker-written read-only mount. A build can
 * override each with --connector-verifier, --connector-release and --connector-envelope.
 */
export const defaults = {
  admission: "/toolpack/badger/admission/hardened-admission",
  envelope: "/run/badger/profile/profile.dsse.json",
  release: "/toolpack/badger/connectors",
} as const

const compiled: Partial<Record<keyof typeof defaults, string>> =
  typeof TESTIFYSEC_CONNECTOR_PATHS !== "undefined" && TESTIFYSEC_CONNECTOR_PATHS
    ? JSON.parse(TESTIFYSEC_CONNECTOR_PATHS)
    : {}

export const paths: Paths = {
  ...defaults,
  ...compiled,
  state: path.join(Global.Path.state, "managed"),
}

const outputLimit = 128 << 10

/** Runs a program on the envelope with a fixed environment in `home` and returns what it printed. */
function run(executable: string, home: string, envelope: Uint8Array) {
  return new Promise<string>((resolve, reject) => {
    const child = spawn(executable, [], {
      cwd: home,
      env: { PATH: "/usr/bin:/bin", HOME: home, TMPDIR: home, LANG: "C" },
      stdio: ["pipe", "pipe", "ignore"],
      timeout: 5_000,
    })
    const chunks: Buffer[] = []
    let size = 0
    child.stdout.on("data", (chunk: Buffer) => {
      size += chunk.byteLength
      if (size > outputLimit) child.kill("SIGKILL")
      else chunks.push(chunk)
    })
    child.on("error", reject)
    // A verifier that exits before reading the whole envelope closes the pipe under the write
    // (EPIPE). That is a refusal like any other failure, never an unhandled stream error.
    child.stdin.on("error", () => reject(new Error("rejected")))
    child.on("close", (code) =>
      code === 0 && size <= outputLimit ? resolve(Buffer.concat(chunks).toString("utf8")) : reject(new Error("rejected")),
    )
    child.stdin.end(envelope)
  })
}

/** The files the verifier's launcher and runtime check by digest themselves, so they are copied beside it unchecked. */
const companion = (name: string) => name === "hardened-runtime" || name.startsWith("librookery")

/**
 * Runs the verifier from the bytes that were checked against the build's pin, written into a new
 * private directory with its companions, so replacing the installed file after the check changes
 * nothing. The directory is removed afterwards.
 */
function verify(launcher: Uint8Array, installed: string, envelope: Uint8Array, state: string) {
  return ManagedConnectors.privateDir(
    state,
    "admission-",
    async (dir) => {
      const bundle = path.dirname(installed)
      for (const name of (await readdir(bundle)).filter(companion)) {
        await copyFile(path.join(bundle, name), path.join(dir, name))
        await chmod(path.join(dir, name), 0o500)
      }
      const executable = path.join(dir, path.basename(installed))
      await writeFile(executable, launcher, { mode: 0o500, flag: "wx" })
      await ManagedConnectors.executable(executable, "the profile verifier")
      return run(executable, dir, envelope)
    },
    false,
  )
}

/** An admitted profile's gateway marking and its connectors, staged. */
export interface Admitted {
  /** When the signed profile expires: no connector call is allowed after it. */
  readonly expires: Date
  readonly gateway: { readonly classification: string }
  readonly connectors: readonly ManagedConnectors.Staged[]
}

const sha = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex")

/**
 * The connectors the administrator's signed profile admits, verified and staged, or none when the
 * build admits no connectors. A build that does admit them refuses to start on any failure:
 * a verifier that does not match the build, a missing or rejected profile, or a connector binary
 * that does not match its pin. It never falls back to running without the profile's controls.
 */
export function load(
  pinned: string = admissionSha256,
  where: Paths = paths,
): Effect.Effect<Admitted | undefined, Refused> {
  if (!pinned) return Effect.succeed(undefined)
  const refuse = (why: string) => new Refused(`Connectors are unavailable: ${why}. Ask your administrator.`)
  return Effect.gen(function* () {
    const verifier = yield* Effect.tryPromise({
      try: () => readFile(where.admission),
      catch: () => refuse("the profile verifier is not installed"),
    })
    if (sha(verifier) !== pinned) return yield* Effect.fail(refuse("the profile verifier does not match this build"))
    const envelope = yield* Effect.tryPromise({
      try: () => readFile(where.envelope),
      catch: () => refuse(`there is no signed profile at ${where.envelope}`),
    })
    if (envelope.byteLength > 65_536) return yield* Effect.fail(refuse("the signed profile is too large"))
    const printed = yield* Effect.tryPromise({
      try: () => verify(verifier, where.admission, envelope, where.state),
      catch: (error) =>
        refuse(
          error instanceof Error && error.message.includes("cannot be executed")
            ? error.message
            : "the signed profile was not admitted",
        ),
    })
    const admitted = yield* Effect.try({
      try: () => {
        const output = JSON.parse(printed) as Record<string, unknown>
        if (
          output.schemaVersion !== 3 ||
          output.admitted !== true ||
          output.scope !== "profile-admission-only" ||
          output.envelopeSha256 !== sha(envelope)
        )
          throw new Error("unbound")
        const expires = new Date(String((output.profile as Record<string, unknown> | null)?.expiresAt))
        if (Number.isNaN(expires.getTime())) throw new Error("no expiry")
        return { ...admittedV3(output.profile), expires }
      },
      catch: () => refuse("the profile verifier returned an admission this build cannot use"),
    })
    // The rule while the worker is untrusted (CONNECTORS.md, "The gateway ceiling"): every connector
    // sits at or below the gateway's accredited marking. Gateway v3 enforces the same; the session
    // high-water check is a second check, not the one that holds.
    const gateway = parse(admitted.gateway.classification)
    const above = admitted.connectors.find((entry) => !dominates(gateway, parse(entry.classification)))
    if (above)
      return yield* Effect.fail(
        refuse(`connector ${above.name} is marked above the model gateway's accreditation, and a worker could carry its content to the gateway`),
      )
    const connectors = yield* Effect.tryPromise({
      try: () => ManagedConnectors.stage(admitted.connectors, where.release, where.state),
      catch: (error) => refuse(error instanceof Error ? error.message : "a connector could not be verified"),
    })
    return { expires: admitted.expires, gateway: admitted.gateway, connectors }
  })
}

/** The session high-water check for an admitted profile, recording its decisions to `audit`. */
export function flow(admitted: Admitted, audit?: string, ceiling = process.env.BADGER_RAISE_CEILING): ManagedFlow.Flow {
  return ManagedFlow.make(
    {
      gateway: admitted.gateway.classification,
      connectors: Object.fromEntries(admitted.connectors.map((entry) => [entry.name, entry.classification])),
      // Set by the workspace controller. Only an unset variable means no ceiling: any value that is
      // not a marking, an empty one included, stops the start.
      ...(ceiling !== undefined ? { ceiling } : {}),
    },
    { audit },
  )
}

/**
 * The plugins a managed server starts with: the caller's, then the connector flow plugin whenever
 * a profile admitted connectors. The managed server takes exactly this list.
 */
export function plugins(
  admitted: Admitted | undefined,
  check: ManagedFlow.Flow | undefined,
  extra: ReadonlyArray<Plugin> = [],
): Plugin[] {
  if (!admitted || !check) return [...extra]
  return [...extra, flowPlugin(check, admitted.connectors.map((entry) => entry.name), admitted.expires)]
}

/**
 * The connector side of the high-water check. A call to a connector, read or write, is refused
 * when the connector's marking does not dominate the label, since its arguments would carry the
 * workspace's content there; an allowed call raises the label to the connector's marking, even if
 * it is then cancelled or declined (that over-labels, never under-labels; reset is an admin action).
 * The label comes only from which connectors were called, never from what they returned. It can
 * only deny: the profile's permission rules still decide the rest.
 */
export function flowPlugin(
  check: ManagedFlow.Flow,
  connectors: readonly string[],
  expires?: Date,
  now: () => number = Date.now,
) {
  // A tool's action is `<connector>_<tool>`. Connector names hold no underscore (the release
  // catalog's never do), so the text before the first one names the connector unambiguously.
  const bad = connectors.find((name) => !/^[a-z0-9-]+$/.test(name))
  if (bad !== undefined) throw new Error(`connector name ${JSON.stringify(bad)} cannot be told apart from its tools`)
  const server = (tool: string) => {
    const name = tool.slice(0, tool.indexOf("_"))
    return tool.includes("_") && connectors.includes(name) ? name : undefined
  }
  return define({
    id: "badger.connectors.flow",
    effect: Effect.fn(function* (ctx) {
      yield* ctx.permission.hook("evaluate", (event) =>
        Effect.sync(() => {
          if (event.effect === "deny") return
          const name = server(event.action)
          if (!name) return
          // The signed profile admits its connectors only until it expires. A call already waiting
          // for the user's approval at expiry can run once when approved; every later call is
          // refused here, and the gateway refuses the next model request (CONNECTORS.md).
          if (expires && now() >= expires.getTime()) {
            event.effect = "deny"
            event.message = `${event.action} was refused: the signed profile expired at ${expires.toISOString()}. Restart with a current profile.`
            return
          }
          const refusal = check.call({ sessionID: event.sessionID, server: name, tool: event.action.slice(name.length + 1) })
          if (!refusal) return
          event.effect = "deny"
          event.message = refusal
        }),
      )
    }),
  })
}
