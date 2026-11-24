export * as ManagedConnectors from "./managed-connectors"

import { createHash } from "node:crypto"
import { constants, rmSync } from "node:fs"
import { access, chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import path from "node:path"
import type { Info } from "@opencode/schema/config"
import { Mcp } from "@opencode/schema/mcp"

/**
 * Enclave service connectors in the managed build (testifysec/CONNECTORS.md, Admission). The
 * administrator's signed profile names each one; admission has already verified the signature and
 * every field. This module turns the admitted entries into local stdio MCP servers and their
 * permission rules, and nothing else can add one: the managed config is this compiled document,
 * and the routes that add or connect an MCP server stay refused.
 */

/** One admitted connector entry, as signed profile v3 carries it (testifysec/managed/profile-v3.ts). */
export interface Connector {
  readonly name: string
  readonly binarySha256: string
  readonly baseUrl: string
  readonly tokenPath: string
  readonly caPath: string | null
  readonly writes: boolean
  readonly classification: string
  readonly notice?: string
  readonly flags: Readonly<Record<string, string>>
  readonly permissions: Readonly<Record<string, "allow" | "ask" | "deny">>
}

/** What the managed runtime takes from an admitted profile. */
export interface Admitted {
  readonly gateway: { readonly classification: string }
  readonly connectors: readonly Connector[]
}

/** A connector whose binary matched its pinned digest, copied where only this process's user can write. */
export interface Staged extends Connector {
  readonly executable: string
}

/** Connector binaries are read from at most this size. */
const maxBinary = 256 << 20

/**
 * A new 0700 directory under `base` (the badger state directory), never the system temp
 * directory, which a hardened worker may mount noexec. It is removed on failure, or when the
 * process exits.
 */
export async function privateDir<T>(base: string, prefix: string, use: (dir: string) => Promise<T>, keep: boolean) {
  await mkdir(base, { recursive: true, mode: 0o700 })
  const dir = await mkdtemp(path.join(base, prefix))
  try {
    await chmod(dir, 0o700)
    const result = await use(dir)
    if (keep) process.once("exit", () => rmSync(dir, { recursive: true, force: true }))
    else await rm(dir, { recursive: true, force: true })
    return result
  } catch (error) {
    await rm(dir, { recursive: true, force: true })
    throw error
  }
}

/** Refuses a file this process cannot execute, such as one on a noexec mount. */
export async function executable(file: string, what: string) {
  await access(file, constants.X_OK).catch(() => {
    throw new Error(`${what} cannot be executed from ${path.dirname(file)}; the state directory must allow execution`)
  })
}

/**
 * Verifies each connector binary in `release` against the digest the profile pins and copies the
 * bytes that were hashed into a new private directory under `base` (the badger state directory),
 * so what runs is exactly what was checked. One mismatch or missing binary, or a directory that
 * does not allow execution, refuses them all.
 */
export async function stage(connectors: readonly Connector[], release: string, base: string): Promise<readonly Staged[]> {
  if (!connectors.length) return []
  return privateDir(base, "connectors-", (dir) => copy(connectors, release, dir), true)
}

async function copy(connectors: readonly Connector[], release: string, dir: string) {
  const staged: Staged[] = []
  for (const connector of connectors) {
    const bytes = await readFile(path.join(release, connector.name)).catch(() => {
      throw new Error(`connector ${connector.name} is not in this release`)
    })
    if (bytes.byteLength > maxBinary) throw new Error(`connector ${connector.name} is too large`)
    if (createHash("sha256").update(bytes).digest("hex") !== connector.binarySha256)
      throw new Error(`connector ${connector.name} does not match the digest the profile pins`)
    const file = path.join(dir, connector.name)
    await writeFile(file, bytes, { mode: 0o500, flag: "wx" })
    await executable(file, `connector ${connector.name}`)
    staged.push({ ...connector, executable: file })
  }
  return staged
}

/**
 * The command line a connector starts with. Every setting is a flag from the admitted entry; the
 * loopback test flag is never passed, and the environment is not inherited (see `servers`), so a
 * `BADGER_CONNECTOR_*` variable in the user's environment cannot set or relax anything.
 */
export function command(connector: Staged): string[] {
  return [
    connector.executable,
    `--base-url=${connector.baseUrl}`,
    `--token-file=${connector.tokenPath}`,
    `--classification=${connector.classification}`,
    ...(connector.notice === undefined ? [] : [`--notice=${connector.notice}`]),
    ...(connector.caPath === null ? [] : [`--ca-file=${connector.caPath}`]),
    ...(connector.writes ? ["--enable-writes"] : []),
    ...Object.entries(connector.flags).map(([flag, value]) => `--${flag}=${value}`),
  ]
}

/** The MCP servers section of the managed config: one local stdio server per admitted connector. */
export function servers(connectors: readonly Staged[]): NonNullable<Info["mcp"]> {
  return {
    servers: Object.fromEntries(
      connectors.map((connector) => [
        connector.name,
        new Mcp.LocalConfig({
          type: "local",
          command: command(connector),
          environment: {},
          inheritEnvironment: false,
          // Code Mode reaches tools only through `execute`, which the managed build denies.
          codemode: false,
        }),
      ]),
    ),
  }
}

/**
 * Permission rules for the connectors' tools, appended after the managed defaults (the last
 * matching rule wins). MCP tool actions are `<server>_<tool>`, and every key the profile gives is
 * already limited to the connector's own tools, so a rule here can only touch that connector.
 */
export function permissions(connectors: readonly Connector[]): NonNullable<Info["permissions"]> {
  return connectors.flatMap((connector) =>
    Object.entries(connector.permissions).map(([tool, effect]) => ({
      action: `${connector.name}_${tool}`,
      resource: "*",
      effect,
    })),
  )
}
