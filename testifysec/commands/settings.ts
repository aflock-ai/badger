import fs from "node:fs/promises"
import { constants } from "node:fs"
import os from "node:os"
import path from "node:path"
import { strictJSON } from "../managed/strict-json"
import { trustMode, type TrustMode } from "./trust-mode"

export interface Settings {
  trustMode?: TrustMode
  platformURL?: string
  stateDirectory?: string
  enrollment?: { name?: string; repository?: string; ttlSeconds?: number }
}

export function xdgHome(value: string | undefined, fallback: string) {
  return value && path.posix.isAbsolute(value) ? value : fallback
}

export function settingsFile(environment: Record<string, string | undefined>, platform: NodeJS.Platform = process.platform) {
  const home = os.homedir()
  if (platform === "darwin") return path.join(home, "Library", "Application Support", "TestifySec", "Aflock", "settings.json")
  if (platform === "win32") return path.join(environment.APPDATA || path.join(home, "AppData", "Roaming"), "TestifySec", "Aflock", "settings.json")
  return path.join(xdgHome(environment.XDG_CONFIG_HOME, path.join(home, ".config")), "aflock", "settings.json")
}

export function platformOrigin(value: string) {
  const url = new URL(value)
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash)
    throw new Error("Badger platform must be an HTTPS origin without credentials, a path, query or fragment")
  return url.origin
}

function object(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some(key => !keys.includes(key)))
    throw new Error("Invalid Badger settings fields")
  return value as Record<string, unknown>
}

function string(value: unknown) {
  if (typeof value !== "string" || !value.trim() || value.length > 4096 || !value.isWellFormed() || /[\x00-\x1f\x7f-\x9f]/.test(value))
    throw new Error("Invalid Badger settings value")
  return value
}

export function parseSettings(contents: string): Settings {
  const raw = object(strictJSON(contents), ["schema", "trustMode", "platformURL", "stateDirectory", "enrollment"])
  if (raw.schema !== "testifysec.aflock.settings/v1") throw new Error("Unsupported Badger settings schema")
  const enrollment = raw.enrollment === undefined ? undefined : object(raw.enrollment, ["name", "repository", "ttlSeconds"])
  const name = enrollment?.name === undefined ? undefined : string(enrollment.name)
  const repository = enrollment?.repository === undefined ? undefined : string(enrollment.repository)
  const ttlSeconds = enrollment?.ttlSeconds
  if (name !== undefined && name.length > 128) throw new Error("Invalid Badger enrollment name")
  if (repository !== undefined && !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) throw new Error("Invalid Badger enrollment repository")
  if (ttlSeconds !== undefined && (typeof ttlSeconds !== "number" || !Number.isSafeInteger(ttlSeconds) || ttlSeconds < 900 || ttlSeconds > 604800))
    throw new Error("Invalid Badger enrollment lifetime")
  const stateDirectory = raw.stateDirectory === undefined ? undefined : string(raw.stateDirectory)
  if (stateDirectory !== undefined && !path.isAbsolute(stateDirectory)) throw new Error("Badger stateDirectory must be absolute")
  return {
    trustMode: raw.trustMode === undefined ? undefined : trustMode(string(raw.trustMode), {}),
    platformURL: raw.platformURL === undefined ? undefined : platformOrigin(string(raw.platformURL)),
    stateDirectory,
    enrollment: enrollment === undefined ? undefined : { name, repository, ttlSeconds: ttlSeconds as number | undefined },
  }
}

// Operator preferences only: never merge repository config, prompts, plugins or
// OPENCODE_CONFIG_CONTENT. A signed profile remains authority in native code.
export async function loadSettings(option: string | undefined, environment: Record<string, string | undefined>): Promise<Settings> {
  if (option !== undefined && (!option || option.length > 4096 || option.includes("\0"))) throw new Error("--settings must name a file")
  const file = option === undefined ? settingsFile(environment) : path.resolve(option)
  let ancestors: Awaited<ReturnType<typeof holdAncestors>> | undefined
  let handle: Awaited<ReturnType<typeof fs.open>>
  try {
    ancestors = await holdAncestors(file)
    handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  }
  catch (error) {
    await ancestors?.close()
    if (option === undefined && (error as NodeJS.ErrnoException).code === "ENOENT") return {}
    throw new Error("Cannot read Badger settings")
  }
  try {
    const stat = await handle.stat()
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > 16384 ||
        (process.platform !== "win32" && (stat.uid !== process.getuid!() || (stat.mode & 0o077) !== 0)))
      throw new Error("Badger settings must be a private regular file of at most 16 KiB")
    const bytes = Buffer.alloc(stat.size + 1)
    let length = 0
    while (length < bytes.length) {
      const part = await handle.read(bytes, length, bytes.length - length)
      if (!part.bytesRead) break
      length += part.bytesRead
    }
    const after = await handle.stat()
    if (length !== stat.size || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs)
      throw new Error("Badger settings changed during read")
    await ancestors.verify()
    const current = await fs.lstat(file)
    if (current.isSymbolicLink() || current.dev !== stat.dev || current.ino !== stat.ino || current.mode !== stat.mode || current.uid !== stat.uid)
      throw new Error("Badger settings path changed during read")
    return parseSettings(new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, length)))
  } finally { try { await handle.close() } finally { await ancestors.close() } }
}

async function holdAncestors(file: string) {
  const held: { file: string; handle: Awaited<ReturnType<typeof fs.open>>; dev: number; ino: number; mode: number; uid: number }[] = []
  const close = async () => { for (const item of held.reverse()) await item.handle.close() }
  try {
    // The native command runner refuses Windows until DACL-backed custody is
    // implemented. This Unix guard does not claim to supply Windows isolation.
    if (process.platform !== "win32") {
      const parent = path.dirname(file)
      const names = parent.split(path.sep).filter(Boolean)
      if (names.length > 64) throw new Error("Badger settings path is too deep")
      for (let index = 0; index <= names.length; index++) {
        const directory = path.join(path.parse(parent).root, ...names.slice(0, index))
        const handle = await fs.open(directory, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
        const stat = await handle.stat()
        held.push({ file: directory, handle, dev: stat.dev, ino: stat.ino, mode: stat.mode, uid: stat.uid })
        if (!stat.isDirectory() || (stat.uid !== 0 && stat.uid !== process.getuid!()) ||
            ((stat.mode & 0o022) !== 0 && !(stat.uid === 0 && (stat.mode & 0o1000) !== 0)))
          throw new Error("Badger settings ancestor custody refused")
      }
    }
    return { close, verify: async () => {
      for (const item of held) {
        const current = await fs.lstat(item.file)
        if (current.isSymbolicLink() || !current.isDirectory() || current.dev !== item.dev || current.ino !== item.ino || current.uid !== item.uid || current.mode !== item.mode)
          throw new Error("Badger settings ancestor changed during read")
      }
    } }
  } catch (error) { await close(); throw error }
}
