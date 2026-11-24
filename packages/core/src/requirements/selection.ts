import fs from "node:fs/promises"
import { constants } from "node:fs"
import { createHash } from "node:crypto"
import os from "node:os"
import path from "node:path"
import z from "zod"
import { numericID, repo } from "./schema"
import { strictJSON } from "./strict-json"

// The only Requirements state on disk: the user's opt-in and repository choice. It holds no
// credential; the bearer is signed in once per TUI launch and kept in memory (see bearer.ts).
const schema = z
  .object({
    version: z.literal(1),
    enabled: z.literal(true),
    directory: z
      .string()
      .max(4096)
      .refine((s) => path.isAbsolute(s) && !/[\p{Cc}\p{Cf}]/u.test(s)),
    repo,
    repository_id: numericID,
  })
  .strict()
export type Selection = z.infer<typeof schema>

type Environment = Record<string, string | undefined>

// Beside Badger's user settings (testifysec/commands/settings.ts), which core cannot import.
function settingsDirectory(environment: Environment, platform: NodeJS.Platform) {
  // The environment's HOME first: Bun's os.homedir() reads the passwd entry, not HOME.
  const home = environment.HOME && path.isAbsolute(environment.HOME) ? environment.HOME : os.homedir()
  if (platform === "darwin") return path.join(home, "Library", "Application Support", "TestifySec", "Aflock")
  const config = environment.XDG_CONFIG_HOME
  return path.join(config && path.isAbsolute(config) ? config : path.join(home, ".config"), "aflock")
}

/**
 * One directory's opt-in, in a file of its own named by a hash of the directory's real path. No
 * launch reads or writes another directory's choice, so opting in or out cannot race one.
 */
export const selectionFile = (environment: Environment, directory: string, platform = process.platform) =>
  path.join(
    settingsDirectory(environment, platform),
    "requirements",
    `${createHash("sha256").update(directory).digest("hex")}.json`,
  )

/** Where Badger 1.x kept the bearer on disk. Never read; only deleted. */
export const legacyCredentialFile = (environment: Environment, platform = process.platform) =>
  path.join(settingsDirectory(environment, platform), "pushgate-read.json")

async function custody(file: string) {
  if (process.platform === "win32") throw new Error("Requirements is not supported on Windows")
  for (let dir = path.dirname(file); ; dir = path.dirname(dir)) {
    const info = await fs.lstat(dir)
    if (
      !info.isDirectory() ||
      info.isSymbolicLink() ||
      (info.uid !== 0 && info.uid !== process.getuid!()) ||
      ((info.mode & 0o022) !== 0 && !(info.uid === 0 && info.mode & 0o1000))
    )
      throw new Error("requirements-custody")
    if (dir === path.dirname(dir)) return
  }
}

export async function loadSelection(file: string): Promise<Selection | undefined> {
  const exists = await fs.lstat(file).then(
    () => true,
    (error: NodeJS.ErrnoException) => error.code !== "ENOENT",
  )
  if (!exists) return undefined
  try {
    await custody(file)
    const handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    try {
      const stat = await handle.stat()
      if (
        !stat.isFile() ||
        stat.nlink !== 1 ||
        stat.uid !== process.getuid!() ||
        (stat.mode & 0o077) !== 0 ||
        stat.size > 8192
      )
        throw new Error("requirements-custody")
      const bytes = Buffer.alloc(stat.size + 1)
      const read = await handle.read(bytes, 0, bytes.length, 0)
      if (read.bytesRead !== stat.size) throw new Error("requirements-selection-changed")
      return schema.parse(strictJSON(new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, read.bytesRead))))
    } finally {
      await handle.close()
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined
    throw new Error("Requirements selection unavailable; reconnect from a terminal")
  }
}

export async function saveSelection(value: unknown, file: string) {
  const data = schema.parse(value)
  if (process.platform === "win32") throw new Error("Requirements is not supported on Windows")
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 })
  await custody(file)
  const old = await fs.lstat(file).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error
  })
  if (
    old &&
    (!old.isFile() || old.isSymbolicLink() || old.nlink !== 1 || old.uid !== process.getuid!() || old.mode & 0o077)
  )
    throw new Error("requirements-custody")
  const temporary = `${file}.${crypto.randomUUID()}.tmp`
  const handle = await fs.open(temporary, "wx", 0o600)
  try {
    await handle.writeFile(JSON.stringify(data))
    await handle.sync()
    await custody(file)
    await fs.rename(temporary, file)
  } finally {
    await handle.close()
    await fs.unlink(temporary).catch(() => {})
  }
}

export async function removeSelection(file: string) {
  await fs.unlink(file).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error
  })
}

/** Deletes a 1.x on-disk bearer without reading it. Returns whether one was there. */
export async function removeLegacyCredential(file: string) {
  return fs.unlink(file).then(
    () => true,
    (error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return false
      throw error
    },
  )
}
