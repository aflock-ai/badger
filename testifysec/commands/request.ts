import os from "node:os"
import path from "node:path"
import { trustMode } from "./trust-mode"
import { platformOrigin, xdgHome, type Settings } from "./settings"

export const DEFAULT_PLATFORM = "https://platform.testifysec.com"

export interface CommandOptions {
  trustMode?: string
  platform?: string
  stateDir?: string
  name?: string
  repository?: string
  ttlSeconds?: number
  noBrowser?: boolean
  session?: string
}

export function stateDirectory(option: string | undefined, environment: Record<string, string | undefined>, platform: NodeJS.Platform = process.platform) {
  if (option !== undefined) {
    if (!option || option.includes("\0")) throw new Error("--state-dir must name a directory")
    return path.resolve(option)
  }
  const home = os.homedir()
  if (platform === "darwin") return path.join(home, "Library", "Application Support", "TestifySec", "Aflock")
  if (platform === "win32") return path.join(environment.LOCALAPPDATA || path.join(home, "AppData", "Local"), "TestifySec", "Aflock")
  return path.join(xdgHome(environment.XDG_STATE_HOME, path.join(home, ".local", "state")), "aflock")
}

function common(options: CommandOptions, environment: Record<string, string | undefined>, settings: Settings) {
  const mode = trustMode(options.trustMode, environment, settings.trustMode)
  if (mode === "local-self-signed" && (options.platform !== undefined || environment.AFLOCK_PLATFORM_URL !== undefined))
    throw new Error("--platform / AFLOCK_PLATFORM_URL cannot be combined with local-self-signed mode")
  return {
    trustMode: mode,
    stateDirectory: stateDirectory(options.stateDir ?? environment.AFLOCK_STATE_DIR ?? settings.stateDirectory, environment),
    ...(mode === "platform" ? { platformURL: platformOrigin(options.platform ?? environment.AFLOCK_PLATFORM_URL ?? settings.platformURL ?? DEFAULT_PLATFORM) } : {}),
  }
}

export function enrollmentRequest(input: CommandOptions, environment: Record<string, string | undefined>, settings: Settings = {}) {
  const request = common(input, environment, settings)
  const options = request.trustMode === "platform" ? {
    ...input,
    name: input.name ?? settings.enrollment?.name,
    repository: input.repository ?? settings.enrollment?.repository,
    ttlSeconds: input.ttlSeconds ?? settings.enrollment?.ttlSeconds,
  } : input
  if (request.trustMode === "local-self-signed" &&
      (options.name !== undefined || options.repository !== undefined || options.ttlSeconds !== undefined))
    throw new Error("Name, repository and lifetime are platform enrollment options")
  if (options.name !== undefined && (!options.name.trim() || options.name.length > 128 || /[\x00-\x1f\x7f]/.test(options.name)))
    throw new Error("--name must be a printable name of at most 128 characters")
  if (options.repository !== undefined && !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(options.repository))
    throw new Error("--repository must be owner/repository")
  if (options.ttlSeconds !== undefined && (!Number.isSafeInteger(options.ttlSeconds) || options.ttlSeconds < 900 || options.ttlSeconds > 604800))
    throw new Error("--ttl-seconds must be a whole number between 900 and 604800")
  return {
    schema: "testifysec.hardened-code.enroll/v1",
    ...request,
    ...(options.name !== undefined ? { name: options.name } : {}),
    ...(options.repository !== undefined ? { repository: options.repository } : {}),
    ...(options.ttlSeconds !== undefined ? { ttlSeconds: options.ttlSeconds } : {}),
    ...(options.noBrowser !== undefined ? { noBrowser: options.noBrowser } : {}),
  }
}

export function attestationRequest(options: CommandOptions, environment: Record<string, string | undefined>, workspaceDirectory: string, settings: Settings = {}) {
  const request = common(options, environment, settings)
  if (options.session !== undefined && !/^[A-Za-z0-9_-]{1,128}$/.test(options.session))
    throw new Error("--session must be a session identifier")
  return {
    schema: "testifysec.hardened-code.attest/v1",
    ...request,
    workspaceDirectory: path.resolve(workspaceDirectory),
    ...(options.session !== undefined ? { sessionID: options.session } : {}),
  }
}

export type EnrollmentRequest = ReturnType<typeof enrollmentRequest>
export type AttestationRequest = ReturnType<typeof attestationRequest>
