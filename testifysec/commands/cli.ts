import fs from "node:fs/promises"
import { attestationRequest, enrollmentRequest } from "./request"
import type { AttestationRequest, EnrollmentRequest } from "./request"
import { runNative, type NativeEvent } from "./embedded"
import { loadSettings } from "./settings"

const publicFields = ["schema", "event", "trustMode", "status", "stage", "code", "browserOpened",
  "platformURL", "tenantID", "agentID", "spiffeID", "expiresAt", "identityReference", "stateDirectory", "assurance",
  "evidenceGitoid", "envelopeSha256", "envelopeFile", "payloadSha256", "commit", "agentSpiffeID",
  "sessionID", "publicKeyFile", "publicKeySha256"]

function text(value: unknown) {
  if (typeof value !== "string" || value.length > 4096) return ""
  return value.replace(/[\x00-\x1f\x7f-\x9f]/g, "")
}

async function execute(role: "enroll" | "attest", request: EnrollmentRequest | AttestationRequest, json: boolean) {
  await fs.mkdir(request.stateDirectory, { recursive: true, mode: 0o700 })
  let completed = false
  const result = await runNative(role, request, (event) => {
    if (event.schema !== "testifysec.hardened-code.command-event/v1" ||
        (event.trustMode !== request.trustMode && !(event.event === "error" && event.trustMode === undefined)))
      throw new Error("Native command returned an invalid event")
    if (!["ceremony", "enrolled", "attested", "error"].includes(String(event.event)))
      throw new Error("Native command returned an unsupported event")
    if (event.url !== undefined) {
      const url = new URL(text(event.url))
      if (request.trustMode !== "platform" || url.origin !== request.platformURL)
        throw new Error("Native command returned an unexpected platform URL")
    }
    if ((role === "enroll" && event.event === "enrolled") || (role === "attest" && event.event === "attested")) {
      if (completed) throw new Error("Native command returned multiple final results")
      completed = true
    }
    presentCommandEvent(role, request.trustMode, event, json)
  })
  if (result.exitCode === 0 && !completed) throw new Error("Native command returned no completed result")
  process.exitCode = result.exitCode
}

const terminalRequired = "A terminal is required to display the enrollment link. Complete enrollment from an interactive terminal, or enable browser opening."

// Called only after native event/origin validation. TTY state comes from the
// actual output stream, never from a model field, command flag or native event.
export function presentCommandEvent(role: "enroll" | "attest", mode: EnrollmentRequest["trustMode"], event: NativeEvent, json: boolean) {
  if (json) {
    const output = Object.fromEntries(publicFields
      .filter((key) => Object.hasOwn(event, key))
      .map((key) => [key, typeof event[key] === "boolean" ? event[key] : text(event[key])]))
    // The native fallback URL contains one-time ceremony parameters. Machine
    // output never carries it, including when stdout happens to be a terminal.
    if (event.event === "ceremony" && event.browserOpened !== true) output.message = terminalRequired
    process.stdout.write(JSON.stringify(output) + "\n")
    return
  }
  if (event.event === "ceremony") {
    if (event.browserOpened === true) process.stdout.write("Complete agent enrollment in your browser.\n")
    else if (process.stdout.isTTY === true) process.stdout.write(`Complete agent enrollment: ${text(event.url)}\n`)
    else process.stdout.write(terminalRequired + "\n")
    return
  }
  if (event.event === "enrolled") {
    const label = mode === "platform" ? "Platform agent enrolled" : "Local self-signed identity ready (not platform trusted)"
    process.stdout.write(`${label}\n${text(event.identityReference || event.spiffeID)}\n`)
    return
  }
  if (event.event === "attested") {
    const label = mode === "local-self-signed"
      ? "Local self-signed attestation saved (not platform trusted)"
      : event.status === "platform-upload-acknowledged"
        ? "Platform acknowledged the attestation upload"
        : "Attestation remains local; platform upload is unconfirmed"
    process.stdout.write(`${label}\n${text(event.evidenceGitoid)}\n${text(event.envelopeFile)}\n`)
    return
  }
  if (event.code === "no-finalized-worker-session") {
    process.stderr.write("No finalized protected session is available. Preview chat history is not execution evidence.\n")
    return
  }
  process.stderr.write(`${role === "enroll" ? "Enrollment" : "Attestation"} failed${event.stage ? ` at ${text(event.stage)}` : ""}.\n`)
}


export interface EnrollOptions {
  trustMode?: string
  settings?: string
  platform?: string
  stateDir?: string
  name?: string
  repository?: string
  ttlSeconds?: number
  browser: boolean
  json: boolean
}

export async function enroll(options: EnrollOptions) {
  const settings = await loadSettings(options.settings, process.env)
  const request = enrollmentRequest({ trustMode: options.trustMode, platform: options.platform, stateDir: options.stateDir,
    name: options.name, repository: options.repository, ttlSeconds: options.ttlSeconds, noBrowser: !options.browser }, process.env, settings)
  await execute("enroll", request, options.json)
}

export interface AttestOptions {
  trustMode?: string
  settings?: string
  platform?: string
  stateDir?: string
  session?: string
  json: boolean
}

export async function attest(options: AttestOptions) {
  const settings = await loadSettings(options.settings, process.env)
  const request = attestationRequest({ trustMode: options.trustMode, platform: options.platform,
    stateDir: options.stateDir, session: options.session }, process.env, process.cwd(), settings)
  await execute("attest", request, options.json)
}
