import { dirname, join } from "node:path"
import { openVerifier } from "../native/binding"
import { admitProfile, envelopeJSON, payloadType, provisionedTrust } from "../managed/profile"
import { strictJSON } from "../managed/strict-json"

declare const MANAGED_TRUST: unknown
declare const MANAGED_TRUST_SHA256: string
declare const ROOKERY_LIBRARY_NAME: string
declare const ROOKERY_LIBRARY_SHA256: string
declare const RUNTIME_BROKER_SOCKET: string
declare const RUNTIME_WORKSPACE_ID: string

// Host admission contains no upstream app imports. OpenCode starts only when the
// independently installed broker has constructed the worker's execution boundary.
try {
  if (Bun.argv.length !== 2) throw new Error("invalid invocation")
  const chunks: Uint8Array[] = []
  let size = 0
  for await (const chunk of Bun.stdin.stream()) {
    size += chunk.byteLength
    if (size > 1024 * 1024) throw new Error("oversized request")
    chunks.push(chunk)
  }
  const raw = Buffer.concat(chunks)
  const input = strictJSON(new TextDecoder("utf-8", { fatal: true }).decode(raw))
  if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).sort().join(",") !== "profile,prompt,schema")
    throw new Error("invalid request")
  const request = input as Record<string, unknown>
  if (request.schema !== "testifysec.hardened-opencode.run/v1" || typeof request.prompt !== "string" ||
      !request.prompt.trim() || request.prompt.length > 64000) throw new Error("invalid request")
  const trust = provisionedTrust(MANAGED_TRUST)
  // This host is a pinned-key consumer; chain-mode trust is for hardened-admission.
  if (trust.mode !== "keys") throw new Error("unsupported trust mode")
  const envelope = envelopeJSON(new TextEncoder().encode(JSON.stringify(request.profile)))
  const verifier = openVerifier(join(dirname(process.execPath), ROOKERY_LIBRARY_NAME), ROOKERY_LIBRARY_SHA256)
  const admission = (() => {
    try {
      const verified = verifier.verify(new TextEncoder().encode(JSON.stringify({
        envelope, publicKeys: trust.publicKeys, threshold: trust.threshold, expectedPayloadType: payloadType,
      })))
      if (!verified.ok || !verified.payloadBase64 || !verified.payloadSha256) throw new Error("invalid signature")
      return { profile: admitProfile(Buffer.from(verified.payloadBase64, "base64"), trust, Date.now()),
        payloadSha256: verified.payloadSha256, signerKeyIds: verified.signerKeyIds }
    } finally {
      verifier.close()
    }
  })()
  const execute = JSON.stringify({
    schema: "testifysec.hardened-opencode.exec/v1", workspace: RUNTIME_WORKSPACE_ID,
    command: "/toolpack/opencode-worker", timeoutSeconds: 60,
    profileEnvelope: JSON.stringify(envelope),
    stdin: JSON.stringify({ schema: "testifysec.hardened-opencode.prompt/v1", prompt: request.prompt, profileDigest: admission.payloadSha256 }),
  })
  const response = await fetch("http://hardened-broker/v1/execute", {
    unix: RUNTIME_BROKER_SOCKET, method: "POST", headers: { "content-type": "application/json" },
    body: execute, redirect: "error", signal: AbortSignal.timeout(75000),
  })
  if (!response.ok || !response.body) throw new Error("broker unavailable")
  const output: Uint8Array[] = []
  let length = 0
  for await (const chunk of response.body) {
    length += chunk.byteLength
    if (length > 2 * 1024 * 1024) throw new Error("broker output too large")
    output.push(chunk)
  }
  const result = JSON.parse(Buffer.concat(output).toString("utf8")) as Record<string, unknown>
  if (result.schema !== "testifysec.hardened-opencode.exec-result/v1" || typeof result.status !== "string")
    throw new Error("invalid broker response")
  process.stdout.write(JSON.stringify({ schema: "testifysec.hardened-opencode.run-result/v1", admission,
    trustSha256: MANAGED_TRUST_SHA256, requestSha256: new Bun.CryptoHasher("sha256").update(raw).digest("hex"),
    broker: result }) + "\n")
  process.exitCode = result.status === "completed" && result.exitCode === 0 && result.cleanup === true ? 0 : 1
} catch {
  process.stdout.write(JSON.stringify({ schema: "testifysec.hardened-opencode.run-result/v1", status: "unavailable",
    message: "Admission or isolated execution unavailable; no host fallback" }) + "\n")
  process.exitCode = 1
}
