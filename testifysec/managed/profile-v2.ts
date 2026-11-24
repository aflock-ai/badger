import { admitProfile, envelopeJSON, provisionedTrust, type SignerCertificate } from "./profile"
import { strictJSON } from "./strict-json"

export const payloadTypeV2 = "application/vnd.testifysec.hardened-opencode.profile.v2+json"

function record(input: unknown, keys: string[]) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("invalid-schema")
  const value = input as Record<string, unknown>
  if (Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key)))
    throw new Error("invalid-schema")
  return value
}

function backend(input: unknown) {
  const value = record(input, ["kind", "manifestSha256"])
  if (value.kind !== "darwin-vz/v1") throw new Error("unsupported-backend")
  if (typeof value.manifestSha256 !== "string" || !/^[0-9a-f]{64}$/.test(value.manifestSha256))
    throw new Error("invalid-backend-pin")
  return Object.freeze({ kind: "darwin-vz/v1" as const, manifestSha256: value.manifestSha256 })
}

export function provisionedTrustV2(input: unknown) {
  const keys = !!input && typeof input === "object" && Object.hasOwn(input, "rootCas") ? ["rootCas", "signerIdentity"] : ["publicKeys"]
  const value = record(input, ["schemaVersion", ...keys, "threshold", "tenantId", "deploymentId", "profileId", "minimumSequence", "backend"])
  if (value.schemaVersion !== 2) throw new Error("unsupported-trust-version")
  const approved = backend(value.backend)
  // Reuse the unchanged v1 assignment/root rules after checking the exact v2
  // shape. This validation view is never signed or passed to native verification.
  const { backend: _, ...common } = value
  return { ...provisionedTrust({ ...common, schemaVersion: 1 }), backend: approved }
}

export function admitProfileV2(bytes: Uint8Array, trust: ReturnType<typeof provisionedTrustV2>, now: number,
  signers: SignerCertificate[] = []) {
  if (!bytes.byteLength || bytes.byteLength > 256 * 1024) throw new Error("invalid-profile-size")
  const value = record(strictJSON(new TextDecoder("utf-8", { fatal: true }).decode(bytes)), [
    "schemaVersion", "profileId", "tenantId", "deploymentId", "sequence", "notBefore", "expiresAt", "controls", "backend",
  ])
  if (value.schemaVersion !== 2) throw new Error("unsupported-profile-version")
  const selected = backend(value.backend)
  if (selected.kind !== trust.backend.kind || selected.manifestSha256 !== trust.backend.manifestSha256)
    throw new Error("backend-assignment-mismatch")
  const { backend: _, ...common } = value
  const profile = admitProfile(new TextEncoder().encode(JSON.stringify({ ...common, schemaVersion: 1 })), trust, now, signers)
  return { ...profile, backend: selected }
}

export function envelopeJSONV2(bytes: Uint8Array) {
  const value = record(strictJSON(new TextDecoder("utf-8", { fatal: true }).decode(bytes)), ["payloadType", "payload", "signatures"])
  if (value.payloadType !== payloadTypeV2) throw new Error("unsupported-profile-type")
  const envelope = envelopeJSON(new TextEncoder().encode(JSON.stringify({
    ...value, payloadType: "application/vnd.testifysec.hardened-opencode.profile.v1+json",
  })))
  return { ...envelope, payloadType: payloadTypeV2 }
}
