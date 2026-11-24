import { strictJSON } from "./strict-json"

export const payloadType = "application/vnd.testifysec.hardened-opencode.profile.v1+json"

function object(input: unknown, keys: string[]): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("invalid-schema")
  if (Object.keys(input).length !== keys.length || keys.some((key) => !Object.hasOwn(input, key)))
    throw new Error("invalid-schema")
  return input as Record<string, unknown>
}

function identifier(value: unknown): string {
  if (typeof value !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(value))
    throw new Error("invalid-schema")
  return value
}

function sequence(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) throw new Error("invalid-schema")
  return value
}

function instant(value: unknown): number {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value))
    throw new Error("invalid-schema")
  const parsed = Date.parse(value)
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString().replace(".000Z", "Z") !== value)
    throw new Error("invalid-schema")
  return parsed
}

function pems(value: unknown, header: string, max: number): string[] {
  if (!Array.isArray(value) || !value.length || value.length > max) throw new Error("invalid-trust")
  const list = value.map((item) => {
    if (typeof item !== "string" || item.length > 16384 || !item.startsWith(header + "\n")) throw new Error("invalid-trust")
    return item
  })
  if (new Set(list).size !== list.length) throw new Error("invalid-trust")
  return list
}

// A signer's leaf certificate as the native verifier reports it in chain mode.
export type SignerCertificate = { keyId: string; notBefore: string; notAfter: string }

// Trust selects one mode for the life of the build: pinned public keys, or a certificate chain
// to pinned root CAs with a signer identity the leaf must carry. Never both, never a fallback.
export function provisionedTrust(input: unknown) {
  const chain = !!input && typeof input === "object" && Object.hasOwn(input, "rootCas")
  const trust = object(input, ["schemaVersion", ...(chain ? ["rootCas", "signerIdentity"] : ["publicKeys"]),
    "threshold", "tenantId", "deploymentId", "profileId", "minimumSequence"])
  if (trust.schemaVersion !== 1) throw new Error("invalid-trust")
  const threshold = sequence(trust.threshold)
  const assignment = {
    tenantId: identifier(trust.tenantId), deploymentId: identifier(trust.deploymentId),
    profileId: identifier(trust.profileId), minimumSequence: sequence(trust.minimumSequence),
  }
  if (!chain) {
    const publicKeys = pems(trust.publicKeys, "-----BEGIN PUBLIC KEY-----", 16)
    if (threshold > publicKeys.length) throw new Error("invalid-trust")
    return { mode: "keys" as const, publicKeys, threshold, ...assignment }
  }
  const rootCas = pems(trust.rootCas, "-----BEGIN CERTIFICATE-----", 8)
  const id = object(trust.signerIdentity, ["san", "extendedKeyUsage"])
  if (typeof id.san !== "string" || !id.san || id.san.length > 1024 || id.extendedKeyUsage !== "codeSigning" || threshold > 16)
    throw new Error("invalid-trust")
  return { mode: "chain" as const, rootCas, signerIdentity: { san: id.san, extendedKeyUsage: "codeSigning" as const }, threshold, ...assignment }
}

// The native request's trust fields for a mode.
export function nativeTrust(trust: ReturnType<typeof provisionedTrust>) {
  return trust.mode === "keys" ? { publicKeys: trust.publicKeys, threshold: trust.threshold }
    : { rootCas: trust.rootCas, signerIdentity: trust.signerIdentity, threshold: trust.threshold }
}

export function admitProfile(bytes: Uint8Array, trust: ReturnType<typeof provisionedTrust>, now: number,
  signers: SignerCertificate[] = []) {
  if (!bytes.byteLength || bytes.byteLength > 256 * 1024) throw new Error("invalid-profile-size")
  const profile = object(strictJSON(new TextDecoder("utf-8", { fatal: true }).decode(bytes)), [
    "schemaVersion", "profileId", "tenantId", "deploymentId", "sequence", "notBefore", "expiresAt", "controls",
  ])
  if (profile.schemaVersion !== 1) throw new Error("unsupported-profile-version")
  const profileId = identifier(profile.profileId)
  const tenantId = identifier(profile.tenantId)
  const deploymentId = identifier(profile.deploymentId)
  const version = sequence(profile.sequence)
  const notBefore = instant(profile.notBefore)
  const expiresAt = instant(profile.expiresAt)
  const controls = object(profile.controls, ["runtimePackageDownloads", "execution", "audit"])
  if (controls.runtimePackageDownloads !== false || controls.execution !== "broker-only" || controls.audit !== "required")
    throw new Error("unsupported-controls")
  if (profileId !== trust.profileId || tenantId !== trust.tenantId || deploymentId !== trust.deploymentId)
    throw new Error("assignment-mismatch")
  if (!Number.isSafeInteger(now) || now < notBefore || expiresAt <= notBefore || now >= expiresAt)
    throw new Error("profile-time-invalid")
  if (version < trust.minimumSequence) throw new Error("profile-rollback")
  // Chain mode: the whole signed window lies inside every counted signer's leaf, so a stolen leaf
  // key cannot sign a backdated notBefore or a far expiresAt that outlives the leaf.
  if (trust.mode === "chain") {
    if (!signers.length) throw new Error("profile-outside-signer-certificate")
    for (const signer of signers)
      if (notBefore < instant(signer.notBefore) || instant(signer.notAfter) < expiresAt)
        throw new Error("profile-outside-signer-certificate")
  }
  return { profileId, tenantId, deploymentId, sequence: version, notBefore: profile.notBefore, expiresAt: profile.expiresAt }
}

export function envelopeJSON(bytes: Uint8Array) {
  const envelope = object(strictJSON(new TextDecoder("utf-8", { fatal: true }).decode(bytes)), ["payloadType", "payload", "signatures"])
  if (envelope.payloadType !== payloadType || typeof envelope.payload !== "string" || !Array.isArray(envelope.signatures))
    throw new Error("invalid-envelope")
  for (const entry of envelope.signatures) {
    const signature = object(entry, ["keyid", "sig"])
    if (typeof signature.keyid !== "string" || typeof signature.sig !== "string") throw new Error("invalid-envelope")
  }
  return envelope
}
