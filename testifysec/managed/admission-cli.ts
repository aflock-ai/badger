import { dirname, join } from "node:path"
import { openVerifier } from "../native/binding"
import { nativeTrust } from "./profile"
import { admissionContract } from "./profile-contract"

declare const MANAGED_TRUST: unknown
declare const MANAGED_TRUST_SHA256: string
declare const ROOKERY_LIBRARY_SHA256: string
declare const ROOKERY_LIBRARY_NAME: string

// This entrypoint imports no upstream OpenCode modules and exposes no execution
// command. A profile admission is not a sandbox or a platform identity ceremony.
try {
  if (Bun.argv.length !== 2) throw new Error("usage: hardened-admission < profile.dsse.json")
  const contract = admissionContract(MANAGED_TRUST)
  const trust = contract.trust
  const chunks: Uint8Array[] = []
  let length = 0
  for await (const chunk of Bun.stdin.stream()) {
    length += chunk.byteLength
    if (length > 512 * 1024) throw new Error("invalid-envelope-size")
    chunks.push(chunk)
  }
  const input = Buffer.concat(chunks)
  const envelope = contract.envelopeJSON(input)
  const verifier = openVerifier(join(dirname(process.execPath), ROOKERY_LIBRARY_NAME), ROOKERY_LIBRARY_SHA256)
  try {
    const result = verifier.verify(new TextEncoder().encode(JSON.stringify({
      envelope, ...nativeTrust(trust), expectedPayloadType: contract.payloadType,
    })))
    if (!result.ok || !result.payloadBase64 || !result.payloadSha256 || !result.signerKeyIds?.length)
      throw new Error("profile-signature-invalid")
    // Chain mode reports one leaf per counted signer; keys mode reports none.
    const signers = result.signerCertificates ?? []
    if ((trust.mode === "chain") !== (signers.length > 0) || (signers.length && (signers.length !== result.signerKeyIds.length ||
      signers.some((signer, i) => signer.keyId !== result.signerKeyIds![i]))))
      throw new Error("profile-signature-invalid")
    const profile = contract.admit(Buffer.from(result.payloadBase64, "base64"), Date.now(), signers)
    process.stdout.write(JSON.stringify({
      schemaVersion: contract.schemaVersion, admitted: true, scope: "profile-admission-only", profile,
      envelopeSha256: new Bun.CryptoHasher("sha256").update(input).digest("hex"),
      payloadSha256: result.payloadSha256, signerKeyIds: result.signerKeyIds,
      trustSha256: MANAGED_TRUST_SHA256, nativeSha256: ROOKERY_LIBRARY_SHA256,
    }) + "\n")
  } finally {
    verifier.close()
  }
} catch (error) {
  // Input bytes, trust material and host paths must not leak through parse errors.
  const known = new Set(["assignment-mismatch", "profile-time-invalid", "profile-rollback", "invalid-schema",
    "unsupported-profile-version", "unsupported-controls", "duplicate-json-key", "invalid-json-number", "profile-signature-invalid",
    "unsupported-profile-type", "unsupported-backend", "invalid-backend-pin", "backend-assignment-mismatch",
    "unknown-connector", "duplicate-connector", "invalid-connector-pin", "invalid-connector-url", "invalid-connector-path",
    "invalid-connector-flag", "invalid-connector-permission", "invalid-classification", "profile-outside-signer-certificate"])
  const reason = error instanceof Error && known.has(error.message) ? error.message : "admission-unavailable"
  const version = (MANAGED_TRUST as { schemaVersion?: unknown })?.schemaVersion
  process.stdout.write(JSON.stringify({ schemaVersion: version === 2 || version === 3 ? version : 1,
    admitted: false, scope: "profile-admission-only", reason }) + "\n")
  process.exitCode = 1
}
