import { admitProfile, envelopeJSON, payloadType, provisionedTrust, type SignerCertificate } from "./profile"
import { admitProfileV2, envelopeJSONV2, payloadTypeV2, provisionedTrustV2 } from "./profile-v2"
import { admitProfileV3, envelopeJSONV3, payloadTypeV3, provisionedTrustV3 } from "./profile-v3"

// Only build-provisioned trust selects a contract. Request bytes, environment
// variables and a failed verification never select another version or pin.
export function admissionContract(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("invalid-trust")
  const version = (input as Record<string, unknown>).schemaVersion
  if (version === 1) {
    const trust = provisionedTrust(input)
    return { schemaVersion: 1, payloadType, trust, envelopeJSON,
      admit: (bytes: Uint8Array, now: number, signers?: SignerCertificate[]) => admitProfile(bytes, trust, now, signers) }
  }
  if (version === 3) {
    const trust = provisionedTrustV3(input)
    return { schemaVersion: 3, payloadType: payloadTypeV3, trust, envelopeJSON: envelopeJSONV3,
      admit: (bytes: Uint8Array, now: number, signers?: SignerCertificate[]) => admitProfileV3(bytes, trust, now, signers) }
  }
  if (version !== 2) throw new Error("unsupported-trust-version")
  const trust = provisionedTrustV2(input)
  return { schemaVersion: 2, payloadType: payloadTypeV2, trust, envelopeJSON: envelopeJSONV2,
    admit: (bytes: Uint8Array, now: number, signers?: SignerCertificate[]) => admitProfileV2(bytes, trust, now, signers) }
}
