// jade:ring local
import { expect, test } from "bun:test"
import { admitProfile, envelopeJSON, provisionedTrust } from "./profile"
import { admissionContract } from "./profile-contract"
import { admitProfileV2, provisionedTrustV2 } from "./profile-v2"

const backend = { kind: "darwin-vz/v1", manifestSha256: "a".repeat(64) }
const trust = { schemaVersion: 2, publicKeys: ["-----BEGIN PUBLIC KEY-----\nfixture"], threshold: 1,
  tenantId: "tenant", deploymentId: "deployment", profileId: "profile", minimumSequence: 10, backend }
const profile = { schemaVersion: 2, tenantId: "tenant", deploymentId: "deployment", profileId: "profile", sequence: 10,
  notBefore: "2026-09-08T00:00:00Z", expiresAt: "2026-09-09T00:00:00Z", backend,
  controls: { runtimePackageDownloads: false, execution: "broker-only", audit: "required" } }
const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value))
const now = Date.parse(profile.notBefore)

test("v2 requires protected backend assignment and preserves exact validity and rollback", () => {
  const assigned = provisionedTrustV2(trust)
  expect(admitProfileV2(bytes(profile), assigned, now).backend).toEqual(backend)
  for (const time of [now - 1, Date.parse(profile.expiresAt)])
    expect(() => admitProfileV2(bytes(profile), assigned, time)).toThrow("profile-time-invalid")
  expect(() => admitProfileV2(bytes({ ...profile, sequence: 9 }), assigned, now)).toThrow("profile-rollback")
  for (const selected of [null, {}, { ...backend, kind: "linux-docker/v1" }, { ...backend, manifestSha256: "b".repeat(64) },
    { ...backend, manifestSha256: "A".repeat(64) }, { ...backend, manifestSha256: "a".repeat(63) }, { ...backend, trusted: true }])
    expect(() => admitProfileV2(bytes({ ...profile, backend: selected }), assigned, now)).toThrow()
})

test("protected contract selection never falls back across versions", () => {
  const { backend: _, ...commonTrust } = trust
  const { backend: __, ...commonProfile } = profile
  const legacyTrust = { ...commonTrust, schemaVersion: 1 }
  const legacyProfile = { ...commonProfile, schemaVersion: 1 }
  expect(admissionContract(legacyTrust).schemaVersion).toBe(1)
  expect(admissionContract(trust).schemaVersion).toBe(2)
  expect(() => admissionContract(legacyTrust).admit(bytes(profile), now)).toThrow()
  expect(() => admissionContract(trust).admit(bytes(legacyProfile), now)).toThrow()
  expect(() => provisionedTrust(trust)).toThrow()
  expect(() => admitProfile(bytes(profile), provisionedTrust(legacyTrust), now)).toThrow()
  expect(() => envelopeJSON(bytes({ payloadType: "application/vnd.testifysec.hardened-opencode.profile.v2+json", payload: "", signatures: [] }))).toThrow()
  for (const value of [undefined, {}, { ...trust, schemaVersion: 3 }, { ...trust, backend: { ...backend, override: true } }])
    expect(() => admissionContract(value)).toThrow()
})

test("v2 rejects duplicate backend keys and lossy raw numbers before the shared v1 validation view", () => {
  const assigned = provisionedTrustV2(trust)
  const raw = JSON.stringify(profile)
  for (const modified of [
    raw.replace('"kind":', '"kind":"darwin-vz/v1","\\u006bind":'),
    raw.replace('"schemaVersion":2', '"schemaVersion":2.00000000000000001'),
    raw.replace('"sequence":10', '"sequence":9.999999999999999999'),
    raw.replace('"sequence":10', '"sequence":1e1'),
    raw.replace('"sequence":10', '"sequence":9007199254740993'),
  ]) expect(() => admitProfileV2(new TextEncoder().encode(modified), assigned, now)).toThrow()
})
