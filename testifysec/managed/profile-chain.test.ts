// jade:ring local
import { expect, test } from "bun:test"
import { admitProfile, nativeTrust, provisionedTrust } from "./profile"
import { admitProfileV2, provisionedTrustV2 } from "./profile-v2"

const root = "-----BEGIN CERTIFICATE-----\nfixture"
const signerIdentity = { san: "spiffe://enclave.example/badger/portal", extendedKeyUsage: "codeSigning" }
const chainTrust = { schemaVersion: 1, rootCas: [root], signerIdentity, threshold: 1,
  tenantId: "tenant", deploymentId: "deployment", profileId: "profile", minimumSequence: 10 }
const profile = {
  schemaVersion: 1, tenantId: "tenant", deploymentId: "deployment", profileId: "profile", sequence: 10,
  notBefore: "2026-10-22T00:00:00Z", expiresAt: "2026-10-29T00:00:00Z",
  controls: { runtimePackageDownloads: false, execution: "broker-only", audit: "required" },
}
const keysTrust = { schemaVersion: 1, publicKeys: ["-----BEGIN PUBLIC KEY-----\nfixture"], threshold: 1,
  tenantId: "tenant", deploymentId: "deployment", profileId: "profile", minimumSequence: 10 }
const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value))
const now = Date.parse(profile.notBefore) + 1000
// A 7-day leaf that covers the profile's window exactly.
const leaf = { keyId: "a".repeat(64), notBefore: "2026-10-22T00:00:00Z", notAfter: "2026-10-29T00:00:00Z" }

test("chain trust is its own mode and asks the native verifier for roots, never keys", () => {
  const trust = provisionedTrust(chainTrust)
  expect(trust.mode).toBe("chain")
  expect(nativeTrust(trust)).toEqual({ rootCas: [root], signerIdentity, threshold: 1 })
  expect(nativeTrust(provisionedTrust(keysTrust))).toEqual({ publicKeys: ["-----BEGIN PUBLIC KEY-----\nfixture"], threshold: 1 })
  for (const bad of [
    { ...chainTrust, publicKeys: ["-----BEGIN PUBLIC KEY-----\nfixture"] },
    { ...chainTrust, rootCas: [] }, { ...chainTrust, rootCas: [root, root] }, { ...chainTrust, rootCas: ["-----BEGIN PUBLIC KEY-----\nx"] },
    { ...chainTrust, signerIdentity: undefined }, { ...chainTrust, signerIdentity: { ...signerIdentity, extendedKeyUsage: "serverAuth" } },
    { ...chainTrust, signerIdentity: { san: "" , extendedKeyUsage: "codeSigning" } },
    { ...chainTrust, signerIdentity: { ...signerIdentity, uri: "x" } }, { ...chainTrust, threshold: 17 },
  ]) expect(() => provisionedTrust(JSON.parse(JSON.stringify(bad)))).toThrow()
})

test("the whole signed window must lie inside every signer's leaf", () => {
  const trust = provisionedTrust(chainTrust)
  expect(admitProfile(bytes(profile), trust, now, [leaf]).sequence).toBe(10)
  for (const signers of [
    [], // chain mode without a reported leaf
    [{ ...leaf, notBefore: "2026-10-22T00:00:01Z" }], // backdated notBefore before the leaf
    [{ ...leaf, notAfter: "2026-10-28T23:59:59Z" }], // expiresAt after the leaf
    [leaf, { ...leaf, keyId: "b".repeat(64), notAfter: "2026-10-25T00:00:00Z" }], // one of two signers too short
  ]) expect(() => admitProfile(bytes(profile), trust, now, signers)).toThrow("profile-outside-signer-certificate")
  // Pinned-key mode is unchanged and needs no leaf.
  expect(admitProfile(bytes(profile), provisionedTrust(keysTrust), now).sequence).toBe(10)
})

test("v2 takes chain trust with the same window rule", () => {
  const backend = { kind: "darwin-vz/v1", manifestSha256: "a".repeat(64) }
  const trust = provisionedTrustV2({ ...chainTrust, schemaVersion: 2, backend })
  const v2 = { ...profile, schemaVersion: 2, backend }
  expect(admitProfileV2(bytes(v2), trust, now, [leaf]).backend).toEqual(backend)
  expect(() => admitProfileV2(bytes(v2), trust, now, [{ ...leaf, notAfter: "2026-10-28T00:00:00Z" }])).toThrow("profile-outside-signer-certificate")
})
