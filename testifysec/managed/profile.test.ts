// jade:ring local
import { expect, test } from "bun:test"
import { admitProfile, provisionedTrust } from "./profile"
import { strictJSON } from "./strict-json"

test("JSON parsing rejects duplicate aliases, malformed documents, and excessive nesting", () => {
  for (const input of [
    '{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"outer":{"key":1,"key":2}}',
    '{"a":true,}', "[1,]", '{} {}', '[true false]', '"unterminated', '"bad\\xescape"',
    '{"a":01}', '{"a":NaN}', '{"a":1e}', " ", "[".repeat(34) + "0" + "]".repeat(34),
  ]) expect(() => strictJSON(input)).toThrow()
  for (const input of ['{"a":[true,false,null,0,12,9007199254740991],"b":{"c":"escaped\\\"string"}}', "[]", "{}", '"value"'])
    expect(strictJSON(input)).toEqual(JSON.parse(input))
})

test("integer-only JSON refuses lossy and noncanonical numeric tokens before conversion", () => {
  for (const value of ["9.999999999999999999", "1.00000000000000001", "1e1", "1e0", "-0", "-1", "9007199254740992", "9007199254740993"])
    expect(() => strictJSON('{"value":' + value + "}")).toThrow("invalid-json-number")
})

test("profile validity is inclusive at not-before and exclusive at expiry", () => {
  const trust = provisionedTrust({
    schemaVersion: 1, publicKeys: ["-----BEGIN PUBLIC KEY-----\nfixture"], threshold: 1,
    tenantId: "tenant", deploymentId: "deployment", profileId: "profile", minimumSequence: 10,
  })
  const profile = {
    schemaVersion: 1, tenantId: "tenant", deploymentId: "deployment", profileId: "profile", sequence: 10,
    notBefore: "2026-09-08T00:00:00Z", expiresAt: "2026-09-09T00:00:00Z",
    controls: { runtimePackageDownloads: false, execution: "broker-only", audit: "required" },
  }
  const bytes = new TextEncoder().encode(JSON.stringify(profile))
  const start = Date.parse(profile.notBefore)
  const end = Date.parse(profile.expiresAt)
  expect(() => admitProfile(bytes, trust, start - 1)).toThrow("profile-time-invalid")
  expect(admitProfile(bytes, trust, start).sequence).toBe(10)
  expect(admitProfile(bytes, trust, end - 1).sequence).toBe(10)
  expect(() => admitProfile(bytes, trust, end)).toThrow("profile-time-invalid")
  for (const override of [
    { schemaVersion: "1" }, { sequence: Number.MAX_SAFE_INTEGER + 1 }, { sequence: -1 },
    { expiresAt: "2026-02-30T00:00:00Z" }, { expiresAt: "2026-09-09T00:00:00+00:00" },
    { notBefore: profile.expiresAt }, { TenantId: "tenant" },
  ]) expect(() => admitProfile(new TextEncoder().encode(JSON.stringify({ ...profile, ...override })), trust, start)).toThrow()
  for (const [field, value] of [["sequence", "9.999999999999999999"], ["schemaVersion", "1.00000000000000001"]]) {
    const signedBytes = JSON.stringify(profile).replace('"' + field + '":' + (field === "sequence" ? "10" : "1"), '"' + field + '":' + value)
    expect(() => admitProfile(new TextEncoder().encode(signedBytes), trust, start)).toThrow("invalid-json-number")
  }
})
