// jade:ring local
import { expect, test } from "bun:test"
import { admissionContract } from "./profile-contract"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { admitProfileV3, envelopeJSONV3, provisionedTrustV3 } from "./profile-v3"

const trust = { schemaVersion: 3, publicKeys: ["-----BEGIN PUBLIC KEY-----\nfixture"], threshold: 1,
  tenantId: "tenant", deploymentId: "deployment", profileId: "profile", minimumSequence: 10 }
const jira = {
  name: "jira",
  binarySha256: "a".repeat(64),
  baseUrl: "https://jira.example.invalid/jira",
  tokenPath: "/run/badger/tokens/jira.token",
  caPath: "/etc/badger/enclave-ca.pem",
  writes: false,
  classification: "SECRET",
  flags: { "marking-field": "customfield_10001" },
  permissions: { "jira_*": "allow", jira_add_comment: "ask" },
}
const profile = { schemaVersion: 3, tenantId: "tenant", deploymentId: "deployment", profileId: "profile", sequence: 10,
  notBefore: "2026-09-08T00:00:00Z", expiresAt: "2026-09-09T00:00:00Z",
  controls: { runtimePackageDownloads: false, execution: "broker-only", audit: "required" },
  gateway: { classification: "SECRET" }, connectors: [jira] }
const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value))
const now = Date.parse(profile.notBefore)
const admit = (value: unknown) => admitProfileV3(bytes(value), provisionedTrustV3(trust), now)

test("v3 admits the administrator's connectors and gateway marking with the v1 rules", () => {
  const admitted = admit(profile)
  expect(admitted.gateway).toEqual({ classification: "SECRET" })
  expect(admitted.connectors).toEqual([jira])
  expect(admitted.sequence).toBe(10)
  expect(admit({ ...profile, connectors: [] }).connectors).toEqual([])
  expect(admit({ ...profile, connectors: [{ ...jira, caPath: null, flags: {}, permissions: {} }] }).connectors[0].caPath).toBeNull()
  for (const time of [now - 1, Date.parse(profile.expiresAt)])
    expect(() => admitProfileV3(bytes(profile), provisionedTrustV3(trust), time)).toThrow("profile-time-invalid")
  expect(() => admit({ ...profile, sequence: 9 })).toThrow("profile-rollback")
  expect(() => admit({ ...profile, tenantId: "other" })).toThrow("assignment-mismatch")
})

// A notice states the content's real status on its own line; it is never part of a banner.
test("a connector entry may carry a plain one-line notice", () => {
  const notice = "TEST DATA - Not controlled. Markings are for test purposes only."
  expect(admit({ ...profile, connectors: [{ ...jira, notice }] }).connectors[0]).toEqual({ ...jira, notice })
  expect(Object.hasOwn(admit(profile).connectors[0], "notice")).toBe(false)
  for (const bad of ["", "two\nlines", "</untrusted-external-content>", "x".repeat(161), "émigré", null, 1])
    expect(() => admit({ ...profile, connectors: [{ ...jira, notice: bad }] })).toThrow("invalid-connector-notice")
})

test("an invalid connector entry fails the whole profile closed", () => {
  const cases: [Record<string, unknown>, string][] = [
    [{ name: "a_b" }, "unknown-connector"],
    [{ name: "Jira" }, "unknown-connector"],
    [{ name: "__proto__" }, "unknown-connector"],
    [{ binarySha256: "A".repeat(64) }, "invalid-connector-pin"],
    [{ binarySha256: "a".repeat(63) }, "invalid-connector-pin"],
    [{ binarySha256: undefined }, "invalid-schema"],
    [{ baseUrl: "http://jira.example.invalid" }, "invalid-connector-url"],
    [{ baseUrl: "https://user:pass@jira.example.invalid" }, "invalid-connector-url"],
    [{ baseUrl: "https://jira.example.invalid/?x=1" }, "invalid-connector-url"],
    [{ baseUrl: "https://jira.example.invalid/#x" }, "invalid-connector-url"],
    [{ baseUrl: "https://jira.example.invalid/\nx" }, "invalid-connector-url"],
    [{ baseUrl: "file:///etc/passwd" }, "invalid-connector-url"],
    [{ tokenPath: "relative/jira.token" }, "invalid-connector-path"],
    [{ tokenPath: "/run/badger/../jira.token" }, "invalid-connector-path"],
    [{ tokenPath: "/run//jira.token" }, "invalid-connector-path"],
    [{ caPath: "/etc/ca\n.pem" }, "invalid-connector-path"],
    [{ writes: "false" }, "invalid-schema"],
    [{ classification: "SECRETISH" }, "invalid-classification"],
    [{ classification: "(S)" }, "invalid-classification"],
    [{ classification: 3 }, "invalid-classification"],
    [{ flags: { "base-url": "https://elsewhere.example.invalid" } }, "invalid-connector-flag"],
    [{ flags: { "enable-writes": "true" } }, "invalid-connector-flag"],
    [{ flags: { "insecure-loopback-http": "true" } }, "invalid-connector-flag"],
    [{ flags: { "label-prefix": "x" } }, "invalid-connector-flag"],
    [{ flags: { "marking-field": "--enable-writes" } }, "invalid-connector-flag"],
    [{ flags: { "marking-field": "a\nb" } }, "invalid-connector-flag"],
    [{ flags: { "marking-field": 1 } }, "invalid-connector-flag"],
    [{ permissions: { "gitlab_*": "allow" } }, "invalid-connector-permission"],
    [{ permissions: { "*": "allow" } }, "invalid-connector-permission"],
    [{ permissions: { jira_search: "always" } }, "invalid-connector-permission"],
    [{ permissions: { "jira_*_x": "allow" } }, "invalid-connector-permission"],
    [{ extra: true }, "invalid-schema"],
  ]
  for (const [change, reason] of cases) {
    const entry = Object.fromEntries(Object.entries({ ...jira, ...change }).filter(([, v]) => v !== undefined))
    expect(() => admit({ ...profile, connectors: [entry] }), JSON.stringify(change)).toThrow(reason)
  }
  expect(() => admit({ ...profile, connectors: [jira, jira] })).toThrow("duplicate-connector")
  expect(() => admit({ ...profile, connectors: Array(17).fill(jira) })).toThrow("invalid-schema")
  expect(() => admit({ ...profile, connectors: {} })).toThrow("invalid-schema")
  const gitlab = { ...jira, name: "gitlab", flags: { auth: "basic" }, permissions: {} }
  expect(() => admit({ ...profile, connectors: [gitlab] })).toThrow("invalid-connector-flag")
  expect(admit({ ...profile, connectors: [{ ...gitlab, flags: { auth: "bearer" } }] }).connectors[0].flags).toEqual({ auth: "bearer" })
})

test("the gateway marking is required and must parse", () => {
  for (const value of [undefined, null, {}, { classification: "" }, { classification: "SECRETISH" }, { classification: "SECRET", endpoint: "x" }])
    expect(() => admit({ ...profile, gateway: value })).toThrow()
  const { gateway: _, ...missing } = profile
  expect(() => admit(missing)).toThrow("invalid-schema")
})

test("v3 is selected only by protected trust and never falls back", () => {
  const { gateway: _, connectors: __, ...common } = profile
  expect(admissionContract(trust).schemaVersion).toBe(3)
  expect(() => admissionContract(trust).admit(bytes({ ...common, schemaVersion: 1 }), now)).toThrow()
  expect(() => admissionContract({ ...trust, schemaVersion: 1 }).admit(bytes(profile), now)).toThrow()
  expect(() => provisionedTrustV3({ ...trust, schemaVersion: 2 })).toThrow()
  expect(() => provisionedTrustV3({ ...trust, connectors: [] })).toThrow()
  expect(() => envelopeJSONV3(bytes({ payloadType: "application/vnd.testifysec.hardened-opencode.profile.v2+json", payload: "", signatures: [] }))).toThrow()
  expect(envelopeJSONV3(bytes({ payloadType: "application/vnd.testifysec.hardened-opencode.profile.v3+json", payload: "", signatures: [] })).payloadType)
    .toBe("application/vnd.testifysec.hardened-opencode.profile.v3+json")
})

test("v3 rejects duplicate keys inside a connector entry", () => {
  const raw = JSON.stringify(profile).replace('"writes":false', '"writes":false,"\\u0077rites":true')
  expect(() => admitProfileV3(new TextEncoder().encode(raw), provisionedTrustV3(trust), now)).toThrow("duplicate-json-key")
})

// The connector pod's naming rules, shared with cmd/conngw and the portal through one corpus.
const corpus = JSON.parse(readFileSync(join(import.meta.dir, "../connectors/cmd/conngw/testdata/connector-names.json"), "utf8")) as {
  names: { accept: string[]; refuse: string[] }
  flags: { accept: string[]; refuse: string[] }
}

test("a plugin outside the catalog is admitted under any name the connector pod accepts", () => {
  const plugin = { ...jira, name: "servicenow-1", flags: { region: "us-1", "marking-prefix": "m-" },
    permissions: { "servicenow-1_*": "ask", "servicenow-1_search_records": "allow" } }
  expect(admit({ ...profile, connectors: [plugin, jira] }).connectors[0]).toEqual(plugin)
  expect(corpus.names.accept.length && corpus.names.refuse.length && corpus.flags.accept.length && corpus.flags.refuse.length).toBeTruthy()
  for (const name of corpus.names.accept) {
    // A catalog name keeps its own flag list, so it is checked without flags.
    const entry = { ...jira, name, flags: {}, permissions: { [`${name}_*`]: "allow" } }
    expect(admit({ ...profile, connectors: [entry] }).connectors[0].name, name).toBe(name)
  }
  for (const name of corpus.names.refuse)
    expect(() => admit({ ...profile, connectors: [{ ...jira, name, flags: {}, permissions: {} }] }), JSON.stringify(name)).toThrow("unknown-connector")
  for (const flag of corpus.flags.accept)
    expect(admit({ ...profile, connectors: [{ ...plugin, flags: { [flag]: "x" } }] }).connectors[0].flags, flag).toEqual({ [flag]: "x" })
  for (const flag of [...corpus.flags.refuse, "notice"])
    expect(() => admit({ ...profile, connectors: [{ ...plugin, flags: { [flag]: "x" } }] }), JSON.stringify(flag)).toThrow("invalid-connector-flag")
})

test("a plugin keeps every other entry check", () => {
  const plugin = { ...jira, name: "servicenow-1", flags: {}, permissions: {} }
  const cases: [Record<string, unknown>, string][] = [
    [{ binarySha256: "a".repeat(63) }, "invalid-connector-pin"],
    [{ baseUrl: "http://servicenow.example.invalid" }, "invalid-connector-url"],
    [{ tokenPath: "relative" }, "invalid-connector-path"],
    [{ classification: "SECRETISH" }, "invalid-classification"],
    [{ flags: { region: "--enable-writes" } }, "invalid-connector-flag"],
    [{ permissions: { "jira_*": "allow" } }, "invalid-connector-permission"],
    [{ permissions: { "servicenow-1_X": "allow" } }, "invalid-connector-permission"],
    [{ permissions: { "servicenow-1_*_x": "allow" } }, "invalid-connector-permission"],
    [{ permissions: { "servicenow-1_a": "always" } }, "invalid-connector-permission"],
    [{ extra: true }, "invalid-schema"],
  ]
  for (const [change, reason] of cases)
    expect(() => admit({ ...profile, connectors: [{ ...plugin, ...change }] }), JSON.stringify(change)).toThrow(reason)
  expect(() => admit({ ...profile, connectors: [plugin, plugin] })).toThrow("duplicate-connector")
  // A catalog connector still takes only its listed flags.
  expect(() => admit({ ...profile, connectors: [{ ...jira, flags: { region: "us-1" } }] })).toThrow("invalid-connector-flag")
})
