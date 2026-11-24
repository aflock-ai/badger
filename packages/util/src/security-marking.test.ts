import { expect, test } from "bun:test"
import { loadScheme } from "@testifysec/marking"
import { SecurityMarking } from "./security-marking.js"

const env = { BADGER_DATA_MARKING: "CUI", BADGER_ALLOWED_MARKINGS: '["CUI","UNCLASSIFIED"]' }

test("marking policy uses only explicit deployment values", () => {
  expect(SecurityMarking.policy({})).toEqual({ marking: null, classification: null, allowed: [] })
  expect(SecurityMarking.policy(env)).toEqual({
    marking: "CUI",
    classification: "UNCLASSIFIED",
    allowed: ["CUI", "UNCLASSIFIED"],
  })
  expect(() => SecurityMarking.policy({ ...env, BADGER_DATA_MARKING: "OTHER" })).toThrow()
  expect(() => SecurityMarking.policy({ BADGER_DATA_MARKING: "DEMO\nFORGED" })).toThrow()
})

test("new session metadata cannot supply or erase the deployment marking", () => {
  expect(
    SecurityMarking.metadata({ deployment_marking: "FORGED", marking_source: "user", note: "example" }, undefined, env),
  ).toEqual({
    note: "example",
    deployment_marking: "CUI",
    marking_source: "deployment",
    classification: "UNCLASSIFIED",
    control_marking: "CUI",
  })
  expect(SecurityMarking.metadata({ deployment_marking: "FORGED" }, undefined, {})).toBeUndefined()
})

test("metadata edits retain historical markings and do not relabel unmarked records", () => {
  const original = { deployment_marking: "UNCLASSIFIED", marking_source: "deployment" }
  expect(SecurityMarking.metadata({ deployment_marking: "CUI", note: "edited" }, original, env)).toEqual({
    note: "edited",
    ...original,
    classification: "UNCLASSIFIED",
  })
  expect(SecurityMarking.metadata({ note: "legacy" }, {}, env)).toEqual({ note: "legacy" })
  // Setting empty metadata on an unmarked record clears it; undefined would mean "leave it".
  expect(SecurityMarking.metadata({}, { note: "old" }, env)).toEqual({})
  // Reserved fields are rebuilt from the stored marking value, so forged ones do not survive an edit.
  const forged = {
    deployment_marking: "CUI",
    control_marking: "NONE",
    classification: "SECRET",
    marking_source: "user",
  }
  expect(SecurityMarking.metadata({ note: "edited" }, forged, env)).toEqual({
    note: "edited",
    deployment_marking: "CUI",
    classification: "UNCLASSIFIED",
    marking_source: "deployment",
    control_marking: "CUI",
  })
  expect(SecurityMarking.metadata({ note: "edited" }, { control_marking: "NONE" }, env)).toEqual({ note: "edited" })
})

// A fork is a new record. It keeps the original's marking only when that is not below the
// current deployment marking, so a deployment that moved to CUI never mints UNCLASSIFIED forks.
test("inherited markings are re-checked against the current deployment", () => {
  const cuiOnly = { BADGER_DATA_MARKING: "CUI", BADGER_ALLOWED_MARKINGS: '["CUI"]' }
  const unclassified = { BADGER_DATA_MARKING: "UNCLASSIFIED", BADGER_ALLOWED_MARKINGS: '["UNCLASSIFIED","CUI"]' }
  const oldUnclassified = {
    deployment_marking: "UNCLASSIFIED",
    classification: "UNCLASSIFIED",
    marking_source: "deployment",
  }
  const oldCui = { ...oldUnclassified, deployment_marking: "CUI", control_marking: "CUI" }
  expect(SecurityMarking.inherit({ note: "x" }, oldUnclassified, cuiOnly)).toEqual({
    note: "x",
    deployment_marking: "CUI",
    classification: "UNCLASSIFIED",
    marking_source: "deployment",
    control_marking: "CUI",
  })
  expect(SecurityMarking.inherit(undefined, oldCui, cuiOnly)).toEqual(oldCui)
  expect(SecurityMarking.inherit(undefined, oldCui, unclassified)).toEqual(oldCui)
  expect(SecurityMarking.inherit(undefined, oldCui, {})).toEqual(oldCui)
  expect(SecurityMarking.inherit({ deployment_marking: "UNCLASSIFIED" }, {}, cuiOnly)).toMatchObject({
    deployment_marking: "CUI",
  })
})

// Session metadata used to be stored straight from client input, so old records can carry any
// reserved fields. Only the marking value is taken from history; the rest is rebuilt from it.
test("a fork rebuilds every reserved field instead of trusting a stored record", () => {
  const cuiOnly = { BADGER_DATA_MARKING: "CUI", BADGER_ALLOWED_MARKINGS: '["CUI"]' }
  const canonical = {
    deployment_marking: "CUI",
    classification: "UNCLASSIFIED",
    marking_source: "deployment",
    control_marking: "CUI",
  }
  const forged = {
    deployment_marking: "CUI",
    control_marking: "NONE",
    classification: "SECRET",
    marking_source: "user",
  }
  expect(SecurityMarking.inherit(undefined, forged, cuiOnly)).toEqual(canonical)
  expect(SecurityMarking.inherit(undefined, { deployment_marking: "TOP", control_marking: "NONE" }, cuiOnly)).toEqual(
    canonical,
  )
  expect(SecurityMarking.inherit({ control_marking: "NONE" }, forged, {})).toEqual(canonical)
})

test("marking admins come from a deployment-named trusted header and fail closed", () => {
  const env = { BADGER_TRUSTED_ROLE_HEADER: "x-forge-role", BADGER_MARKING_ADMIN_ROLES: '["admin","superAdmin"]' }
  expect(SecurityMarking.markingAdmin({ "x-forge-role": "admin" }, env)).toBe(true)
  expect(SecurityMarking.markingAdmin({ "x-forge-role": "superAdmin" }, env)).toBe(true)
  expect(SecurityMarking.markingAdmin({ "x-forge-role": "user" }, env)).toBe(false)
  expect(SecurityMarking.markingAdmin({}, env)).toBe(false)
  expect(SecurityMarking.markingAdmin({ "x-forge-role": "admin" }, {})).toBe(false)
  expect(
    SecurityMarking.markingAdmin({ "x-forge-role": "admin" }, { BADGER_TRUSTED_ROLE_HEADER: "x-forge-role" }),
  ).toBe(false)
  expect(() => SecurityMarking.markingAdmin({}, { ...env, BADGER_MARKING_ADMIN_ROLES: "admin" })).toThrow()
})

// A managed build carries its deployment's marking policy compiled in. The environment may only
// tighten it: never lower the marking, unset it, or widen what may be chosen.
const managed = { managed: true, marking: "UNCLASSIFIED", allowed: ["UNCLASSIFIED", "CUI"] }

test("in a managed build the compiled marking is the floor the environment cannot lower or unset", () => {
  const cui = { ...managed, marking: "CUI" }
  expect(SecurityMarking.policy({}, cui).marking).toBe("CUI")
  expect(SecurityMarking.policy({ BADGER_DATA_MARKING: "UNCLASSIFIED" }, cui).marking).toBe("CUI")
  expect(SecurityMarking.policy({ BADGER_DATA_MARKING: "" }, cui).marking).toBe("CUI")
  // An allowlist that leaves out the marking in force is refused, not quietly widened.
  expect(() => SecurityMarking.policy({ BADGER_ALLOWED_MARKINGS: "[]" }, cui)).toThrow()
})

test("in a managed build the environment may raise the marking and narrow the choices", () => {
  expect(SecurityMarking.policy({ BADGER_DATA_MARKING: "CUI" }, managed)).toEqual({
    marking: "CUI",
    classification: "UNCLASSIFIED",
    allowed: ["UNCLASSIFIED", "CUI"],
  })
  expect(SecurityMarking.policy({ BADGER_ALLOWED_MARKINGS: '["UNCLASSIFIED"]' }, managed).allowed).toEqual([
    "UNCLASSIFIED",
  ])
  // A choice the build does not allow cannot be added by the environment.
  expect(
    SecurityMarking.policy(
      { BADGER_ALLOWED_MARKINGS: '["CUI","UNCLASSIFIED"]' },
      { ...managed, allowed: ["UNCLASSIFIED"] },
    ).allowed,
  ).toEqual(["UNCLASSIFIED"])
})

test("in a managed build the environment cannot raise the marking to one the build excludes", () => {
  const unclassifiedOnly = { managed: true, marking: "UNCLASSIFIED", allowed: ["UNCLASSIFIED"] }
  expect(() => SecurityMarking.policy({ BADGER_DATA_MARKING: "CUI" }, unclassifiedOnly)).toThrow()
  expect(() =>
    SecurityMarking.policy({ BADGER_DATA_MARKING: "CUI", BADGER_ALLOWED_MARKINGS: '["CUI"]' }, unclassifiedOnly),
  ).toThrow()
  expect(SecurityMarking.policy({ BADGER_DATA_MARKING: "UNCLASSIFIED" }, unclassifiedOnly).allowed).toEqual([
    "UNCLASSIFIED",
  ])
})

test("in a managed build an env allowlist cannot exclude the marking in force", () => {
  expect(() => SecurityMarking.policy({ BADGER_ALLOWED_MARKINGS: '["CUI"]' }, managed)).toThrow()
  expect(SecurityMarking.policy({ BADGER_DATA_MARKING: "CUI", BADGER_ALLOWED_MARKINGS: '["CUI"]' }, managed)).toEqual({
    marking: "CUI",
    classification: "UNCLASSIFIED",
    allowed: ["CUI"],
  })
})

test("a managed build compiled without a marking has none, whatever the environment says", () => {
  const none = { managed: true, marking: null, allowed: [] }
  expect(SecurityMarking.policy({ BADGER_DATA_MARKING: "CUI", BADGER_ALLOWED_MARKINGS: '["CUI"]' }, none)).toEqual({
    marking: null,
    classification: null,
    allowed: [],
  })
})

test("a build that is not managed keeps reading the marking from the environment", () => {
  const build = { managed: false, marking: null, allowed: [] }
  expect(SecurityMarking.policy(env, build)).toEqual(SecurityMarking.policy(env))
  expect(SecurityMarking.policy({}, build).marking).toBeNull()
})

// An unknown marking has no place in the order, so no comparison with it may answer either way.
// indexOf gave it -1, which made it read as below every known marking.
test("a marking outside the order is refused, never compared as the lowest", () => {
  const [lowest, controlled] = SecurityMarking.levels()
  expect(SecurityMarking.known(controlled)).toBe(true)
  expect(SecurityMarking.known("SECRET")).toBe(false)
  expect(SecurityMarking.known("")).toBe(false)
  expect(SecurityMarking.lowers(lowest, controlled)).toBe(true)
  expect(SecurityMarking.lowers(controlled, null)).toBe(false)
  expect(() => SecurityMarking.lowers(controlled, "SECRET")).toThrow()
  expect(() => SecurityMarking.lowers("SECRET", controlled)).toThrow()
})

// The deployment's classification scheme: us-gov unless the deployment names another, by preset or
// by a scheme file pinned to its digest. A managed build's scheme is compiled in.
const corporate = { BADGER_MARKING_SCHEME: "corporate", BADGER_DATA_MARKING: "INTERNAL", BADGER_ALLOWED_MARKINGS: '["INTERNAL","CONFIDENTIAL"]' }

test("a deployment on another scheme sets and stamps that scheme's markings", () => {
  const scheme = SecurityMarking.scheme(corporate)
  expect(scheme.name).toBe("corporate")
  expect(SecurityMarking.policy(corporate)).toEqual({
    marking: "INTERNAL",
    classification: "INTERNAL",
    allowed: ["INTERNAL", "CONFIDENTIAL"],
  })
  expect(SecurityMarking.metadata({ note: "n", marking_scheme: "forged" }, undefined, corporate)).toEqual({
    note: "n",
    deployment_marking: "INTERNAL",
    classification: "INTERNAL",
    marking_source: "deployment",
    marking_scheme: scheme.digest,
  })
  // The other scheme's words are not markings here, and us-gov's are not markings there.
  const [, controlled] = SecurityMarking.levels({})
  expect(() =>
    SecurityMarking.policy({ ...corporate, BADGER_DATA_MARKING: controlled, BADGER_ALLOWED_MARKINGS: JSON.stringify([controlled]) }),
  ).toThrow()
  expect(() => SecurityMarking.policy({ BADGER_DATA_MARKING: "INTERNAL" })).toThrow()
  expect(() => SecurityMarking.policy({ ...corporate, BADGER_MARKING_SCHEME: "no-such-preset" })).toThrow("absolute path")
})

test("a record stamped under another scheme is never edited or forked under this one", () => {
  const [unclassified, controlled] = SecurityMarking.levels({})
  const usGovRecord = { deployment_marking: controlled, marking_source: "deployment", classification: unclassified, control_marking: controlled }
  expect(() => SecurityMarking.metadata({ note: "x" }, usGovRecord, corporate)).toThrow("another marking scheme")
  expect(() => SecurityMarking.inherit({ note: "x" }, usGovRecord, corporate)).toThrow("another marking scheme")
  const corporateRecord = SecurityMarking.metadata({}, undefined, corporate)!
  expect(() => SecurityMarking.metadata({ note: "x" }, corporateRecord, env)).toThrow("another marking scheme")
  // Its own records keep their marking.
  expect(SecurityMarking.metadata({ note: "x" }, corporateRecord, corporate)).toEqual({ note: "x", ...corporateRecord })
})

test("a scheme file must be pinned to its digest", () => {
  const { mkdtempSync, writeFileSync } = require("node:fs") as typeof import("node:fs")
  const dir = mkdtempSync(require("node:path").join(require("node:os").tmpdir(), "scheme-"))
  const file = require("node:path").join(dir, "s.json")
  writeFileSync(file, JSON.stringify({ schema: "badger.marking-scheme/v1", name: "t", version: 1, levels: [{ name: "LOW" }, { name: "HIGH" }], groups: [] }))
  const digest = loadScheme("s.json", require("node:fs").readFileSync(file, "utf8")).digest
  const pinned = { BADGER_MARKING_SCHEME: file, BADGER_MARKING_SCHEME_SHA256: digest, BADGER_DATA_MARKING: "LOW" }
  expect(SecurityMarking.policy(pinned).allowed).toEqual(["LOW"])
  expect(() => SecurityMarking.policy({ ...pinned, BADGER_MARKING_SCHEME_SHA256: undefined })).toThrow("pinned")
  expect(() => SecurityMarking.policy({ ...pinned, BADGER_MARKING_SCHEME_SHA256: "sha256:" + "0".repeat(64) })).toThrow("digest")
  // Only a built-in preset's name is a preset; anything else is a file, which must be an absolute path
  // on this platform.
  expect(() => SecurityMarking.policy({ ...pinned, BADGER_MARKING_SCHEME: "relative.json" })).toThrow("absolute path")
  expect(() => SecurityMarking.policy({ ...pinned, BADGER_MARKING_SCHEME: "dir/relative.json" })).toThrow("absolute path")
  if (process.platform !== "win32")
    expect(() => SecurityMarking.policy({ ...pinned, BADGER_MARKING_SCHEME: "C:/policy/site.json" })).toThrow("absolute path")
})

test("a managed build's scheme is compiled in; the environment may only assert its digest", () => {
  const scheme = SecurityMarking.scheme(corporate)
  const compiled = { managed: true, marking: "INTERNAL", allowed: ["INTERNAL", "CONFIDENTIAL"], scheme: { preset: "corporate" } }
  expect(SecurityMarking.policy({}, compiled)).toEqual({ marking: "INTERNAL", classification: "INTERNAL", allowed: ["INTERNAL", "CONFIDENTIAL"] })
  expect(SecurityMarking.policy({ BADGER_MARKING_SCHEME_SHA256: scheme.digest }, compiled).marking).toBe("INTERNAL")
  expect(() => SecurityMarking.policy({ BADGER_MARKING_SCHEME_SHA256: SecurityMarking.scheme({}).digest }, compiled)).toThrow("digest")
  expect(() => SecurityMarking.policy({ BADGER_MARKING_SCHEME: "us-gov" }, compiled)).toThrow("compiled")
  // A managed build compiled without a scheme is us-gov, as every managed build before schemes.
  const [, controlled] = SecurityMarking.levels({})
  expect(SecurityMarking.policy({}, { managed: true, marking: controlled, allowed: [controlled], scheme: null }).marking).toBe(controlled)
})
