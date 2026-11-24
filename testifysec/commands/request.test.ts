// jade:ring local
import { expect, test } from "bun:test"
import os from "node:os"
import path from "node:path"
import { attestationRequest, enrollmentRequest, stateDirectory } from "./request"
import { trustMode } from "./trust-mode"

test("platform is the default and explicit CLI mode overrides the environment", () => {
  expect(trustMode(undefined, {})).toBe("platform")
  expect(trustMode(undefined, { AFLOCK_TRUST_MODE: "local-self-signed" })).toBe("local-self-signed")
  expect(trustMode("platform", { AFLOCK_TRUST_MODE: "local-self-signed" })).toBe("platform")
  expect(trustMode("local-self-signed", { AFLOCK_TRUST_MODE: "platform" })).toBe("local-self-signed")
})

test("ambiguous, empty and legacy trust modes refuse instead of downgrading", () => {
  for (const value of ["", "local", "INSECURE_SELFSIGNED", "true", "PLATFORM", " platform", "platform ", "self-signed"]) {
    expect(() => trustMode(value, {})).toThrow()
    expect(() => trustMode(undefined, { AFLOCK_TRUST_MODE: value })).toThrow()
  }
})

test("local enrollment contains no platform authority or platform-only hints", () => {
  const local = enrollmentRequest({ trustMode: "local-self-signed", stateDir: "/tmp/hardened-request-fixture" }, {})
  expect(local.trustMode).toBe("local-self-signed")
  expect("platformURL" in local).toBe(false)
  for (const options of [{ platform: "https://platform.testifysec.com" }, { name: "agent" }, { repository: "owner/repo" }, { ttlSeconds: 60 }])
    expect(() => enrollmentRequest({ trustMode: "local-self-signed", ...options }, {})).toThrow()
})

test("platform enrollment accepts only HTTPS origins and bounded ceremony hints", () => {
  expect(enrollmentRequest({}, {}).platformURL).toBe("https://platform.testifysec.com")
  for (const platform of ["http://platform.testifysec.com", "https://user:password@example.test", "https://example.test/other", "https://example.test/?redirect=x", "https://example.test/#fragment"])
    expect(() => enrollmentRequest({ platform }, {})).toThrow()
  for (const options of [{ name: "\nspoof" }, { repository: "owner/repo/extra" }, { ttlSeconds: 1.5 }, { ttlSeconds: 899 }, { ttlSeconds: 604801 }, { stateDir: "" }])
    expect(() => enrollmentRequest(options, {})).toThrow()
})

test("attest requests carry a session selector rather than arbitrary evidence or signing identity", () => {
  const request = attestationRequest({ session: "ses_fixture" }, {}, "/tmp/workspace")
  expect(request).toMatchObject({ trustMode: "platform", sessionID: "ses_fixture", workspaceDirectory: "/tmp/workspace" })
  for (const name of ["payload", "credential", "privateKey", "spiffeID", "signer"]) expect(name in request).toBe(false)
  for (const session of ["../other", "/other", "", "session\0suffix", "x".repeat(129)])
    expect(() => attestationRequest({ session }, {}, "/tmp/workspace")).toThrow()
})

test("implicit Linux state discovery ignores relative and empty XDG homes", () => {
  const fallback = path.join(os.homedir(), ".local", "state", "aflock")
  for (const value of [undefined, "", ".", "./state", "../repository", "~/.local/state", " ", "C:\\state"]) {
    const directory = stateDirectory(undefined, { XDG_STATE_HOME: value }, "linux")
    expect(directory).toBe(fallback)
    expect(path.isAbsolute(directory)).toBe(true)
  }
  expect(stateDirectory(undefined, { XDG_STATE_HOME: "/operator/state" }, "linux"))
    .toBe("/operator/state/aflock")
})

test("explicit relative state options and AFLOCK_STATE_DIR retain operator precedence", () => {
  const environment = { XDG_STATE_HOME: "./repository-state", AFLOCK_STATE_DIR: "./operator-state" }
  expect(stateDirectory("./flag-state", environment, "linux")).toBe(path.resolve("./flag-state"))
  expect(enrollmentRequest({}, environment).stateDirectory).toBe(path.resolve("./operator-state"))
  expect(attestationRequest({ stateDir: "./flag-state" }, environment, ".").stateDirectory).toBe(path.resolve("./flag-state"))
})
