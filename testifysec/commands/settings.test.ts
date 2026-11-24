// jade:ring local
import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { attestationRequest, enrollmentRequest } from "./request"
import { loadSettings, parseSettings, settingsFile } from "./settings"

const settings = parseSettings(JSON.stringify({ schema: "testifysec.aflock.settings/v1", trustMode: "platform",
  platformURL: "https://platform.example.test", stateDirectory: "/private/tmp/aflock-test-state",
  enrollment: { name: "workstation", repository: "testifysec/example", ttlSeconds: 3600 } }))

test("Badger errors preserve the existing settings schema and storage paths", () => {
  expect(() => parseSettings('{"schema":"unknown"}')).toThrow("Unsupported Badger settings schema")
  expect(() => parseSettings('{"schema":"testifysec.aflock.settings/v1","stateDirectory":"relative"}'))
    .toThrow("Badger stateDirectory must be absolute")
  expect(settingsFile({ XDG_CONFIG_HOME: "/operator/config" }, "linux")).toBe("/operator/config/aflock/settings.json")
})

test("enrollment and attestation resolve the same operator settings without taking model claims", () => {
  const enroll = enrollmentRequest({}, {}, settings)
  const attest = attestationRequest({}, {}, "/private/tmp/workspace", settings)
  expect(enroll).toMatchObject({ trustMode: "platform", platformURL: "https://platform.example.test",
    stateDirectory: "/private/tmp/aflock-test-state", name: "workstation", repository: "testifysec/example", ttlSeconds: 3600 })
  for (const key of ["trustMode", "platformURL", "stateDirectory"] as const) expect(attest[key]).toBe(enroll[key])
  for (const key of ["agentID", "tenantID", "spiffeID", "assurance", "evidence", "signer", "payload", "repository", "name"])
    expect(key in attest).toBe(false)
})

test("flags override environment, environment overrides settings, settings override defaults", () => {
  const environment = { AFLOCK_PLATFORM_URL: "https://environment.example.test", AFLOCK_STATE_DIR: "/private/tmp/aflock-env" }
  expect(enrollmentRequest({}, environment, settings)).toMatchObject({ platformURL: environment.AFLOCK_PLATFORM_URL, stateDirectory: environment.AFLOCK_STATE_DIR })
  expect(enrollmentRequest({ platform: "https://flag.example.test", stateDir: "/private/tmp/aflock-flag", name: "explicit" }, environment, settings))
    .toMatchObject({ platformURL: "https://flag.example.test", stateDirectory: "/private/tmp/aflock-flag", name: "explicit" })
  expect(attestationRequest({}, { AFLOCK_TRUST_MODE: "local-self-signed" }, "/private/tmp/workspace", settings).trustMode).toBe("local-self-signed")
  expect(attestationRequest({ trustMode: "platform" }, { AFLOCK_TRUST_MODE: "local-self-signed" }, "/private/tmp/workspace", settings).trustMode).toBe("platform")
})

test("explicit local mode drops platform defaults and never forwards platform enrollment hints", () => {
  const local = enrollmentRequest({ trustMode: "local-self-signed" }, {}, settings)
  expect(local.trustMode).toBe("local-self-signed")
  for (const key of ["platformURL", "name", "repository", "ttlSeconds"]) expect(key in local).toBe(false)
  expect(() => enrollmentRequest({ trustMode: "local-self-signed" }, { AFLOCK_PLATFORM_URL: "https://example.test" }, settings)).toThrow()
  expect(() => enrollmentRequest({}, { AFLOCK_TRUST_MODE: "invalid" }, settings)).toThrow()
  expect(() => enrollmentRequest({}, { AFLOCK_PLATFORM_URL: "" }, settings)).toThrow()
})

test("settings reject injected identity, permissive mode aliases, duplicate keys and invalid values", () => {
  const base = { schema: "testifysec.aflock.settings/v1" }
  for (const fields of [{ agentID: "claimed" }, { signer: "claimed" }, { trustMode: "INSECURE_SELFSIGNED" },
    { trustMode: true }, { stateDirectory: "./relative" }, { platformURL: "http://example.test" },
    { platformURL: "https://user:password@example.test" }, { platformURL: "https://example.test/redirect" },
    { enrollment: { name: "\nspoof" } }, { enrollment: { repository: "a/b/c" } },
    { enrollment: { ttlSeconds: 604801 } }, { enrollment: { ttlSeconds: "3600" } }, { enrollment: { tenantID: "claimed" } }])
    expect(() => parseSettings(JSON.stringify({ ...base, ...fields }))).toThrow()
  expect(() => parseSettings('{"schema":"testifysec.aflock.settings/v1","trustMode":"platform","trustMode":"local-self-signed"}')).toThrow()
  for (const text of ["{}", "[]", "null", "", '{"schema":"unknown"}']) expect(() => parseSettings(text)).toThrow()
})

test("file loader bounds and validates a private file without following links", async () => {
  const directory = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "aflock-settings-")))
  const file = path.join(directory, "settings.json")
  try {
    await fs.writeFile(file, JSON.stringify({ schema: "testifysec.aflock.settings/v1", trustMode: "local-self-signed" }), { mode: 0o600 })
    expect((await loadSettings(file, {})).trustMode).toBe("local-self-signed")
    await fs.symlink(file, path.join(directory, "link.json"))
    await expect(loadSettings(path.join(directory, "link.json"), {})).rejects.toThrow()
    const real = path.join(directory, "real")
    await fs.mkdir(real, { mode: 0o700 })
    await fs.writeFile(path.join(real, "settings.json"), JSON.stringify({ schema: "testifysec.aflock.settings/v1", trustMode: "local-self-signed" }), { mode: 0o600 })
    await fs.symlink(real, path.join(directory, "ancestor-link"))
    await expect(loadSettings(path.join(directory, "ancestor-link", "settings.json"), {})).rejects.toThrow()
    await fs.link(file, path.join(directory, "hardlink.json"))
    await expect(loadSettings(file, {})).rejects.toThrow()
    await fs.unlink(path.join(directory, "hardlink.json"))
    if (process.platform !== "win32") {
      await fs.chmod(real, 0o777)
      await expect(loadSettings(path.join(real, "settings.json"), {})).rejects.toThrow()
      await fs.chmod(real, 0o700)
      await fs.chmod(file, 0o644)
      await expect(loadSettings(file, {})).rejects.toThrow()
      await fs.chmod(file, 0o600)
    }
    await fs.writeFile(file, " ".repeat(16385))
    await expect(loadSettings(file, {})).rejects.toThrow()
    await fs.writeFile(file, Buffer.from([0xff, 0xfe]))
    await expect(loadSettings(file, {})).rejects.toThrow()
    await expect(loadSettings(directory, {})).rejects.toThrow()
    await expect(loadSettings(path.join(directory, "missing.json"), {})).rejects.toThrow()
  } finally { await fs.rm(directory, { recursive: true, force: true }) }
})

test("upstream repository and inline config variables cannot select Aflock authority", () => {
  const environment = { OPENCODE_CONFIG: "/repository/opencode.json", OPENCODE_CONFIG_CONTENT: JSON.stringify({ trustMode: "local-self-signed", platformURL: "https://attacker.example.test" }) }
  expect(enrollmentRequest({}, environment).trustMode).toBe("platform")
  expect(enrollmentRequest({}, environment).platformURL).toBe("https://platform.testifysec.com")
  expect(settingsFile(environment)).not.toContain("repository")
})

test("implicit Linux settings discovery ignores relative and empty XDG homes", () => {
  const fallback = path.join(os.homedir(), ".config", "aflock", "settings.json")
  for (const value of [undefined, "", ".", "./config", "../repository", "~/.config", " ", "C:\\config"]) {
    const file = settingsFile({ XDG_CONFIG_HOME: value }, "linux")
    expect(file).toBe(fallback)
    expect(path.isAbsolute(file)).toBe(true)
  }
  expect(settingsFile({ XDG_CONFIG_HOME: "/operator/config" }, "linux"))
    .toBe("/operator/config/aflock/settings.json")
})

test("an explicit relative settings file remains an operator selection", async () => {
  const directory = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "aflock-settings-explicit-")))
  const file = path.join(directory, "settings.json")
  try {
    await fs.writeFile(file, JSON.stringify({ schema: "testifysec.aflock.settings/v1", trustMode: "local-self-signed" }), { mode: 0o600 })
    const option = path.relative(process.cwd(), file)
    expect(path.isAbsolute(option)).toBe(false)
    expect((await loadSettings(option, { XDG_CONFIG_HOME: "./repository-config" })).trustMode).toBe("local-self-signed")
  } finally { await fs.rm(directory, { recursive: true, force: true }) }
})
