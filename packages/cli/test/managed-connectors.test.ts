import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { afterEach, beforeEach, expect, test } from "bun:test"
import { Effect, Exit } from "effect"
import { Global } from "@opencode/util/global"
import { ManagedConnectorProfile } from "../src/managed-connectors"

const sha = (bytes: string | Uint8Array) => createHash("sha256").update(bytes).digest("hex")

let root: string
let where: ManagedConnectorProfile.Paths
const envelope = JSON.stringify({ payloadType: "application/vnd.testifysec.hardened-opencode.profile.v3+json", payload: "", signatures: [] })
const binary = "jira binary"
const connector = {
  name: "jira",
  binarySha256: sha(binary),
  baseUrl: "https://jira.example.invalid",
  tokenPath: "/run/badger/tokens/jira.token",
  caPath: null,
  writes: false,
  classification: "SECRET",
  flags: {},
  permissions: { "jira_*": "allow" },
}
const admission = (change: Record<string, unknown> = {}) => ({
  schemaVersion: 3,
  admitted: true,
  scope: "profile-admission-only",
  envelopeSha256: sha(envelope),
  profile: { profileId: "p", expiresAt: "2099-01-01T00:00:00Z", gateway: { classification: "SECRET" }, connectors: [connector] },
  ...change,
})

// A stand-in verifier: it reads the envelope, notes where it ran from, and prints a fixed admission or fails.
async function verifier(output: unknown, exit = 0) {
  const ran = path.join(root, "ran-from")
  const script = `#!/bin/sh\ncat > /dev/null\nprintf '%s' "$0" > '${ran}'\nprintf '%s' '${JSON.stringify(output)}'\nexit ${exit}\n`
  await fs.writeFile(where.admission, script, { mode: 0o755 })
  return sha(script)
}

beforeEach(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), "badger-admission-test-"))
  where = { admission: path.join(root, "hardened-admission"), envelope: path.join(root, "profile.dsse.json"), release: path.join(root, "connectors"), state: path.join(root, "state") }
  await fs.mkdir(where.release)
  await fs.writeFile(path.join(where.release, "jira"), binary)
  await fs.writeFile(where.envelope, envelope)
})
afterEach(() => fs.rm(root, { recursive: true, force: true }))

const run = (pinned: string) => Effect.runPromiseExit(ManagedConnectorProfile.load(pinned, where))
const refusal = async (pinned: string) => {
  const exit = await run(pinned)
  if (Exit.isSuccess(exit)) throw new Error("admitted")
  return String(exit.cause)
}

test("a build that pins no verifier admits no connectors", async () => {
  expect(await run("")).toEqual(Exit.succeed(undefined))
})

test("admits and stages the connectors the verifier admitted", async () => {
  const exit = await run(await verifier(admission()))
  if (!Exit.isSuccess(exit)) throw new Error(String(exit.cause))
  expect(exit.value?.gateway).toEqual({ classification: "SECRET" })
  expect(exit.value?.expires.toISOString()).toBe("2099-01-01T00:00:00.000Z")
  expect(exit.value?.connectors.map((entry) => entry.name)).toEqual(["jira"])
  expect(await fs.readFile(exit.value!.connectors[0]!.executable, "utf8")).toBe(binary)
})

test("runs the checked bytes from a private copy, not the installed file, and removes the copy", async () => {
  const pinned = await verifier(admission())
  // Whatever replaces the installed verifier after the check is never run.
  const exit = await run(pinned)
  expect(Exit.isSuccess(exit)).toBe(true)
  const ranFrom = await fs.readFile(path.join(root, "ran-from"), "utf8")
  expect(ranFrom).not.toBe(where.admission)
  // Under the state directory, never the system temp directory.
  expect(path.dirname(path.dirname(ranFrom))).toBe(where.state)
  expect(path.basename(ranFrom)).toBe("hardened-admission")
  expect(await fs.access(path.dirname(ranFrom)).then(() => true, () => false)).toBe(false)
})

test("refuses a verifier that does not match the build", async () => {
  await verifier(admission())
  expect(await refusal("0".repeat(64))).toContain("the profile verifier does not match this build")
})

test("refuses to start without a signed profile", async () => {
  const pinned = await verifier(admission())
  await fs.rm(where.envelope)
  expect(await refusal(pinned)).toContain("there is no signed profile")
})

test("refuses a profile the verifier rejects", async () => {
  expect(await refusal(await verifier({ schemaVersion: 3, admitted: false, reason: "profile-signature-invalid" }, 1))).toContain(
    "the signed profile was not admitted",
  )
})

test("refuses an admission that is not v3, not admitted, or bound to another envelope", async () => {
  for (const change of [
    { schemaVersion: 1 },
    { admitted: false },
    { scope: "other" },
    { envelopeSha256: sha("another envelope") },
    { profile: { expiresAt: "2099-01-01T00:00:00Z", gateway: { classification: "SECRET" }, connectors: [{ ...connector, name: "a_b", permissions: {} }] } },
    { profile: { gateway: { classification: "SECRETISH" }, connectors: [] } },
    { profile: { gateway: { classification: "SECRET" }, connectors: [connector] } }, // no expiry
  ])
    expect(await refusal(await verifier(admission(change)))).toContain("returned an admission this build cannot use")
})

test("refuses a connector marked above the gateway's accreditation", async () => {
  const higher = { ...connector, classification: "TOP SECRET" }
  const pinned = await verifier(admission({ profile: { expiresAt: "2099-01-01T00:00:00Z", gateway: { classification: "SECRET" }, connectors: [higher] } }))
  expect(await refusal(pinned)).toContain("connector jira is marked above the model gateway's accreditation")
})

test("admits connectors at different markings: the high-water check keeps content from flowing down", async () => {
  const lower = { ...connector, name: "confluence", classification: "UNCLASSIFIED", writes: true, permissions: {} }
  const pinned = await verifier(
    admission({ profile: { expiresAt: "2099-01-01T00:00:00Z", gateway: { classification: "SECRET" }, connectors: [connector, lower] } }),
  )
  // Past admission: refused only for the missing confluence binary.
  expect(await refusal(pinned)).toContain("connector confluence")
  expect(await refusal(pinned)).not.toContain("is marked below")
})

test("a verifier that exits before reading the envelope is a refusal, not a crash", async () => {
  // A large envelope makes the write outlive the verifier, so the pipe closes under it (EPIPE).
  await fs.writeFile(where.envelope, JSON.stringify({ payloadType: "x", payload: "a".repeat(60_000), signatures: [] }))
  const script = "#!/bin/sh\nexit 1\n"
  await fs.writeFile(where.admission, script, { mode: 0o755 })
  for (let i = 0; i < 5; i++) expect(await refusal(sha(script))).toContain("not admitted")
})

// The managed server's plugin list (ServerConnection.resolve passes exactly this): with admitted
// connectors it carries the flow plugin, and that plugin enforces the high-water check.
test("the managed server's plugins carry the connector flow plugin whenever connectors are admitted", () => {
  const extra = { id: "caller", effect: () => Effect.void }
  expect(ManagedConnectorProfile.plugins(undefined, undefined, [extra]).map((p) => p.id)).toEqual(["caller"])
  const admitted = {
    expires: new Date("2099-01-01T00:00:00Z"),
    gateway: { classification: "SECRET" },
    connectors: [
      { name: "confluence", classification: "SECRET" },
      { name: "jira", classification: "CONFIDENTIAL" },
    ],
  } as unknown as ManagedConnectorProfile.Admitted
  const flow = ManagedConnectorProfile.flow(admitted)
  const list = ManagedConnectorProfile.plugins(admitted, flow, [extra])
  expect(list.map((p) => p.id)).toEqual(["caller", "badger.connectors.flow"])
  // Its hooks, registered through a stand-in context, refuse a lower connector after a higher one.
  const registered: Record<string, (event: any) => Effect.Effect<unknown>> = {}
  const hook = (domain: string) => (name: string, fn: (event: any) => Effect.Effect<unknown>) =>
    Effect.sync(() => void (registered[`${domain}.${name}`] = fn))
  Effect.runSync(list[1]!.effect({ tool: { hook: hook("tool") }, permission: { hook: hook("permission") } } as any) as any)
  const evaluate = (action: string) => {
    const event = { sessionID: "ses_a", action, resources: ["*"], effect: "allow", message: undefined as string | undefined }
    Effect.runSync(registered["permission.evaluate"]!(event))
    return event.effect
  }
  expect(evaluate("confluence_confluence_get_page")).toBe("allow")
  expect(evaluate("jira_jira_search")).toBe("deny")
})

test("refuses every connector when a binary does not match its pin", async () => {
  await fs.writeFile(path.join(where.release, "jira"), "jira binary, replaced")
  expect(await refusal(await verifier(admission()))).toContain("connector jira does not match the digest the profile pins")
})

test("an unconfigured build reads from the broker's mounts and copies into the state directory", () => {
  expect(ManagedConnectorProfile.paths.admission).toBe("/toolpack/badger/admission/hardened-admission")
  expect(ManagedConnectorProfile.paths.release).toBe("/toolpack/badger/connectors")
  expect(ManagedConnectorProfile.paths.envelope).toBe("/run/badger/profile/profile.dsse.json")
  // Under Badger's own state directory, never the system temp directory itself.
  expect(ManagedConnectorProfile.paths.state).toBe(path.join(Global.Path.state, "managed"))
  expect(path.resolve(ManagedConnectorProfile.paths.state)).not.toBe(path.resolve(os.tmpdir()))
})
