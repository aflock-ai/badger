import { expect, test } from "bun:test"
import { mkdtemp, rm, stat } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { ConnectorMarking } from "../src/connector-marking"
const policy = () => ({ marking: "CUI", classification: "UNCLASSIFIED", allowed: ["CUI", "UNCLASSIFIED"] })

async function withStore(run: (file: string) => Promise<void>) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "connector-marking-"))
  try {
    await run(path.join(dir, "markings.json"))
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

test("connector selections persist independently and reject unsupported markings", () =>
  withStore(async (file) => {
    const store = ConnectorMarking.store(file, policy)
    expect((await store.get("gitlab")).marking).toBe("CUI")
    await Promise.all([store.set("gitlab", "UNCLASSIFIED", { mayLower: true }), store.set("other", "CUI")])
    await expect(store.set("gitlab", "SECRET", { mayLower: true })).rejects.toThrow("not enabled")
    const restored = ConnectorMarking.store(file, policy)
    expect((await restored.get("gitlab")).marking).toBe("UNCLASSIFIED")
    expect((await restored.get("other")).marking).toBe("CUI")
    expect((await stat(file)).mode & 0o777).toBe(0o600)
    expect((await store.set("gitlab", "CUI")).previous).toBe("UNCLASSIFIED")
  }))

// Lowering CUI is decontrol; only an admin may do it. Anyone may raise.
test("only an admin may set a marking below the deployment marking", () =>
  withStore(async (file) => {
    const store = ConnectorMarking.store(file, policy)
    await expect(store.set("gitlab", "UNCLASSIFIED")).rejects.toThrow("requires an admin")
    expect((await store.get("gitlab")).marking).toBe("CUI")
    expect((await store.get("gitlab")).allowed).toEqual(["CUI"])
    expect((await store.get("gitlab", { mayLower: true })).allowed).toEqual(["CUI", "UNCLASSIFIED"])
    await store.set("gitlab", "UNCLASSIFIED", { mayLower: true })
    expect((await store.set("gitlab", "CUI")).marking).toBe("CUI")
  }))

// Lowering is judged against the connector's current marking too, not only the deployment's:
// on an UNCLASSIFIED deployment that allows CUI, a connector raised to CUI stays CUI for users.
test("a connector raised above the deployment marking can only be lowered by an admin", () =>
  withStore(async (file) => {
    const unclassified = () => ({
      marking: "UNCLASSIFIED",
      classification: "UNCLASSIFIED",
      allowed: ["UNCLASSIFIED", "CUI"],
    })
    const store = ConnectorMarking.store(file, unclassified)
    expect((await store.get("gitlab")).allowed).toEqual(["UNCLASSIFIED", "CUI"])
    await store.set("gitlab", "CUI")
    expect((await store.get("gitlab")).allowed).toEqual(["CUI"])
    await expect(store.set("gitlab", "UNCLASSIFIED")).rejects.toThrow("requires an admin")
    expect((await store.get("gitlab")).marking).toBe("CUI")
    expect((await store.set("gitlab", "UNCLASSIFIED", { mayLower: true })).marking).toBe("UNCLASSIFIED")
  }))

// Two Badger processes can share the state file. Each decision must use the file as it is now,
// or a stale process lets a non-admin undo another process's raise.
test("a second process sees a raise made by the first and cannot undo it without an admin", () =>
  withStore(async (file) => {
    const unclassified = () => ({
      marking: "UNCLASSIFIED",
      classification: "UNCLASSIFIED",
      allowed: ["UNCLASSIFIED", "CUI"],
    })
    const first = ConnectorMarking.store(file, unclassified)
    const second = ConnectorMarking.store(file, unclassified)
    expect((await second.get("gitlab")).marking).toBe("UNCLASSIFIED")
    await first.set("gitlab", "CUI")
    expect((await second.get("gitlab")).marking).toBe("CUI")
    await expect(second.set("gitlab", "UNCLASSIFIED")).rejects.toThrow("requires an admin")
    expect((await first.get("gitlab")).marking).toBe("CUI")
  }))

test("concurrent writes from two processes are serialized and none is lost", () =>
  withStore(async (file) => {
    const policy = () => ({ marking: "CUI", classification: "UNCLASSIFIED", allowed: ["CUI"] })
    const [a, b] = [ConnectorMarking.store(file, policy), ConnectorMarking.store(file, policy)]
    await Promise.all(Array.from({ length: 10 }, (_, i) => (i % 2 ? a : b).set(`c${i}`, "CUI")))
    const fresh = ConnectorMarking.store(file, policy)
    for (let i = 0; i < 10; i++) expect((await fresh.get(`c${i}`)).marking).toBe("CUI")
    expect(JSON.parse(await Bun.file(file).text())).toEqual(
      Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`c${i}`, "CUI"])),
    )
  }))

// Writers in other processes run this script. "hold" takes the lock and never lets go: its
// policy is read under the lock, so it announces itself there and spins until it is killed.
const writer = (dir: string) =>
  Bun.write(
    path.join(dir, "writer.ts"),
    `import { writeSync } from "node:fs"
import { ConnectorMarking } from ${JSON.stringify(path.join(import.meta.dir, "../src/connector-marking"))}
const [file, mode, from, count] = process.argv.slice(2)
if (mode === "hold")
  await ConnectorMarking.store(file, () => {
    writeSync(1, "holding\\n")
    for (;;);
  }).set("held", "CUI")
const policy = () => ({ marking: "CUI", classification: "UNCLASSIFIED", allowed: ["CUI"] })
await Promise.all(
  Array.from({ length: Number(count) }, (_, i) => ConnectorMarking.store(file, policy).set("c" + (Number(from) + i), "CUI")),
)
`,
  )

async function holder(file: string) {
  const child = Bun.spawn([process.execPath, path.join(path.dirname(file), "writer.ts"), file, "hold"], {
    stdout: "pipe",
  })
  const reader = child.stdout.getReader()
  let seen = ""
  while (!seen.includes("holding")) {
    const chunk = await reader.read()
    if (chunk.done) throw new Error("holder exited before taking the lock")
    seen += new TextDecoder().decode(chunk.value)
  }
  return child
}

// The lock belongs to a live process however long it holds it, and is released the moment that
// process dies, however it dies: a paused writer is never interleaved, a killed one never wedges.
test("a live writer's lock is waited for; a killed writer's lock is released", () =>
  withStore(async (file) => {
    const policy = () => ({ marking: "CUI", classification: "UNCLASSIFIED", allowed: ["CUI"] })
    await writer(path.dirname(file))
    const child = await holder(file)
    let done = false
    const pending = ConnectorMarking.store(file, policy)
      .set("gitlab", "CUI")
      .then(() => (done = true))
    await new Promise((resolve) => setTimeout(resolve, 300))
    expect(done).toBe(false)
    child.kill("SIGKILL")
    await child.exited
    await pending
    expect(done).toBe(true)
  }))

// A writer can crash after the lock exists but before it records anything in it.
test("a lock left empty by a crash does not block writers", () =>
  withStore(async (file) => {
    const policy = () => ({ marking: "CUI", classification: "UNCLASSIFIED", allowed: ["CUI"] })
    await Bun.write(file + ".lock", "")
    expect((await ConnectorMarking.store(file, policy).set("gitlab", "CUI")).marking).toBe("CUI")
  }))

// Recovering from a dead writer must not let two live writers in at once: several processes
// contend right after one is killed holding the lock, and every write lands.
test(
  "writers from several processes contending after a crash lose nothing",
  () =>
    withStore(async (file) => {
      await writer(path.dirname(file))
      const child = await holder(file)
      const writers = [0, 10, 20, 30].map((from) =>
        Bun.spawn([process.execPath, path.join(path.dirname(file), "writer.ts"), file, "write", String(from), "10"]),
      )
      child.kill("SIGKILL")
      expect(await Promise.all(writers.map((w) => w.exited))).toEqual([0, 0, 0, 0])
      const stored = JSON.parse(await Bun.file(file).text())
      expect(Object.keys(stored).sort()).toEqual(Array.from({ length: 40 }, (_, i) => `c${i}`).sort())
    }),
  20_000,
)

// A stored entry that is not a known marking fails closed: it reads as the most restrictive
// marking, so a corrupted raise cannot turn into UNCLASSIFIED without an admin.
test("an invalid stored marking reads as the most restrictive one", () =>
  withStore(async (file) => {
    const unclassified = () => ({
      marking: "UNCLASSIFIED",
      classification: "UNCLASSIFIED",
      allowed: ["UNCLASSIFIED", "CUI"],
    })
    for (const bad of [5, "SECRET", null]) {
      await Bun.write(file, JSON.stringify({ gitlab: bad }))
      const store = ConnectorMarking.store(file, unclassified)
      expect((await store.get("gitlab")).marking).toBe("CUI")
      await expect(store.set("gitlab", "UNCLASSIFIED")).rejects.toThrow("requires an admin")
    }
    expect(
      (await ConnectorMarking.store(file, unclassified).set("gitlab", "UNCLASSIFIED", { mayLower: true })).marking,
    ).toBe("UNCLASSIFIED")
  }))

// A deployment on another scheme keeps its selections pinned to that scheme; a file written under
// one scheme is never read under another, since its markings have no place there.
test("connector selections are pinned to the deployment's marking scheme", () =>
  withStore(async (file) => {
    const { preset } = await import("@testifysec/marking")
    const { readFile, writeFile } = await import("node:fs/promises")
    const corporate = preset("corporate")
    const corporatePolicy = () => ({ marking: "INTERNAL", classification: "INTERNAL", allowed: ["INTERNAL", "CONFIDENTIAL"] })
    const store = ConnectorMarking.store(file, corporatePolicy, () => corporate)
    await store.set("gitlab", "CONFIDENTIAL")
    expect(JSON.parse(await readFile(file, "utf8"))).toEqual({
      "connector-markings": 2,
      scheme: corporate.digest,
      markings: { gitlab: "CONFIDENTIAL" },
    })
    expect((await store.get("gitlab")).marking).toBe("CONFIDENTIAL")
    // An entry that is not an allowed marking reads as the scheme's most restrictive marking.
    const controlled = preset("us-gov").levels[1].name
    await writeFile(file, JSON.stringify({ "connector-markings": 2, scheme: corporate.digest, markings: { gitlab: controlled } }))
    expect((await store.get("gitlab")).marking).toBe("RESTRICTED")
    // us-gov selections (the plain map) are refused under corporate, and corporate ones under us-gov.
    await writeFile(file, JSON.stringify({ gitlab: controlled }))
    await expect(store.get("gitlab")).rejects.toThrow("another marking scheme")
    await writeFile(file, JSON.stringify({ "connector-markings": 2, scheme: corporate.digest, markings: {} }))
    await expect(ConnectorMarking.store(file, policy).get("gitlab")).rejects.toThrow("another marking scheme")
    await writeFile(file, JSON.stringify({ "connector-markings": 3, scheme: corporate.digest, markings: {} }))
    await expect(store.get("gitlab")).rejects.toThrow("Invalid connector marking state")
    // A malformed envelope is refused, never read as the plain map: under us-gov that would drop the
    // other scheme's pin and its selections and fall back to the deployment default.
    const usGov = ConnectorMarking.store(file, policy)
    for (const bad of [
      { "connector-markings": "2", scheme: corporate.digest, markings: { gitlab: "CONFIDENTIAL" } },
      { "connector-markings": 2, scheme: corporate.digest },
      { "connector-markings": 2, markings: {} },
      { "connector-markings": null, gitlab: "INTERNAL" },
    ]) {
      await writeFile(file, JSON.stringify(bad))
      await expect(usGov.get("gitlab")).rejects.toThrow("Invalid connector marking state")
    }
  }))

test("a us-gov deployment keeps writing the plain map every existing deployment has", () =>
  withStore(async (file) => {
    const { readFile } = await import("node:fs/promises")
    const { preset } = await import("@testifysec/marking")
    const controlled = preset("us-gov").levels[1].name
    await ConnectorMarking.store(file, policy).set("gitlab", controlled)
    expect(await readFile(file, "utf8")).toBe(JSON.stringify({ gitlab: controlled }))
  }))

// The classification reported with a connector's marking is that marking's, not the deployment
// default's: under corporate each level is its own classification.
test("a connector's classification follows its own marking", () =>
  withStore(async (file) => {
    const { preset } = await import("@testifysec/marking")
    const { writeFile } = await import("node:fs/promises")
    const corporate = preset("corporate")
    const corporatePolicy = () => ({ marking: "INTERNAL", classification: "INTERNAL", allowed: ["INTERNAL", "CONFIDENTIAL"] })
    const store = ConnectorMarking.store(file, corporatePolicy, () => corporate)
    expect(await store.get("gitlab")).toMatchObject({ marking: "INTERNAL", classification: "INTERNAL" })
    expect(await store.set("gitlab", "CONFIDENTIAL")).toMatchObject({ marking: "CONFIDENTIAL", classification: "CONFIDENTIAL" })
    await writeFile(file, JSON.stringify({ "connector-markings": 2, scheme: corporate.digest, markings: { gitlab: "OTHER" } }))
    expect(await store.get("gitlab")).toMatchObject({ marking: "RESTRICTED", classification: "RESTRICTED" })
  }))

// The file's envelope key is not a connector name: a selection under it would turn the plain map
// into something every later read refuses.
test("the envelope's key is refused as a connector name", () =>
  withStore(async (file) => {
    const store = ConnectorMarking.store(file, policy)
    await expect(store.set("connector-markings", policy().marking)).rejects.toThrow("reserved")
    await store.set("gitlab", policy().marking)
    expect((await store.get("gitlab")).marking).toBe(policy().marking)
  }))

