import { expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"

// A managed build keeps a crash report inside the organization: the copied report is plain text
// for the administrator, never a link that would post the stack trace to the upstream tracker.
test("the copied crash report is an upstream issue link only in an upstream build", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "badger-crash-report-"))
  try {
    const entry = path.join(directory, "entry.ts")
    await Bun.write(
      entry,
      [
        `import { CrashReport } from ${JSON.stringify(path.resolve(import.meta.dir, "../src/util/crash-report.ts"))}`,
        `console.log(JSON.stringify(CrashReport.make({ message: "boom", stack: "at secret/path.ts:1", version: "2.0.32" })))`,
      ].join("\n"),
    )
    for (const enabled of [true, false]) {
      const result = await Bun.build({
        entrypoints: [entry],
        target: "bun",
        define: { HARDENED_BUILD: String(enabled), HARDENED_PREVIEW: "false", HARDENED_VERSION: '"9.8.7"' },
      })
      expect(result.success).toBe(true)
      const output = path.join(directory, `${enabled}.mjs`)
      await Bun.write(output, result.outputs[0])
      const child = Bun.spawn([process.execPath, output], { stdout: "pipe", stderr: "pipe" })
      const report = JSON.parse(await new Response(child.stdout).text())
      expect(await child.exited).toBe(0)
      if (enabled) {
        expect(report.text).not.toContain("github.com")
        expect(report.text).toContain("boom")
        expect(report.text).toContain("at secret/path.ts:1")
        expect(report.text).toContain("Badger 9.8.7 crashed")
        expect(report.hint).toContain("administrator")
      } else {
        expect(report.text.startsWith("https://github.com/anomalyco/opencode/issues/new")).toBe(true)
        expect(report.hint).toContain("GitHub issue")
      }
    }
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}, 60_000)
