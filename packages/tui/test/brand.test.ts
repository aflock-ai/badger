import { expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"

// The product name is a compile-time choice: a managed build defines HARDENED_BUILD and every
// piece of TUI chrome follows it, while an upstream build keeps OpenCode's text exactly.
test("TUI chrome follows the compiled product name", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "badger-tui-brand-"))
  try {
    const entry = path.join(directory, "entry.ts")
    await Bun.write(
      entry,
      [
        `import { Brand } from ${JSON.stringify(path.resolve(import.meta.dir, "../src/brand.ts"))}`,
        `import { sessionEpilogue } from ${JSON.stringify(path.resolve(import.meta.dir, "../src/util/presentation.ts"))}`,
        `console.log(JSON.stringify({ title: Brand.title("Plan"), idle: Brand.title(), name: Brand.name, version: Brand.displayVersion("2.0.32"),`,
        `  epilogue: sessionEpilogue({ title: "Plan", sessionID: "ses_brand" }) }))`,
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
      const shown = JSON.parse(await new Response(child.stdout).text())
      expect(await child.exited).toBe(0)
      if (enabled) {
        expect(shown.name).toBe("Badger")
        expect(shown.version).toBe("9.8.7")
        expect(shown.idle).toBe("Badger")
        expect(shown.title).toBe("Badger | Plan")
        expect(shown.epilogue).toContain("Badger")
        expect(shown.epilogue).toContain(process.execPath)
        expect(shown.epilogue).not.toContain("opencode -s")
      } else {
        expect(shown.name).toBe("OpenCode")
        expect(shown.version).toBe("2.0.32")
        expect(shown.idle).toBe("OpenCode")
        expect(shown.title).toBe("OC | Plan")
        expect(shown.epilogue).toContain("opencode -s ses_brand")
      }
    }
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}, 60_000)
