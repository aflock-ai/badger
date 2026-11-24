import { expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"

// The command's name, description and --version follow the compiled product; the upstream
// version stays visible in a managed build so a report can be traced to the OpenCode release, and
// `about` carries the upstream license in every build.
test("the CLI's name, description, version and about follow the compiled product", async () => {
  const license = await Bun.file(path.resolve(import.meta.dir, "../../../LICENSE")).text()
  expect(license).toStartWith("MIT License")
  const directory = await mkdtemp(path.join(tmpdir(), "badger-cli-brand-"))
  try {
    const entry = path.join(directory, "entry.ts")
    await Bun.write(
      entry,
      [
        `import { CliBrand } from ${JSON.stringify(path.resolve(import.meta.dir, "../src/brand.ts"))}`,
        `console.log(JSON.stringify({ name: CliBrand.name, description: CliBrand.description,`,
        `  directory: CliBrand.directory, version: CliBrand.version("2.0.32"),`,
        `  aboutDescription: CliBrand.aboutDescription, about: CliBrand.about("2.0.32") }))`,
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
      expect(shown).toEqual(
        enabled
          ? {
              name: "badger",
              description: "Badger command line interface",
              directory: "Directory to start Badger in",
              version: "9.8.7 (OpenCode 2.0.32)",
              aboutDescription: "about Badger and upstream licenses",
              about:
                "Badger 9.8.7\nOpenCode 2.0.32\nBuilt on OpenCode. Upstream licenses and attribution are preserved.\n\n" +
                license,
            }
          : {
              name: "opencode",
              description: "OpenCode command line interface",
              directory: "Directory to start OpenCode in",
              version: "2.0.32",
              aboutDescription: "about OpenCode and upstream licenses",
              about: "2.0.32\n\n" + license,
            },
      )
    }
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}, 60_000)
