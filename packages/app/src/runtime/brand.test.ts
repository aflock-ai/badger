import { expect, test } from "bun:test"
import { flatten } from "@solid-primitives/i18n"
import { mkdtemp, rm } from "node:fs/promises"
import path from "node:path"

// The product name and the English copy follow the compiled product. A managed build renames the
// product, never an OpenCode service (Go, Zen, Console, Free), the upstream version a server runs,
// or Settings > About, which credits OpenCode's authors. Every changed English string is listed here.
test("the app's name and English copy follow the compiled product", async () => {
  // Inside the package, so the probe resolves workspace dependencies.
  const directory = await mkdtemp(path.join(import.meta.dir, "../../.brand-probe-"))
  try {
    const entry = path.join(directory, "entry.ts")
    await Bun.write(
      entry,
      [
        `import { flatten } from "@solid-primitives/i18n"`,
        `import { AppBrand } from ${JSON.stringify(path.resolve(import.meta.dir, "brand.ts"))}`,
        `import en from ${JSON.stringify(path.resolve(import.meta.dir, "i18n/en.ts"))}`,
        `import { dict } from "@opencode/ui/i18n/en"`,
        `const base = flatten({ ...en, ...dict })`,
        `const branded = AppBrand.withProductBrand(base)`,
        `console.log(JSON.stringify({ name: AppBrand.name, changed: Object.fromEntries(`,
        `  Object.entries(branded).filter(([key, text]) => text !== base[key])) }))`,
      ].join("\n"),
    )
    for (const enabled of [true, false]) {
      const result = await Bun.build({
        entrypoints: [entry],
        target: "bun",
        define: { HARDENED_BUILD: String(enabled), HARDENED_PRODUCT_NAME: '"Badger"' },
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
              name: "Badger",
              changed: {
                "desktop.menu.app": "Badger",
                "desktop.menu.ariaLabel": "Badger menu",
                "desktop.recovery.loadFailed": "Badger failed to load",
                "desktop.recovery.terminated": "Badger window terminated unexpectedly",
                "desktop.recovery.unresponsive": "Badger is not responding",
                "provider.connect.apiKey.description":
                  "Enter your {{provider}} API key to connect your account and use {{provider}} models in Badger.",
                "provider.connect.chatgptWelcome.description": "Eligible requests in Badger can use your ChatGPT plan.",
                "server.connect.scan.invalid":
                  "This is not a Badger pairing code. Scan the code shown by opencode pair.",
                "server.connect.link.legacy":
                  "This pairing code is from an older version of Badger. Update Badger on the server, then run opencode pair again.",
                "error.page.report.prefix": "",
                "error.page.report.discord": "",
                "settings.about.website": "",
                "error.chain.mcpFailed": 'MCP server "{{name}}" failed. Note, Badger does not support MCP authentication yet.',
                "project.settings.name.description": "The name shown for this project throughout Badger",
                "project.settings.extensions.empty.mcps.description": "MCPs available to Badger will appear here",
                "project.settings.extensions.empty.plugins.description": "Plugins available to Badger will appear here",
                "project.settings.extensions.empty.skills.description": "Skills available to Badger will appear here",
                "settings.general.row.language.description": "Change the display language for Badger",
                "settings.general.row.colorScheme.description":
                  "Choose whether Badger follows the system, light, or dark theme",
                "settings.general.row.theme.description": "Customise how Badger is themed.",
                "settings.workspaces.empty.description": "Worktrees created in Badger will appear here",
              },
            }
          : { name: "OpenCode", changed: {} },
      )
    }
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}, 60_000)

test("an upstream build's dictionary is returned untouched", async () => {
  const { AppBrand } = await import("./brand")
  const dictionary = flatten({ title: "OpenCode" })
  expect(AppBrand.withProductBrand(dictionary)).toBe(dictionary)
})

// The managed build defaults to the Badger theme, which must exist in the UI's theme set; an
// upstream build passes no default and keeps OpenCode's.
test("the default theme follows the compiled product", async () => {
  const directory = await mkdtemp(path.join(import.meta.dir, "../../.brand-probe-"))
  try {
    const entry = path.join(directory, "entry.ts")
    await Bun.write(
      entry,
      `import { AppBrand } from ${JSON.stringify(path.resolve(import.meta.dir, "brand.ts"))}\n` +
        `console.log(JSON.stringify(AppBrand.defaultTheme ?? null))\n`,
    )
    for (const enabled of [true, false]) {
      const result = await Bun.build({
        entrypoints: [entry],
        target: "bun",
        define: { HARDENED_BUILD: String(enabled), HARDENED_PRODUCT_NAME: '"Badger"' },
      })
      expect(result.success).toBe(true)
      const output = path.join(directory, `${enabled}.mjs`)
      await Bun.write(output, result.outputs[0])
      const child = Bun.spawn([process.execPath, output], { stdout: "pipe", stderr: "pipe" })
      const shown = JSON.parse(await new Response(child.stdout).text())
      expect(await child.exited).toBe(0)
      expect(shown).toBe(enabled ? "badger" : null)
    }
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
  const theme = await Bun.file(path.resolve(import.meta.dir, "../../../ui/src/theme/themes/badger.json")).json()
  expect(theme.id).toBe("badger")
  for (const mode of ["light", "dark"]) {
    for (const key of ["neutral", "ink", "primary", "success", "warning", "error", "info"]) {
      expect(theme[mode].palette[key]).toMatch(/^#[0-9a-f]{6}$/)
    }
  }
}, 60_000)
