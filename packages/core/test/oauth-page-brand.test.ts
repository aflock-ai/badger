import { expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"

// The OAuth callback page a browser shows after a provider sign-in names the compiled product:
// Badger with its plain monogram in a managed build, OpenCode's page otherwise. A managed page names no
// vendor and links nowhere.
test("the OAuth callback page follows the compiled product", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "badger-oauth-brand-"))
  try {
    const entry = path.join(directory, "entry.ts")
    await Bun.write(
      entry,
      [
        `import { OauthCallbackPage } from ${JSON.stringify(path.resolve(import.meta.dir, "../src/oauth/page.ts"))}`,
        `console.log(JSON.stringify({`,
        `  success: OauthCallbackPage.success({ provider: "xAI" }),`,
        `  plain: OauthCallbackPage.success(),`,
        `  error: OauthCallbackPage.error("denied", { provider: "xAI" }),`,
        `  bootstrap: OauthCallbackPage.bootstrap({ provider: "xAI", tokenPath: "/token" }),`,
        `}))`,
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
      const page = JSON.parse(await new Response(child.stdout).text())
      expect(await child.exited).toBe(0)
      const name = enabled ? "Badger" : "OpenCode"
      expect(page.success).toContain(`${name} is now connected to xAI.`)
      expect(page.plain).toContain(`${name} is now authorized.`)
      expect(page.error).toContain(`${name} couldn't finish connecting to xAI.`)
      expect(page.error).toContain(`Close this window and try again from ${name}.`)
      expect(page.success).toContain(`<title>Authorization successful · ${name}</title>`)
      expect(page.bootstrap).toContain(`var APP_NAME="${name}";`)
      if (enabled) {
        for (const html of [page.success, page.error, page.bootstrap]) {
          expect(html).toContain('class="product-brand"')
          expect(html).not.toMatch(/testifysec|discord/i)
          expect(html.match(/https?:\/\/[^\s"'<>]+/g)?.filter((url: string) => !url.startsWith("http://www.w3.org/")) ?? []).toEqual([])
          expect(html).not.toContain('aria-label="OpenCode"')
          expect(html).not.toContain("OpenCode is now")
        }
      } else {
        expect(page.success).toContain('aria-label="OpenCode"')
        expect(page.success).not.toContain(`class="product-brand"`)
      }
    }
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}, 60_000)
