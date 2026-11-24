import { expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { branding } from "./vite.js"

const app = readFileSync(new URL("./index.html", import.meta.url), "utf8")
const desktop = readFileSync(new URL("../desktop/src/renderer/index.html", import.meta.url), "utf8")
const logo = fileURLToPath(new URL("./src/runtime/product-logo.tsx", import.meta.url))

function plugin(hardened: boolean, base: string) {
  const value = branding(hardened)
  value.configResolved({ base })
  const emitted: Array<{ fileName: string; source: unknown }> = []
  value.generateBundle.call({ emitFile: (file: { fileName: string; source: unknown }) => emitted.push(file) })
  return {
    config: value.config(),
    html: (html: string) => value.transformIndexHtml.handler(html),
    emitted,
  }
}

// The web UI and the desktop renderer share this plugin. A managed build gets the product name, the
// product's plain monogram and no OpenCode icons; every other build is left exactly as upstream ships it.
test("an upstream build keeps OpenCode's name, logo and icons", () => {
  const upstream = plugin(false, "/")
  expect(upstream.config).toEqual({
    define: { HARDENED_BUILD: "false", HARDENED_PRODUCT_NAME: '"OpenCode"' },
  })
  expect(upstream.html(app)).toBe(app)
  expect(upstream.html(desktop)).toBe(desktop)
  expect(upstream.emitted).toEqual([])
})

test("a managed build names the product Badger and shows its own monogram", () => {
  const web = plugin(true, "/")
  expect(web.config).toEqual({
    define: { HARDENED_BUILD: "true", HARDENED_PRODUCT_NAME: '"Badger"' },
    resolve: { alias: { "@opencode/ui/logo": logo } },
  })
  expect(web.emitted.map((file) => file.fileName)).toEqual(["badger-mark.svg"])
  expect(String(web.emitted[0].source)).toBe(
    readFileSync(new URL("../../testifysec/branding/badger-mark.svg", import.meta.url), "utf8"),
  )
  const html = web.html(app)
  expect(html).toContain('<title>Badger</title>\n    <link rel="icon" type="image/svg+xml" href="/badger-mark.svg" />')
  expect(html).toContain('<meta property="og:image" content="/badger-mark.svg" />')
  expect(html).toContain('<meta property="twitter:image" content="/badger-mark.svg" />')
  expect(html).not.toMatch(/OpenCode|%OPENCODE_|apple-touch-icon|site\.webmanifest|social-share/)

  const renderer = plugin(true, "./").html(desktop)
  expect(renderer).toContain('<title>Badger</title>\n    <link rel="icon" type="image/svg+xml" href="./badger-mark.svg" />')
  expect(renderer).not.toMatch(/OpenCode|favicon-v3|apple-touch-icon|social-share/)
})
