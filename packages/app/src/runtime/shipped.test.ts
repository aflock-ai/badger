import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises"
import path from "node:path"
import vm from "node:vm"
import { DESKTOP_NATIVE_LOCALES } from "./i18n/desktop-native"

// The managed web UI ships into networks that reach nothing outside the deployment, and carries no vendor mark.
// These tests build it exactly as the CLI's --managed build does (packages/cli/script/app-assets.ts) and read what
// ships: every http(s) address must be on the list below with its reason, and no user-visible string may name
// TestifySec or Discord.

const app = path.resolve(import.meta.dir, "../..")
const repo = path.resolve(app, "../..")
const vendor = /testifysec|discord/i

// Binary assets (fonts, wasm, images) carry their own embedded license metadata; the browser never shows or follows it.
const binary = /\.(?:ttf|otf|woff2?|wasm|png|ico|jpe?g|gif|webp|avif|mp3|wav|ogg|mp4|webm|bin)$/i

// An address names a host with a dot in it (or this machine). Template fragments such as `http://${host}` take their
// host from the deployment at run time, and "https://action/" is a parse base, not a host.
const words = (text: string) =>
  (text.match(/https?:\/\/[^\s"'`<>()\\{}|^[\]]+/g) ?? []).filter((url) =>
    /^https?:\/\/(?:localhost|[^/$]*\.[^/$]*)(?:[/:?#]|$)/.test(url),
  )
const trim = (url: string) => url.replace(/[.,;:]+$/, "")

/** Every address the managed web UI may contain, with why. Nothing here is a link a person can follow or a request the app makes. */
async function allowed() {
  const tokens = await Bun.file(path.join(repo, "testifysec/connectors/internal/marking/tokens.json")).text()
  const directory = path.join(app, "src/settings/about/notices")
  const notice = (
    await Promise.all(
      (await readdir(directory, { recursive: true, withFileTypes: true }))
        .filter((entry) => entry.isFile() && /\.(?:ts|txt)$/.test(entry.name))
        .map((entry) => readFile(path.join(entry.parentPath, entry.name), "utf8")),
    )
  ).join("\n")
  // Example addresses in form placeholders, in every language: shown greyed out in an empty field, never followed.
  const i18n = (
    await Promise.all(
      [path.join(app, "src/runtime/i18n"), path.join(app, "../ui/src/i18n")].map(async (directory) =>
        Promise.all((await readdir(directory)).map((file) => readFile(path.join(directory, file), "utf8"))),
      ),
    )
  )
    .flat()
    .join("\n")
  const placeholders = [...i18n.matchAll(/"[\w.]+\.placeholder":\s*"([^"]*)"/g)].flatMap((match) => words(match[1]))

  return {
    // XML namespace names in SVG and Office documents: identifiers that are compared, never fetched.
    prefixes: [
      "http://www.w3.org/",
      "http://schemas.openxmlformats.org/",
      "http://schemas.microsoft.com/office/",
      "http://purl.oclc.org/ooxml/",
      "http://purl.org/dc/",
      "http://ns.adobe.com/",
      // Chevrotain's (Mermaid's parser) own developer error messages, raised only while a grammar is built.
      "https://chevrotain.io/docs/",
      // Motion's developer warnings point at its troubleshooting pages; never rendered.
      "https://motion.dev/troubleshooting/",
      // This machine: the local server address a desktop shell connects to. Not another host.
      "http://localhost:",
      "http://127.0.0.1:",
    ],
    exact: new Set([
      // Third-party license and copyright notices, reproduced verbatim (Settings > About > Notices). In a managed
      // build ExternalLink renders them as plain text, so none is a link.
      ...words(notice).map(trim),
      // Source citations inside the bundled marking vocabulary. The app reads the tokens; it never shows these.
      ...words(tokens).map(trim),
      // The JSON Schema name each bundled theme file declares as "$schema". An identifier; nothing fetches it.
      "https://opencode.ai/desktop-theme.json",
      ...placeholders.map(trim),
      // Third-party library text that never renders as a link and is never fetched:
      // Mermaid's grammar runtime (Langium on Chevrotain) cites its docs in errors raised only while a grammar is
      // being built; Mermaid's builds are fixed, so these fire only for a broken library.
      "https://langium.org/docs/reference/configuration-services/#resolving-cyclic-dependencies",
      "https://en.wikipedia.org/wiki/LL_parser#Left_factoring",
      "https://github.com/chevrotain/chevrotain/issues",
      "https://github.com/chevrotain/chevrotain/issues/564#issuecomment-349062346",
      // Mermaid's and Marked's internal-bug error messages ("please report this to ...") and a deprecation note.
      "https://github.com/mermaid-js/mermaid/issues",
      "https://github.com/mermaid-js/mermaid/releases/tag/v11.0.0",
      "https://github.com/markedjs/marked",
      // A comment inside the bundled F# syntax grammar.
      "https://github.com/ionide/ionide-fsgrammar/issues/155",
      // core-js's version record (its `copyright`/`source` fields), kept by the polyfill, never shown.
      "https://github.com/zloirock/core-js",
      "https://github.com/zloirock/core-js/blob/v3.50.0/LICENSE",
      // Workbox's precache error message points developers at its docs; the worker never fetches it.
      "https://bit.ly/wb-precache",
      // Tailwind's license banner comment in the stylesheet.
      "https://tailwindcss.com",
      // CSS attribute selectors that style GitHub links a person or model writes in a message: matched, never fetched.
      "https://github.com",
      "https://github.com/",
      "http://github.com",
      "http://github.com/",
    ]),
  }
}

let dist = ""

beforeAll(async () => {
  dist = await mkdtemp(path.join(app, ".shipped-"))
  const child = Bun.spawn([process.execPath, "run", "build"], {
    cwd: app,
    env: {
      ...process.env,
      HARDENED_BUILD: "true",
      VITE_OPENCODE_SERVER_MODE: "origin",
      OPENCODE_CHANNEL: "prod",
      OPENCODE_APP_OUT_DIR: dist,
      SENTRY_AUTH_TOKEN: "",
    },
    stdout: "pipe",
    stderr: "pipe",
  })
  const [code, err] = await Promise.all([child.exited, new Response(child.stderr).text()])
  if (code !== 0) throw new Error(`managed web UI build failed (${code}):\n${err}`)
}, 300_000)

afterAll(async () => {
  if (dist) await rm(dist, { recursive: true, force: true })
})

async function shipped() {
  const files = (await readdir(dist, { recursive: true, withFileTypes: true }))
    .filter((entry) => entry.isFile())
    .map((entry) => path.relative(dist, path.join(entry.parentPath, entry.name)).split(path.sep).join("/"))
    .filter((file) => !file.endsWith(".map"))
  return Promise.all(
    files.map(async (file) => ({ file, text: binary.test(file) ? "" : await readFile(path.join(dist, file), "utf8") })),
  )
}

describe("the managed web UI", () => {
  test("contains no address outside the deployment except the listed identifiers", async () => {
    const allow = await allowed()
    const found = (await shipped()).flatMap(({ file, text }) =>
      words(text)
        .map(trim)
        .filter((url) => !allow.exact.has(url) && !allow.prefixes.some((prefix) => url.startsWith(prefix)))
        .map((url) => `${file}: ${url}`),
    )
    expect([...new Set(found)].toSorted()).toEqual([])
  })

  test("ships no TestifySec or Discord mark", async () => {
    const files = await shipped()
    expect(files.map((entry) => entry.file).filter((file) => vendor.test(file))).toEqual([])
    // Markup, styles, manifests and images are shown as they are.
    const shown = files.filter((entry) => /\.(?:html|svg|css|json|webmanifest|txt)$/i.test(entry.file))
    expect(shown.filter((entry) => vendor.test(entry.text)).map((entry) => entry.file)).toEqual([])
    // Scripts may name the build's own compile-time switches (TESTIFYSEC_*), which no one sees; nothing else.
    const scripts = files.filter((entry) => /\.m?js$/.test(entry.file))
    expect(
      scripts
        .flatMap((entry) => entry.text.replace(/\bTESTIFYSEC_[A-Z_]+\b/g, "").match(/.{0,40}testifysec.{0,40}/gi) ?? [])
        .toSorted(),
    ).toEqual([])
  })

  test("names the product and its own mark in the page head", async () => {
    const html = await readFile(path.join(dist, "index.html"), "utf8")
    expect(html).toContain("<title>Badger</title>")
    expect(html).toMatch(/<link rel="icon" type="image\/svg\+xml" href="\/badger-mark\.svg" \/>/)
    expect(await Bun.file(path.join(dist, "badger-mark.svg")).exists()).toBe(true)
  })
})

// The origin can host other services under their own path prefixes (an admin console, a gateway). The built service
// worker, run as a browser runs it, must answer a navigation with the app only for the app's own pages.
describe("the service worker", () => {
  async function navigate(pathname: string) {
    const listeners = new Map<string, ((event: unknown) => void)[]>()
    const origin = "https://app.example.test"
    const scope = {
      location: new URL(`${origin}/sw.js`),
      registration: { scope: `${origin}/` },
      addEventListener: (type: string, listener: (event: unknown) => void) =>
        listeners.set(type, [...(listeners.get(type) ?? []), listener]),
      clients: { claim: () => Promise.resolve() },
      skipWaiting: () => Promise.resolve(),
      caches: { open: () => new Promise(() => {}), keys: () => Promise.resolve([]), match: () => Promise.resolve(undefined) },
      fetch: () => new Promise(() => {}),
    }
    // A worker resolves relative request URLs against its own location.
    class WorkerRequest extends Request {
      constructor(input: string | Request, init?: RequestInit) {
        super(typeof input === "string" ? new URL(input, origin).href : input, init)
      }
    }
    class FetchEvent {
      answered = false
      constructor(readonly request: unknown) {}
      respondWith(response: Promise<unknown>) {
        this.answered = true
        response.catch(() => {})
      }
      waitUntil() {}
    }
    vm.runInContext(
      await readFile(path.join(dist, "sw.js"), "utf8"),
      vm.createContext({ ...scope, self: scope, URL, Request: WorkerRequest, Response, Headers, Promise, FetchEvent }),
    )
    const event = new FetchEvent({
      url: `${origin}${pathname}`,
      mode: "navigate",
      method: "GET",
      destination: "document",
      headers: new Headers(),
    })
    for (const listener of listeners.get("fetch") ?? []) listener(event)
    return event.answered
  }

  test("answers the app's own pages with the app", async () => {
    for (const page of ["/", "/?auth_token=x", "/settings", "/new-session", "/server/c2VydmVy/session/ses_1"])
      expect([page, await navigate(page)]).toEqual([page, true])
  })

  test("leaves every other path on the origin to the network", async () => {
    for (const page of [
      "/broker/admin/v1/ui/",
      "/broker/admin/v1/ui/usage",
      "/_gateway/me",
      "/admin/v1/ui/",
      "/managed/raise",
      "/auth/connect/abc",
      "/api/session",
      "/settings/extra/path",
      "/unknown",
    ])
      expect([page, await navigate(page)]).toEqual([page, false])
  })
})

// What a managed build shows in every language: the dictionaries after the product rename, built with the same
// compile-time switch the app uses (as brand.test.ts does).
test("no language of the managed app names TestifySec or Discord, or links outside", async () => {
  const directory = await mkdtemp(path.join(app, ".shipped-dict-"))
  try {
    const entry = path.join(directory, "entry.ts")
    const locales = DESKTOP_NATIVE_LOCALES.filter((locale) => locale !== "en")
    await Bun.write(
      entry,
      [
        `import { flatten } from "@solid-primitives/i18n"`,
        `import { AppBrand } from ${JSON.stringify(path.resolve(import.meta.dir, "brand.ts"))}`,
        `import en from ${JSON.stringify(path.resolve(import.meta.dir, "i18n/en.ts"))}`,
        `import { dict as uiEn } from "@opencode/ui/i18n/en"`,
        `import { dict as own } from ${JSON.stringify(path.resolve(import.meta.dir, "i18n/testifysec.ts"))}`,
        ...locales.map(
          (locale) =>
            `import * as app_${locale} from ${JSON.stringify(path.resolve(import.meta.dir, `i18n/${locale}.ts`))}\n` +
            `import { dict as ui_${locale} } from "@opencode/ui/i18n/${locale}"`,
        ),
        `const base = AppBrand.withProductBrand(flatten({ ...en, ...uiEn, ...own }))`,
        `const all = { en: base, ${locales.map((locale) => `${locale}: { ...base, ...AppBrand.withProductBrand(flatten({ ...(app_${locale}.dict ?? app_${locale}.default), ...ui_${locale} })) }`).join(", ")} }`,
        `console.log(JSON.stringify(all))`,
      ].join("\n"),
    )
    const result = await Bun.build({
      entrypoints: [entry],
      target: "bun",
      define: { HARDENED_BUILD: "true", HARDENED_PRODUCT_NAME: '"Badger"' },
    })
    expect(result.success).toBe(true)
    const output = path.join(directory, "out.mjs")
    await Bun.write(output, result.outputs[0])
    const child = Bun.spawn([process.execPath, output], { stdout: "pipe", stderr: "pipe" })
    const all = JSON.parse(await new Response(child.stdout).text()) as Record<string, Record<string, string>>
    expect(await child.exited).toBe(0)
    expect(Object.keys(all).length).toBe(DESKTOP_NATIVE_LOCALES.length)

    // Example addresses typed into a field's placeholder: shown greyed out, never a link or a request.
    const placeholders = new Set([
      "provider.custom.field.baseURL.placeholder",
      "dialog.server.add.placeholder",
      "server.connect.link.placeholder",
    ])
    const found = Object.entries(all).flatMap(([locale, dictionary]) =>
      Object.entries(dictionary).flatMap(([key, text]) => [
        ...(vendor.test(text) ? [`${locale} ${key}: ${text}`] : []),
        ...(!placeholders.has(key) && (words(text).length > 0 || /\bwww\.[a-z]/i.test(text))
          ? [`${locale} ${key}: ${text}`]
          : []),
      ]),
    )
    expect(found).toEqual([])
    expect(all.en["error.page.report.administrator"]).toBe("Contact your administrator.")
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}, 120_000)

// The product's own names, as the CLI, TUI and OAuth page show them in either build.
test("the product strings name no vendor and link nowhere", async () => {
  const product = await Bun.file(path.join(repo, "testifysec/branding/product.json")).json()
  const source = await Bun.file(path.join(repo, "testifysec/branding/product.ts")).text()
  const mark = await Bun.file(path.join(repo, "testifysec/branding/badger-mark.svg")).text()
  for (const text of [JSON.stringify(product), source.replace(/^\s*\/\/.*$/gm, ""), mark]) {
    expect(text).not.toMatch(vendor)
    expect(words(text).filter((url) => !url.startsWith("http://www.w3.org/"))).toEqual([])
  }
})
