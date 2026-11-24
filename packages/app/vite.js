import { readFileSync } from "node:fs"
import { createRequire } from "node:module"
import solidPlugin from "vite-plugin-solid"
import tailwindcss from "@tailwindcss/vite"
import { fileURLToPath } from "url"

const theme = fileURLToPath(new URL("./public/oc-theme-preload.js", import.meta.url))

const product = JSON.parse(readFileSync(new URL("../../testifysec/branding/product.json", import.meta.url), "utf8"))

const productMark = readFileSync(new URL("../../testifysec/branding/badger-mark.svg", import.meta.url))

const themeScript = readFileSync(theme, "utf8")

const tailwind = tailwindcss()

const tailwindGenerate = tailwind.find((plugin) => plugin.name === "@tailwindcss/vite:generate:serve")

const tailwindHotUpdate = tailwindGenerate?.hotUpdate

// Tailwind 4.3.3 expects a server that Vite's bundled dev hook does not provide.
if (tailwindGenerate && typeof tailwindHotUpdate === "function") {
  tailwindGenerate.hotUpdate = function (context) {
    if (!context.server) return

    return tailwindHotUpdate.call(this, context)
  }
}

// The markdown worker imports these directly, so they are served unbundled to keep worker startup
// stable. Vite applies `exclude` to every import inside a pre-bundle too, which would leave a bare
// `import "marked"` in mermaid's chunk that the browser cannot resolve from this package.
const workerDeps = ["@shikijs/stream", "marked", "marked-shiki", "remend"]

// The Office previews load their wasm and fonts through `new URL(..., import.meta.url)`, which a pre-bundle would move
// away from the files.
const officeDeps = ["@betteroffice/docx", "@betteroffice/fonts", "@betteroffice/pptx", "@betteroffice/xlsx"]

// The build emits the Office engines' wasm and worker files for every `new URL(..., import.meta.url)` it sees, even in
// code that tree shaking drops. A file that no other emitted file names never loads, so it is left out of the build.
const officeEmitted = /^(?:docx_\w+_bg|ooxml_opc_bg|pptx_wasm_bg|xlsx_wasm_bg|residentEngineWorker)\b/

/** @type {import("vite").Plugin} */
const dropUnloadedOfficeFiles = {
  name: "opencode-desktop:drop-unloaded-office-files",
  apply: "build",
  generateBundle: {
    order: "post",
    handler(_, bundle) {
      const files = Object.values(bundle).filter((file) => !file.fileName.endsWith(".map"))
      const name = (file) => file.fileName.split("/").pop() ?? file.fileName
      const source = (file) => (file.type === "chunk" ? file.code : typeof file.source === "string" ? file.source : "")
      const named = (file) => files.some((other) => other !== file && source(other).includes(name(file)))

      files
        .filter((file) => officeEmitted.test(name(file)) && !named(file))
        .forEach((file) => {
          delete bundle[file.fileName]
          delete bundle[`${file.fileName}.map`]
        })
    },
  },
}

/** @type {import("rolldown").Plugin} */
const bundleNestedWorkerDeps = {
  name: "opencode-desktop:bundle-nested-worker-deps",
  resolveId(id, importer) {
    if (!importer || !workerDeps.includes(id) || !importer.includes("node_modules")) return

    try {
      return createRequire(importer).resolve(id)
    } catch {
      return
    }
  },
}

export const channel = (() => {
  const raw = process.env.OPENCODE_CHANNEL

  if (raw === "local" || raw === "dev" || raw === "beta" || raw === "prod") return raw

  if (process.env.OPENCODE_CHANNEL === "latest") return "prod"

  return "dev"
})()

/**
 * @type {import("vite").PluginOption}
 */
export default [
  {
    name: "opencode-desktop:config",
    config() {
      return {
        resolve: {
          alias: {
            "@": fileURLToPath(new URL("./src", import.meta.url)),
            // The font package imports its 33 MB Chinese, Japanese and Korean add-on on demand; the app does not ship it.
            "@betteroffice/fonts-cjk": fileURLToPath(
              new URL("../gui-extensions/src/microsoft-office/fonts-cjk.ts", import.meta.url),
            ),
          },
        },
        define: {
          "import.meta.env.VITE_OPENCODE_CHANNEL": JSON.stringify(channel),
        },
        worker: {
          format: "es",
        },
        optimizeDeps: {
          exclude: [...workerDeps, ...officeDeps],
          include: ["@opencode/session-ui > mermaid", "@opencode/session-ui > mermaid > katex"],
          rolldownOptions: { plugins: [bundleNestedWorkerDeps] },
        },
      }
    },
  },
  branding(),
  dropUnloadedOfficeFiles,
  {
    name: "opencode-desktop:theme-preload",
    transformIndexHtml: {
      order: "pre",
      handler: inlineThemePreload,
    },
  },
  ...tailwind,
  solidPlugin(),
]

/**
 * Display only: the product name and marks. A managed build (HARDENED_BUILD=true, set by the CLI's
 * `build.ts --managed`) shows Badger and its plain monogram; every other build is left as upstream.
 *
 * @param {boolean} hardened
 */
export function branding(hardened = process.env.HARDENED_BUILD === "true") {
  const name = hardened ? product.name : "OpenCode"
  const file = "badger-mark.svg"
  let base = "/"

  return {
    name: "opencode-app:branding",
    config() {
      /** @type {import("vite").UserConfig} */
      const config = {
        define: { HARDENED_BUILD: JSON.stringify(hardened), HARDENED_PRODUCT_NAME: JSON.stringify(name) },
      }
      if (hardened)
        config.resolve = {
          alias: { "@opencode/ui/logo": fileURLToPath(new URL("./src/runtime/product-logo.tsx", import.meta.url)) },
        }
      return config
    },
    /** @param {{ base: string }} config */
    configResolved(config) {
      base = config.base
    },
    generateBundle() {
      if (hardened) this.emitFile({ type: "asset", fileName: file, source: productMark })
    },
    /** @param {import("vite").ViteDevServer} server */
    configureServer(server) {
      if (!hardened) return
      server.middlewares.use((request, response, next) => {
        if (request.url?.split("?")[0] !== `/${file}`) return next()
        response.setHeader("Content-Type", "image/svg+xml")
        response.end(productMark)
      })
    },
    transformIndexHtml: {
      order: "pre",
      /** @param {string} html */
      handler(html) {
        if (!hardened) return html
        const href = `${base}${file}`
        return html
          .replace(/[ \t]*<link rel="(?:icon|shortcut icon|apple-touch-icon|manifest)"[^>]*>\n/g, "")
          .replace(/<title>OpenCode<\/title>/, `<title>${name}</title>\n    <link rel="icon" type="image/svg+xml" href="${href}" />`)
          .replace(/(<meta property="(?:og|twitter):image" content=")[^"]*(")/g, `$1${href}$2`)
      },
    },
  }
}

export function inlineThemePreload(html) {
  return html.replace(
    /<script id="oc-theme-preload-script" src="(?:\.\/|\/)oc-theme-preload\.js"><\/script>/,
    `<script id="oc-theme-preload-script">${themeScript}</script>`,
  )
}
