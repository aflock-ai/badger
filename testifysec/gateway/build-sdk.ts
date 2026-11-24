// jade:ring local
// Compiles sdk-responses.ts. It sits outside the workspace, so its own bare imports (effect, @opencode/ai) resolve
// from packages/ai, the package whose client it exercises; every other import resolves normally. Core's PTY
// binding is stubbed (runtime/no-pty.ts).
import path from "node:path"
import { noPty } from "../runtime/no-pty"

const output = process.argv[2]
if (!output || process.argv.length !== 3) throw new Error("usage: build-sdk.ts ABSOLUTE_OUTPUT")
const entry = path.join(import.meta.dir, "sdk-responses.ts")
const ai = path.resolve(import.meta.dir, "../../packages/ai")
const build = await Bun.build({
  entrypoints: [entry],
  external: ["node-gyp"],
  compile: { outfile: path.resolve(output), autoloadBunfig: false, autoloadDotenv: false, autoloadPackageJson: false, autoloadTsconfig: false },
  plugins: [noPty, {
    name: "resolve-client-imports-from-packages-ai",
    setup(builder) {
      builder.onResolve({ filter: /^(?:effect|@opencode\/ai)(?:\/|$)/ }, (args) =>
        args.importer === entry ? { path: Bun.resolveSync(args.path, ai) } : undefined)
    },
  }],
})
if (!build.success) throw new AggregateError(build.logs, "SDK fixture build failed")
