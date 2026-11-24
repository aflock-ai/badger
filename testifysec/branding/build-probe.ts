// jade:ring local
// Compiles probe.ts for branding/uat.py: build-probe.ts OUTPUT VERSION true|false|unset, where the last
// argument is HARDENED_BUILD. The managed profile pulls in the server graph, so this builds the way
// packages/cli/script/build.ts does: node-gyp is external, and core's PTY binding is stubbed (no-pty.ts).
import path from "node:path"
import { noPty } from "../runtime/no-pty"

const [output, version, mode] = process.argv.slice(2)
if (process.argv.length !== 5 || !["true", "false", "unset"].includes(mode))
  throw new Error("usage: build-probe.ts OUTPUT VERSION true|false|unset")
const build = await Bun.build({
  entrypoints: [path.join(import.meta.dir, "probe.ts")],
  external: ["node-gyp"],
  define: {
    TESTIFYSEC_MANAGED_WORKER: "true",
    TESTIFYSEC_FIXTURE_MODEL: "false",
    HARDENED_VERSION: JSON.stringify(version),
    ...(mode === "unset" ? {} : { HARDENED_BUILD: mode }),
  },
  compile: { outfile: path.resolve(output), autoloadBunfig: false, autoloadDotenv: false, autoloadPackageJson: false, autoloadTsconfig: false },
  plugins: [noPty],
})
if (!build.success) throw new AggregateError(build.logs, "branding probe build failed")
