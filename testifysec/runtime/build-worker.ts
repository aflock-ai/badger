import path from "node:path"
import { copyFile, mkdtemp, rm } from "node:fs/promises"
import os from "node:os"
import { markingFlags } from "../../packages/cli/script/marking-flags"
import { workerArgs } from "./worker-args"
import product from "../branding/product.json"

// Builds the Linux worker the runtime and VM boundaries start as /toolpack/opencode-worker, through the
// OpenCode 2.0 managed build (`packages/cli/script/build.ts --managed --worker`), and writes the
// manifest the UAT harnesses check. `fixture` compiles in the UAT fixture model; release builds refuse
// to contain it.
const root = path.resolve(import.meta.dir, "../..")
// The deployment's data marking is compiled into the worker (build.ts --data-marking, --allowed-markings);
// without it the worker has none and refuses connector data.
const { output, target, fixture, markingArgs } = workerArgs(process.argv.slice(2))
const dataMarking = markingFlags(markingArgs, true)
// The managed build's output binary name under <target>/bin: the product command (see script/executable.ts).
const binary = "badger"
const targets: Record<string, string> = {
  "bun-linux-arm64": "opencode-linux-arm64",
  "bun-linux-x64": "opencode-linux-x64",
  "bun-linux-arm64-musl": "opencode-linux-arm64-musl",
  "bun-linux-x64-musl": "opencode-linux-x64-musl",
}
if (!output || !targets[target])
  throw new Error(
    "usage: build-worker.ts OUTPUT [bun-linux-arm64|bun-linux-x64|bun-linux-arm64-musl|bun-linux-x64-musl] [fixture] [--data-marking=M] [--allowed-markings=A,B] [--marking-scheme=S]",
  )

const cli = path.join(root, "packages/cli")
const version = (await Bun.file(path.join(cli, "package.json")).json()).version as string
const productVersion = (await Bun.file(path.join(root, "VERSION")).text()).trim()
const outdir = await mkdtemp(path.join(os.tmpdir(), "badger-worker-build-"))
try {
  const flags = [
    "--managed",
    "--worker",
    ...(fixture ? ["--fixture-model"] : []),
    ...markingArgs,
    `--target=${targets[target]}`,
    "--skip-web-ui",
  ]
  const build = Bun.spawn([process.execPath, "run", "script/build.ts", ...flags, `--outdir=${outdir}`], {
    cwd: cli,
    env: { ...process.env, OPENCODE_CHANNEL: process.env.OPENCODE_CHANNEL ?? "hardened" },
    stdout: "ignore",
    stderr: "inherit",
  })
  // Throw rather than exit so the temporary build directory is still removed.
  if ((await build.exited) !== 0) throw new Error("managed worker build failed")
  await copyFile(path.join(outdir, targets[target].replace("opencode", "cli"), "bin", binary), path.resolve(output))
} finally {
  await rm(outdir, { recursive: true, force: true })
}

const files = [
  "testifysec/runtime/worker.ts",
  "testifysec/runtime/fixture-model.ts",
  "testifysec/runtime/build-worker.ts",
  "testifysec/runtime/worker-args.ts",
  "testifysec/branding/product.ts",
  "testifysec/branding/product.json",
  "VERSION",
  "packages/cli/src/index.ts",
  "packages/cli/src/managed.ts",
  "packages/cli/src/services/server-connection.ts",
  "packages/cli/script/build.ts",
  "packages/cli/script/marking-flags.ts",
  "packages/cli/script/verify-artifact.ts",
  "packages/server/src/managed.ts",
  "packages/util/src/security-marking.ts",
  "bun.lock",
]
const sourceFiles = Object.fromEntries(
  await Promise.all(
    files.map(async (file) => [
      file,
      new Bun.CryptoHasher("sha256").update(await Bun.file(path.join(root, file)).arrayBuffer()).digest("hex"),
    ]),
  ),
)
const manifest = {
  component: "hardened-opencode-worker",
  target,
  fixtureModel: fixture,
  dataMarking,
  product: { ...product, version: productVersion },
  binarySha256: new Bun.CryptoHasher("sha256").update(await Bun.file(path.resolve(output)).arrayBuffer()).digest("hex"),
  upstream: version,
  upstreamCommit: (await Bun.file(path.join(root, "testifysec/upstream.commit")).text()).trim(),
  bun: Bun.version,
  sourceFiles,
  qualified: false,
}
await Bun.write(path.resolve(output) + ".manifest.json", JSON.stringify(manifest, null, 2) + "\n")
process.stdout.write(JSON.stringify(manifest) + "\n")
