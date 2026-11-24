import { stat } from "node:fs/promises"
import path from "node:path"
import { collectFiles } from "./files"

const forbidden = [
  "@napi-rs/canvas",
  "@fontsource/commit-mono",
  "@fontsource/noto-sans",
  "SimulationPng",
  "frontend/png",
  "Failed to register screenshot font",
  "commit-mono-latin-400-normal",
  "noto-sans-symbols-symbols-400-normal",
  "noto-sans-math-math-400-normal",
  "CommitMono-400-Regular.otf",
  "NotoSansSymbols.ttf",
  "src/frontend/png.ts",
  "skia.darwin-",
  "skia.linux-",
  "skia.win32-",
]

/** What any `--fixture-requirements` origin starts with; a release build carries no https://localhost at all. */
export const fixtureRequirementsMarker = "https://localhost"

export async function verifyArtifact(target: string, markers: readonly string[] = forbidden) {
  const files = await artifactFiles(target)
  if (files.length === 0) throw new Error(`Artifact contains no published files: ${target}`)
  for (const file of files) await scan(file, markers)
}

export function verifySimulationGraph(inputs: Iterable<string>) {
  const modules = Array.from(inputs, (input) => input.replaceAll("\\", "/"))
  const required = [
    "/packages/simulation/src/frontend/simulation.ts",
    "/packages/simulation/src/frontend/server.ts",
    "/packages/simulation/src/control-server.ts",
  ]
  const missing = required.filter((input) => !modules.some((module) => module.endsWith(input)))
  if (missing.length > 0) throw new Error(`Build graph is missing simulation bridge inputs: ${missing.join(", ")}`)
  const leaked = modules.find((module) => module.includes("/packages/simulation/src/frontend/png."))
  if (leaked) throw new Error(`Build graph contains Drive-only rendering input: ${leaked}`)
}

async function artifactFiles(target: string): Promise<string[]> {
  if ((await stat(target)).isFile()) return [target]
  return (await collectFiles(target)).map((file) => path.join(target, file))
}

async function scan(file: string, markers: readonly string[]) {
  const overlap = Math.max(...markers.map((value) => value.length)) - 1
  let trailing = ""
  const reader = Bun.file(file).stream().getReader()
  while (true) {
    const chunk = await reader.read()
    if (chunk.done) return
    const text = trailing + Buffer.from(chunk.value).toString("latin1")
    const leaked = markers.find((marker) => text.includes(marker))
    if (leaked) throw new Error(`Artifact file ${file} contains forbidden payload: ${leaked}`)
    trailing = text.slice(-overlap)
  }
}

if (import.meta.main) {
  const target = process.argv[2]
  if (!target) throw new Error("Usage: bun run script/verify-artifact.ts <file-or-directory>")
  await verifyArtifact(target)
}
