import path from "node:path"
import fs from "node:fs/promises"
import { constants } from "node:fs"
import { strictJSON } from "../managed/strict-json"
import { nativeTarget, validateAssets, type NativeAsset } from "./native-assets"

export const NATIVE_COMMAND_SOURCES = ["testifysec/commands/embedded.ts", "testifysec/commands/assets.ts", "testifysec/commands/native-assets.ts", "testifysec/commands/assets-build.ts", "testifysec/commands/request.ts", "testifysec/commands/trust-mode.ts", "testifysec/commands/settings.ts", "testifysec/commands/cli.ts", "testifysec/managed/strict-json.ts"]
const sha = (bytes: Uint8Array) => new Bun.CryptoHasher("sha256").update(bytes).digest("hex")
async function read(file: string, limit: number) {
  const fd = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    const stat = await fd.stat()
    if (!stat.isFile() || stat.nlink !== 1 || stat.size <= 0 || stat.size > limit) throw new Error("native regular file bounds")
    const bytes = Buffer.alloc(stat.size + 1)
    let offset = 0
    while (offset < bytes.length) {
      const { bytesRead } = await fd.read(bytes, offset, bytes.length - offset)
      if (!bytesRead) break
      offset += bytesRead
    }
    if (offset !== stat.size) throw new Error("native input changed")
    return bytes.subarray(0, offset)
  } finally { await fd.close() }
}
export async function nativeAssets(manifest: string | undefined, target: string) {
  const match = /^bun-(darwin|linux|windows)-(arm64|x64)$/.exec(target)
  if (!match) throw new Error("native asset target")
  const os = match[1], arch = match[2] === "x64" ? "amd64" : "arm64"
  if (!manifest) return { assets: [] as NativeAsset[], bytes: new Map<string, Uint8Array>(), manifestSha256: null }
  const raw = await read(path.resolve(manifest), 16384)
  const value = strictJSON(new TextDecoder("utf-8", { fatal: true }).decode(raw))
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== "assets,schema" ||
    (value as Record<string, unknown>).schema !== "testifysec.hardened-code.native-assets/v1") throw new Error("native asset schema")
  const assets = validateAssets((value as Record<string, unknown>).assets, os, arch, true)
  const bytes = new Map<string, Uint8Array>()
  for (const asset of assets) {
    if (!path.isAbsolute(asset.file)) throw new Error("native asset absolute path required")
    const content = await read(asset.file, asset.size)
    if (content.length !== asset.size || sha(content) !== asset.sha256) throw new Error("native asset integrity")
    nativeTarget(content, os, arch)
    bytes.set(asset.role, content)
  }
  return { assets, bytes, manifestSha256: sha(raw) }
}
export async function nativeAssetsPlugin(selected: Awaited<ReturnType<typeof nativeAssets>>, stage: string): Promise<Bun.BunPlugin> {
  const files = []
  for (const [index, asset] of selected.assets.entries()) {
    const file = path.join(stage, asset.role + "-" + index + ".native")
    await fs.writeFile(file, selected.bytes.get(asset.role)!, { flag: "wx", mode: 0o400 })
    files.push(file)
  }
  return { name: "testifysec-native-commands", setup(build) {
    build.onLoad({ filter: /[\\/]commands[\\/]assets\.ts$/ }, args => {
      if (path.resolve(args.path) !== path.join(import.meta.dir,"assets.ts")) return undefined
      return { loader: "ts", contents:
      files.map((file, i) => `import file${i} from ${JSON.stringify(file)} with {type:"file"};`).join("\n") +
      `\nexport const assets=[${selected.assets.map((asset, i) => `{...${JSON.stringify(asset)},file:file${i}}`).join(",")}];` }
    })
  } }
}
