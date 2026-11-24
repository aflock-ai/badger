import path from "node:path"

/**
 * The executable's file name, which is also the name its help shows. A managed build installs as the product's
 * command (`badger`); every other build keeps `opencode`.
 */
export async function executableName(managed: boolean) {
  if (!managed) return "opencode"
  const product = await Bun.file(path.resolve(import.meta.dirname, "../../../testifysec/branding/product.json")).json()
  return product.command as string
}
