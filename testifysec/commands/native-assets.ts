// Build and runtime share target/manifest checks; no helper is discovered on PATH.
export type NativeRole = "enroll" | "attest"
export interface NativeAsset {
  role: NativeRole
  file: string
  os: "darwin" | "linux" | "windows"
  arch: "arm64" | "amd64"
  sha256: string
  size: number
  timeoutSeconds: number
}
export function validateAssets(value: unknown, os: string, arch: string, requireBoth: boolean): NativeAsset[] {
  if (!Array.isArray(value) || value.length > 2 || (requireBoth && value.length !== 2)) throw new Error("native asset count")
  const roles = new Set<string>()
  for (const item of value) {
    if (!item || typeof item !== "object" || Object.keys(item).sort().join(",") !== "arch,file,os,role,sha256,size,timeoutSeconds" ||
      (item.role !== "enroll" && item.role !== "attest") || roles.has(item.role) || item.os !== os || item.arch !== arch ||
      typeof item.file !== "string" || !item.file || typeof item.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(item.sha256) ||
      !Number.isSafeInteger(item.size) || item.size < 1024 || item.size > 128 * 1024 * 1024 ||
      !Number.isSafeInteger(item.timeoutSeconds) || item.timeoutSeconds < 1 || item.timeoutSeconds > 600) throw new Error("native asset manifest")
    roles.add(item.role)
  }
  return value as NativeAsset[]
}
export function nativeTarget(bytes: Uint8Array, os: string, arch: string) {
  const data = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  if (os === "darwin" && data.length >= 32 && data.readUInt32LE(0) === 0xfeedfacf &&
    data.readUInt32LE(4) === (arch === "arm64" ? 0x100000c : 0x1000007) && data.readUInt32LE(12) === 2) return
  if (os === "linux" && data.length >= 64 && data.subarray(0, 6).equals(Buffer.from([127, 69, 76, 70, 2, 1])) &&
    data.readUInt16LE(18) === (arch === "arm64" ? 183 : 62) && [2, 3].includes(data.readUInt16LE(16))) return
  if (os === "windows" && data.length >= 128 && data.readUInt16LE(0) === 0x5a4d) {
    const offset = data.readUInt32LE(0x3c)
    if (offset <= data.length - 26 && data.readUInt32LE(offset) === 0x4550 &&
      data.readUInt16LE(offset + 4) === (arch === "arm64" ? 0xaa64 : 0x8664) && data.readUInt16LE(offset + 24) === 0x20b) return
  }
  throw new Error("native executable target mismatch")
}
