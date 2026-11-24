import { dirname, join } from "node:path"
import { openVerifier } from "./binding"

declare const ROOKERY_LIBRARY_SHA256: string
declare const ROOKERY_LIBRARY_NAME: string

// Component diagnostic only. Trust keys in the request are for verification testing;
// managed profile admission will source them from protected installation policy.
try {
  if (Bun.argv.length !== 2) throw new Error("usage: rookery-verify < request.json")
  const chunks: Uint8Array[] = []
  let length = 0
  for await (const chunk of Bun.stdin.stream()) {
    length += chunk.byteLength
    if (length > 4 * 1024 * 1024) throw new Error("invalid request size")
    chunks.push(chunk)
  }
  const verifier = openVerifier(join(dirname(process.execPath), ROOKERY_LIBRARY_NAME), ROOKERY_LIBRARY_SHA256)
  try {
    const result = verifier.verify(Buffer.concat(chunks))
    process.stdout.write(JSON.stringify(result) + "\n")
    process.exitCode = result.ok ? 0 : 1
  } finally {
    verifier.close()
  }
} catch {
  process.stderr.write("native verification unavailable\n")
  process.exitCode = 2
}
