import { CString, dlopen, FFIType, ptr } from "bun:ffi"
import { readFileSync, lstatSync } from "node:fs"

// Go's c-shared runtime cannot safely be dlclosed (golang/go#11100).
// Pin its handle for process lifetime; profile updates do not reload native code.
const handles: unknown[] = []

export type Verification = {
  abiVersion: 1
  ok: boolean
  error?: string
  payloadType?: string
  payloadBase64?: string
  payloadSha256?: string
  signerKeyIds?: string[]
  signerCertificates?: { keyId: string; notBefore: string; notAfter: string }[]
}

// The caller supplies an administrator/compiled-in digest, never one from the envelope.
// Installation directories must be protected from writers for the whole process lifetime:
// hashing before dlopen does not protect against a privileged concurrent replacement.
export function openVerifier(path: string, digest: string) {
  if (handles.length) throw new Error("native verifier already loaded")
  if (!/^[a-f0-9]{64}$/.test(digest) || !lstatSync(path).isFile()) throw new Error("invalid native library")
  if (new Bun.CryptoHasher("sha256").update(readFileSync(path)).digest("hex") !== digest)
    throw new Error("native library digest mismatch")
  const library = dlopen(path, {
    RookeryABIVersion: { args: [], returns: FFIType.u32 },
    RookeryVerify: { args: [FFIType.ptr, FFIType.usize], returns: FFIType.ptr },
    RookeryFree: { args: [FFIType.ptr], returns: FFIType.void },
  })
  handles.push(library)
  if (library.symbols.RookeryABIVersion() !== 1) {
    throw new Error("unsupported native ABI")
  }
  let closed = false
  return {
    verify(input: Uint8Array): Verification {
      if (closed) throw new Error("verifier closed")
      if (!input.byteLength || input.byteLength > 4 * 1024 * 1024) throw new Error("invalid request size")
      const output = library.symbols.RookeryVerify(ptr(input), input.byteLength)
      if (!output) throw new Error("native verifier returned no result")
      try {
        const result = JSON.parse(new CString(output).toString()) as Verification
        if (result.abiVersion !== 1 || typeof result.ok !== "boolean") throw new Error("invalid native result")
        return result
      } finally {
        library.symbols.RookeryFree(output)
      }
    },
    close() {
      if (closed) return
      closed = true
    },
  }
}
