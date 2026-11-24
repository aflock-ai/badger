import { expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { readdirSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { sha256Hex } from "./sha256"

const ref = (s: string) => createHash("sha256").update(s, "utf8").digest("hex")

test("sha256Hex matches the FIPS 180-4 examples", () => {
  expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  expect(sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  expect(sha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).toBe(
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
})

test("sha256Hex equals node:crypto across padding boundaries, unicode and large inputs", () => {
  const cases = ["a", "é", "€", "𝄞", "LEVEL//SUB-ONE", "{\"name\":\"us-gov\"}"]
  for (let n = 0; n <= 200; n++) cases.push("x".repeat(n))
  for (const n of [55, 56, 57, 63, 64, 65, 119, 120, 128]) cases.push("é".repeat(n), "z".repeat(n))
  let seed = 7
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff)
  for (let i = 0; i < 300; i++) {
    let s = ""
    const len = rnd() % 300
    for (let j = 0; j < len; j++) s += String.fromCodePoint(rnd() % 0x2fff)
    cases.push(s)
  }
  cases.push("m".repeat(1 << 20))
  for (const s of cases) expect(sha256Hex(s)).toBe(ref(s))
})

// The marking modules run in the browser app; node:* is a stub there, so no non-test file may import it.
test("no browser-reachable marking file imports a node: module", () => {
  const offenders = readdirSync(import.meta.dir)
    .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))
    .filter((f) => /from\s+["']node:/.test(readFileSync(join(import.meta.dir, f), "utf8")))
  expect(offenders).toEqual([])
})
