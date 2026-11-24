import { describe, expect, test } from "bun:test"
import { createHash } from "crypto"
import { RipgrepBinary } from "@opencode/core/ripgrep/binary"

describe("RipgrepBinary", () => {
  test("pins a SHA-256 for every platform it downloads", () => {
    for (const [key, config] of Object.entries(RipgrepBinary.PLATFORM))
      expect(config.sha256, key).toMatch(/^[0-9a-f]{64}$/)
  })

  test("refuses a downloaded archive whose bytes do not match the pin", () => {
    const config = RipgrepBinary.PLATFORM["arm64-darwin"]
    const tampered = new TextEncoder().encode("not the ripgrep release")
    expect(() => RipgrepBinary.verify(config, tampered)).toThrow(/checksum/)
  })

  test("accepts bytes that match the pin", () => {
    const bytes = new TextEncoder().encode("fixture")
    const sha256 = createHash("sha256").update(bytes).digest("hex")
    expect(() => RipgrepBinary.verify({ ...RipgrepBinary.PLATFORM["arm64-darwin"], sha256 }, bytes)).not.toThrow()
  })
})
