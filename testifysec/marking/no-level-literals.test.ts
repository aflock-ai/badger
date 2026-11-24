import { expect, test } from "bun:test"
import { readdirSync, readFileSync } from "node:fs"
import path from "node:path"
import { preset } from "./marking"

// Every word that is a marking comes from the scheme. A level word written as a string literal in
// the product's TypeScript outside this package is a rule the scheme does not control (the literal
// order and stamp that security-marking had before schemes), so it fails the build. Tests may use
// literals: they check behaviour under a known scheme.
const root = path.resolve(import.meta.dir, "../..")
const skip = new Set(["node_modules", ".git", "dist", "test", "tests", "__tests__", "testdata"])
const words = preset("us-gov").levels.map((l) => l.name)
const literal = new RegExp(`(["'\`])(${words.join("|")})\\1`)

function* sources(dir: string): Generator<string> {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith(".") || skip.has(entry.name)) continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (full !== import.meta.dir) yield* sources(full)
    } else if (/\.tsx?$/.test(entry.name) && !/\.(test|spec)\.tsx?$/.test(entry.name)) yield full
  }
}

test("no us-gov level word is a string literal in product TypeScript outside the marking package", () => {
  const found: string[] = []
  for (const top of ["packages", "testifysec"])
    for (const file of sources(path.join(root, top)))
      readFileSync(file, "utf8")
        .split("\n")
        .forEach((line, i) => {
          if (literal.test(line)) found.push(`${path.relative(root, file)}:${i + 1}: ${line.trim()}`)
        })
  expect(found).toEqual([])
})
