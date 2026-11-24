import { expect, test } from "bun:test"
import { preset } from "@testifysec/marking"
import { markingFlags } from "../script/marking-flags"

test("a managed build compiles in the deployment's marking and the markings it allows", () => {
  expect(markingFlags(["--data-marking=CUI", "--allowed-markings=UNCLASSIFIED,CUI"], true)).toEqual({
    marking: "CUI",
    allowed: ["UNCLASSIFIED", "CUI"],
  })
  // With no list, only the marking itself may be chosen.
  expect(markingFlags(["--data-marking=CUI"], true)).toEqual({ marking: "CUI", allowed: ["CUI"] })
  // A managed build with no marking compiles in none; its connector data is then refused.
  expect(markingFlags([], true)).toEqual({ marking: null, allowed: [] })
})

test("marking flags are refused outside a managed build, and invalid ones are refused", () => {
  expect(() => markingFlags(["--data-marking=CUI"], false)).toThrow("require --managed")
  expect(() => markingFlags(["--allowed-markings=CUI"], false)).toThrow("require --managed")
  expect(markingFlags([], false)).toEqual({ marking: null, allowed: [] })
  expect(() => markingFlags(["--data-marking=SECRET"], true)).toThrow()
  expect(() => markingFlags(["--data-marking=CUI", "--allowed-markings=UNCLASSIFIED"], true)).toThrow()
  expect(() => markingFlags(["--allowed-markings=CUI"], true)).toThrow("requires --data-marking")
})

test("--marking-scheme compiles in a preset or a scheme file, and the markings come from it", () => {
  expect(markingFlags(["--marking-scheme=corporate", "--data-marking=INTERNAL", "--allowed-markings=INTERNAL,RESTRICTED"], true)).toEqual({
    marking: "INTERNAL",
    allowed: ["INTERNAL", "RESTRICTED"],
    scheme: { preset: "corporate" },
  })
  // us-gov's words are not markings of another scheme, nor the other way round.
  const controlled = preset("us-gov").levels[1].name
  expect(() => markingFlags(["--marking-scheme=corporate", `--data-marking=${controlled}`], true)).toThrow("markings must be one of")
  expect(() => markingFlags(["--data-marking=INTERNAL"], true)).toThrow("markings must be one of")
  expect(() => markingFlags(["--marking-scheme=no-such-preset", "--data-marking=INTERNAL"], true)).toThrow()
  expect(() => markingFlags(["--marking-scheme=corporate"], false)).toThrow("require --managed")

  const { mkdtempSync, writeFileSync } = require("node:fs") as typeof import("node:fs")
  const path = require("node:path") as typeof import("node:path")
  const dir = mkdtempSync(path.join(require("node:os").tmpdir(), "scheme-"))
  const file = path.join(dir, "site.json")
  const raw = JSON.stringify({ schema: "badger.marking-scheme/v1", name: "site", version: 1, levels: [{ name: "LOW" }, { name: "HIGH" }], groups: [] })
  writeFileSync(file, raw)
  expect(markingFlags([`--marking-scheme=${file}`, "--data-marking=HIGH"], true)).toEqual({
    marking: "HIGH",
    allowed: ["HIGH"],
    scheme: { file: "site.json", raw },
  })
  // A file named without a directory is still a file; only a built-in preset's name is a preset.
  const cwd = process.cwd()
  process.chdir(dir)
  try {
    expect(markingFlags(["--marking-scheme=site.json", "--data-marking=HIGH"], true).scheme).toEqual({ file: "site.json", raw })
  } finally {
    process.chdir(cwd)
  }
  writeFileSync(file, "{}")
  expect(() => markingFlags([`--marking-scheme=${file}`, "--data-marking=HIGH"], true)).toThrow("marking scheme")
})
