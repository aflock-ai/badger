import { describe, expect, test } from "bun:test"
import { readFileSync, readdirSync } from "node:fs"
import path from "node:path"
import {
  bottom,
  dominatesIn,
  formatIn,
  joinIn,
  loadScheme,
  loadPresetShape,
  NoBanner,
  parseIn,
  preset,
  SchemeMismatch,
  type Marking,
} from "./marking"

const testdata = path.join(import.meta.dir, "../connectors/internal/marking/testdata/schemes")
const fixture = (name: string) => loadScheme(`${name}.json`, readFileSync(path.join(testdata, `${name}.json`), "utf8"))
const tokens = JSON.parse(readFileSync(path.join(import.meta.dir, "../connectors/internal/marking/tokens.json"), "utf8"))

describe("schemes", () => {
  // The Go loader pins the same digests (scheme_test.go, TestPresetDigestsPinned).
  test("preset digests are the Go loader's", () => {
    expect(preset("us-gov").digest).toBe("sha256:f06d5cd645497e86b647d8f800c8ec92b14b03a225484b8a44735d6be75a2189")
    expect(preset("corporate").digest).toBe("sha256:90db5dc18987919f5b118a4e81dcef9a95a80903235ee41c6d6999c3cd7cb62d")
  })

  test("every refusal fixture is refused with the Go loader's message", () => {
    const doc = JSON.parse(readFileSync(path.join(testdata, "refusals.json"), "utf8")) as { refusals: Record<string, string> }
    const files = readdirSync(path.join(testdata, "refusals")).filter((f) => f.endsWith(".json"))
    expect(files.length).toBe(Object.keys(doc.refusals).length)
    const wrong: string[] = []
    for (const [name, want] of Object.entries(doc.refusals)) {
      try {
        loadScheme(`${name}.json`, readFileSync(path.join(testdata, "refusals", `${name}.json`), "utf8"))
        wrong.push(`${name}: loaded`)
      } catch (e) {
        if (!(e as Error).message.includes(want)) wrong.push(`${name}: ${(e as Error).message} (want ${want})`)
      }
    }
    expect(wrong).toEqual([])
  })

  test("preset names never reach a file", () => {
    for (const name of ["", "nope", "../tokens", "us-gov.json", "US-GOV"]) expect(() => preset(name)).toThrow()
  })

  test("the us-gov preset is the token tables", () => {
    const s = preset("us-gov")
    expect(s.levels.map((l) => l.name)).toEqual(tokens.levels.map((l: { banner: string }) => l.banner))
    expect(s.groups.find((g) => g.name === "sci")!.tokens.map((t) => t.token)).toEqual(tokens.sci.tokens)
    expect(s.retired.map((r) => r.token)).toEqual(tokens.legacy.tokens)
  })
})

describe("corporate and custom schemes", () => {
  const corp = preset("corporate")
  const p = (b: string) => parseIn(corp, b)

  test("round trips, tags in order", () => {
    expect(formatIn(corp, p("confidential//pii/phi"))).toBe("CONFIDENTIAL//PHI/PII")
    expect(formatIn(corp, p("CONFIDENTIAL//CUSTOMER-A1"))).toBe("CONFIDENTIAL//CUSTOMER-A1")
    expect(p("CONFIDENTIAL//PHI").tags).toEqual({ handling: ["PHI"] })
    expect(p("PUBLIC").tags).toBeUndefined()
  })

  test("a tag below its minimum level is refused, never raised", () => {
    expect(() => p("INTERNAL//PHI")).toThrow("PHI is not allowed at INTERNAL")
    expect(() => p("PUBLIC//EXPORT")).toThrow("EXPORT is not allowed at PUBLIC")
    expect(() => p("HIGHLY CONFIDENTIAL")).toThrow("unknown classification level")
  })

  test("join keeps every tag and the higher level; dominance needs every tag", () => {
    expect(formatIn(corp, joinIn(corp, p("CONFIDENTIAL//PHI"), p("RESTRICTED//PCI")))).toBe("RESTRICTED//PCI/PHI")
    expect(dominatesIn(corp, p("RESTRICTED"), p("CONFIDENTIAL//PHI"))).toBe(false)
    expect(dominatesIn(corp, p("CONFIDENTIAL//CUSTOMER-A1"), p("CONFIDENTIAL//CUSTOMER-B2"))).toBe(false)
    expect(dominatesIn(corp, p("RESTRICTED//PCI/PHI"), p("CONFIDENTIAL//PHI"))).toBe(true)
  })

  test("the example tables", () => {
    const hc = fixture("healthcare")
    expect(() => parseIn(hc, "CONFIDENTIAL//SUD")).toThrow()
    expect(formatIn(hc, joinIn(hc, parseIn(hc, "RESTRICTED//SUD"), parseIn(hc, "CONFIDENTIAL//PHI/PII")))).toBe("RESTRICTED//PHI/PII/SUD")
    const fs = fixture("finserv")
    expect(formatIn(fs, parseIn(fs, "RESTRICTED//MNPI//DEAL-ALPHA 7"))).toBe("RESTRICTED//MNPI//DEAL-ALPHA 7")
  })

  test("markings from different schemes are never compared or combined", () => {
    const gov = preset("us-gov")
    const g = parseIn(gov, tokens.levels[0].banner)
    const c = p("PUBLIC")
    for (const [a, b] of [[g, c], [c, g], [bottom, c], [c, bottom]] as [Marking, Marking][])
      for (const s of [gov, corp]) {
        expect(dominatesIn(s, a, b)).toBe(false)
        expect(() => joinIn(s, a, b)).toThrow(SchemeMismatch)
      }
    expect(() => formatIn(gov, c)).toThrow(SchemeMismatch)
    expect(g).toEqual(bottom)
    expect(dominatesIn(preset("corporate"), c, p("PUBLIC"))).toBe(true)
  })

  test("invariants: join is the max level, keeps every tag, dominates both, reads back", () => {
    for (const s of [corp, fixture("healthcare"), fixture("finserv")]) {
      const words = s.groups.flatMap((g) => [...g.tokens.map((t) => t.token), ...(g.prefix ? [g.prefix + "X1"] : [])])
      const ms: Marking[] = []
      for (const l of s.levels)
        for (const w of ["", ...words]) {
          try {
            ms.push(parseIn(s, w ? `${l.name}//${w}` : l.name))
          } catch {}
        }
      for (const a of ms) {
        expect(parseIn(s, formatIn(s, a))).toEqual(a)
        for (const b of ms) {
          let j: Marking
          try {
            j = joinIn(s, a, b)
          } catch (e) {
            expect(e).toBeInstanceOf(NoBanner)
            continue
          }
          expect(j.level).toBe(Math.max(a.level, b.level))
          expect(dominatesIn(s, j, a) && dominatesIn(s, j, b)).toBe(true)
        }
      }
    }
  })
})

describe("configure", () => {
  // configure is once per process, so it runs in a process of its own.
  test("once; the same scheme again; a change refused; old markings refused", () => {
    const script = `
      import { configure, parse, dominates, join, lowest, format, preset, SchemeMismatch } from ${JSON.stringify(path.join(import.meta.dir, "marking.ts"))}
      const before = parse(${JSON.stringify(tokens.levels[1].banner)})
      configure(preset("corporate"))
      configure(preset("corporate"))
      let changed = false
      try { configure(preset("us-gov")) } catch { changed = true }
      const m = parse("CONFIDENTIAL//PHI")
      let oldParses = true
      try { parse(${JSON.stringify(tokens.levels[1].banner)}) } catch { oldParses = false }
      let mixed = false
      try { join(m, before) } catch (e) { mixed = e instanceof SchemeMismatch }
      console.log(JSON.stringify({ changed, banner: format(m), oldParses, cross: dominates(m, before), mixed, low: format(lowest()) }))
    `
    const run = Bun.spawnSync([process.execPath, "--eval", script])
    expect(run.exitCode).toBe(0)
    expect(JSON.parse(run.stdout.toString())).toEqual({
      changed: true,
      banner: "CONFIDENTIAL//PHI",
      oldParses: false,
      cross: false,
      mixed: true,
      low: "PUBLIC",
    })
  })
})

test("a loaded scheme cannot be changed", () => {
  const s = preset("corporate")
  expect(() => {
    ;(s.groups as unknown as unknown[]).length = 0
  }).toThrow()
  expect(() => {
    ;(s.groups[0].tokens[0] as { token: string }).token = "X"
  }).toThrow()
})

test("(preset shapes) release lines and the no-release token in any group, at their levels; joins that read back", () => {
  const s = loadPresetShape(
    "r.json",
    JSON.stringify({
      schema: "badger.marking-scheme/v1", name: "r", version: 1, levels: [{ name: "LOW" }, { name: "HIGH" }],
      groups: [
        { name: "handling", kind: "require", position: 1, tokens: [{ token: "HOME ONLY", portion: "HO" }, { token: "X", levels: [0] }] },
        { name: "rel", kind: "release", position: 1, levels: [0], inGroup: "handling", home: "AAA", noReleasePortion: "HO",
          releaseLine: "REL TO", displayLine: "SHOW TO", countries: ["AAA", "BBB", "CCC"] },
      ],
    }),
  )
  const j = joinIn(s, parseIn(s, "LOW//REL TO AAA, BBB"), parseIn(s, "LOW//REL TO AAA, CCC"))
  expect(formatIn(s, j)).toBe("LOW//HOME ONLY")
  expect(parseIn(s, formatIn(s, j))).toEqual(j)
  expect(() => parseIn(s, "HIGH//REL TO AAA, BBB")).toThrow("REL TO is not allowed at HIGH")
  expect(() => joinIn(s, parseIn(s, "LOW//X"), parseIn(s, "HIGH"))).toThrow(NoBanner)
})

test("(preset shapes) a sourced token's levels; sub-compartments in the release-hosting group stay distinct", () => {
  const s = loadPresetShape(
    "c.json",
    JSON.stringify({
      schema: "badger.marking-scheme/v1", name: "c", version: 1, levels: [{ name: "LOW" }, { name: "HIGH" }],
      groups: [
        { name: "handling", kind: "require", position: 1, tokens: [{ token: "HOME ONLY", portion: "HO" }, { token: "X", suffix: true }] },
        { name: "rel", kind: "release", position: 1, inGroup: "handling", home: "AAA", noReleasePortion: "HO",
          releaseLine: "REL TO", displayLine: "SHOW TO", countries: ["AAA", "BBB"] },
        { name: "src", kind: "sourced", position: 2, tokens: [{ token: "SRC", levels: [1] }] },
      ],
    }),
  )
  expect(() => parseIn(s, "LOW//SRC")).toThrow("SRC is not allowed at LOW")
  parseIn(s, "HIGH//SRC BBB")
  const a = parseIn(s, "LOW//X-A")
  const b = parseIn(s, "LOW//X-B")
  expect(dominatesIn(s, a, b) || dominatesIn(s, b, a)).toBe(false)
  expect(formatIn(s, joinIn(s, a, b))).toBe("LOW//X-A/X-B")
  expect(formatIn(s, parseIn(s, "LOW//X-B/HOME ONLY/X-A"))).toBe("LOW//HOME ONLY/X-A/X-B")
})

test("the shapes only presets may use are still validated when a preset uses them", () => {
  const doc = JSON.parse(readFileSync(path.join(testdata, "preset-refusals.json"), "utf8")) as { refusals: Record<string, string> }
  const files = readdirSync(path.join(testdata, "preset-refusals")).filter((f) => f.endsWith(".json"))
  expect(files.length).toBe(Object.keys(doc.refusals).length)
  const wrong: string[] = []
  for (const [name, want] of Object.entries(doc.refusals)) {
    try {
      loadPresetShape(`${name}.json`, readFileSync(path.join(testdata, "preset-refusals", `${name}.json`), "utf8"))
      wrong.push(`${name}: loaded`)
    } catch (e) {
      if (!(e as Error).message.includes(want)) wrong.push(`${name}: ${(e as Error).message} (want ${want})`)
    }
  }
  expect(wrong).toEqual([])
})

test("a join keeps each token in its own group at the joined level", () => {
  const s = loadScheme(
    "x.json",
    JSON.stringify({
      schema: "badger.marking-scheme/v1", name: "x", version: 1, levels: [{ name: "LOW" }, { name: "HIGH" }],
      groups: [
        { name: "a", kind: "require", position: 1, tokens: [{ token: "X", levels: [0] }] },
        { name: "b", kind: "require", position: 2, tokens: [{ token: "X", levels: [1] }] },
      ],
    }),
  )
  expect(parseIn(s, "LOW//X").tags).toEqual({ a: ["X"] })
  expect(parseIn(s, "HIGH//X").tags).toEqual({ b: ["X"] })
  expect(() => joinIn(s, parseIn(s, "LOW//X"), parseIn(s, "HIGH"))).toThrow(NoBanner)
})

test("a group named like an Object.prototype member is a group like any other", () => {
  const s = loadScheme(
    "p.json",
    JSON.stringify({
      schema: "badger.marking-scheme/v1", name: "p", version: 1, levels: [{ name: "LOW" }, { name: "HIGH" }],
      groups: [
        { name: "constructor", kind: "require", position: 1, tokens: [{ token: "C" }] },
        { name: "handling", kind: "require", position: 2, tokens: [{ token: "H" }] },
      ],
    }),
  )
  const h = parseIn(s, "HIGH//H")
  expect(formatIn(s, h)).toBe("HIGH//H")
  expect(dominatesIn(s, h, parseIn(s, "LOW//H"))).toBe(true)
  expect(formatIn(s, joinIn(s, h, parseIn(s, "LOW//C")))).toBe("HIGH//C//H")
})

test("a word ending in a space is refused: the banner would read as the trimmed word", () => {
  const scheme = (levels: string[]) =>
    JSON.stringify({ schema: "badger.marking-scheme/v1", name: "t", version: 1, levels: levels.map((name) => ({ name })), groups: [] })
  expect(() => loadScheme("t.json", scheme(["LOW", "LOW "]))).toThrow('level name "LOW " is not a banner word')
})

test("(preset shapes) the no-release token's owner is the group with its portion", () => {
  const s = loadPresetShape(
    "n.json",
    JSON.stringify({
      schema: "badger.marking-scheme/v1", name: "n", version: 1, levels: [{ name: "LOW" }, { name: "HIGH" }],
      groups: [
        { name: "low", kind: "require", position: 1, levels: [0], tokens: [{ token: "HOME ONLY" }] },
        { name: "high", kind: "require", position: 2, levels: [1], tokens: [{ token: "HOME ONLY", portion: "HO" }] },
        { name: "rel", kind: "release", position: 2, inGroup: "high", home: "AAA", noReleasePortion: "HO",
          releaseLine: "REL TO", displayLine: "SHOW TO", countries: ["AAA", "BBB"] },
      ],
    }),
  )
  expect(() => parseIn(s, "HIGH//HOME ONLY/REL TO AAA, BBB")).toThrow("contradicts")
})

test("versions past 2^53 never share a digest: every number is a whole number from 0 to 999999", () => {
  const scheme = (version: string) =>
    `{"schema": "badger.marking-scheme/v1", "name": "t", "version": ${version}, "levels": [{"name": "LOW"}, {"name": "HIGH"}], "groups": []}`
  // JSON.parse reads both as 9007199254740992, so unbounded they would load as one scheme.
  expect(JSON.parse(scheme("9007199254740992")).version).toBe(JSON.parse(scheme("9007199254740993")).version)
  for (const v of ["9007199254740992", "9007199254740993", "1000000", "1e0", "1.0", "-1"])
    expect(() => loadScheme("t.json", scheme(v))).toThrow(`number ${v} is not a whole number from 0 to 999999`)
  expect(loadScheme("a.json", scheme("999999")).digest).not.toBe(loadScheme("b.json", scheme("999998")).digest)
})

test("(preset shapes) two schemes that differ only in the no-release owner never share a digest", () => {
  const scheme = (portion: string) =>
    loadPresetShape(
      "n.json",
      JSON.stringify({
        schema: "badger.marking-scheme/v1", name: "n", version: 1, levels: [{ name: "LOW" }, { name: "HIGH" }],
        groups: [
          { name: "low", kind: "require", position: 1, levels: [0], tokens: [{ token: "HOME ONLY", portion: "HL" }] },
          { name: "high", kind: "require", position: 2, levels: [1], tokens: [{ token: "HOME ONLY", portion: "HH" }] },
          { name: "rel", kind: "release", position: 2, inGroup: "high", home: "AAA", noReleasePortion: portion,
            releaseLine: "REL TO", displayLine: "SHOW TO", countries: ["AAA", "BBB"] },
        ],
      }),
    )
  const low = scheme("HL")
  const high = scheme("HH")
  // The Go loader's digests for the same two files.
  expect(low.digest).toBe("sha256:22d51e72efcc8169081d25cf537c830565d7fe6322421c98d0153ee4d64eb826")
  expect(high.digest).toBe("sha256:ccd178eb292b511caac614644a3fee4384da0dc9ff74ce91eb6f3dc1acae0d61")
  expect(() => parseIn(high, "HIGH//HOME ONLY/REL TO AAA, BBB")).toThrow("contradicts")
  expect(formatIn(low, parseIn(low, "HIGH//HOME ONLY/REL TO AAA, BBB"))).toBe("HIGH//HOME ONLY/REL TO AAA, BBB")
  expect(() => joinIn(low, parseIn(low, "HIGH//HOME ONLY"), parseIn(high, "HIGH//HOME ONLY"))).toThrow(SchemeMismatch)
})

test("(preset shapes) a sourced token of several words is removed whole before the countries", () => {
  const s = loadPresetShape(
    "w.json",
    JSON.stringify({
      schema: "badger.marking-scheme/v1", name: "w", version: 1, levels: [{ name: "LOW" }, { name: "HIGH" }],
      groups: [
        { name: "handling", kind: "require", position: 1, tokens: [{ token: "HOME ONLY", portion: "HO" }] },
        { name: "rel", kind: "release", position: 1, inGroup: "handling", home: "AAA", noReleasePortion: "HO",
          releaseLine: "REL TO", displayLine: "SHOW TO", countries: ["AAA", "BBB"] },
        { name: "src", kind: "sourced", position: 2, tokens: [{ token: "SRC INFO" }] },
      ],
    }),
  )
  const hidden = parseIn(s, "HIGH//SRC INFO")
  expect(hidden.hasFgi).toBe(true)
  expect(hidden.fgi).toEqual([])
  expect(formatIn(s, hidden)).toBe("HIGH//SRC INFO")
  const named = parseIn(s, "HIGH//SRC INFO BBB")
  expect(named.fgi).toEqual(["BBB"])
  expect(formatIn(s, named)).toBe("HIGH//SRC INFO BBB")
})

test("(preset shapes) keys that look like integers keep the Go loader's order in the digest", () => {
  // JavaScript puts integer-like keys first, in numeric order ("2" before "10"); Go sorts keys as
  // strings ("10" before "2"). The canonical form must be Go's.
  const s = loadPresetShape(
    "k.json",
    JSON.stringify({
      schema: "badger.marking-scheme/v1", name: "k", version: 1, levels: [{ name: "LOW" }, { name: "HIGH" }],
      groups: [
        { name: "handling", kind: "require", position: 1, tokens: [{ token: "HOME ONLY", portion: "HO" }] },
        { name: "rel", kind: "release", position: 1, inGroup: "handling", home: "AAA", noReleasePortion: "HO",
          releaseLine: "REL TO", displayLine: "SHOW TO", countries: ["AAA", "BBB", "CCC"],
          tetragraphs: { "10": ["BBB"], "2": ["CCC"] } },
      ],
    }),
  )
  expect(s.digest).toBe("sha256:3918f3b0ff3be6219df11d59a96906826fe8ed3f9e530d6e15f5a3892fd4cd71")
})

test("(preset shapes) equal release and display lines are refused: display-only would read as release", () => {
  const scheme = (releaseLine: string, displayLine: string) =>
    JSON.stringify({
      schema: "badger.marking-scheme/v1", name: "r", version: 1, levels: [{ name: "LOW" }, { name: "HIGH" }],
      groups: [
        { name: "tags", kind: "require", position: 1, tokens: [{ token: "HOME ONLY", portion: "HO" }] },
        { name: "rel", kind: "release", position: 1, inGroup: "tags", home: "AAA", noReleasePortion: "HO",
          releaseLine, displayLine, countries: ["AAA", "BBB"] },
      ],
    })
  for (const [r, d] of [["REL TO", "REL TO"], ["REL", "REL TO"], ["SHOW TO", "SHOW"]])
    expect(() => loadPresetShape("r.json", scheme(r, d))).toThrow("the release and display lines must differ")
  const s = loadPresetShape("r.json", scheme("REL TO", "SHOW TO"))
  const shown = parseIn(s, "HIGH//SHOW TO AAA, BBB")
  expect(shown.relTo).toBeNull()
  expect(shown.displayOnly).toEqual(["AAA", "BBB"])
})
