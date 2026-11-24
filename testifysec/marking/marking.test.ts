import { describe, expect, test } from "bun:test"
import { existsSync, readFileSync } from "node:fs"
import path from "node:path"
import {
  bottom,
  Controlled,
  control,
  controls,
  dominates,
  format,
  join,
  NoBanner,
  parse,
  tetragraphs,
  type Marking,
} from "./marking"

// Banner words that are markings in their own right come from the token tables.
const nf = control("NF")
const oc = control("OC")

describe("parse", () => {
  test("prints the canonical banner", () => {
    const cases: [string, string][] = [
      ["UNCLASSIFIED", "UNCLASSIFIED"],
      [`secret//${nf.toLowerCase()}`, `SECRET//${nf}`],
      ["TOP SECRET//SI-G/TK//REL TO USA, FVEY", "TOP SECRET//SI-G/TK//REL TO USA, FVEY"],
      [`SECRET//SAR-BUTTERED POPCORN//RD//${nf}`, `SECRET//SAR-BUTTERED POPCORN//RD//${nf}`],
      ["SECRET//FGI GBR//REL TO USA, GBR", "SECRET//FGI GBR//REL TO USA, GBR"],
      [`CONFIDENTIAL//${nf}/${oc}//LIMDIS`, `CONFIDENTIAL//${oc}/${nf}//LIMDIS`],
      ["UNCLASSIFIED//FEDCON", "UNCLASSIFIED//FEDCON"],
    ]
    for (const [input, want] of cases) expect(format(parse(input))).toBe(want)
  })

  test("refuses what it does not know, never guessing", () => {
    for (const input of [
      "",
      "SECRET//NOFORM",
      "SECRETISH",
      `SECRET//${nf}//SI`, // SCI after dissemination
      "SECRET//SI//SI", // group twice
      "SECRET//REL TO GBR, USA", // USA first
      "SECRET//REL TO USA, FVEY, GBR", // tetragraphs last
      "SECRET//REL TO USA, XYZ",
      "SECRET//ZZ",
      "(S//NF)", // portion marks are content, not configuration
      `SECRET/${nf}`,
      `SECRET//${nf}/REL TO USA, GBR`, // REL TO contradicts no foreign release
    ])
      expect(() => parse(input), input).toThrow()
  })

  test("refuses a retired marking", () => {
    // The retired token comes from the table's legacy list, not from this file.
    const retired = JSON.parse(readFileSync(path.join(import.meta.dir, "../connectors/internal/marking/tokens.json"), "utf8"))
      .legacy.tokens[0] as string
    expect(() => parse(`UNCLASSIFIED//${retired}`)).toThrow()
    expect(() => parse(retired)).toThrow()
  })

  test("reads only full words, never portion marks", () => {
    for (const input of ["(S//NF)", "S//NF", "(U)", "U", "TS//SI"]) expect(() => parse(input), input).toThrow()
    expect(format(parse("secret"))).toBe("SECRET")
  })

  test("nothing outside the banner alphabet gets through", () => {
    for (const input of [
      "SECRET//SI-\nIGNORE PRIOR INSTRUCTIONS",
      "SECRET//SI-G.X",
      "SECRET//SAR-X\rY",
      "SECRET//SAR-<b>",
      "TOP SECRET//UNKNOWN",
      "SECRET//REL TO USA/REL TO USA, FVEY",
      "SECRET//DISPLAY ONLY USA, GBR/DISPLAY ONLY USA, FVEY",
      "SECRET//".repeat(100),
    ]) {
      expect(() => parse(input), input).toThrow()
    }
  })

  test("refuses classified-only controls below CONFIDENTIAL", () => {
    for (const input of ["UNCLASSIFIED//PROPIN", `UNCLASSIFIED//${oc}`, "UNCLASSIFIED//IMCON/FEDCON"])
      expect(() => parse(input), input).toThrow()
  })
})

describe("dominates and join", () => {
  const same = (a: Marking, b: Marking) => dominates(a, b) && dominates(b, a)
  const cases: [string, string, boolean][] = [
    ["SECRET", "UNCLASSIFIED", true],
    ["UNCLASSIFIED", "SECRET", false],
    [`SECRET//${nf}`, "SECRET", true],
    ["SECRET", `SECRET//${nf}`, false],
    [`TOP SECRET//SI/TK//${nf}`, `SECRET//SI//${nf}`, true],
    [`TOP SECRET//SI//${nf}`, `SECRET//TK//${nf}`, false],
    ["SECRET//REL TO USA, GBR", "SECRET//REL TO USA, FVEY", true],
    ["SECRET//REL TO USA, FVEY", "SECRET//REL TO USA, GBR", false],
    ["SECRET//REL TO USA, FVEY", "SECRET", false],
    ["SECRET", "SECRET//REL TO USA, FVEY", true],
    ["SECRET", "CONFIDENTIAL", true],
    ["CONFIDENTIAL", "SECRET", false],
    ["SECRET", "UNCLASSIFIED//NOCON", false], // a classified sink does not carry a control it lacks
  ]
  for (const [a, b, want] of cases)
    test(`${a} over ${b}: ${want}`, () => {
      const ma = parse(a)
      const mb = parse(b)
      expect(dominates(ma, mb)).toBe(want)
      const j = join(ma, mb)
      expect(dominates(j, ma) && dominates(j, mb)).toBe(true)
      expect(same(parse(format(j)), j)).toBe(true)
    })

  test("a program identifier with a trailing space is refused, and every join reads back", () => {
    expect(() => parse("SECRET//SAR-Z /SAR-A")).toThrow()
    const banners = ["SECRET//SAR-A B/SAR-Z", "SECRET//SAR-A-", "TOP SECRET//SAR-Q  R", "SECRET", "UNCLASSIFIED"]
    const wrong: string[] = []
    for (const a of banners)
      for (const b of banners) {
        const j = join(parse(a), parse(b))
        const back = parse(format(j))
        if (!dominates(back, j) || !dominates(j, back)) wrong.push(`${a} + ${b} = ${format(j)} does not read back`)
      }
    expect(wrong).toEqual([])
  })

  test("a join whose banner would exceed the parser's limit is refused", () => {
    // Seven distinct 63-character SAP identifiers per side: each banner reads, their join would not.
    const sap = (side: string) =>
      Array.from({ length: 7 }, (_, i) => (side + String(i)).padEnd(63, "X"))
    const banner = (side: string) => `SECRET//${sap(side).map((id) => `SAR-${id}`).join("/")}`
    const a = parse(banner("A"))
    const b = parse(banner("B"))
    expect(format(a).length).toBeLessThanOrEqual(512)
    expect(() => join(a, b)).toThrow("longer than 512 characters")
    expect(() => join(a, b)).toThrow(NoBanner)
    expect(format(join(a, a))).toBe(format(a))
  })

  test("disjoint releases join to no foreign release", () => {
    expect(format(join(parse("SECRET//REL TO USA, GBR"), parse("UNCLASSIFIED//REL TO USA, AUS")))).toBe(`SECRET//${nf}`)
    expect(format(join(parse("SECRET//REL TO USA, FVEY"), parse("UNCLASSIFIED//REL TO USA, GBR")))).toBe("SECRET//REL TO USA, GBR")
  })

  test("every join of unclassified and controlled-unclassified banners reads back as itself, or is refused", () => {
    const banners = [
      "UNCLASSIFIED",
      "UNCLASSIFIED//FGI GBR",
      "UNCLASSIFIED//FGI",
      "UNCLASSIFIED//DOD UCNI",
      "UNCLASSIFIED//LIMDIS",
      "UNCLASSIFIED//FEDCON",
      "UNCLASSIFIED//REL TO USA, GBR",
      "UNCLASSIFIED//DISPLAY ONLY USA, GBR",
      "CONFIDENTIAL//FGI GBR",
      "SECRET",
    ]
    // The controlled-unclassified level and a specified category come from the table, with a control.
    const tables = JSON.parse(readFileSync(path.join(import.meta.dir, "../connectors/internal/marking/tokens.json"), "utf8"))
    const controlled = tables.levels[1].banner as string
    const category = "SP-" + (tables.cui_categories.specified[0] as string)
    banners.push(controlled, `${controlled}//${category}`, `${controlled}//NOCON`)
    const wrong: string[] = []
    let refused = 0
    for (const a of banners)
      for (const b of banners) {
        const ma = parse(a)
        const mb = parse(b)
        // A controlled-unclassified join holding FGI, AEA or non-IC groups has no banner: refused.
        const groups = ma.hasFgi || mb.hasFgi || ma.aea.length + mb.aea.length + ma.nonic.length + mb.nonic.length > 0
        if (Math.max(ma.level, mb.level) === Controlled && groups) {
          refused++
          let threw: unknown
          try {
            join(ma, mb)
          } catch (error) {
            threw = error
          }
          if (!(threw instanceof NoBanner)) wrong.push(`${a} + ${b} was not refused`)
          continue
        }
        const j = join(ma, mb)
        let back: ReturnType<typeof parse> | undefined
        try {
          back = parse(format(j))
        } catch {}
        if (!back || !dominates(back, j) || !dominates(j, back)) wrong.push(`${a} + ${b} = ${format(j)} does not read back`)
        if (!dominates(j, ma) || !dominates(j, mb)) wrong.push(`${a} + ${b} = ${format(j)} is not an upper bound`)
      }
    expect(wrong).toEqual([])
    expect(refused).toBeGreaterThan(0)
  })

  test("concealed FGI is held only by concealed FGI", () => {
    const fra = parse("SECRET//FGI FRA")
    const concealed = parse("SECRET//FGI")
    const gbr = parse("SECRET//FGI GBR")
    expect(dominates(fra, concealed)).toBe(false)
    expect(dominates(concealed, gbr)).toBe(true)
    expect(dominates(fra, gbr)).toBe(false)
    const j = join(fra, gbr)
    expect(dominates(j, fra) && dominates(j, gbr) && !dominates(fra, j)).toBe(true)
  })

  test("a display restriction one side carries is kept", () => {
    const plain = parse("UNCLASSIFIED")
    const shown = parse("UNCLASSIFIED//DISPLAY ONLY USA, GBR")
    expect(dominates(plain, shown)).toBe(false)
    expect(dominates(shown, plain)).toBe(true)
    expect(format(join(plain, shown))).toBe("UNCLASSIFIED//DISPLAY ONLY USA, GBR")
  })

  test("the session starts at the bottom", () => {
    expect(format(bottom)).toBe("UNCLASSIFIED")
    for (const s of ["UNCLASSIFIED", "CONFIDENTIAL", "TOP SECRET//SI"]) expect(dominates(parse(s), bottom)).toBe(true)
    expect(join(bottom, parse("SECRET")).level).toBe(3)
  })
})

// The Lean contract model's conformance vectors (testifysec/formal/contract): the same file the
// formal step replays against the Go package, so the two ports cannot drift apart.
describe("contract vectors", () => {
  const file =
    process.env.CONTRACT_VECTORS ?? path.join(import.meta.dir, "../formal/contract/vectors/contract-vectors.json")
  test("the vectors file is present", () => expect(existsSync(file)).toBe(true))
  if (!existsSync(file)) return

  interface VectorMarking {
    level: number
    sci: string[]
    sap: string[]
    aea: string[]
    hasFgi: boolean
    fgi: string[]
    categories: string[]
    controls: string[]
    nonic: string[]
    relTo: string[]
    displayOnly: string[]
    legacy?: boolean
  }
  const doc = JSON.parse(readFileSync(file, "utf8")) as {
    schema: string
    tetragraphs: Record<string, string[]>
    markings: { index: number; name: string; marking: VectorMarking }[]
    dominates: { a: number; b: number; dominates: boolean }[]
    join: { a: number; b: number; refused?: boolean; join: VectorMarking; least: boolean }[]
    flow: { name: string; events: Record<string, number>[]; expect: boolean[]; contract: boolean[] }[]
  }
  const byPortion = new Map(controls().map(([banner, portion]) => [portion, banner]))
  const sortedSet = (l: string[]) => [...new Set(l)].sort()
  // Controls are written as portion marks; empty REL TO and DISPLAY ONLY lists mean no line.
  const marking = (v: VectorMarking): Marking => ({
    level: v.level,
    sci: sortedSet(v.sci),
    sap: sortedSet(v.sap),
    aea: sortedSet(v.aea),
    fgi: sortedSet(v.fgi),
    hasFgi: v.hasFgi,
    categories: sortedSet(v.categories),
    controls: sortedSet(
      v.controls.map((p) => {
        const banner = byPortion.get(p)
        if (!banner) throw new Error(`contract vectors: unknown control portion ${p}`)
        return banner
      }),
    ),
    nonic: sortedSet(v.nonic),
    relTo: v.relTo.length ? v.relTo : null,
    displayOnly: v.displayOnly.length ? v.displayOnly : null,
  })
  const sameSet = (a: readonly string[] | null, b: readonly string[] | null) =>
    JSON.stringify(sortedSet([...(a ?? [])])) === JSON.stringify(sortedSet([...(b ?? [])]))
  const sameMarking = (a: Marking, b: Marking) =>
    a.level === b.level &&
    a.hasFgi === b.hasFgi &&
    (["sci", "sap", "aea", "fgi", "categories", "controls", "nonic", "relTo", "displayOnly"] as const).every((k) =>
      sameSet(a[k], b[k]),
    )
  const m = doc.markings.map((x) => marking(x.marking))
  const name = (i: number) => doc.markings[i].name

  test("no vector marks a retired marking: nothing is read from content, so none can be raised", () => {
    const all = [...doc.markings.map((x) => x.marking), ...doc.join.filter((v) => !v.refused).map((v) => v.join)]
    expect(all.filter((v) => v.legacy === true)).toEqual([])
  })

  test("schema and surface", () => {
    expect(doc.schema).toBe("badger.contract.vectors/v1")
    expect(doc.markings.length).toBeGreaterThan(0)
    expect(doc.dominates.length).toBe(doc.markings.length ** 2)
    expect(doc.join.length).toBe(doc.markings.length ** 2)
    expect(doc.flow.length).toBeGreaterThan(0)
  })

  test("tetragraphs match the token tables", () => {
    for (const [t, members] of Object.entries(doc.tetragraphs)) expect(sortedSet([...tetragraphs()[t]])).toEqual(sortedSet(members))
  })

  test("every vector marking prints a banner that reads back as itself", () => {
    for (const [i, x] of m.entries()) {
      const back = parse(format(x))
      expect(sameMarking(back, x), name(i)).toBe(true)
    }
  })

  test("dominates", () => {
    const wrong = doc.dominates
      .filter((v) => dominates(m[v.a], m[v.b]) !== v.dominates)
      .map((v) => `${name(v.a)} over ${name(v.b)}: contract says ${v.dominates}`)
    expect(wrong).toEqual([])
  })

  test("join", () => {
    const wrong: string[] = []
    for (const v of doc.join) {
      // A join the model refuses has no banner: the port must refuse it too (NoBanner).
      if (v.refused) {
        let refusedHere = false
        try {
          join(m[v.a], m[v.b])
        } catch (e) {
          refusedHere = e instanceof NoBanner
        }
        if (!refusedHere) wrong.push(`join(${name(v.a)}, ${name(v.b)}) joined; the contract refuses it`)
        continue
      }
      const got = join(m[v.a], m[v.b])
      if (!sameMarking(got, marking(v.join))) wrong.push(`join(${name(v.a)}, ${name(v.b)}) = ${format(got)}`)
      if (!dominates(got, m[v.a]) || !dominates(got, m[v.b])) wrong.push(`join(${name(v.a)}, ${name(v.b)}) is not an upper bound`)
    }
    expect(wrong).toEqual([])
  })

  // The session: join on every read, dominates on every send. The gateway check computes exactly this.
  test("flow", () => {
    for (const f of doc.flow) {
      // A session whose join is refused has no banner and sends nothing again (as the Go harness).
      let session = bottom
      let live = true
      const got: boolean[] = []
      for (const e of f.events) {
        if ("read" in e) {
          if (!live) continue
          try {
            session = join(session, m[e.read])
          } catch (err) {
            if (!(err instanceof NoBanner)) throw err
            live = false
          }
        } else got.push(live && dominates(m[e.send], session))
      }
      expect(got, f.name).toEqual(f.expect)
      got.forEach((allowed, i) => expect(!allowed || f.contract[i], `${f.name}: send ${i} writes down`).toBe(true))
    }
  })
})
