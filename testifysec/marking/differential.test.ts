import { expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import path from "node:path"
import * as engine from "./marking"
import * as legacy from "./testdata/legacy"

// The scheme-driven port, with the us-gov preset, against a frozen copy of the port before it
// (testdata/legacy.ts), as the Go differential test does: banners built from the token tables, near
// misses included, must parse to the same marking or be refused by both, and pairs of markings must
// get the same dominates and join.
const tab = JSON.parse(readFileSync(path.join(import.meta.dir, "../connectors/internal/marking/tokens.json"), "utf8"))

function candidates(): string[][] {
  const sci = tab.sci.tokens.flatMap((t: string) => [t, `${t}-G`, `${t}-G1-X`, `${t}-`])
  const sap = ["BUTTERED POPCORN", "X-", "X ", "", "-A"].map((x) => tab.sap.prefix + x)
  const f = tab.fgi.token
  const fgi = [f, `${f} GBR`, `${f} FRA GBR`, `${f} FVEY`, `${f} XYZ`, `${f}GBR`]
  const cat = [
    ...tab.cui_categories.basic.flatMap((t: string, i: number) => (i % 7 === 0 ? [t, "SP-" + t] : [t])),
    ...tab.cui_categories.specified.flatMap((t: string, i: number) => (i % 5 === 0 ? ["SP-" + t, t] : ["SP-" + t])),
    ...tab.cui_categories.either.flatMap((t: string) => [t, "SP-" + t]),
  ]
  const ctl = [...tab.dissem.tokens, ...tab.cui_ldc.tokens].flat()
  const rel = [
    "REL TO USA, GBR", "REL TO USA, FVEY", "REL TO USA, AUS, GBR, FVEY", "REL TO GBR, USA", "REL TO USA",
    "REL TO USA, GBR, AUS", "REL TO USA, NATO, FVEY", "REL TO USA, XYZ", "DISPLAY ONLY USA, GBR", "DISPLAY ONLY USA, FVEY",
    "DISPLAY ONLY GBR", "REL TO USA, USA",
  ]
  const junk = ["ZZ", "", " ", "SECRETISH", ...tab.legacy.tokens]
  return [sci, sap, [...tab.aea.tokens], fgi, cat, [...tab.nonic.tokens], ctl, rel, junk]
}

// A seeded generator, so the corpus is the same on every run.
function rng(seed: number) {
  return () => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff
    return seed / 0x80000000
  }
}

function banners(): string[] {
  const cands = candidates()
  const all = cands.flat()
  const out: string[] = []
  for (const l of tab.levels) {
    out.push(l.banner, l.banner.toLowerCase(), ` ${l.banner} `)
    for (const c of all) out.push(`${l.banner}//${c}`)
  }
  const r = rng(1)
  const pick = (g: string[]) => g[Math.floor(r() * g.length)]
  for (let i = 0; i < 20000; i++) {
    const l = tab.levels[Math.floor(r() * tab.levels.length)].banner
    const g1 = cands[Math.floor(r() * (cands.length - 1))]
    out.push(`${l}//${pick(g1)}/${pick(g1)}`)
    const parts = [l]
    for (let k = 0, n = 1 + Math.floor(r() * 3); k < n; k++) parts.push(pick(cands[Math.floor(r() * cands.length)]))
    out.push(parts.join("//"))
  }
  return out
}

const attempt = <T>(f: () => T): { ok: true; v: T } | { ok: false; e: unknown } => {
  try {
    return { ok: true, v: f() }
  } catch (e) {
    return { ok: false, e }
  }
}

test("parse and banner match the frozen port", () => {
  const wrong: string[] = []
  let parsed = 0
  let refused = 0
  for (const b of banners()) {
    const want = attempt(() => legacy.parse(b))
    const got = attempt(() => engine.parse(b))
    if (want.ok !== got.ok) wrong.push(`${b}: engine ${got.ok}, legacy ${want.ok}`)
    else if (!want.ok) refused++
    else if (!Bun.deepEquals(got.ok && got.v, want.v, true) || engine.format(got.ok ? got.v : engine.bottom) !== legacy.format(want.v))
      wrong.push(`${b}: differs`)
    else parsed++
  }
  console.log(`${parsed} banners parse, ${refused} refused, the same way in both`)
  expect(wrong.slice(0, 10)).toEqual([])
  expect(parsed).toBeGreaterThan(500)
  expect(refused).toBeGreaterThan(500)
}, 120_000)

test("dominates and join match the frozen port", () => {
  const seen = new Set<string>()
  const ms: legacy.Marking[] = []
  for (const b of banners()) {
    const r = attempt(() => legacy.parse(b))
    if (r.ok && !seen.has(legacy.format(r.v))) {
      seen.add(legacy.format(r.v))
      ms.push(r.v)
    }
  }
  const sample = ms.filter((_, i) => i % Math.max(1, Math.floor(ms.length / 300)) === 0)
  const wrong: string[] = []
  for (const a of sample)
    for (const b of sample) {
      if (engine.dominates(a, b) !== legacy.dominates(a, b)) wrong.push(`dominates(${legacy.format(a)}, ${legacy.format(b)})`)
      const want = attempt(() => legacy.join(a, b))
      const got = attempt(() => engine.join(a, b))
      const same =
        want.ok && got.ok
          ? Bun.deepEquals(got.v, want.v, true)
          : !want.ok && !got.ok && (want.e as Error).message === (got.e as Error).message
      if (!same) wrong.push(`join(${legacy.format(a)}, ${legacy.format(b)})`)
    }
  console.log(`${sample.length} markings, ${sample.length ** 2} pairs`)
  expect(wrong.slice(0, 10)).toEqual([])
  expect(sample.length).toBeGreaterThan(200)
}, 120_000)
