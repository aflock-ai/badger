// A frozen copy of marking.ts as it was before the engine read its rules from a scheme. The
// differential test (differential.test.ts) holds the scheme-driven port with the us-gov preset to
// exactly this behaviour. Do not edit it to make a test pass: a difference is a regression.
//
// Words that are themselves markings come from the token tables, not from literals here.

import tokens from "../../connectors/internal/marking/tokens.json" with { type: "json" }

type Pair = readonly [banner: string, portion: string]

interface Tables {
  version: number
  levels: { banner: string; portion: string }[]
  sci: { tokens: string[] }
  sap: { prefix: string }
  aea: { tokens: string[] }
  fgi: { token: string }
  dissem: { tokens: Pair[] }
  nonic: { tokens: string[] }
  cui_ldc: { tokens: Pair[] }
  cui_categories: { basic: string[]; specified: string[]; either: string[] }
  release: { countries: string[]; tetragraphs: Record<string, string[]> }
  legacy: { tokens: string[] }
}

const tab = tokens as unknown as Tables
if (tab.version !== 1) throw new Error("marking: tokens.json: unsupported version")

/** Levels, in dominance order. The controlled unclassified level sits above UNCLASSIFIED and below CONFIDENTIAL. */
export const Unclassified = 0
export const Controlled = 1
export const Confidential = 2
export const Secret = 3
export const TopSecret = 4

/** One parsed banner. Set fields are sorted; relTo and displayOnly keep banner order. null means no such line. */
export interface Marking {
  readonly level: number
  readonly sci: readonly string[]
  readonly sap: readonly string[]
  readonly aea: readonly string[]
  /** Country codes after FGI; empty with hasFgi means the source is concealed. */
  readonly fgi: readonly string[]
  readonly hasFgi: boolean
  /** Controlled unclassified categories as written, the specified prefix kept. */
  readonly categories: readonly string[]
  /** Dissemination controls by banner word, without REL TO / DISPLAY ONLY. */
  readonly controls: readonly string[]
  readonly nonic: readonly string[]
  readonly relTo: readonly string[] | null
  readonly displayOnly: readonly string[] | null
}

/** The lowest label: UNCLASSIFIED with nothing else. A session that has read nothing holds it. */
export const bottom: Marking = Object.freeze({
  level: Unclassified,
  sci: [],
  sap: [],
  aea: [],
  fgi: [],
  hasFgi: false,
  categories: [],
  controls: [],
  nonic: [],
  relTo: null,
  displayOnly: null,
})

/** Every dissemination control, classified first, in canonical order. */
const controlOrder: readonly Pair[] = [...tab.dissem.tokens, ...tab.cui_ldc.tokens]

/** The banner word of the control whose portion mark is `portion`. */
export function control(portion: string): string {
  const pair = controlOrder.find((p) => p[1] === portion)
  if (!pair) throw new Error(`marking: no dissemination control with portion mark ${portion}`)
  return pair[0]
}

/** The no-foreign-release control: release to the USA only. */
const noForeign = control("NF")
const specifiedPrefix = "SP-"

export class MarkingError extends Error {
  override name = "MarkingError"
}

/** Reads a configured banner: full words, never portion abbreviations; a retired marking is refused. */
export function parse(input: string): Marking {
  return read(input)
}

// Everything a banner may hold. It is printed outside the untrusted-content block, so nothing else may pass.
const maxBanner = 512
const bannerChars = new RegExp(`^[A-Z0-9 ,/-]{1,${maxBanner}}$`)
const sciToken = /^[A-Z0-9]+(-[A-Z0-9]+)?$/
// A program identifier ends in a letter, digit or hyphen: a trailing space would not survive a
// banner's trim, so the label would not read back.
const sapToken = /^[A-Z0-9](?:[A-Z0-9 -]{0,61}[A-Z0-9-])?$/

interface Draft {
  level: number
  sci: string[]
  sap: string[]
  aea: string[]
  fgi: string[]
  hasFgi: boolean
  categories: string[]
  controls: string[]
  nonic: string[]
  relTo: string[] | null
  displayOnly: string[] | null
}

function read(input: string): Marking {
  const s = input.trim().toUpperCase()
  if (!bannerChars.test(s)) throw new MarkingError("a marking holds only letters, digits, spaces, commas, hyphens and slashes")
  const groups = s.split("//")
  const m: Draft = {
    level: -1,
    sci: [],
    sap: [],
    aea: [],
    fgi: [],
    hasFgi: false,
    categories: [],
    controls: [],
    nonic: [],
    relTo: null,
    displayOnly: null,
  }
  if (groups.some((g) => tab.legacy.tokens.includes(g)))
    throw new MarkingError("that marking is retired (DoDI 5200.48); configure a current one")
  m.level = tab.levels.findIndex((l) => groups[0] === l.banner)
  if (m.level < 0) throw new MarkingError(`unknown classification level ${JSON.stringify(groups[0])}`)
  let last = 0
  groups.slice(1).forEach((g, gi) => {
    const kind = group(m, g.split("/"), gi === 0)
    if (kind <= last) throw new MarkingError(`marking group ${JSON.stringify(g)} is out of order or repeated`)
    last = kind
  })
  if (m.relTo !== null && m.controls.includes(noForeign)) throw new MarkingError(`REL TO contradicts ${noForeign}`)
  // Below CONFIDENTIAL only the controlled-unclassified dissemination controls apply, so a joined
  // label always prints and reads back the same.
  if (m.level < Confidential)
    for (const c of m.controls)
      if (!tab.cui_ldc.tokens.some((p) => p[0] === c)) throw new MarkingError(`${c} is a classified dissemination control`)
  return Object.freeze(m)
}

/** Records one //-separated group and returns its place in the order SCI, SAP, AEA, FGI, categories, dissemination, non-IC. */
function group(m: Draft, toks: string[], first: boolean): number {
  const all = (f: (t: string) => boolean) => toks.every(f)
  const classified = m.level >= Confidential
  if (classified && all((t) => sciToken.test(t) && tab.sci.tokens.includes(t.split("-")[0]))) {
    m.sci = sorted(toks)
    return 1
  }
  if (classified && all((t) => t.startsWith(tab.sap.prefix) && sapToken.test(t.slice(tab.sap.prefix.length)))) {
    m.sap = sorted(toks)
    return 2
  }
  if (m.level !== Controlled && all((t) => tab.aea.tokens.includes(t))) {
    m.aea = sorted(toks)
    return 3
  }
  if (m.level !== Controlled && toks.length === 1 && (toks[0] === tab.fgi.token || toks[0].startsWith(tab.fgi.token + " "))) {
    m.hasFgi = true
    for (const c of fields(toks[0]).slice(1)) {
      if (!tab.release.countries.includes(c) && !tab.release.tetragraphs[c])
        throw new MarkingError(`unknown country code ${JSON.stringify(c)} in FGI`)
      m.fgi.push(c)
    }
    return 4
  }
  if (m.level === Controlled && first && all(validCategory)) {
    m.categories = [...toks].sort(byCategory)
    return 5
  }
  if (m.level !== Controlled && all((t) => tab.nonic.tokens.includes(t))) {
    m.nonic = sorted(toks)
    return 7
  }
  for (const t of toks) {
    if (t.startsWith("REL TO ")) {
      const l = releaseList(t.slice("REL TO ".length))
      if (m.relTo !== null) throw new MarkingError("REL TO appears more than once")
      m.relTo = l
    } else if (t.startsWith("DISPLAY ONLY ")) {
      const l = releaseList(t.slice("DISPLAY ONLY ".length))
      if (m.displayOnly !== null) throw new MarkingError("DISPLAY ONLY appears more than once")
      m.displayOnly = l
    } else {
      const table = m.level === Controlled ? tab.cui_ldc.tokens : controlOrder
      const pair = table.find((p) => t === p[0])
      if (!pair) throw new MarkingError(`unknown marking token ${JSON.stringify(t)}`)
      if (!m.controls.includes(pair[0])) m.controls.push(pair[0])
    }
  }
  return 6
}

function validCategory(t: string) {
  const sp = t.startsWith(specifiedPrefix)
  const c = sp ? t.slice(specifiedPrefix.length) : t
  if (tab.cui_categories.either.includes(c)) return true
  return sp ? tab.cui_categories.specified.includes(c) : tab.cui_categories.basic.includes(c)
}

/** Specified categories sort before basic ones, each alphabetically. */
function byCategory(a: string, b: string) {
  const key = (c: string) => (c.startsWith(specifiedPrefix) ? "0" : "1") + c
  return compare(key(a), key(b))
}

/** "USA, AUS, GBR, FVEY": USA first, then trigraphs, then tetragraphs, each alphabetical and known. */
function releaseList(s: string): string[] {
  const l = s.split(",").map((c) => c.trim())
  if (l[0] !== "USA") throw new MarkingError("a release list must start with USA")
  l.slice(1).forEach((c, i) => {
    const prev = l[i]
    const tetra = Object.hasOwn(tab.release.tetragraphs, c)
    const prevTetra = Object.hasOwn(tab.release.tetragraphs, prev)
    if ((!tetra && !tab.release.countries.includes(c)) || c === "USA")
      throw new MarkingError(`unknown or repeated country code ${JSON.stringify(c)}`)
    if (i > 0 && ((prevTetra && !tetra) || (prevTetra === tetra && prev >= c)))
      throw new MarkingError(`release list out of order at ${JSON.stringify(c)}`)
  })
  return l
}

/** The canonical banner. */
export function format(m: Marking): string {
  const g = [tab.levels[m.level].banner]
  const add = (l: readonly string[]) => {
    if (l.length) g.push(l.join("/"))
  }
  add(m.sci)
  add(m.sap)
  add(m.aea)
  if (m.hasFgi) g.push([tab.fgi.token, ...m.fgi].join(" "))
  add(m.categories)
  const d: string[] = []
  for (const [banner] of controlOrder) if (m.controls.includes(banner) && !d.includes(banner)) d.push(banner)
  if (m.relTo !== null) d.push("REL TO " + m.relTo.join(", "))
  if (m.displayOnly !== null) d.push("DISPLAY ONLY " + m.displayOnly.join(", "))
  add(d)
  add(m.nonic)
  return g.join("//")
}

/**
 * Whether a system or sink accredited at `a` may hold content marked `b` (no write down): a's level
 * is at least b's; a carries every SCI, SAP, AEA, FGI, non-IC and dissemination control b carries;
 * FGI with its countries concealed is held only by concealed FGI; a's foreign release is no wider
 * than b's; and below CONFIDENTIAL a carries b's categories.
 */
export function dominates(a: Marking, b: Marking): boolean {
  if (
    a.level < b.level ||
    !superset(a.sci, b.sci) ||
    !superset(a.sap, b.sap) ||
    !superset(a.aea, b.aea) ||
    !superset(a.nonic, b.nonic) ||
    !superset(a.controls, b.controls) ||
    (b.hasFgi && (!a.hasFgi || (a.fgi.length > 0 && (b.fgi.length === 0 || !superset(a.fgi, b.fgi))))) ||
    (a.level < Confidential && !superset(a.categories, b.categories))
  )
    return false
  return subset(release(a), release(b)) && subset(display(a), display(b))
}

/** Join's refusal, as Go's ErrNoBanner: no banner prints the combination. */
export class NoBanner extends Error {
  override name = "NoBanner"
  constructor(
    message = "these markings cannot be combined: no banner prints controlled unclassified information with FGI, atomic-energy or non-IC markings",
  ) {
    super(message)
  }
}

/**
 * A label that dominates both: the high-water mark after reading a and b. It is the least such
 * label except where it marks higher on purpose (disjoint REL TO lists become no foreign release; a
 * display restriction only one side carries becomes DISPLAY ONLY USA), as in Go. It throws
 * `NoBanner`, and returns nothing, when the join would sit at the controlled-unclassified level
 * and carry FGI, AEA or non-IC groups: no banner prints that, and raising the level is not this
 * function's call. A caller fails closed on it.
 */
export function join(a: Marking, b: Marking): Marking {
  const j: Draft = {
    level: Math.max(a.level, b.level),
    sci: union(a.sci, b.sci),
    sap: union(a.sap, b.sap),
    aea: union(a.aea, b.aea),
    nonic: union(a.nonic, b.nonic),
    controls: union(a.controls, b.controls),
    hasFgi: a.hasFgi || b.hasFgi,
    fgi: [],
    categories: [],
    relTo: null,
    displayOnly: null,
  }
  // A controlled-unclassified banner has no place for FGI, AEA or non-IC groups.
  if (j.level === Controlled && (j.hasFgi || j.aea.length > 0 || j.nonic.length > 0)) throw new NoBanner()
  if (j.level < Confidential) j.categories = union(a.categories, b.categories).sort(byCategory)
  if (j.hasFgi && !((a.hasFgi && a.fgi.length === 0) || (b.hasFgi && b.fgi.length === 0))) j.fgi = union(a.fgi, b.fgi)
  const ra = release(a)
  const rb = release(b)
  if (subset(ra, rb)) j.relTo = a.relTo && [...a.relTo]
  else if (subset(rb, ra)) j.relTo = b.relTo && [...b.relTo]
  else {
    // Neither is a subset, so neither is unrestricted.
    const l = [...ra!].filter((c) => rb!.has(c) && c !== "USA").sort(compare)
    if (l.length === 0) j.controls = union(j.controls, [noForeign])
    else j.relTo = ["USA", ...l]
  }
  if (j.controls.includes(noForeign)) j.relTo = null
  // Display: who may see it without release. The join may show it only where both may.
  const da = display(a)
  const db = display(b)
  if (da !== null || db !== null) {
    let d = da
    const rj = release(j)
    if (d === null) d = db
    else if (db !== null) d = new Set([...d].filter((c) => db.has(c)))
    const extra = [...d!].filter((c) => c !== "USA" && (rj === null || !rj.has(c))).sort(compare)
    // An unrestricted release would let it be shown to anyone: restrict it to the list.
    if (extra.length > 0 || rj === null) j.displayOnly = ["USA", ...extra]
  }
  // A label that does not read back cannot be checked or recorded: too long a banner is refused.
  const banner = format(j)
  if (banner.length > maxBanner)
    throw new NoBanner(`these markings cannot be combined: their joined banner would be longer than ${maxBanner} characters`)
  return Object.freeze(j)
}

/** Who may see the content: those it may be released to, plus a DISPLAY ONLY list. null means anyone. */
function display(m: Marking): Set<string> | null {
  const r = release(m)
  if (r === null) return null
  const d = new Set(r)
  for (const c of expand(m.displayOnly ?? [])) d.add(c)
  return d
}

/** The countries the marking allows release to; null means unrestricted. */
function release(m: Marking): Set<string> | null {
  if (m.controls.includes(noForeign)) return new Set(["USA"])
  if (m.relTo !== null) return expand(m.relTo)
  if (m.level >= Confidential) return new Set(["USA"]) // no release decision recorded
  if (m.displayOnly !== null) return new Set(["USA"]) // display, not release, to the listed countries
  return null
}

function expand(l: readonly string[]): Set<string> {
  const s = new Set<string>()
  for (const c of l) {
    const members = Object.hasOwn(tab.release.tetragraphs, c) ? tab.release.tetragraphs[c] : [c]
    for (const x of members) s.add(x)
  }
  return s
}

/** null is the universe. */
function subset(a: Set<string> | null, b: Set<string> | null) {
  if (b === null) return true
  if (a === null) return false
  for (const c of a) if (!b.has(c)) return false
  return true
}

function superset(a: readonly string[], b: readonly string[]) {
  return b.every((x) => a.includes(x))
}

function union(a: readonly string[], b: readonly string[]) {
  return sorted([...a, ...b])
}

/** Byte order, as Go's sort.Strings, not locale order. */
function compare(a: string, b: string) {
  return a < b ? -1 : a > b ? 1 : 0
}

function sorted(s: readonly string[]) {
  return [...new Set(s)].sort(compare)
}

function fields(s: string) {
  return s.split(/\s+/).filter(Boolean)
}

/** Every dissemination control as [banner, portion], for callers that build markings from vectors. */
export function controls(): readonly Pair[] {
  return controlOrder
}

/** Tetragraph membership from the token tables. */
export function tetragraphs(): Readonly<Record<string, readonly string[]>> {
  return tab.release.tetragraphs
}
