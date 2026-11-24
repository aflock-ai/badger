// A TypeScript port of testifysec/connectors/internal/marking (engine.go, scheme.go): the same
// scheme files load to the same schemes with the same digests, a banner a connector prints parses
// here to the same label, and dominates/join decide the same way. A connector's marking is one
// configured banner set by the administrator, and nothing is read from service content, so only
// configured banners parse. The Lean contract model's vectors (testifysec/formal/contract/vectors)
// are replayed against both ports. Markings are labels for people and policy; they are not a
// security boundary.
//
// Every rule that names a level, a token or a country comes from the scheme (scheme.ts); the kinds
// of group are the code here. Words that are themselves markings come from the tables, not from
// literals.

import { preset, type Group, type Scheme, type Token } from "./scheme.js"

export { loadPresetShape, loadScheme, preset, presetNames, SchemeError, type Scheme } from "./scheme.js"
export { deployment, type Deployment } from "./deployment.js"

/** The default scheme, the one a process uses unless it is configured otherwise. */
const usGov = preset("us-gov")
let current: Scheme | undefined

function process(): Scheme {
  return current ?? usGov
}

/** Levels of the us-gov scheme, in dominance order. */
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
  /** Require groups no field above names (another scheme's groups), each sorted. Absent under us-gov. */
  readonly tags?: Readonly<Record<string, readonly string[]>>
  /** The digest of the scheme the marking was read under. Absent is the us-gov preset. */
  readonly scheme?: string
}

/** The lowest us-gov label: UNCLASSIFIED with nothing else. A session that has read nothing holds it. */
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

export class MarkingError extends Error {
  override name = "MarkingError"
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

/** The refusal to compare or combine markings read under different schemes, as Go's ErrSchemeMismatch. */
export class SchemeMismatch extends Error {
  override name = "SchemeMismatch"
  constructor() {
    super("these markings belong to different classification schemes and are never compared or combined")
  }
}

/**
 * Sets the scheme this process uses, once, before it reads any label. The same scheme again is
 * allowed; any other change is refused: a deployment has one scheme, and changing it is a migration.
 */
export function configure(s: Scheme) {
  if (current === undefined) current = s
  else if (current.digest !== s.digest)
    throw new Error(`marking: this process already uses the ${current.name} scheme (${current.digest}); it cannot change to ${s.name} (${s.digest})`)
}

/** The process scheme's lowest label. */
export function lowest(): Marking {
  const s = process()
  return s.digest === usGov.digest ? bottom : Object.freeze({ ...bottom, scheme: s.digest })
}

const maxBanner = 512
const bannerChars = new RegExp(`^[A-Z0-9 ,/-]{1,${maxBanner}}$`)
// An opaque identifier ends in a letter, digit or hyphen: a trailing space would not survive a
// banner's trim, so the label would not read back.
const opaqueId = /^[A-Z0-9](?:[A-Z0-9 -]{0,61}[A-Z0-9-])?$/
const suffixWord = /^[A-Z0-9]+$/

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
  tags: Record<string, string[]>
  scheme: string | undefined
}

/** The field holding a require group's tokens, or undefined for a group no field holds (those are in tags). */
const fieldOf: Record<string, "sci" | "sap" | "aea" | "nonic" | "controls" | "categories"> = {
  sci: "sci",
  sap: "sap",
  aea: "aea",
  nonic: "nonic",
  controls: "controls",
  categories: "categories",
}

function get(m: Marking, group: string): readonly string[] {
  const f = Object.hasOwn(fieldOf, group) ? fieldOf[group] : undefined
  if (f) return m[f]
  // Own properties only: a group named like an Object.prototype member reads as empty, not as it.
  return m.tags && Object.hasOwn(m.tags, group) ? m.tags[group] : []
}

function put(m: Draft, group: string, l: string[]) {
  const f = Object.hasOwn(fieldOf, group) ? fieldOf[group] : undefined
  if (f) m[f] = l
  else if (l.length === 0) delete m.tags[group]
  else m.tags[group] = l
}

function draft(s: Scheme, level: number): Draft {
  return {
    level,
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
    tags: {},
    scheme: mark(s),
  }
}

/** What a marking read under s records: nothing for us-gov, so a us-gov marking is the same value however it was made. */
function mark(s: Scheme) {
  return s.digest === usGov.digest ? undefined : s.digest
}

/** Freezes a draft, leaving out the fields a us-gov marking does not have. */
function freeze(m: Draft): Marking {
  const { tags, scheme, ...rest } = m
  const out: Marking = { ...rest, ...(Object.keys(tags).length ? { tags } : {}), ...(scheme ? { scheme } : {}) }
  return Object.freeze(out)
}

function schemeDigest(m: Marking) {
  return m.scheme ?? usGov.digest
}

function owns(s: Scheme, ...ms: Marking[]) {
  return ms.every((m) => schemeDigest(m) === s.digest)
}

const kind = (s: Scheme, k: Group["kind"]) => s.groups.find((g) => g.kind === k)
const catchAll = (s: Scheme) => {
  const rel = kind(s, "release")
  return rel ? s.groups.find((g) => g.name === rel.inGroup) : undefined
}
const allowed = (g: Group, level: number) => g.levels.length === 0 || g.levels.includes(level)
const tokenAllowed = (g: Group, t: Token, level: number) => (t.levels.length === 0 ? allowed(g, level) : t.levels.includes(level))

function lookup(g: Group, w: string): Token | undefined {
  return (
    g.tokens.find((t) => t.token === w) ??
    g.tokens.find((t) => t.suffix && w.startsWith(t.token + "-") && suffixWord.test(w.slice(t.token.length + 1)))
  )
}

function accepts(g: Group, w: string, level: number) {
  if (g.prefix !== "") return w.startsWith(g.prefix) && opaqueId.test(w.slice(g.prefix.length))
  if (g.specifiedPrefix !== "") {
    const specified = w.startsWith(g.specifiedPrefix)
    const t = lookup(g, specified ? w.slice(g.specifiedPrefix.length) : w)
    if (!t || !tokenAllowed(g, t, level)) return false
    return t.variant === "either" || (t.variant === "specified") === specified
  }
  const t = lookup(g, w)
  return t !== undefined && tokenAllowed(g, t, level)
}

/** Specified tokens sort before basic ones, each alphabetically. */
const byVariant = (g: Group) => (a: string, b: string) => {
  const key = (c: string) => (c.startsWith(g.specifiedPrefix) ? "0" : "1") + c
  return compare(key(a), key(b))
}

/** Reads a configured banner under the process scheme: full words, never portion abbreviations; a retired marking is refused. */
export function parse(input: string): Marking {
  return parseIn(process(), input)
}

/** Reads a banner under the given scheme. */
export function parseIn(s: Scheme, input: string): Marking {
  const text = input.trim().toUpperCase()
  if (!bannerChars.test(text)) throw new MarkingError("a marking holds only letters, digits, spaces, commas, hyphens and slashes")
  const groups = text.split("//")
  for (const g of groups) for (const r of s.retired) if (g === r.token) throw new MarkingError(r.message)
  const level = s.levels.findIndex((l) => l.name === groups[0])
  if (level < 0) throw new MarkingError(`unknown classification level ${JSON.stringify(groups[0])}`)
  const m = draft(s, level)
  let last = 0
  groups.slice(1).forEach((g, gi) => {
    const pos = group(s, m, g.split("/"), gi === 0)
    if (pos <= last) throw new MarkingError(`marking group ${JSON.stringify(g)} is out of order or repeated`)
    last = pos
  })
  const rel = kind(s, "release")
  if (rel && m.relTo !== null && homeOnly(s, m))
    throw new MarkingError(`${rel.releaseLine} contradicts ${rel.noRelease}`)
  return freeze(m)
}

/** Records one //-separated group and returns its banner position (engine.go, group). */
function group(s: Scheme, m: Draft, toks: string[], first: boolean): number {
  const all = catchAll(s)
  for (const g of s.groups) {
    if (g.kind === "release" || g === all || !allowed(g, m.level) || (g.first && !first)) continue
    if (g.kind === "sourced") {
      const word = g.tokens[0].token
      if (toks.length !== 1 || (toks[0] !== word && !toks[0].startsWith(word + " "))) continue
      if (!tokenAllowed(g, g.tokens[0], m.level)) throw new MarkingError(`${word} is not allowed at ${s.levels[m.level].name}`)
      const rel = kind(s, "release")!
      m.hasFgi = true
      for (const c of fields(toks[0].slice(word.length))) {
        if (!rel.countries.includes(c) && !Object.hasOwn(rel.tetragraphs, c))
          throw new MarkingError(`unknown country code ${JSON.stringify(c)} in ${word}`)
        m.fgi.push(c)
      }
      return g.position
    }
    if (!toks.every((t) => accepts(g, t, m.level))) continue
    put(m, g.name, g.specifiedPrefix !== "" ? [...toks].sort(byVariant(g)) : sorted(toks))
    return g.position
  }
  if (!all) throw refusal(s, toks, m.level)
  const rel = kind(s, "release")!
  for (const t of toks) {
    for (const line of [rel.releaseLine, rel.displayLine])
      if (t.startsWith(line + " ") && !allowed(rel, m.level)) throw new MarkingError(`${line} is not allowed at ${s.levels[m.level].name}`)
    if (t.startsWith(rel.releaseLine + " ")) {
      const l = releaseList(s, t.slice(rel.releaseLine.length + 1))
      if (m.relTo !== null) throw new MarkingError(`${rel.releaseLine} appears more than once`)
      m.relTo = l
    } else if (t.startsWith(rel.displayLine + " ")) {
      const l = releaseList(s, t.slice(rel.displayLine.length + 1))
      if (m.displayOnly !== null) throw new MarkingError(`${rel.displayLine} appears more than once`)
      m.displayOnly = l
    } else {
      const tok = lookup(all, t)
      if (!tok) throw new MarkingError(`unknown marking token ${JSON.stringify(t)}`)
      if (!tokenAllowed(all, tok, m.level)) throw new MarkingError(`${t} is not allowed at ${s.levels[m.level].name}`)
      // The word as written: a token with a sub-compartment keeps it, so two compartments stay two labels.
      const word = tok.suffix ? t : tok.token
      const l = [...get(m, all.name)]
      if (!l.includes(word)) put(m, all.name, [...l, word])
    }
  }
  return all.position
}

/** Why no group took a banner group. A marking is never raised to make a word fit. */
function refusal(s: Scheme, toks: string[], level: number): MarkingError {
  for (const t of toks) {
    if (s.groups.some((g) => g.kind === "require" && accepts(g, t, level))) continue
    if (s.groups.some((g) => g.kind === "require" && lookup(g, t))) return new MarkingError(`${t} is not allowed at ${s.levels[level].name}`)
    return new MarkingError(`unknown marking token ${JSON.stringify(t)}`)
  }
  return new MarkingError(`marking group ${JSON.stringify(toks.join("/"))} mixes groups`)
}

/** "USA, AUS, GBR, FVEY": the home country first, then countries, then tetragraphs, each alphabetical and known. */
function releaseList(s: Scheme, text: string): string[] {
  const rel = kind(s, "release")!
  const l = text.split(",").map((c) => c.trim())
  if (l[0] !== rel.home) throw new MarkingError(`a release list must start with ${rel.home}`)
  l.slice(1).forEach((c, i) => {
    const prev = l[i]
    const tetra = Object.hasOwn(rel.tetragraphs, c)
    const prevTetra = Object.hasOwn(rel.tetragraphs, prev)
    if ((!tetra && !rel.countries.includes(c)) || c === rel.home)
      throw new MarkingError(`unknown or repeated country code ${JSON.stringify(c)}`)
    if (i > 0 && ((prevTetra && !tetra) || (prevTetra === tetra && prev >= c)))
      throw new MarkingError(`release list out of order at ${JSON.stringify(c)}`)
  })
  return l
}

function schemeOf(m: Marking): Scheme {
  const d = schemeDigest(m)
  if (d === usGov.digest) return usGov
  if (current?.digest === d) return current
  throw new SchemeMismatch()
}

/** The canonical banner, under the scheme the marking was read under. */
export function format(m: Marking): string {
  return banner(schemeOf(m), m)
}

/** The banner under the given scheme; SchemeMismatch when the marking was read under another. */
export function formatIn(s: Scheme, m: Marking): string {
  if (!owns(s, m)) throw new SchemeMismatch()
  return banner(s, m)
}

function banner(s: Scheme, m: Marking): string {
  const out = [s.levels[m.level].name]
  const add = (l: readonly string[]) => {
    if (l.length) out.push(l.join("/"))
  }
  const all = catchAll(s)
  const rel = kind(s, "release")
  for (const g of [...s.groups].sort((a, b) => a.position - b.position)) {
    if (g.kind === "release") continue
    if (g.kind === "sourced") {
      if (m.hasFgi) out.push([g.tokens[0].token, ...m.fgi].join(" "))
    } else if (all && g.name === all.name) {
      // Table order; a token's sub-compartments, sorted, where the token stands.
      const words = sorted(get(m, g.name))
      const d = g.tokens.flatMap((t) => words.filter((w) => w === t.token || (t.suffix && w.startsWith(t.token + "-"))))
      if (m.relTo !== null) d.push(rel!.releaseLine + " " + m.relTo.join(", "))
      if (m.displayOnly !== null) d.push(rel!.displayLine + " " + m.displayOnly.join(", "))
      add(d)
    } else add(get(m, g.name))
  }
  return out.join("//")
}

/**
 * Whether a system or sink accredited at `a` may hold content marked `b` (no write down), by the
 * process scheme: a's level is at least b's; a carries every token of every require group b
 * carries, except a group a's level absorbs; sourced content is held only by a holder naming at
 * least its countries (concealed only by concealed); a's release and display are within b's. A
 * marking read under another scheme dominates nothing and is dominated by nothing.
 */
export function dominates(a: Marking, b: Marking): boolean {
  return dominatesIn(process(), a, b)
}

/** dominates under the given scheme; false when either marking was read under another. */
export function dominatesIn(s: Scheme, a: Marking, b: Marking): boolean {
  if (!owns(s, a, b) || a.level < b.level) return false
  for (const g of s.groups) {
    if (g.kind === "require") {
      if (g.absorbedFrom >= 0 && a.level >= g.absorbedFrom) continue
      if (!superset(get(a, g.name), get(b, g.name))) return false
    } else if (g.kind === "sourced") {
      if (b.hasFgi && (!a.hasFgi || (a.fgi.length > 0 && (b.fgi.length === 0 || !superset(a.fgi, b.fgi))))) return false
    }
  }
  return subset(release(s, a), release(s, b)) && subset(display(s, a), display(s, b))
}

/**
 * A label that dominates both: the high-water mark after reading a and b, by the process scheme. It
 * is the least such label except where it marks higher on purpose (disjoint release lists become
 * home-only; a display restriction only one side carries becomes a display list of the home
 * country), as in Go. It throws `NoBanner` when the joined level does not allow a group the join
 * carries, or when the banner would not read back, and `SchemeMismatch` when either marking was read
 * under another scheme. A caller fails closed on any of them.
 */
export function join(a: Marking, b: Marking): Marking {
  return joinIn(process(), a, b)
}

/** join under the given scheme. */
export function joinIn(s: Scheme, a: Marking, b: Marking): Marking {
  if (!owns(s, a, b)) throw new SchemeMismatch()
  const j = draft(s, Math.max(a.level, b.level))
  j.hasFgi = a.hasFgi || b.hasFgi
  for (const g of s.groups) {
    if (g.kind !== "require" || (g.absorbedFrom >= 0 && j.level >= g.absorbedFrom)) continue
    const l = union(get(a, g.name), get(b, g.name))
    put(j, g.name, g.specifiedPrefix !== "" ? l.sort(byVariant(g)) : l)
  }
  for (const g of s.groups) {
    const carried = (g.kind === "sourced" && j.hasFgi) || (g.kind === "require" && get(j, g.name).length > 0)
    if (carried && !allowed(g, j.level)) throw new NoBanner()
  }
  if (j.hasFgi && !((a.hasFgi && a.fgi.length === 0) || (b.hasFgi && b.fgi.length === 0))) j.fgi = union(a.fgi, b.fgi)
  const rel = kind(s, "release")
  if (rel) {
    const ra = release(s, a)
    const rb = release(s, b)
    if (subset(ra, rb)) j.relTo = a.relTo && [...a.relTo]
    else if (subset(rb, ra)) j.relTo = b.relTo && [...b.relTo]
    else {
      // Neither is a subset, so neither is unrestricted.
      const l = [...ra!].filter((c) => rb!.has(c) && c !== rel.home).sort(compare)
      if (l.length === 0) put(j, noReleaseGroup(s), union(get(j, noReleaseGroup(s)), [rel.noRelease]))
      else j.relTo = [rel.home, ...l]
    }
    if (homeOnly(s, j)) j.relTo = null
    // Display: who may see it without release. The join may show it only where both may.
    const da = display(s, a)
    const db = display(s, b)
    if (da !== null || db !== null) {
      let d = da
      const rj = release(s, j)
      if (d === null) d = db
      else if (db !== null) d = new Set([...d].filter((c) => db.has(c)))
      const extra = [...d!].filter((c) => c !== rel.home && (rj === null || !rj.has(c))).sort(compare)
      // An unrestricted release would let it be shown to anyone: restrict it to the list.
      if (extra.length > 0 || rj === null) j.displayOnly = [rel.home, ...extra]
    }
  }
  const out = freeze(j)
  // A label that does not read back cannot be checked or recorded: too long a banner is refused,
  // and so is one the scheme's own parser would refuse (a token outside its levels, for one).
  const text = banner(s, out)
  if (text.length > maxBanner)
    throw new NoBanner(`these markings cannot be combined: their joined banner would be longer than ${maxBanner} characters`)
  // Every carried token must stand, in its own group, at the joined level, and the banner must
  // read back as exactly this marking: otherwise it would reread as another group's token.
  for (const g of s.groups) {
    if (g.kind === "require" && get(out, g.name).some((w) => !accepts(g, w, out.level))) throw new NoBanner()
    if (g.kind === "sourced" && out.hasFgi && !tokenAllowed(g, g.tokens[0], out.level)) throw new NoBanner()
  }
  let back: Marking
  try {
    back = parseIn(s, text)
  } catch {
    throw new NoBanner()
  }
  if (!sameMarking(s, back, out)) throw new NoBanner()
  return out
}

/** Whether two markings of one scheme are the same label: level, every group's tokens as sets, sourced and release parts. */
function sameMarking(s: Scheme, a: Marking, b: Marking): boolean {
  const same = (x: readonly string[] | null, y: readonly string[] | null) =>
    (x === null) === (y === null) && JSON.stringify(sorted(x ?? [])) === JSON.stringify(sorted(y ?? []))
  return (
    a.level === b.level &&
    a.hasFgi === b.hasFgi &&
    same(a.fgi, b.fgi) &&
    same(a.relTo, b.relTo) &&
    same(a.displayOnly, b.displayOnly) &&
    s.groups.every((g) => g.kind !== "require" || same(get(a, g.name), get(b, g.name)))
  )
}

/** The require group that owns the release group's no-release token, resolved by portion at load. */
function noReleaseGroup(s: Scheme): string {
  return kind(s, "release")!.noReleaseIn
}

/** Whether m carries the no-release token. */
function homeOnly(s: Scheme, m: Marking | Draft): boolean {
  return get(m as Marking, noReleaseGroup(s)).includes(kind(s, "release")!.noRelease)
}

/** Who may see the content: those it may be released to, plus its display list. null means anyone. */
function display(s: Scheme, m: Marking): Set<string> | null {
  const r = release(s, m)
  if (r === null) return null
  const d = new Set(r)
  for (const c of expand(s, m.displayOnly ?? [])) d.add(c)
  return d
}

/** The countries the marking allows release to; null means unrestricted. */
function release(s: Scheme, m: Marking): Set<string> | null {
  const rel = kind(s, "release")
  if (!rel) return null
  if (homeOnly(s, m)) return new Set([rel.home])
  if (m.relTo !== null) return expand(s, m.relTo)
  if (rel.restrictedFrom >= 0 && m.level >= rel.restrictedFrom) return new Set([rel.home]) // no release decision recorded
  if (m.displayOnly !== null) return new Set([rel.home]) // display, not release, to the listed countries
  return null
}

function expand(s: Scheme, l: readonly string[]): Set<string> {
  const rel = kind(s, "release")!
  const out = new Set<string>()
  for (const c of l) for (const x of Object.hasOwn(rel.tetragraphs, c) ? rel.tetragraphs[c] : [c]) out.add(x)
  return out
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

/** The banner word of the token whose portion mark is `portion`, in the process scheme. */
export function control(portion: string): string {
  for (const g of process().groups) for (const t of g.tokens) if (t.portion === portion && portion !== "") return t.token
  throw new Error(`marking: no dissemination control with portion mark ${portion}`)
}

/** Every us-gov dissemination control as [banner, portion], for callers that build markings from vectors. */
export function controls(): readonly (readonly [string, string])[] {
  const g = catchAll(usGov)!
  return g.tokens.map((t) => [t.token, t.portion] as const)
}

/** Tetragraph membership from the us-gov tables. */
export function tetragraphs(): Readonly<Record<string, readonly string[]>> {
  return kind(usGov, "release")!.tetragraphs
}
