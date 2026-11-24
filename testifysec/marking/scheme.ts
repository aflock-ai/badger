// Classification schemes as data: the TypeScript port of testifysec/connectors/internal/marking
// scheme.go. The same files load to the same scheme with the same digest, and the same files are
// refused with the same messages (the refusal fixtures in testdata/schemes are replayed by both).

import { sha256Hex } from "./sha256.js"
import tokens from "../connectors/internal/marking/tokens.json" with { type: "json" }
import usGovFile from "../connectors/internal/marking/schemes/us-gov.json" with { type: "json" }
import corporateFile from "../connectors/internal/marking/schemes/corporate.json" with { type: "json" }

export interface Level {
  readonly name: string
}

export interface Token {
  readonly token: string
  readonly portion: string
  /** Empty: the group's levels. */
  readonly levels: readonly number[]
  readonly variant: "" | "basic" | "specified" | "either"
  readonly suffix: boolean
}

export interface Group {
  readonly name: string
  readonly kind: "require" | "release" | "sourced"
  readonly position: number
  readonly first: boolean
  /** Empty: every level. */
  readonly levels: readonly number[]
  /** -1: never. */
  readonly absorbedFrom: number
  readonly prefix: string
  readonly specifiedPrefix: string
  readonly tokens: readonly Token[]
  readonly home: string
  readonly noRelease: string
  readonly restrictedFrom: number
  readonly releaseLine: string
  readonly displayLine: string
  readonly inGroup: string
  /** The require group that owns noRelease, resolved by its portion at load (not in the digest). */
  readonly noReleaseIn: string
  readonly countries: readonly string[]
  readonly tetragraphs: Readonly<Record<string, readonly string[]>>
}

export interface Retired {
  readonly token: string
  readonly message: string
}

export interface Scheme {
  readonly name: string
  readonly version: number
  readonly levels: readonly Level[]
  readonly groups: readonly Group[]
  readonly retired: readonly Retired[]
  /** "sha256:<hex>" over the canonical form; equal digests are the same scheme. */
  readonly digest: string
}

export class SchemeError extends Error {
  override name = "SchemeError"
}

const maxSchemeBytes = 256 << 10
const maxLevels = 16
const maxGroups = 64
const maxTokens = 4096
const maxCountries = 400
// A word starts and ends with a letter, digit or hyphen: a banner is trimmed before it is read, so
// "LOW " would read as "LOW".
const schemeWord = /^[A-Z0-9](?:[A-Z0-9 -]{0,62}[A-Z0-9-])?$/
const groupName = /^[a-z][a-z0-9-]{0,31}$/
const printable = /^[\x20-\x7e]*$/
const pointer = /^(\/[a-z_]+)+$/
const freeText = (s: unknown) => s === undefined || (typeof s === "string" && s.length <= 1024 && printable.test(s))

/** Every key the format defines, in its one spelling, by object kind. */
const fields = {
  scheme: ["schema", "name", "version", "vocabulary", "note", "levels", "levelsFrom", "groups", "retired"],
  level: ["name", "reason"],
  group: [
    "name", "kind", "position", "first", "levels", "minLevel", "absorbedFrom", "prefix", "specifiedPrefix", "tokens",
    "tokensFrom", "home", "noReleasePortion", "restrictedFrom", "releaseLine", "displayLine", "inGroup", "countries",
    "countriesFrom", "tetragraphs", "tetragraphsFrom", "source",
  ],
  token: ["token", "portion", "minLevel", "levels", "suffix", "reason"],
  tokensFrom: ["pointer", "levels", "variant", "suffix"],
  retired: ["token", "tokensFrom", "message"],
}
const allFields = new Set(Object.values(fields).flat())

/**
 * Walks the raw text as Go's checks do: a key repeated in one object (compared without case, as
 * encoding/json matches field names) or spelled differently from its field is refused. JSON.parse
 * would keep the last copy of a repeated key silently.
 */
function noDuplicateKeys(raw: string) {
  let i = 0
  const ws = () => {
    while (i < raw.length && " \t\n\r".includes(raw[i])) i++
  }
  const fail = (): never => {
    throw new SchemeError("not JSON")
  }
  const string = () => {
    if (raw[i] !== '"') fail()
    const start = i++
    while (i < raw.length && raw[i] !== '"') i += raw[i] === "\\" ? 2 : 1
    if (i >= raw.length) fail()
    i++
    return JSON.parse(raw.slice(start, i)) as string
  }
  const value = (): void => {
    ws()
    if (raw[i] === "{") {
      i++
      const keys = new Set<string>()
      ws()
      if (raw[i] === "}") return void i++
      for (;;) {
        ws()
        const key = string()
        if (keys.has(key.toLowerCase())) throw new SchemeError(`key ${JSON.stringify(key)} appears twice in one object`)
        keys.add(key.toLowerCase())
        if (!allFields.has(key))
          for (const f of allFields)
            if (f.toLowerCase() === key.toLowerCase())
              throw new SchemeError(`key ${JSON.stringify(key)} is spelled ${JSON.stringify(f)}`)
        ws()
        if (raw[i++] !== ":") fail()
        value()
        ws()
        if (raw[i] === ",") i++
        else if (raw[i] === "}") return void i++
        else fail()
      }
    }
    if (raw[i] === "[") {
      i++
      ws()
      if (raw[i] === "]") return void i++
      for (;;) {
        value()
        ws()
        if (raw[i] === ",") i++
        else if (raw[i] === "]") return void i++
        else fail()
      }
    }
    if (raw[i] === '"') return void string()
    const m = /^(-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?|true|false|null)/.exec(raw.slice(i))
    if (!m) fail()
    // null would read as an empty list, level 0 or no restriction.
    if (m![0] === "null") throw new SchemeError("a value is never null")
    // Every number is a version, position or level. Bounded, it reads exactly in JavaScript (an
    // integer past 2^53 rounds, so two versions could share a digest), and 1e0 or 1.0 are refused
    // as Go refuses them.
    if (/^-?\d/.test(m![0]) && !/^(0|[1-9][0-9]{0,5})$/.test(m![0]))
      throw new SchemeError(`number ${m![0]} is not a whole number from 0 to 999999`)
    i += m![0].length
  }
  value()
}

type Json = null | boolean | number | string | Json[] | { [k: string]: Json }
const isObject = (v: Json | undefined): v is { [k: string]: Json } => typeof v === "object" && v !== null && !Array.isArray(v)

const presetFiles: Record<string, unknown> = { "us-gov": usGovFile, corporate: corporateFile }

/** The built-in schemes' names. Any other name given where a scheme is chosen is a file. */
export const presetNames: readonly string[] = Object.freeze(Object.keys(presetFiles))

/** Loads a built-in scheme by name: "us-gov" (the default) or "corporate". */
export function preset(name: string): Scheme {
  const files = presetFiles
  if (!groupName.test(name) || !Object.hasOwn(files, name)) throw new SchemeError(`unknown marking scheme preset ${JSON.stringify(name)}`)
  return load(`${name}.json`, JSON.stringify(files[name]), true)
}

/** Reads a deployment's scheme file. It must be self-contained: only presets read a vocabulary. */
export function loadScheme(file: string, raw: string): Scheme {
  return load(file, raw, false)
}

/** Loads a file with the shapes only presets may use (tests replay the preset-shape refusals). */
export function loadPresetShape(file: string, raw: string): Scheme {
  return load(file, raw, true)
}

function load(file: string, raw: string, isPreset: boolean): Scheme {
  const fail = (path: string, message: string): never => {
    throw new SchemeError(`marking scheme ${file}: ${path}: ${message}`)
  }
  if (new TextEncoder().encode(raw).length > maxSchemeBytes) fail("$", `larger than ${maxSchemeBytes} bytes`)
  try {
    noDuplicateKeys(raw)
  } catch (e) {
    fail("$", (e as Error).message)
  }
  let f: Json
  try {
    f = JSON.parse(raw) as Json
  } catch {
    return fail("$", "trailing data")
  }
  if (!isObject(f)) return fail("$", "not a scheme")
  // Each field has one JSON type, as the Go decoder's typed fields do: a string where a list belongs
  // is refused, never read as an empty list.
  const types: Record<string, "string" | "int" | "bool" | "array" | "object" | "level"> = {
    schema: "string", name: "string", version: "int", vocabulary: "string", note: "string", levels: "array",
    levelsFrom: "string", groups: "array", retired: "array", reason: "string", kind: "string", position: "int",
    first: "bool", minLevel: "level", absorbedFrom: "level", prefix: "string", specifiedPrefix: "string",
    tokens: "array", tokensFrom: "array", home: "string", noReleasePortion: "string", restrictedFrom: "level",
    releaseLine: "string", displayLine: "string", inGroup: "string", countries: "array", countriesFrom: "string",
    tetragraphs: "object", tetragraphsFrom: "string", source: "string", token: "string", portion: "string",
    suffix: "bool", variant: "string", pointer: "string", message: "string",
  }
  const known = (o: { [k: string]: Json }, kind: keyof typeof fields, path: string) => {
    for (const [k, v] of Object.entries(o)) {
      if (!fields[kind].includes(k)) fail(path, `not a scheme: unknown field ${JSON.stringify(k)}`)
      const t = kind === "retired" && k === "tokensFrom" ? "string" : types[k]
      const ok =
        t === "string" ? typeof v === "string"
        : t === "int" ? typeof v === "number" && Number.isInteger(v)
        : t === "bool" ? typeof v === "boolean"
        : t === "array" ? Array.isArray(v)
        : t === "object" ? isObject(v)
        : typeof v === "string" || (typeof v === "number" && Number.isInteger(v))
      if (!ok) fail(path, `not a scheme: field ${JSON.stringify(k)} is not a ${t === "level" ? "level name or position" : t}`)
    }
  }
  known(f, "scheme", "$")
  // Every nested object's fields and types first, as Go's decoder checks the whole document before
  // any rule runs: the same file is refused for the same reason in both.
  const nested = (v: Json | undefined, kind: keyof typeof fields, path: string) => {
    if (!Array.isArray(v)) return
    v.forEach((o, i) => {
      if (!isObject(o)) fail(`${path}[${i}]`, "not a scheme: not an object")
      known(o as { [k: string]: Json }, kind, `${path}[${i}]`)
      if (kind === "group") {
        nested((o as { [k: string]: Json }).tokens, "token", `${path}[${i}].tokens`)
        nested((o as { [k: string]: Json }).tokensFrom, "tokensFrom", `${path}[${i}].tokensFrom`)
      }
    })
  }
  nested(f.levels, "level", "levels")
  nested(f.groups, "group", "groups")
  nested(f.retired, "retired", "retired")
  if (f.schema !== "badger.marking-scheme/v1") fail("schema", "must be badger.marking-scheme/v1")
  if (!freeText(f.note ?? undefined)) fail("note", "only printable ASCII, at most 1024 bytes")
  if (typeof f.name !== "string" || !groupName.test(f.name) || typeof f.version !== "number" || !Number.isInteger(f.version) || f.version < 1)
    fail("name", "a scheme needs a lower-case name and a version of at least 1")
  let vocab: Json | undefined
  if (f.vocabulary !== undefined || f.levelsFrom !== undefined) {
    if (!isPreset || f.vocabulary !== "tokens.json") fail("vocabulary", "only a built-in preset reads a vocabulary file")
    vocab = tokens as unknown as Json
  }
  const at = (p: string): Json => {
    if (vocab === undefined || !pointer.test(p)) throw new SchemeError(`pointer ${JSON.stringify(p)} needs a preset vocabulary`)
    let v: Json = vocab
    for (const k of p.slice(1).split("/")) {
      if (!isObject(v) || v[k] === undefined || v[k] === null) throw new SchemeError(`pointer ${JSON.stringify(p)} does not resolve`)
      v = v[k]
    }
    return v
  }
  const wrap = <T>(path: string, run: () => T): T => {
    try {
      return run()
    } catch (e) {
      if (e instanceof SchemeError && !e.message.startsWith("marking scheme ")) return fail(path, e.message)
      throw e
    }
  }
  let levelsIn: { name: Json; reason?: Json }[] = []
  if (f.levelsFrom !== undefined) {
    if (f.levels !== undefined) fail("levelsFrom", "levels are given twice")
    const v = wrap("levelsFrom", () => at(String(f.levelsFrom)))
    if (!Array.isArray(v)) fail("levelsFrom", "not a list of levels")
    levelsIn = (v as Json[]).map((l) => ({ name: isObject(l) ? l.banner : null }))
  } else if (Array.isArray(f.levels)) {
    levelsIn = f.levels.map((l, i) => {
      if (!isObject(l)) return fail(`levels[${i}]`, "not a level")
      known(l, "level", `levels[${i}]`)
      return l as { name: Json; reason?: Json }
    })
  }
  if (levelsIn.length < 2 || levelsIn.length > maxLevels) fail("levels", `a scheme has between 2 and ${maxLevels} levels`)
  const levels: Level[] = []
  levelsIn.forEach((l, i) => {
    if (typeof l.name !== "string" || !schemeWord.test(l.name) || !freeText(l.reason ?? undefined))
      fail(`levels[${i}]`, `level name ${JSON.stringify(l.name)} is not a banner word`)
    if (levels.some((x) => x.name === l.name)) fail(`levels[${i}]`, `level ${JSON.stringify(l.name)} appears twice`)
    levels.push({ name: l.name as string })
  })
  const n = levels.length
  const level = (r: Json): number => {
    if (r === null) throw new SchemeError("a level is a name or a position, never null")
    if (typeof r === "number" && Number.isInteger(r)) {
      if (r < 0 || r >= n) throw new SchemeError(`no level at position ${r}`)
      return r
    }
    if (typeof r !== "string") throw new SchemeError("a level is a name or a position")
    const i = levels.findIndex((l) => l.name === r)
    if (i < 0) throw new SchemeError(`no level ${JSON.stringify(r)}`)
    return i
  }
  const optLevel = (r: Json | undefined) => (r === undefined ? -1 : level(r))
  const levelList = (rs: Json | undefined, min: Json | undefined): number[] => {
    const out: number[] = []
    for (const r of (rs as Json[] | undefined) ?? []) {
      const x = level(r)
      if (out.includes(x)) throw new SchemeError(`level ${x} listed twice`)
      out.push(x)
    }
    if (min !== undefined) {
      if (out.length > 0) throw new SchemeError("levels and minLevel are given together")
      for (let x = level(min); x < n; x++) out.push(x)
    }
    return out.sort((a, b) => a - b)
  }
  const all = (l: readonly number[]) => (l.length ? l : [...Array(n).keys()])
  const groupsIn = Array.isArray(f.groups) ? f.groups : []
  if (groupsIn.length > maxGroups) fail("groups", `more than ${maxGroups} groups`)
  const groups: (Group & { tokens: Token[]; noRelease: string; noReleaseIn: string })[] = []
  let count = 0
  groupsIn.forEach((fgRaw, gi) => {
    const path = `groups[${gi}]`
    if (!isObject(fgRaw)) return fail(path, "not a group")
    known(fgRaw, "group", path)
    const fg = fgRaw as Record<string, Json | undefined>
    // A deployment's file uses the plain shapes only (scheme.go): require groups of literal tokens,
    // with minimum levels, sub-compartments and opaque prefixes.
    if (!isPreset) {
      const plain =
        fg.kind === "require" && fg.specifiedPrefix === undefined && fg.absorbedFrom === undefined && fg.first !== true &&
        !((fg.tokens as Json[] | undefined) ?? []).some((t) => isObject(t) && t.portion !== undefined)
      if (!plain)
        fail(path, "a deployment scheme has require groups of tokens only (levels, minimum levels, sub-compartments, prefixes); release lists, sourced groups, specified variants, absorption and portion marks belong to the built-in presets")
    }
    const str = (k: string) => (typeof fg[k] === "string" ? (fg[k] as string) : "")
    const name = str("name")
    if (!groupName.test(name) || groups.some((x) => x.name === name)) fail(path, `group name ${JSON.stringify(name)} is not a lower-case name, or repeats`)
    if (!freeText(fg.source)) fail(`${path}.source`, "only printable ASCII")
    const g = {
      name, kind: str("kind") as Group["kind"], position: typeof fg.position === "number" ? fg.position : 0, first: fg.first === true,
      levels: wrap(`${path}.levels`, () => levelList(fg.levels, fg.minLevel)),
      absorbedFrom: wrap(`${path}.absorbedFrom`, () => optLevel(fg.absorbedFrom)),
      prefix: str("prefix"), specifiedPrefix: str("specifiedPrefix"), tokens: [] as Token[], home: str("home"), noRelease: "",
      restrictedFrom: wrap(`${path}.restrictedFrom`, () => optLevel(fg.restrictedFrom)),
      releaseLine: str("releaseLine"), displayLine: str("displayLine"), inGroup: str("inGroup"), noReleaseIn: "",
      countries: [] as string[], tetragraphs: {} as Record<string, string[]>,
    }
    if (g.position < 1 || groups.some((x) => x.position === g.position && x.inGroup !== g.name && g.inGroup !== x.name))
      fail(`${path}.position`, "a position of at least 1 that no other group has")
    for (const w of [g.prefix, g.specifiedPrefix, g.home, g.releaseLine, g.displayLine])
      if (w !== "" && !schemeWord.test(w.replace(/-$/, ""))) fail(path, `${JSON.stringify(w)} is not a banner word`)
    const add = (t: Token, merge: boolean) => {
      if (!schemeWord.test(t.token) || (t.portion !== "" && !schemeWord.test(t.portion)))
        throw new SchemeError(`token ${JSON.stringify(t.token)} is not a banner word`)
      if (levels.some((l) => l.name === t.token)) throw new SchemeError(`token ${JSON.stringify(t.token)} is a level name`)
      const i = g.tokens.findIndex((x) => x.token === t.token)
      if (i >= 0) {
        if (!merge || g.tokens[i].portion !== t.portion) throw new SchemeError(`token ${JSON.stringify(t.token)} appears twice`)
        g.tokens[i] = { ...g.tokens[i], levels: [...new Set([...all(g.tokens[i].levels), ...all(t.levels)])].sort((a, b) => a - b) }
        return
      }
      g.tokens.push(t)
    }
    const variant = (v: Json | undefined): Token["variant"] => {
      const s = v === undefined ? "" : v
      if (!["", "basic", "specified", "either"].includes(s as string) || (s !== "") !== (g.specifiedPrefix !== ""))
        throw new SchemeError(`variant ${JSON.stringify(s)} needs a group with a specified prefix, and only such a group takes variants`)
      return s as Token["variant"]
    }
    ;((fg.tokens as Json[] | undefined) ?? []).forEach((ftRaw, ti) =>
      wrap(`${path}.tokens[${ti}]`, () => {
        if (!isObject(ftRaw)) throw new SchemeError("not a token")
        known(ftRaw, "token", `${path}.tokens[${ti}]`)
        const ft = ftRaw as Record<string, Json | undefined>
        const lv = levelList(ft.levels, ft.minLevel)
        if (!freeText(ft.reason)) throw new SchemeError("reason: only printable ASCII")
        if (g.specifiedPrefix !== "") throw new SchemeError("a group with a specified prefix takes its tokens from the vocabulary")
        add({ token: String(ft.token ?? ""), portion: typeof ft.portion === "string" ? ft.portion : "", levels: lv, suffix: ft.suffix === true, variant: "" }, false)
      }),
    )
    ;((fg.tokensFrom as Json[] | undefined) ?? []).forEach((fromRaw, ti) =>
      wrap(`${path}.tokensFrom[${ti}]`, () => {
        if (!isObject(fromRaw)) throw new SchemeError("not a token source")
        known(fromRaw, "tokensFrom", `${path}.tokensFrom[${ti}]`)
        const from = fromRaw as Record<string, Json | undefined>
        const lv = levelList(from.levels, undefined)
        const v = variant(from.variant)
        const list = at(String(from.pointer ?? ""))
        for (const e of Array.isArray(list) ? list : []) {
          const [token, portion] = typeof e === "string" ? [e, ""] : Array.isArray(e) && e.length === 2 ? [String(e[0]), String(e[1])] : ["", ""]
          add({ token, portion, levels: lv, variant: v, suffix: from.suffix === true }, true)
        }
      }),
    )
    // Containment first: a token listed at every level is still refused in a group that allows fewer.
    for (const t of g.tokens)
      if (t.levels.length && g.levels.length && !t.levels.every((x) => g.levels.includes(x)))
        fail(path, `token ${JSON.stringify(t.token)} is allowed at a level its group is not`)
    g.tokens = g.tokens.map((t) => (t.levels.length === n ? { ...t, levels: [] } : t))
    count += g.tokens.length
    const releaseFields = ["home", "noReleasePortion", "restrictedFrom", "releaseLine", "displayLine", "inGroup", "countries", "countriesFrom", "tetragraphs", "tetragraphsFrom"].some(
      (k) => fg[k] !== undefined && fg[k] !== "" && !(Array.isArray(fg[k]) && (fg[k] as Json[]).length === 0),
    )
    if (releaseFields && g.kind !== "release") fail(path, "only a release group takes home, lines, countries, inGroup or restrictedFrom")
    if (g.kind !== "require" && (fg.absorbedFrom !== undefined || g.prefix !== "" || g.specifiedPrefix !== "" || g.first))
      fail(path, "only a require group takes absorbedFrom, prefix, specifiedPrefix or first")
    if (g.prefix !== "" && g.tokens.length) fail(path, "a prefix group takes no tokens")
    if (g.kind === "release" && g.tokens.length) fail(path, "a release group takes no tokens")
    if (g.kind === "require") {
      if (!g.tokens.length && g.prefix === "") fail(path, "a require group needs tokens or a prefix")
    } else if (g.kind === "sourced") {
      if (g.tokens.length !== 1) fail(path, "a sourced group has exactly one token")
    } else if (g.kind === "release") {
      const words = (v: Json, what: string) => {
        if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) throw new SchemeError(`not a list of ${what}`)
        return v as string[]
      }
      g.countries = wrap(`${path}.countries`, () =>
        fg.countriesFrom !== undefined ? words(at(String(fg.countriesFrom)), "words") : words(fg.countries ?? [], "words"),
      )
      g.tetragraphs = wrap(`${path}.tetragraphs`, () => {
        const v = fg.tetragraphsFrom !== undefined ? at(String(fg.tetragraphsFrom)) : (fg.tetragraphs ?? {})
        if (!isObject(v)) throw new SchemeError("not a map of tetragraphs")
        return Object.fromEntries(Object.entries(v).map(([k, m]) => [k, words(m, "words")]))
      })
      if (!g.countries.length || g.countries.length > maxCountries || !g.countries.includes(g.home) || !g.releaseLine || !g.displayLine)
        fail(path, `a release group needs a home country among at most ${maxCountries} countries and both lines`)
      // A banner part is read as a release line before a display line, so equal lines, or one that
      // begins the other, would grant release to countries listed for display only (as in Go).
      const [r, d] = [g.releaseLine + " ", g.displayLine + " "]
      if (r.startsWith(d) || d.startsWith(r)) fail(path, "the release and display lines must differ, and neither may begin the other")
      for (const c of g.countries) if (!schemeWord.test(c) || c.includes(" ")) fail(path, `country ${JSON.stringify(c)} is not a code`)
      for (const [t, members] of Object.entries(g.tetragraphs)) {
        if (g.countries.includes(t) || !schemeWord.test(t)) fail(path, `tetragraph ${JSON.stringify(t)} is a country or not a code`)
        for (const m of members) if (!g.countries.includes(m)) fail(path, `tetragraph ${t} member ${JSON.stringify(m)} is not a known country`)
      }
      if (str("noReleasePortion") === "") fail(`${path}.noReleasePortion`, "a release group names its no-release token by portion")
      g.noRelease = str("noReleasePortion")
    } else fail(`${path}.kind`, `unknown group kind ${JSON.stringify(g.kind)}`)
    groups.push(g)
  })
  if (count > maxTokens) fail("groups", `more than ${maxTokens} tokens`)
  groups.forEach((g, gi) => {
    if (g.inGroup !== "" && !groups.some((x) => x.name === g.inGroup && x.kind === "require"))
      fail(`groups[${gi}].inGroup`, `no require group ${JSON.stringify(g.inGroup)}`)
    if (g.kind === "release") {
      let found = ""
      let owner = ""
      let owners = 0
      for (const x of groups)
        for (const t of x.tokens)
          if (t.portion === g.noRelease && x.kind === "require") {
            found = t.token
            owner = x.name
            owners++
          }
      if (!found) fail(`groups[${gi}].noReleasePortion`, `no require token has portion ${JSON.stringify(g.noRelease)}`)
      // One group owns the no-release token, so a label carries it, or not, in one place.
      if (owners > 1) fail(`groups[${gi}].noReleasePortion`, `the no-release token ${JSON.stringify(found)} is in ${owners} groups; it must be in one`)
      g.noRelease = found
      g.noReleaseIn = owner
    }
  })
  const kinds = { release: 0, sourced: 0 } as Record<string, number>
  const portions = new Map<string, string>()
  for (const g of groups) {
    kinds[g.kind] = (kinds[g.kind] ?? 0) + 1
    for (const t of g.tokens) {
      const other = portions.get(t.portion)
      if (other !== undefined && t.portion !== "" && other !== t.token)
        fail("groups", `portion ${JSON.stringify(t.portion)} stands for both ${JSON.stringify(other)} and ${JSON.stringify(t.token)}`)
      portions.set(t.portion, t.token)
    }
  }
  if (kinds.release > 1 || kinds.sourced > 1 || kinds.sourced > kinds.release)
    fail("groups", "at most one release group, and at most one sourced group, which needs the release group's countries")
  const ambiguity = unambiguous(groups, n)
  if (ambiguity) fail("groups", ambiguity)
  if (Array.isArray(f.retired) && f.retired.length > 0 && !isPreset) fail("retired", "retired markings belong to the built-in presets")
  const retired: Retired[] = []
  ;((f.retired as Json[] | undefined) ?? []).forEach((frRaw, ri) => {
    if (!isObject(frRaw)) return fail(`retired[${ri}]`, "not a retired marking")
    known(frRaw, "retired", `retired[${ri}]`)
    const fr = frRaw as Record<string, Json | undefined>
    let words = [String(fr.token ?? "")]
    if (fr.tokensFrom !== undefined) {
      if (fr.token !== undefined) fail(`retired[${ri}]`, "token and tokensFrom are given together")
      const v = wrap(`retired[${ri}]`, () => at(String(fr.tokensFrom)))
      words = Array.isArray(v) ? v.map(String) : []
    }
    for (const w of words) {
      if (!schemeWord.test(w) || typeof fr.message !== "string" || fr.message === "" || !freeText(fr.message))
        fail(`retired[${ri}]`, "a retired marking needs a banner word and a message")
      retired.push({ token: w, message: fr.message as string })
    }
  })
  const scheme = { name: f.name as string, version: f.version as number, levels, groups, retired }
  const digest = "sha256:" + sha256Hex(canonical(scheme))
  return deepFreeze({ ...scheme, digest })
}

interface Form {
  group: string
  /** The token the shape stands for; "" for a prefix group or a release line. */
  token: string
  kind: "word" | "suffix" | "prefix"
  text: string
  levels: number[]
}

/**
 * One word that could stand for two things at a common level, two groups or two tokens of one
 * group, as scheme.go's forms and unambiguous: every way each token is written, its sub-compartment
 * shapes, prefixed identifiers, the sourced group's word and country form, and the release lines.
 */
function unambiguous(groups: readonly Group[], n: number): string | undefined {
  const all = (l: readonly number[]) => (l.length ? [...l] : [...Array(n).keys()])
  const fs: Form[] = []
  for (const g of groups) {
    const glv = all(g.levels)
    if (g.kind === "sourced") {
      const w = g.tokens[0].token
      const lv = g.tokens[0].levels.length ? [...g.tokens[0].levels] : glv
      fs.push({ group: g.name, token: w, kind: "prefix", text: w + " ", levels: lv })
      fs.push({ group: g.name, token: w, kind: "word", text: w, levels: lv })
    }
    if (g.kind === "release")
      for (const line of [g.releaseLine, g.displayLine])
        fs.push({ group: g.inGroup + " lines", token: "", kind: "prefix", text: line + " ", levels: glv })
    if (g.kind !== "require") continue
    if (g.prefix !== "") fs.push({ group: g.name, token: "", kind: "prefix", text: g.prefix, levels: glv })
    for (const t of g.tokens) {
      const lv = t.levels.length ? [...t.levels] : glv
      const written = [
        ...(t.variant !== "specified" ? [t.token] : []),
        ...(t.variant === "specified" || t.variant === "either" ? [g.specifiedPrefix + t.token] : []),
      ]
      for (const w of written) {
        fs.push({ group: g.name, token: t.token, kind: "word", text: w, levels: lv })
        if (t.suffix) fs.push({ group: g.name, token: t.token, kind: "suffix", text: w + "-", levels: lv })
      }
    }
  }
  const overlap = (a: Form, b: Form) => {
    if (a.kind === "word" && b.kind === "word") return a.text === b.text
    if (a.kind === "word") return a.text.startsWith(b.text) && a.text.length > b.text.length
    if (b.kind === "word") return b.text.startsWith(a.text) && b.text.length > a.text.length
    return a.text.startsWith(b.text) || b.text.startsWith(a.text)
  }
  for (let i = 0; i < fs.length; i++)
    for (const b of fs.slice(i + 1)) {
      const a = fs[i]
      // Two forms of one token may share a word only if they are the same form.
      const same = a.group === b.group && a.token === b.token && a.kind === b.kind && a.text === b.text
      // Across groups, levels decide the group; within one group a word is looked up before its
      // level is known, so any two forms that can spell the same word are refused, whatever their levels.
      if (same || !overlap(a, b) || (a.group !== b.group && !a.levels.some((x) => b.levels.includes(x)))) continue
      if (a.group === b.group && a.token === b.token)
        return `token ${JSON.stringify(a.token)} of group ${a.group} can be read two ways (${JSON.stringify(a.text)}, ${JSON.stringify(b.text)})`
      if (a.group === b.group)
        return `tokens ${JSON.stringify(a.token)} and ${JSON.stringify(b.token)} of group ${a.group} can be written the same way (${JSON.stringify(a.text)}, ${JSON.stringify(b.text)})`
      return a.kind === "word" && b.kind === "word"
        ? `token ${JSON.stringify(a.text)} is in groups ${a.group} and ${b.group} at the same level`
        : `groups ${a.group} and ${b.group} accept the same words (${JSON.stringify(a.text)}, ${JSON.stringify(b.text)}) at the same level`
    }
  return undefined
}

/** Freezes a value and everything in it: a loaded scheme never changes. */
function deepFreeze<T>(v: T): T {
  if (v && typeof v === "object") {
    for (const x of Object.values(v)) deepFreeze(x)
    Object.freeze(v)
  }
  return v
}

/** Canonical JSON (sorted keys, no whitespace) of what a label means, as scheme.go writes it. */
function canonical(s: Omit<Scheme, "digest">): string {
  // Written out by hand, keys in Go's order: an object rebuilt with sorted keys would still put
  // integer-like keys ("2", "10") first, in numeric order, and the digest would differ from Go's.
  const encode = (v: unknown): string =>
    Array.isArray(v)
      ? `[${v.map(encode).join(",")}]`
      : v && typeof v === "object"
        ? `{${Object.keys(v)
            .filter((k) => (v as Record<string, unknown>)[k] !== undefined)
            .sort()
            .map((k) => `${JSON.stringify(k)}:${encode((v as Record<string, unknown>)[k])}`)
            .join(",")}}`
        : JSON.stringify(v)
  return encode(
    {
      schema: "badger.marking-scheme/v1",
      name: s.name,
      version: s.version,
      levels: s.levels.map((l) => l.name),
      groups: s.groups.map((g) => ({
        name: g.name, kind: g.kind, position: g.position, first: g.first, levels: g.levels, absorbedFrom: g.absorbedFrom,
        prefix: g.prefix, specifiedPrefix: g.specifiedPrefix, home: g.home, noRelease: g.noRelease,
        restrictedFrom: g.restrictedFrom, releaseLine: g.releaseLine, displayLine: g.displayLine, inGroup: g.inGroup,
        countries: g.countries,
        tetragraphs: Object.fromEntries(Object.entries(g.tetragraphs).map(([k, m]) => [k, [...m].sort()])),
        tokens: g.tokens.map((t) => ({ token: t.token, portion: t.portion, levels: t.levels, variant: t.variant, suffix: t.suffix })),
        // The owner is in the digest only when more than one group holds the no-release word, as in
        // Go; otherwise the word implies it and the pinned digests stay.
        ...(g.noRelease !== "" && s.groups.filter((x) => x.tokens.some((t) => t.token === g.noRelease)).length > 1
          ? { noReleaseIn: g.noReleaseIn }
          : {}),
      })),
      retired: s.retired.map((r) => ({ token: r.token, message: r.message })),
    },
  )
}
