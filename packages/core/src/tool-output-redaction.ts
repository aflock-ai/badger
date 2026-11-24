import { Schema } from "effect"
import { types } from "node:util"

export * as ToolOutputRedaction from "./tool-output-redaction"

// Match recognizable credentials, not identifiers such as `token = input.token`. URL userinfo is found
// by parsing (see urlCredentials), not by this pattern.
// A repeated scheme ("Bearer Bearer value", a common misconfiguration) is taken with the value, so the
// first scheme cannot use the second as its value and leave the real one.
// A tab inside the scheme word ("Bea\trer") does not hide it: tabs are kept in every view, so the
// pattern reads through them. A newline is not: a stream reads one line at a time.
const scheme = String.raw`(?:B\t*e\t*a\t*r\t*e\t*r|B\t*a\t*s\t*i\t*c)`
const credentials = new RegExp(String.raw`\b(?:${scheme}[ \t]+)+[A-Za-z0-9._~+\/-]+=*`, "gi")
// Prefixed key formats match anywhere, with no boundary before them: a removed terminal sequence, a
// dropped encoded control or any other glue ("status\x1b[2Kghp_…") cannot hide one, and a key-shaped
// run inside a longer identifier is redacted too. Variable-length keys run to the end of their
// alphabet, so a long run is one match, scanned once. Fixed-length keys (fixedKeys, see
// fixedKeySpans()) must not continue into a word character, so a longer identifier that merely starts
// like one is kept.
const keys =
  /gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|glpat-[A-Za-z0-9_-]{20,}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{16,}/g
const fixedKeys = /(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35}|npm_[A-Za-z0-9]{36}/g
// A JWT, matched at one position by jwts().
const jwt = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/y
const credentialValueAt = /[A-Za-z0-9._~+\/-]+=*/y
const credentialAt = new RegExp(String.raw`(?:${scheme}[ \t]+)+[A-Za-z0-9._~+\/-]+=*`, "iy")
// Display mode: a scheme whose value is on the next line.
const lineSchemes = new RegExp(String.raw`\b${scheme}\s+[A-Za-z0-9._~+\/-]+=*`, "gi")
const privateKeyBegin = /-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY-----/g

/**
 * Tool output with recognizable credentials replaced. `display` adds stricter rules for untrusted
 * remote text shown as a label to a person or a model (the Requirements sidebar and tool), where
 * code readability does not matter: labelled values (`password=…`, `"token": …`), every URL query
 * and fragment, and a scheme whose value is on the next line.
 */
export function text(input: string, options: { display?: boolean } = {}): string {
  const clean = terminal(true)
  const source = clean(input) + clean.flush()
  return apply(source, spans(source, { views: 0 }, options.display))
}

// Display mode only (see text()).
const labelled =
  /\b(?:access_token|refresh_token|id_token|token|password|secret|api[_-]?key|state|seal_pub)["']?\s*[=:]\s*["']?[^\s&#"']+/gi
const queries = /\b(?:https?|wss?|ftp|ssh):\/\/[^\s?#]+[?#][^\s]*/gi

// Where a standalone control character stood; output shows it as a space. U+FFFF is a noncharacter,
// so it never occurs in real text.
const separator = "\uffff"
// Where terminal() removed an escape sequence or a format character. Detection treats it like a
// separator (a boundary between words, dropped inside a token); output shows nothing, so color inside
// a word does not split it. Also a noncharacter.
const joint = "\ufffe"
const marks = /[\uffff\ufffe]/

// The decoding search stops here; an output whose decoded views exceed either bound is redacted whole.
// Ordinary output reaches a handful of views. In the seeded fuzz (tool-output-redaction.test.ts), random
// mixes of up to five JSON and percent layers stay under 256; deeper ones may not. Tool output is capped
// at 50 KiB, so 256 views of it fit the character bound with room to spare; only a caller passing far
// larger text reaches it.
const maxViews = 256
// How many layers of escaping are decoded: a secret encoded twice is the deepest this covers (see
// TOOL-OUTPUT-REDACTION.md).
const maxLayers = 2
const maxViewChars = 16 * 1024 * 1024

// A span is replaced with "[redacted]", or removed outright when `remove` is set.
type Span = { start: number; end: number; remove?: boolean }

const shortEscapes: Record<string, string> = { n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", '"': '"', "\\": "\\" }
// A JSON \uXXXX escape decodes to any UTF-16 unit, so an escaped format character ("\u200b") or
// control is read like the literal one.
const escape = /^(?:%([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})|\\(\/)|\\([nrtbf"\\]))/

// Whether the input ends outside every terminal sequence, raw or in a decoded view, so text after it
// cannot be read into a sequence it left open. Callers that join outputs before text() use it to decide
// whether a tail may be joined raw.
export function closed(input: string): boolean {
  const clean = terminal(true)
  const source = clean(input)
  if (!clean.idle()) return false
  const stats = { views: 0, open: false }
  spans(source, stats)
  return !stats.open && stats.views <= maxViews
}

// How many views text() inspects for this input, past maxViews when the bound redacts it whole. For
// tests that hold the decoding search to its bound.
export function viewCount(input: string): number {
  const stats = { views: 0 }
  spans(terminal()(input), stats)
  return stats.views
}

// A whole, valid UTF-8 sequence of percent bytes starting at i ("%E2%80%8B"), as its character and the
// length of its spelling; undefined for a stray or invalid byte.
const utf8decoder = new TextDecoder("utf-8", { fatal: true })
function utf8(input: string, i: number) {
  const byte = (at: number) => {
    const hex = input.slice(at + 1, at + 3)
    return input[at] === "%" && /^[0-9a-fA-F]{2}$/.test(hex) ? parseInt(hex, 16) : undefined
  }
  const lead = byte(i)
  if (lead === undefined || lead < 0xc2 || lead > 0xf4) return undefined
  const size = lead >= 0xf0 ? 4 : lead >= 0xe0 ? 3 : 2
  const bytes = [lead]
  for (let k = 1; k < size; k++) {
    const next = byte(i + 3 * k)
    if (next === undefined || next < 0x80 || next > 0xbf) return undefined
    bytes.push(next)
  }
  try {
    return { text: utf8decoder.decode(new Uint8Array(bytes)), length: 3 * size }
  } catch {
    return undefined
  }
}

// Where recognizable credentials sit in already-cleaned text.
// stats.views: how many views were inspected (past maxViews when the bound redacts the whole input).
// stats.open: some decoded view ends inside a terminal sequence, so text after this input may still
// belong to it (see stream()).
// stats.base64 and stats.decoded: the base64 layer this text came from, and how many decoded characters
// base64 has produced so far (both shared with the nested scans).
function spans(
  source: string,
  stats: { views: number; open?: boolean; secret?: boolean; auths?: boolean; base64?: number; decoded?: number } = {
    views: 0,
  },
  display = false,
): Span[] {
  // Decode only a detection view. Keep source spelling and offsets outside matches. Terminal controls
  // that only appear once decoded (an escaped "\\u001b[31m") are stripped from the view as well, so
  // they cannot sit against a token and hide its word boundary.
  // What the view strips is also removed from the output: terminal metadata the detector cannot
  // read (an escaped OSC payload holding an encoded URL) must not reach an observer either.
  const found: Span[] = []
  const spaced = source.replaceAll(separator, " ").replaceAll(joint, " ")
  // Without an escape character the decoded view equals the spaced view (the source is already
  // terminal-cleaned), and without a separator or joint the joined view equals it too: skip both then.
  const decodes = /[%\\]/.test(source)
  // One decoded view and its compact form. Every view records what it strips, the JSON-only one
  // included: decoding fully can end terminal metadata early ("%07" read as BEL) that the JSON-only
  // view correctly reads to its escaped terminator, so neither view's removals cover the other's.
  const decode = (input: string, map: readonly number[] | undefined, percent: boolean) => {
    const at = (i: number) => (map ? map[i] : i)
    const offsets: number[] = []
    let normalized = ""
    // The decoded view again without the separators and whitespace escapes it decoded, so an encoded
    // control inside a token ("%0d", "\\r") cannot split it.
    const compactOffsets: number[] = []
    const compact: string[] = []
    const strip = terminal()
    // What a view strips is removed from the output at its source position, at every layer: terminal
    // metadata found only under nested escapes is no more readable than at the first.
    const remove = (i: number, length: number) => {
      const last = found.at(-1)
      if (last?.remove && last.end === at(i)) last.end = at(i + length)
      else found.push({ start: at(i), end: at(i + length), remove: true })
    }
    for (let i = 0; i < input.length; ) {
      // Only "%" and "\\" start an escape. A run of other printable ASCII outside a terminal sequence
      // reads as itself, so it is copied whole.
      const code = input.charCodeAt(i)
      if (code >= 0x20 && code <= 0x7e && code !== 0x25 && code !== 0x5c && strip.plain()) {
        let end = i + 1
        for (; end < input.length; end++) {
          const next = input.charCodeAt(end)
          if (next < 0x20 || next > 0x7e || next === 0x25 || next === 0x5c) break
        }
        const run = input.slice(i, end)
        normalized += run
        compact.push(run)
        for (let k = i; k < end; k++) {
          offsets.push(at(k))
          compactOffsets.push(at(k))
        }
        i = end
        continue
      }
      let match = code === 0x25 || code === 0x5c ? escape.exec(input.slice(i, i + 6)) : null
      // The JSON-only view keeps percent escapes as written: "%2F" in a JSON-escaped URL's password is
      // still a password byte, not the "/" that would end the authority.
      if (!percent && match?.[1] !== undefined) match = null
      // A percent byte of 0x80 or more is part of a UTF-8 sequence, not a character on its own: a whole,
      // valid sequence ("%E2%80%8B") decodes to its character, so an encoded format character reads like
      // the literal one; anything else keeps the source spelling rather than mistaking a stray byte for
      // a terminal control.
      let sequence: { text: string; length: number } | undefined
      if (match?.[1] !== undefined && parseInt(match[1], 16) >= 0x80) {
        sequence = percent ? utf8(input, i) : undefined
        match = null
      }
      // A JSON surrogate pair ("\uDB40\uDC20") is one character, read whole so a format character
      // outside the BMP is recognized like any other.
      if (match?.[2] !== undefined && /^d[89ab]/i.test(match[2])) {
        const low = escape.exec(input.slice(i + 6, i + 12))
        if (low?.[2] !== undefined && /^d[c-f]/i.test(low[2])) {
          sequence = { text: String.fromCharCode(parseInt(match[2], 16), parseInt(low[2], 16)), length: 12 }
          match = null
        }
      }
      // So is a pair assembled across decoding passes: "\\uDB40\\\\uDC20" reads on the next pass as a raw high
      // surrogate before an escaped low one, and either half can be raw or escaped.
      if (!sequence) {
        const head = match ? (match[2] !== undefined ? parseInt(match[2], 16) : undefined) : code
        if (head !== undefined && head >= 0xd800 && head <= 0xdbff) {
          const after = i + (match?.[0].length ?? 1)
          const low = escape.exec(input.slice(after, after + 6))
          const tail = low ? (low[2] !== undefined ? parseInt(low[2], 16) : undefined) : input.charCodeAt(after)
          if (tail !== undefined && tail >= 0xdc00 && tail <= 0xdfff) {
            sequence = { text: String.fromCharCode(head, tail), length: after - i + (low?.[0].length ?? 1) }
            match = null
          }
        }
      }
      const length = sequence?.length ?? match?.[0].length ?? 1
      // A JSON short escape is a separator (whitespace) or a literal quote or backslash: decoded for
      // detection only. It still advances the terminal state, so an escaped string terminator ("\\\\"
      // after an escaped ESC) ends an escaped OSC sequence instead of swallowing the text after it.
      if (match?.[4] !== undefined && strip(shortEscapes[match[4]]) !== "") {
        const space = "nrtbf".includes(match[4])
        offsets.push(at(i))
        normalized += space ? " " : match[4]
        if (!space) {
          compactOffsets.push(at(i))
          compact.push(match[4])
        }
        i += length
        continue
      }
      const kept =
        match?.[4] !== undefined
          ? ""
          : strip(
              sequence
                ? sequence.text
                : match
                  ? (match[3] ?? String.fromCharCode(parseInt(match[1] ?? match[2], 16)))
                  : input[i],
            )
      if (kept === joint) {
        // A removed sequence starts here: a boundary in this view, nothing in the compact one, and
        // removed from the output like the rest of the sequence.
        offsets.push(at(i))
        normalized += " "
        remove(i, length)
      } else if (kept) {
        // A character outside the BMP is two UTF-16 units, both at this source position.
        for (let unit = 0; unit < kept.length; unit++) offsets.push(at(i))
        normalized += kept === separator ? " " : kept
        // Decoded whitespace ("%0a", "\\u0009") is left out of the compact view like a separator.
        if (kept !== separator && !((match || sequence) && /\s/.test(kept))) {
          for (let unit = 0; unit < kept.length; unit++) compactOffsets.push(at(i))
          compact.push(kept)
        }
      } else remove(i, length)
      i += length
    }
    if (!strip.plain()) stats.open = true
    offsets.push(at(input.length))
    compactOffsets.push(at(input.length))
    return [
      [normalized, offsets],
      [compact.join(""), compactOffsets],
    ] as const
  }
  // Detect on every view the decoders can reach: separators and joints as spaces (a control or removed
  // sequence between words is a boundary), both removed (one inside a token cannot split it), and the
  // closure of both
  // under decoding. Every view is decoded JSON-only (percent escapes kept, so "%2F" in a password stays
  // a password byte) and in full (percent and JSON, so a percent-encoded JSON escape like "%5Cu003a"
  // is exposed), and each decode also yields a compact form without the controls and whitespace it
  // decoded. Each new view is decoded again, up to maxLayers layers in any order. An output that would
  // still decode past maxLayers, or that passes maxViews views or maxViewChars characters, is not
  // inspected further and is redacted whole.
  type View = readonly [string, readonly number[] | undefined]
  const views: View[] = [[spaced, undefined]]
  // Views still to decode, with how many layers of decoding made them.
  const pending: Array<readonly [string, readonly number[] | undefined, number]> = [[source, undefined, 0]]
  // The source without some characters, mapped back to source offsets.
  const without = (drop: (char: string) => boolean): View => {
    const kept: number[] = []
    const parts: string[] = []
    for (let i = 0; i < source.length; i++)
      if (!drop(source[i])) {
        kept.push(i)
        parts.push(source[i])
      }
    kept.push(source.length)
    return [parts.join(""), kept]
  }
  if (marks.test(source)) {
    const joined = without((char) => char === separator || char === joint)
    views.push(joined)
    pending.push([...joined, 0])
  }
  if (decodes) {
    // Views with the same text are the same view only if they map to the same source offsets.
    const seen = new Map<string, Array<readonly number[] | undefined>>()
    const same = (a: readonly number[] | undefined, b: readonly number[] | undefined, length: number) => {
      for (let i = 0; i <= length; i++) if ((a ? a[i] : i) !== (b ? b[i] : i)) return false
      return true
    }
    for (const [text, map] of pending) seen.set(text, [...(seen.get(text) ?? []), map])
    let count = 0
    let chars = 0
    for (let next = pending.shift(); next; next = pending.shift()) {
      const [view, map, layer] = next
      if (!/[\\%]/.test(view)) continue
      for (const percent of [true, false])
        for (const child of decode(view, map, percent)) {
          const maps = seen.get(child[0]) ?? []
          if (maps.some((known) => same(known, child[1], child[0].length))) continue
          // A view a third layer would still decode is not inspected, so the output is withheld whole,
          // as past the size bound.
          if (layer >= maxLayers) {
            stats.views = maxViews + 1
            return [{ start: 0, end: source.length }]
          }
          seen.set(child[0], [...maps, child[1]])
          count++
          chars += child[0].length
          if (count > maxViews || chars > maxViewChars) {
            stats.views = maxViews + 1
            return [{ start: 0, end: source.length }]
          }
          views.push(child)
          pending.push([...child, layer + 1])
        }
    }
  }
  stats.views = views.length
  for (const [view, map] of views) {
    // Base64 is read in every view, so a run another layer encoded (percent-encoded in a query) is whole.
    const encoded = base64Spans(view, stats, display)
    if (encoded === "withhold") {
      stats.views = maxViews + 1
      return [{ start: 0, end: source.length }]
    }
    const local = [
      ...encoded,
      ...urlCredentials(view),
      ...jwts(view),
      ...fixedKeySpans(view, map),
      ...shapeSpans(view, stats),
    ]
    local.push(...privateKeySpans(source, view, map, stats))
    for (const match of [...view.matchAll(credentials), ...view.matchAll(keys)])
      local.push({ start: match.index, end: match.index + match[0].length })
    if (display) {
      for (const match of [...view.matchAll(labelled), ...view.matchAll(lineSchemes)])
        local.push({ start: match.index, end: match.index + match[0].length })
      // A query or fragment is withheld from its "?" or "#"; the scheme, host and path stay.
      for (const match of view.matchAll(queries)) {
        const at = match[0].search(/[?#]/)
        local.push({ start: match.index + at, end: match.index + match[0].length })
      }
    }
    if (map) schemeValues(view, map, local)
    for (const span of local)
      found.push({ start: map ? map[span.start] : span.start, end: map ? map[span.end] : span.end })
  }
  return found
}

// Kubernetes Secrets and Docker registry config, by shape: their values are bare secrets (a base64
// password, "user:pass") that no pattern recognizes, so the values are redacted wherever the shape
// appears, and the keys are kept so a reader can still tell what was there. A data or stringData block
// is redacted when the output declares kind Secret; kubectl prints data before kind, so until a kind
// line arrives, and while a block may still go on, a stream holds it (stats.open). A stream remembers a
// declared Secret or auths map for the rest of the output. In a mixed list a ConfigMap's data goes too.
const secretKind = /^[ \t]*(?:-[ \t]+)?kind:[ \t]*["']?Secret["']?[ \t]*$|"kind"[ \t]*:[ \t]*"Secret"/m
const anyKind = /^[ \t]*(?:-[ \t]+)?kind:|"kind"[ \t]*:/m
const yamlBlock = /^([ \t]*)(?:-[ \t]+)?(?:data|stringData):[ \t]*$/gm
const yamlEntry = /^([ \t]*)(?:"[^"\n]*"|'[^'\n]*'|[^\s:#][^:\n]*):[ \t]+(\S[^\n]*)$/
const jsonBlock = /"(?:data|stringData)"[ \t]*:[ \t]*\{/g
const jsonEntry = /\s*"(?:[^"\\]|\\.)*"\s*:\s*"((?:[^"\\]|\\.)*)"\s*,?/y
const dockerAuths = /"auths"[ \t]*:/
const dockerSecret = /"(?:auth|password|identitytoken|registrytoken)"\s*:\s*"((?:[^"\\]|\\.)*)"/gi

function shapeSpans(view: string, stats: { open?: boolean; secret?: boolean; auths?: boolean }): Span[] {
  const found: Span[] = []
  const blocks: Span[] = []
  let headers = 0
  // A block that runs to the end of this text may go on in the next piece of a stream.
  let unended = false
  for (const header of view.matchAll(yamlBlock)) {
    headers++
    const indent = header[1].length
    let line = header.index + header[0].length + 1
    for (;;) {
      if (line >= view.length) {
        unended = true
        break
      }
      let next = view.indexOf("\n", line)
      if (next < 0) next = view.length
      const text = view.slice(line, next)
      // Blank lines and comments inside the block are skipped; a comment at the block's own indent or
      // less ends it, like any other line there.
      const comment = /^([ \t]*)(#|\r?$)/.exec(text)
      if (comment && (comment[2] === "" || comment[2] === "\r" || comment[1].length > indent)) {
        line = next + 1
        continue
      }
      const entry = yamlEntry.exec(text)
      if (!entry || entry[1].length <= indent) break
      const start = line + entry[0].length - entry[2].length
      let end = start + entry[2].length
      while (end > start && " \t\r".includes(view[end - 1])) end--
      // A value goes on over every following line indented deeper than its key, or blank: a block
      // scalar ("|", ">-") or a folded plain scalar.
      line = next + 1
      for (;;) {
        if (line >= view.length) {
          unended = true
          break
        }
        let after = view.indexOf("\n", line)
        if (after < 0) after = view.length
        const text = view.slice(line, after)
        let depth = 0
        while (depth < text.length && (text[depth] === " " || text[depth] === "\t")) depth++
        if (depth < text.length && text[depth] !== "\r" && depth <= entry[1].length) break
        if (depth < text.length && text[depth] !== "\r") end = line + text.length
        line = after + 1
      }
      while (end > start && " \t\r".includes(view[end - 1])) end--
      blocks.push({ start, end })
      if (unended) break
    }
  }
  for (const header of view.matchAll(jsonBlock)) {
    headers++
    // A failed sticky match resets lastIndex, so where the entries stop is kept here.
    let at = header.index + header[0].length
    jsonEntry.lastIndex = at
    for (let entry = jsonEntry.exec(view); entry; entry = jsonEntry.exec(view)) {
      const end = jsonEntry.lastIndex - entry[0].length + entry[0].lastIndexOf('"')
      blocks.push({ start: end - entry[1].length, end })
      at = jsonEntry.lastIndex
    }
    if (/^\s*$/.test(view.slice(at))) unended = true
  }
  if (secretKind.test(view)) stats.secret = true
  if (stats.secret) found.push(...blocks)
  if (headers > 0 && (unended || (!stats.secret && !anyKind.test(view)))) stats.open = true
  if (dockerAuths.test(view)) stats.auths = true
  if (stats.auths)
    for (const match of view.matchAll(dockerSecret)) {
      const end = match.index + match[0].length - 1
      found.push({ start: end - match[1].length, end })
    }
  return found
}

// Base64 runs of 24 or more characters that decode to text are decoded and scanned, up to two layers
// (a secret encoded twice). A run whose decoded text holds a credential is redacted whole. A run that
// would still decode to text at a third layer withholds the output, as past the other bounds.
const base64Run = /[A-Za-z0-9+/_-]{24,}={0,2}/g
const maxBase64Layers = 2
const strictUtf8 = new TextDecoder("utf-8", { fatal: true })
function base64Text(run: string): string | undefined {
  const normalized = run.replaceAll("-", "+").replaceAll("_", "/")
  if (normalized.replace(/=+$/, "").length % 4 === 1) return undefined
  let decoded: string
  try {
    decoded = strictUtf8.decode(Buffer.from(normalized, "base64"))
  } catch {
    return undefined
  }
  // Text, not binary: no controls but tab, newline and carriage return.
  return /^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+$/.test(decoded) ? decoded : undefined
}
function base64Spans(
  view: string,
  stats: { views: number; base64?: number; decoded?: number },
  display = false,
): Span[] | "withhold" {
  const found: Span[] = []
  const layer = stats.base64 ?? 0
  for (const match of view.matchAll(base64Run)) {
    const decoded = base64Text(match[0])
    if (decoded === undefined) continue
    if (layer >= maxBase64Layers) return "withhold"
    stats.decoded = (stats.decoded ?? 0) + decoded.length
    if (stats.decoded > maxViewChars) return "withhold"
    const clean = terminal(true)
    const inner = clean(decoded) + clean.flush()
    const sub = { views: 0, base64: layer + 1, decoded: stats.decoded }
    const hits = spans(inner, sub, display)
    stats.decoded = sub.decoded
    if (sub.views > maxViews) return "withhold"
    if (hits.length > 0) found.push({ start: match.index, end: match.index + match[0].length })
  }
  return found
}

// Private key blocks, by allowlist. A BEGIN marker starts a block, and the block runs to the end of the
// view (fail closed) unless it has the strict raw PEM shape: nothing but blanks after BEGIN on its line,
// then only PEM header lines ("Name: value", printable ASCII), base64 lines ([A-Za-z0-9+/=]), and blank
// lines, up to an END line with the same label and nothing else on it. Lines may be indented and end in
// blanks or a carriage return. In a mapped view the block must also be untouched by decoding (every
// character maps to the next source character, removed controls aside), so a newline, quote or marker an escape produced never
// counts. Anything else, JSON-escaped, percent-encoded or otherwise, runs to the end: where such a block
// really ends cannot be told reliably, so the text after it is lost too. A stream holds the lines after
// an open block until it closes or the output ends.
// Both are tested on a line with its blanks trimmed, so no two repetitions overlap (linear time).
const pemHeader = /^[\x21-\x39\x3b-\x7e]+:[\x20-\x7e]*$/
const pemBody = /^[A-Za-z0-9+/=]*$/
function privateKeySpans(
  source: string,
  view: string,
  map: readonly number[] | undefined,
  stats: { open?: boolean },
): Span[] {
  const found: Span[] = []
  // Only removed controls (a carriage return, say) may sit between two characters of the block.
  const untouched = (from: number, to: number) => {
    if (map)
      for (let i = from; i < to; i++) if (!/^[\uffff\ufffe]*$/.test(source.slice(map[i] + 1, map[i + 1]))) return false
    return true
  }
  // The end of the block starting at this BEGIN, or -1 if it does not have the strict shape.
  const close = (begin: RegExpExecArray) => {
    const marker = new RegExp(String.raw`^[ \t]*-----END ${begin[1]}PRIVATE KEY-----[ \t\r]*$`)
    let line = privateKeyBegin.lastIndex
    let next = view.indexOf("\n", line)
    if (next < 0 || !/^[ \t\r]*$/.test(view.slice(line, next))) return -1
    for (line = next + 1; line < view.length; line = next + 1) {
      next = view.indexOf("\n", line)
      if (next < 0) next = view.length
      const text = view.slice(line, next)
      if (marker.test(text)) {
        const end = line + text.indexOf("-----END") + `-----END ${begin[1]}PRIVATE KEY-----`.length
        return untouched(begin.index, end) ? end : -1
      }
      let first = 0
      let last = text.length
      while (first < last && (text[first] === " " || text[first] === "\t")) first++
      while (last > first && " \t\r".includes(text[last - 1])) last--
      const trimmed = text.slice(first, last)
      if (!pemHeader.test(trimmed) && !pemBody.test(trimmed)) return -1
    }
    return -1
  }
  privateKeyBegin.lastIndex = 0
  for (let begin = privateKeyBegin.exec(view); begin; begin = privateKeyBegin.exec(view)) {
    const end = close(begin)
    if (end < 0) {
      found.push({ start: begin.index, end: view.length })
      stats.open = true
      break
    }
    found.push({ start: begin.index, end })
    privateKeyBegin.lastIndex = end
  }
  return found
}

// Fixed-length keys whose end is a boundary: the end of the view, a character that cannot continue a
// word, or (in a mapped view) a place where something was removed or decoded, so "AKIA…\x1b[0mnext"
// joined to "AKIA…next" still ends at the removed sequence. A rejected candidate resumes one character
// on, so a key starting inside it is still tried; the patterns are fixed-length, so this is linear.
function fixedKeySpans(view: string, map: readonly number[] | undefined): Span[] {
  const found: Span[] = []
  fixedKeys.lastIndex = 0
  for (let match = fixedKeys.exec(view); match; match = fixedKeys.exec(view)) {
    const end = match.index + match[0].length
    if (end === view.length || !/[A-Za-z0-9_]/.test(view[end]) || (map && map[end] - map[end - 1] > 1)) {
      found.push({ start: match.index, end })
      continue
    }
    fixedKeys.lastIndex = match.index + 1
  }
  return found
}

// JWTs anywhere, in one pass. Any later "eyJ" inside a candidate's first segment sees the same dots
// after it, so it matches or fails the same way and ends no later: the search resumes after the first
// segment, whether the candidate matched or not. A match is not skipped whole, because an "eyJ" in its
// second or third segment can start the real JWT ("eyJx.a." + a JWT matches up to the JWT's header);
// overlapping spans merge. Each character is then scanned by at most three candidates, and a run like
// "eyJ-eyJ-…" or "eyJeyJ….a.b" once, not once per "eyJ".
function jwts(view: string): Span[] {
  const found: Span[] = []
  let from = 0
  for (let start = view.indexOf("eyJ"); start !== -1; start = view.indexOf("eyJ", from)) {
    jwt.lastIndex = start
    const match = jwt.exec(view)
    if (match) {
      found.push({ start, end: start + match[0].length })
      from = start + match[0].indexOf(".")
      continue
    }
    from = start + 3
    while (from < view.length && /[A-Za-z0-9_-]/.test(view[from])) from++
  }
  return found
}

// Bearer and Basic keep their word boundary (the schemes are English words). A mapped view is not a
// straight copy of the source where the previous character was decoded from an escape or something
// was dropped (a terminal sequence or format character in the joined view, an encoded control in a
// compact one); a boundary lost there must not hide a credential. At each such position this looks
// for a scheme starting there ("status\x1b[2KBea\x1b[31mrer x" joins to "statusBearer x"), and for a
// value starting there right after a scheme ("Bearer%20abc%0ddef" compacts to "Bearerabcdef"). Each
// position is looked at once and a match skips past its value, so this is linear.
// Where a "Bearer" or "Basic" with any tabs inside it ends at p, read backward with no fixed window
// (a long run of tabs inside the word is still the word), or -1.
function schemeEndingAt(view: string, p: number) {
  for (const word of ["bearer", "basic"]) {
    let i = p
    let ok = true
    for (let k = word.length - 1; k >= 0 && ok; k--) {
      if (k < word.length - 1) while (i > 0 && view[i - 1] === "\t") i--
      ok = i > 0 && view[i - 1].toLowerCase() === word[k]
      i--
    }
    if (ok) return i
  }
  return -1
}

function schemeValues(view: string, map: readonly number[], found: Span[]) {
  const gap = (p: number) => p > 0 && map[p] - map[p - 1] > 1
  let after = 0
  for (let p = 1; p < view.length; p++) {
    if (p < after || !gap(p)) continue
    credentialAt.lastIndex = p
    const credential = credentialAt.exec(view)
    if (credential) {
      after = p + credential[0].length
      found.push({ start: p, end: after })
      continue
    }
    const start = schemeEndingAt(view, p)
    if (start < 0) continue
    if (start > 0 && /[A-Za-z0-9_]/.test(view[start - 1]) && !gap(start)) continue
    credentialValueAt.lastIndex = p
    const value = credentialValueAt.exec(view)
    if (!value) continue
    after = p + value[0].length
    found.push({ start, end: after })
  }
}

// Special schemes (WHATWG) take any run of "/" or "\\" after the colon, none included; ssh needs "//".
// URL parsers drop tabs anywhere, so a tab inside the scheme or its slashes ("ht\ttps://") does not
// hide it. A tab in the authority still ends a candidate, like any whitespace (see urlCredentials).
const schemes = /(?:h\t*t\t*t\t*p(?:\t*s)?|w\t*s(?:\t*s)?|f\t*t\t*p)\t*:[\t\/\\]*|s\t*s\t*h\t*:\t*\/\t*\//gi

// URL userinfo, found the way a URL client reads it (WHATWG URL parsing): the authority ends at "/", "?",
// "#" (and "\\" for special schemes), and userinfo runs to its last "@". Literal whitespace or a double
// quote ends the candidate: matching across them would misread prose as a credential, and text() and
// stream() (which splits at newlines) must read a URL the same way. Every other character a URL client
// accepts in userinfo ("<", ">", "`", ...) stays inside it; around a URL ("<https://...>") it can only
// widen the candidate, which redacts more, not less. A candidate is redacted when the parsed URL has a
// username or password; one the parser rejects (an scp-style "ssh://git@host:org/repo") is redacted on
// its raw userinfo instead.
// Only the userinfo is replaced, so the scheme and host stay readable.
function urlCredentials(view: string): Span[] {
  const found: Span[] = []
  // A candidate whose authority starts inside the authority just scanned adds nothing: it ends at or
  // before the same delimiter, its last "@" is covered by the earlier span, and skipping it keeps the
  // scan linear ("https:https:..."). One whose authority starts past it ("https:https://") is scanned.
  let scanned = 0
  for (const match of view.matchAll(schemes)) {
    const start = match.index + match[0].length
    if (start < scanned) continue
    const scheme = match[0].replaceAll("\t", "")
    const special = !scheme.toLowerCase().startsWith("ssh")
    const name = scheme.slice(0, scheme.indexOf(":"))
    // The authority read two ways: ending at the first tab, as before, and read through tabs the
    // way a URL client drops them. Read through a tab, prose ("https://example.test\tbob@example.test")
    // looks like a username, so that reading counts only when it holds a password.
    const read = (throughTabs: boolean) => {
      let end = start
      let at = -1
      let authority = ""
      let tabbed = false
      for (; end < view.length; end++) {
        const char = view[end]
        if (char === "\t" && throughTabs) {
          tabbed = true
          continue
        }
        if ("/?#".includes(char) || (special && char === "\\") || /[\s"]/.test(char)) break
        if (char === "@") at = end
        authority += char
      }
      let parsed: URL | undefined
      if (at !== -1)
        try {
          parsed = new URL(`${name}://${authority}/`)
        } catch {}
      return { end, at, tabbed, parsed, userinfo: authority.slice(0, authority.lastIndexOf("@")) }
    }
    const plain = read(false)
    // Only an authority that stopped at a tab is read again.
    const tabs = view[plain.end] === "\t" ? read(true) : undefined
    // The tabbed reading covers its whole authority too, so candidates inside it are not read again.
    scanned = Math.max(plain.end, tabs?.end ?? 0)
    if (plain.at > start && !(plain.parsed && !plain.parsed.username && !plain.parsed.password))
      found.push({ start, end: plain.at })
    // One that does not parse (a bad port or host after the "@") still counts if it reads as user:password.
    const password = tabs?.parsed ? tabs.parsed.password !== "" : tabs?.userinfo.includes(":")
    if (tabs?.tabbed && tabs.at > start && password) found.push({ start, end: tabs.at })
  }
  return found
}

// Replace every span; overlapping spans merge into one, so no part of either survives. A merge is
// removed outright only if every span in it is a removal.
function apply(source: string, found: readonly Span[]): string {
  let result = ""
  let at = 0
  let open: Span | undefined
  const close = (span: Span) => {
    result += span.remove ? "" : "[redacted]"
    at = span.end
  }
  for (const span of [...found].sort((a, b) => a.start - b.start || b.end - a.end)) {
    if (open && span.start < open.end) {
      open.end = Math.max(open.end, span.end)
      open.remove = open.remove && span.remove
      continue
    }
    if (open) close(open)
    result += source.slice(at, span.start)
    open = { ...span }
  }
  if (open) close(open)
  return (result + source.slice(at)).replaceAll(separator, " ").replaceAll(joint, "")
}

// Nesting past this depth is not walked: a recursive copy would overflow the stack (20,000 nested
// arrays fit in well under 50 KiB of JSON). The value there is replaced with tooDeep, which carries
// nothing from the input, so it fails closed. Every walker over tool data (here and in tool.ts) stops
// at the same depth.
export const maxDepth = 100
export const tooDeep = "[too deep]"

/** JSON-shaped display data only; never apply to command arguments or domain execution values. */
export function value<T>(input: T): T {
  return redactValue(snapshot(input)) as T
}

// Plain JSON-shaped data read from the input exactly once (each own enumerable property, getters
// included, is read a single time), so nothing can change shape between the check and the copy.
// Functions and symbols are dropped; an object that contains itself becomes "[circular]".
function snapshot(
  input: unknown,
  path = new WeakSet<object>(),
  done = new WeakMap<object, unknown>(),
  depth = 0,
): unknown {
  if (typeof input === "function" || typeof input === "symbol") return undefined
  if (!input || typeof input !== "object") return input
  if (depth > maxDepth) return tooDeep
  // A shared reference reuses its one copy; only an object on the current path is a cycle.
  if (done.has(input)) return done.get(input)
  if (path.has(input)) return "[circular]"
  path.add(input)
  const copy = Array.isArray(input)
    ? Array.from(input, (item) => snapshot(item, path, done, depth + 1)).filter((item) => item !== undefined)
    : Object.fromEntries(
        Object.entries(input)
          .map(([key, item]) => [key, snapshot(item, path, done, depth + 1)] as const)
          .filter(([, item]) => item !== undefined),
      )
  path.delete(input)
  done.set(input, copy)
  return copy
}

function redactValue<T>(input: T, depth = 0): T {
  if (typeof input === "string") return text(input) as T
  // JSON data only: a function (such as a toJSON hook) or symbol could serialize anything.
  if (typeof input === "function" || typeof input === "symbol") return undefined as T
  if (input && typeof input === "object" && depth > maxDepth) return tooDeep as T
  if (Array.isArray(input)) {
    const items = input
      .filter((item) => typeof item !== "function" && typeof item !== "symbol")
      .map((item) => (isText(item) ? item : redactValue(item, depth + 1)))
    return textBlocks(items, (item) => redactValue(item, depth + 1)) as T
  }
  if (input && typeof input === "object")
    return Object.fromEntries(
      Object.entries(input)
        .filter(([, item]) => typeof item !== "function" && typeof item !== "symbol")
        .map(([key, item]) => [text(key), redactValue(item, depth + 1)]),
    ) as T
  return input
}

// MCP and Core both carry text blocks, and a credential may span blocks. `rest` redacts a block's
// other fields; non-text items are returned as they are.
export function textBlocks(items: readonly unknown[], rest: (item: object) => object = (item) => item): unknown[] {
  // One cleaner across the blocks, so a surrogate pair split between two blocks is read as its character
  // (a format character inside a credential is removed, not left between two harmless halves).
  const clean = terminal(true)
  const blocks = items.filter(isText).map((item) => clean(item.text))
  if (blocks.length > 0) blocks[blocks.length - 1] += clean.flush()
  const joined = blocks.join("")
  // Offsets are computed incrementally and each span is placed by binary search: linear in the text,
  // however many blocks there are.
  const bounds: number[] = []
  let total = 0
  for (const block of blocks) {
    bounds.push(total)
    total += block.length
  }
  const found = [
    ...spans(joined),
    ...blocks.flatMap((block, index) =>
      spans(block).map((span) => ({ ...span, start: span.start + bounds[index], end: span.end + bounds[index] })),
    ),
  ]
  // The last block starting at or before the span; an empty block shares its start with the next.
  const owner = (span: Span) => {
    let low = 0
    let high = blocks.length - 1
    let best = -1
    while (low <= high) {
      const middle = (low + high) >> 1
      if (bounds[middle] <= span.start) {
        best = middle
        low = middle + 1
      } else high = middle - 1
    }
    return best
  }
  const local: Span[][] = blocks.map(() => [])
  let crosses = false
  for (const span of found) {
    const index = owner(span)
    if (index === -1 || blocks[index].length === 0 || span.end > bounds[index] + blocks[index].length) {
      crosses = true
      break
    }
    local[index].push({ ...span, start: span.start - bounds[index], end: span.end - bounds[index] })
  }
  if (!crosses) {
    let index = 0
    return items.map((item) => {
      if (!isText(item)) return item
      const position = index++
      return { ...rest(item), text: apply(blocks[position], local[position]) }
    })
  }
  // A credential crosses a block boundary: carry the whole redacted text in the first block.
  const safe = apply(joined, found)
  let first = true
  return items.map((item) => {
    if (!isText(item)) return item
    const result = { ...rest(item), text: first ? safe : "" }
    first = false
    return result
  })
}

/** Whether no credential spans the text blocks of `items` once they are joined. */
export function textBlocksClean(items: readonly unknown[]): boolean {
  const clean = terminal(true)
  const joined =
    items
      .filter(isText)
      .map((item) => clean(item.text))
      .join("") + clean.flush()
  return spans(joined).length === 0
}

function isText(input: unknown): input is { type: "text"; text: string } {
  return (
    !!input &&
    typeof input === "object" &&
    "type" in input &&
    input.type === "text" &&
    "text" in input &&
    typeof input.text === "string"
  )
}

// Prototypes an error may inherit from without being suspected of leaking: the built-in errors and
// Effect's error bases (taken from a probe Schema error, past its own two class prototypes).
class Probe extends Schema.TaggedError<Probe>()("ToolOutputRedaction.Probe", {}) {}
const trusted = new Set<object>(
  [Error, TypeError, RangeError, SyntaxError, ReferenceError, EvalError, URIError, AggregateError].map(
    (base) => base.prototype,
  ),
)
for (
  let proto = Object.getPrototypeOf(Object.getPrototypeOf(Object.getPrototypeOf(new Probe())));
  proto;
  proto = Object.getPrototypeOf(proto)
)
  trusted.add(proto)

/**
 * Whether an object's prototype chain can be kept: every prototype before a trusted base adds only a
 * constructor, a string name and Effect's schema class marker. An inherited toJSON, toString, inspect
 * hook, getter or other function could serialize data the own-property checks never saw.
 */
// Error classes from this codebase whose prototypes add more than that (a message getter) but are
// matched by class downstream. Their prototypes are code, not data, and are kept.
const vouched = new Set<object>()
export function trust(...classes: ReadonlyArray<abstract new (...args: never) => Error>) {
  for (const base of classes) vouched.add(base.prototype)
}

// Effect's schema class marker: an accessor whose getter is Effect's own code (the probe class's
// getter, compared by source) and returns exactly its own key, which has already been checked clean.
// Anything else under that prefix, a data value or another getter, is not exempt.
const probeMarker = (() => {
  const out = Object.getPrototypeOf(Object.getPrototypeOf(new Probe()))
  return Object.getOwnPropertyDescriptor(out, "~effect/Schema/Class/ToolOutputRedaction.Probe")?.get
})()
function genuineMarker(proto: object, key: string, input: object) {
  const descriptor = Object.getOwnPropertyDescriptor(proto, key)
  if (!descriptor?.get || descriptor.set || "value" in descriptor || !probeMarker) return false
  if (String(descriptor.get) !== String(probeMarker)) return false
  try {
    return descriptor.get.call(input) === key
  } catch {
    return false
  }
}

export function safePrototype(input: object): boolean {
  for (let proto = Object.getPrototypeOf(input); proto && !trusted.has(proto); proto = Object.getPrototypeOf(proto)) {
    if (vouched.has(proto)) continue
    // oxlint-disable-next-line no-restricted-globals -- genuine reflection: every own key of the prototype
    for (const key of Reflect.ownKeys(proto)) {
      const name = typeof key === "string" ? key : (key.description ?? "")
      if (text(name) !== name) return false
      if (key === "constructor") continue
      // Effect's schema class marker is an accessor that only Effect's internals read; display and
      // serialization never do. Any other prototype key must be a plain string such as `name`.
      if (typeof key === "string" && key.startsWith("~effect/Schema/Class/")) {
        if (genuineMarker(proto, key, input)) continue
        return false
      }
      const descriptor = Object.getOwnPropertyDescriptor(proto, key)!
      if (key !== "name" || !("value" in descriptor) || typeof descriptor.value !== "string") return false
      if (text(descriptor.value) !== descriptor.value) return false
    }
  }
  return true
}

/**
 * A copy with every own field redacted and no reference to the original. The prototype is kept only
 * when it is trusted (see safePrototype), so instanceof still matches errors the runner relies on;
 * otherwise the copy is a plain Error, with no route back to untrusted prototype data or code.
 */
export function error(input: unknown): unknown {
  const seen = new WeakMap<object, object>()
  function clone(item: unknown, depth = 0): unknown {
    if (typeof item === "string") return text(item)
    if (typeof item === "function") return "[omitted diagnostic function]"
    if (typeof item === "symbol") return text(String(item))
    if (!item || typeof item !== "object") return item
    if (depth > maxDepth) return tooDeep
    const previous = seen.get(item)
    if (previous) return previous
    const safe: object =
      item instanceof Error
        ? Object.setPrototypeOf(
            new Error(),
            !types.isProxy(item) && cleanKeys(item) && safePrototype(item)
              ? Object.getPrototypeOf(item)
              : Error.prototype,
          )
        : Array.isArray(item)
          ? []
          : {}
    seen.set(item, safe)
    // oxlint-disable-next-line no-restricted-globals -- genuine reflection: copy every own field, symbols and non-enumerables included, so no diagnostic keeps a raw credential
    for (const key of Reflect.ownKeys(item)) {
      if (Array.isArray(item) && key === "length") continue
      if (item instanceof Error && ["message", "name", "stack"].includes(String(key))) continue
      const descriptor = Object.getOwnPropertyDescriptor(item, key)!
      // Accessors and functions may close over the original response/credential.
      Object.defineProperty(safe, typeof key === "string" ? text(key) : Symbol(text(key.description ?? "")), {
        value: "value" in descriptor ? clone(descriptor.value, depth + 1) : "[omitted diagnostic accessor]",
        enumerable: descriptor.enumerable,
        configurable: true,
        writable: true,
      })
    }
    // A credential split across text blocks is caught on the join, as in value().
    // Each block's own text was redacted above, which can break up a credential that only the join
    // shows: detect on the original text, then redact block and join together.
    if (Array.isArray(safe)) {
      const raw = safe.map((copy, index) => {
        const original: unknown = Object.getOwnPropertyDescriptor(item, index)?.value
        const source =
          original && typeof original === "object"
            ? Object.getOwnPropertyDescriptor(original, "text")?.value
            : undefined
        return isText(copy) && typeof source === "string" ? { ...copy, text: source } : copy
      })
      // Assigned one by one: spreading a large array into call arguments overflows the argument limit.
      textBlocks(raw).forEach((block, index) => {
        safe[index] = block
      })
    }
    if (item instanceof Error) {
      for (const key of ["message", "name", "stack"] as const)
        Object.defineProperty(safe, key, { value: clone(item[key], depth + 1), configurable: true, writable: true })
    }
    return safe
  }
  return clone(input)
}

// An inherited key that itself holds a credential must not survive on a kept prototype either.
function cleanKeys(item: object) {
  for (let proto = Object.getPrototypeOf(item); proto && !trusted.has(proto); proto = Object.getPrototypeOf(proto))
    // oxlint-disable-next-line no-restricted-globals -- genuine reflection: every own key of the prototype
    for (const key of Reflect.ownKeys(proto)) {
      const name = typeof key === "string" ? key : (key.description ?? "")
      if (text(name) !== name) return false
    }
  return true
}

/** Hold unfinished lines before any observer sees a prefix; never flush on interruption/capture loss. */
// Shown once in place of everything a stream withholds after an overlong line.
export const withheldMarker = "[output withheld after an overlong line]"

export function stream() {
  const clean = terminal(true)
  let pending = ""
  // A line past 64 Ki withholds the rest of the stream: one marker, then nothing. The line is not kept,
  // and what it held (an unterminated escape, the label of a credential on the next line) can change
  // how everything after it reads, so nothing after it is trusted. Readers that persist output or show
  // it to the model use text() on the whole output instead (see TOOL-OUTPUT-REDACTION.md).
  let dropped = false
  let withheld = false
  // Length of a held block when it was last found open: it is checked again only once it has doubled,
  // so a block of many short lines is not rescanned at every newline.
  let checked = 0
  // Whether the output has declared a Kubernetes Secret or a Docker auths map: a data block after the
  // kind line, or an auth field after "auths", is read in a later piece of the stream (see shapeSpans()).
  const shapes = { secret: false, auths: false }
  // The redacted line, or undefined to hold it (or, once output is withheld, to drop it): a line that
  // ends inside a terminal sequence only a decoded view sees (an encoded OSC title whose terminator
  // follows a raw newline, as in "Bearer%1b]0;x\n%07 value") is read together with the lines after
  // it, the way text() reads the whole output. The held block is still capped at 64 Ki; finish() emits
  // whatever is held.
  const take = (final: boolean) => {
    if (dropped) {
      if (withheld) return undefined
      withheld = true
      return withheldMarker
    }
    if (!final && checked > 0 && pending.length < 2 * checked) return undefined
    // pending already went through clean(), so it is redacted as text() would without cleaning again.
    const stats = { views: 0, open: false, ...shapes }
    const found = spans(pending, stats)
    shapes.secret = stats.secret
    shapes.auths = stats.auths
    // Past the decoding bound the line is redacted whole, and where it left any terminal sequence is
    // unknown, so the rest of the stream is withheld as after an overlong line.
    if (stats.views > maxViews) {
      pending = ""
      checked = 0
      dropped = true
      withheld = true
      return withheldMarker
    }
    if (!final && stats.open) {
      checked = pending.length
      return undefined
    }
    const safe = apply(pending, found)
    pending = ""
    checked = 0
    return safe
  }
  const feed = (cleaned: string) => {
    let result = ""
    for (const char of cleaned) {
      if (char === "\n") {
        const line = take(false)
        if (line !== undefined) {
          result += line + "\n"
          continue
        }
      }
      if (dropped) continue
      pending += char
      if (pending.length <= 64 * 1024) continue
      pending = ""
      dropped = true
    }
    return result
  }
  return {
    push: (chunk: string) => feed(clean(chunk)),
    finish: () => feed(clean.flush()) + (take(true) ?? ""),
    // Whether this stream has emitted withheldMarker and is withholding the rest.
    withheld: () => withheld,
    // Whether complete lines are being held because they end inside a decoded terminal sequence; text
    // after them is not safe to show until they are released.
    held: () => checked > 0,
    // Whether every complete line pushed so far has been emitted as it reads in the whole output: no
    // line is held or withheld, no terminal sequence or surrogate half is open, and no cleaned text is
    // waiting for its newline (a raw newline inside a removed sequence leaves the line before it there).
    settled: () => !dropped && checked === 0 && pending === "" && clean.idle(),
  }
}

// Stateful terminal stripping removes OSC/DCS metadata, even with embedded newlines
// or chunk-split terminators. Formatting controls cannot separate credential bytes.
// With `carry`, a high surrogate that ends one call is held for the next, so a pair split between chunks
// or blocks is read as one character; flush() returns a held one at the end.
function terminal(carry = false) {
  let state = "text"
  let held = ""
  // Whether the next character is outside any sequence, so printable text passes through unchanged.
  const plain = () => state === "text"
  const flush = () => {
    const rest = held
    held = ""
    return rest
  }
  const strip = (chunk: string) => {
    let input = held + chunk
    held = ""
    const last = input.charCodeAt(input.length - 1)
    if (carry && last >= 0xd800 && last <= 0xdbff) {
      held = input.slice(-1)
      input = input.slice(0, -1)
    }
    let result = ""
    for (const char of input) {
      // Printable ASCII outside a sequence is the common case and needs none of the checks below.
      if (state === "text" && char >= " " && char <= "~") {
        result += char
        continue
      }
      if (state === "string" || state === "string-escape") {
        if (char === "\x07" || char === "\x9c" || (state === "string-escape" && char === "\\")) state = "text"
        else state = char === "\x1b" ? "string-escape" : "string"
        continue
      }
      if (state === "escape") {
        // Intermediate bytes (0x20-0x2F, as in "ESC ( B" from tput sgr0) run until a final byte.
        state =
          char === "["
            ? "csi"
            : "]PX^_".includes(char)
              ? "string"
              : char >= " " && char <= "/"
                ? "intermediate"
                : "text"
        continue
      }
      if (state === "intermediate") {
        if (char >= " " && char <= "/") continue
        state = "text"
        // A final byte ends the sequence; anything else (a newline) is ordinary output again.
        if (char >= "0" && char <= "~") continue
      }
      if (state === "csi") {
        if (char >= "@" && char <= "~") state = "text"
        continue
      }
      // A sequence leaves a joint where it started: a boundary for detection, nothing in the output.
      if (char === "\x1b") {
        state = "escape"
        result += joint
        continue
      }
      if (char === "\x9b") {
        state = "csi"
        result += joint
        continue
      }
      if (char === "\x9d" || char === "\x90") {
        state = "string"
        result += joint
        continue
      }
      if (char === "\n" || char === "\t") {
        result += char
        continue
      }
      // A standalone control (a carriage return, a NUL) separates words: dropping it would join them
      // and could hide a token's boundary. It is kept as a separator, shown as a space. Format
      // characters (zero-width and the like) leave a joint like an escape sequence: invisible in the
      // output, a boundary between words, and dropped inside a token.
      if (/[\p{Cc}\p{Zl}\p{Zp}]/u.test(char)) {
        result += separator
        continue
      }
      if (/\p{Cf}/u.test(char)) {
        result += joint
        continue
      }
      result += char
    }
    return result
  }
  // Whether nothing is carried into the next call: outside any sequence, with no surrogate half held.
  const idle = () => state === "text" && held === ""
  return Object.assign(strip, { plain, flush, idle })
}
