// Helpers for generate.ts, kept apart so lib.test.ts can test them without touching the tree.
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fromMarkdown } from "mdast-util-from-markdown"
import ts from "typescript"

// Every BEGIN GENERATED marker must be closed by the END marker of the same name before the next
// BEGIN. generate.ts rewrites only complete pairs, so an unpaired marker would otherwise leave a
// stale section that --check reports as current.
export function markerProblems(text: string): string[] {
  const problems: string[] = []
  let open: string | undefined
  for (const [line, kind, id] of text.matchAll(/^<!-- (BEGIN|END) GENERATED: ([a-z-]+) -->$/gm)) {
    if (kind === "BEGIN" && open) problems.push(`${line} opens inside the unclosed section ${open}`)
    if (kind === "END" && open !== id) problems.push(open ? `${line} closes ${id} but ${open} is open` : `${line} has no BEGIN`)
    open = kind === "BEGIN" ? id : undefined
  }
  if (open) problems.push(`section ${open} has no END marker`)
  const stray = text.match(/^.*GENERATED:.*$/gm)?.filter((l) => !/^<!-- (BEGIN|END) GENERATED: [a-z-]+ -->$/.test(l)) ?? []
  return [...problems, ...stray.map((l) => `malformed marker line: ${l}`)]
}

// How the reference labels a tool's access, from its MCP annotations. readOnlyHint defaults to
// false in MCP, so only an explicit true is read-only.
export function toolAccess(annotations: { readOnlyHint?: boolean } | undefined): string {
  if (annotations?.readOnlyHint === true) return "Read"
  if (annotations?.readOnlyHint === false) return "Write"
  return "Not annotated; may change the service"
}

// Every link and image target in Markdown prose (code already removed): inline links, with or
// without a title, and reference-style link definitions.
export function linkTargets(prose: string): string[] {
  const inline = [...prose.matchAll(/\]\(\s*<?([^)\s>]+)>?(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)/g)].map((m) => m[1])
  const defined = [...prose.matchAll(/^ {0,3}\[[^\]]+\]:\s*<?([^\s>]+)>?/gm)].map((m) => m[1])
  return [...inline, ...defined]
}

// The environment generate.ts runs the Go toolchain in. It is built, not inherited: only PATH comes
// from the caller, so no variable that changes what Go fetches, runs or uploads (GOCACHEPROG,
// GOPRIVATE, GONOPROXY, GOFLAGS, GOTOOLCHAIN, a proxy, ...) can reach it. HOME, the config
// directory, GOPATH and the caches live in `scratch`, a fresh directory the caller owns, so the
// caller's Go telemetry mode and `go env -w` file are never read and telemetry stays local-only.
// The installed toolchain only, no module proxy, no checksum database, no version-control fetch,
// no change to go.mod: a connector whose dependencies are not present fails instead of fetching
// them, so --check never reaches the network.
export function offlineGoEnv(base: Record<string, string | undefined>, scratch: string): Record<string, string | undefined> {
  return {
    PATH: base.PATH,
    HOME: scratch,
    XDG_CONFIG_HOME: `${scratch}/config`,
    GOPATH: `${scratch}/gopath`,
    GOCACHE: `${scratch}/cache`,
    GOMODCACHE: `${scratch}/mod`,
    GOENV: "off",
    GOWORK: "off",
    GOFLAGS: "-mod=readonly",
    GOPROXY: "off",
    GOSUMDB: "off",
    GONOPROXY: "none",
    GONOSUMDB: "none",
    GOVCS: "*:off",
    GOTOOLCHAIN: "local",
    CGO_ENABLED: "0",
  }
}

// Code references. A page cites code with {{ref [root:]path[#Symbol]}}; the line numbers come from
// the declaration at build time, never from the page, so a citation cannot drift from the code.
export type Ref = { raw: string; index: number; root: string; path: string; symbol: string | undefined }
export type Span = { start: number; end: number }
export type Root = { name: string; version: string | undefined; sha: string; url: string | undefined }

const refArg = /^(?:([a-z][a-z0-9-]*):)?([A-Za-z0-9_][A-Za-z0-9_./-]*)(?:#([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?))?$/

// Code blocks blanked out, offsets and newlines kept, so a marker or citation shown as an example is
// not read. Blocks are found by a CommonMark parser (micromark, through mdast-util-from-markdown):
// fenced and indented code, in blockquotes and list items at any depth, as a renderer sees them.
export function blankFences(text: string): string {
  const out = text.split("")
  const walk = (node: { type: string; position?: { start: { offset?: number }; end: { offset?: number } }; children?: unknown[] }) => {
    if (node.type === "code" && node.position) {
      for (let k = node.position.start.offset!; k < node.position.end.offset!; k++) if (out[k] !== "\n") out[k] = " "
      return
    }
    for (const c of node.children ?? []) walk(c as typeof node)
  }
  walk(fromMarkdown(text))
  return out.join("")
}

export function parseRefs(text: string): Ref[] {
  return [...blankFences(text).matchAll(/\{\{ref ([^}]*)\}\}/g)].flatMap((m) => {
    const a = refArg.exec(m[1])
    if (!a || a[2].split("/").includes("..")) return []
    return [{ raw: m[0], index: m.index!, root: a[1] ?? "badger", path: a[2], symbol: a[3] }]
  })
}

export function refMarkerProblems(text: string): string[] {
  return [...blankFences(text).matchAll(/\{\{\s*ref[^}]*\}\}/g)]
    .filter((m) => {
      const a = /^\{\{ref (.*)\}\}$/.exec(m[0])
      const p = a && refArg.exec(a[1])
      return !p || p[2].split("/").includes("..")
    })
    .map((m) => `malformed ref marker ${m[0]}`)
    .concat([...blankFences(text).matchAll(/\{\{\s*ref\b[^}\n]*(?=\n|$|\}(?!\}))/g)].map((m) => `unterminated ref marker ${m[0].trim()}`))
}

export type Decl = { name: string; start: number; end: number }

// Every declaration a ref can name in one file, with its lines, read by the language's own parser
// (go/parser through goref, the TypeScript compiler API), or why the file cannot be read. Names are
// top-level declarations and Owner.member for the members of a type: Go methods, struct fields and
// interface methods; TypeScript class, interface and enum members and the properties of a const
// holding an object literal. A span runs from the line that declares the name (doc comments are
// outside it) to the line where the declaration ends.
export function declarationsIn(path: string, source: string): Decl[] | string {
  if (path.endsWith(".go")) return goDeclarations(path, source)
  if (/\.tsx?$/.test(path)) return tsDeclarations(path, source)
  return "symbols resolve only in .go, .ts and .tsx files"
}

export function findDeclaration(path: string, source: string, symbol: string): Span | string {
  const all = declarationsIn(path, source)
  if (typeof all === "string") return all
  const found = all.filter((d) => d.name === symbol)
  if (found.length === 0) return `no declaration of ${symbol}`
  if (found.length > 1) return `${symbol} is declared ${found.length} times`
  const { start, end } = found[0]
  // A span that starts on a decorator, say, would not show the reader the name it cites.
  if (!source.split("\n")[start - 1].includes(symbol.split(".").pop()!))
    return `${symbol}: its declaration starts on line ${start}, which does not name it; cite the file`
  return { start, end }
}

// goref is built once per run, offline, into a scratch directory removed on exit.
let goref: string | undefined
function runGoref(input: string): { code: number | null; out: string; err: string } | string {
  if (!goref) {
    if (!Bun.which("go")) return "needs the go command on PATH"
    const scratch = mkdtempSync(join(tmpdir(), "badger-docs-goref-"))
    process.on("exit", () => rmSync(scratch, { recursive: true, force: true }))
    const out = join(scratch, "goref")
    const build = Bun.spawnSync(["go", "build", "-o", out, "."], { cwd: join(import.meta.dir, "goref"), env: offlineGoEnv(process.env, scratch) })
    if (build.exitCode !== 0) throw new Error(`building goref: ${build.stderr.toString()}`)
    goref = out
  }
  const run = Bun.spawnSync([goref], { stdin: Buffer.from(input) })
  return { code: run.exitCode, out: run.stdout.toString(), err: run.stderr.toString().trim() }
}

function goDeclarations(path: string, source: string): Decl[] | string {
  const run = runGoref(source)
  if (typeof run === "string") return `citing a Go symbol ${run} (docs/tools/goref parses the file)`
  if (run.code !== 0) return `${path} does not parse as Go: ${run.err}`
  return JSON.parse(run.out)
}

// The identity (device and inode) of a directory, as goref checks it before it writes under it, or
// why it has none.
function tsDeclarations(path: string, source: string): Decl[] | string {
  const kind = path.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS
  const sf = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, kind)
  // The parser recovers from syntax errors and keeps going; its own list of them is not in the
  // public typings. Any error refuses the file: a recovered tree is a guess.
  const errors = (sf as unknown as { parseDiagnostics: ts.Diagnostic[] }).parseDiagnostics
  if (errors.length > 0) return `${path} does not parse as TypeScript: ${ts.flattenDiagnosticMessageText(errors[0].messageText, " ")}`
  // Lines are counted by \n alone, as GitHub numbers them; the parser's own line map also breaks at
  // U+2028, U+2029 and a lone \r.
  const breaks = [...source.matchAll(/\n/g)].map((m) => m.index!)
  const line = (pos: number) => {
    let n = 0
    while (n < breaks.length && breaks[n] < pos) n++
    return n + 1
  }
  const out: Decl[] = []
  // getStart skips leading comments and JSDoc, so a span starts at the declaration itself.
  const add = (name: string, node: ts.Node) => out.push({ name, start: line(node.getStart(sf)), end: line(node.getEnd()) })
  const nameOf = (n: ts.Node | undefined) => (n && (ts.isIdentifier(n) || ts.isStringLiteral(n)) ? n.text : undefined)
  const members = (owner: string, list: readonly ts.Node[]) => {
    for (const m of list) {
      const name = nameOf((m as ts.NamedDeclaration).name)
      if (name) add(`${owner}.${name}`, m)
    }
  }
  for (const s of sf.statements) {
    if (ts.isVariableStatement(s)) {
      const list = s.declarationList.declarations
      for (const d of list) {
        const name = nameOf(d.name)
        if (!name) continue
        add(name, list.length === 1 ? s : d)
        let init = d.initializer
        while (init && (ts.isAsExpression(init) || ts.isSatisfiesExpression(init) || ts.isParenthesizedExpression(init))) init = init.expression
        if (init && ts.isObjectLiteralExpression(init)) members(name, init.properties)
      }
      continue
    }
    const named = ts.isFunctionDeclaration(s) || ts.isClassDeclaration(s) || ts.isInterfaceDeclaration(s) || ts.isTypeAliasDeclaration(s) || ts.isEnumDeclaration(s) || ts.isModuleDeclaration(s)
    const name = named && s.name && ts.isIdentifier(s.name) ? s.name.text : undefined
    if (!name) continue
    add(name, s)
    if (ts.isClassDeclaration(s) || ts.isInterfaceDeclaration(s) || ts.isEnumDeclaration(s)) members(name, s.members)
  }
  return out
}

const short = (r: Root) => r.sha.slice(0, 12)

export function formatRef(ref: Pick<Ref, "root" | "path" | "symbol">, span: Span | undefined, root: Root): string {
  const lines = span ? (span.start === span.end ? `${span.start}` : `${span.start}-${span.end}`) : ""
  const label = `${ref.path}${lines && ":" + lines}`
  if (!root.url) return `\`${root.name}:${label}\` (${short(root)})`
  const anchor = span ? (span.start === span.end ? `#L${span.start}` : `#L${span.start}-L${span.end}`) : ""
  return `[\`${label}\`](${root.url}/blob/${root.sha}/${ref.path}${anchor})`
}

export function footer(roots: Root[], date: string): string {
  const parts = roots.map((r) => `${r.name}${r.version ? " " + r.version : ""} at ${short(r)}`)
  return `*Generated from ${parts.join(" and ")} on ${date}.*`
}

// A line number typed by hand next to a source file. Pages cite code with {{ref}} instead.
export function handTypedCitations(body: string): string[] {
  const exts = "go|ts|tsx|js|py|lean|sh|rs|c|h"
  return [...blankFences(body).matchAll(new RegExp(`(?<![\\w/.-])[A-Za-z0-9_][\\w./-]*\\.(?:${exts}):\\d+(?:-\\d+)?\\b`, "g"))].map((m) => m[0])
}

// A patch that git apply reads, replacing the file at path (relative to its checkout's top) that
// holds before with after: one hunk over the whole file. generate.ts --diff prints it, so git, not
// the generator, writes the page.
export function replacePatch(path: string, before: string, after: string): string {
  const side = (text: string, sign: string) => {
    const lines = text.split("\n")
    const eol = lines[lines.length - 1] === ""
    if (eol) lines.pop()
    const body = lines.map((l) => `${sign}${l}\n`).join("") + (eol || !lines.length ? "" : "\\ No newline at end of file\n")
    return { n: lines.length, body }
  }
  const a = side(before, "-")
  const b = side(after, "+")
  const range = (n: number) => (n ? `1,${n}` : "0,0")
  return `diff --git a/${path} b/${path}\n--- a/${path}\n+++ b/${path}\n@@ -${range(a.n)} +${range(b.n)} @@\n${a.body}${b.body}`
}
