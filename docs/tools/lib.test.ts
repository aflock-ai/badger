import { expect, setDefaultTimeout, test } from "bun:test"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { declarationsIn, findDeclaration as resolve, footer, formatRef, handTypedCitations, linkTargets, markerProblems, offlineGoEnv, parseRefs, refMarkerProblems, replacePatch, toolAccess, type Decl } from "./lib"

// Every span a test resolves is also checked for what makes a citation right, independently of how
// the span was found: its first line names the symbol, and blanking its lines removes that
// declaration (and only what is part of it) while the rest of the file still parses. A span cut
// short leaves a fragment that does not parse; one that runs on removes a neighbour.
function findDeclaration(path: string, source: string, symbol: string) {
  const span = resolve(path, source, symbol)
  if (typeof span === "string") return span
  const lines = source.split("\n")
  expect(lines[span.start - 1]).toContain(symbol.split(".").pop()!)
  const before = declarationsIn(path, source) as Decl[]
  const after = declarationsIn(path, lines.map((l, i) => (i >= span.start - 1 && i < span.end ? "" : l)).join("\n"))
  if (typeof after === "string") throw new Error(`${symbol}: blanking lines ${span.start}-${span.end} leaves a file that does not parse: ${after}`)
  const gone = before.filter((d) => !after.some((a) => a.name === d.name && a.start === d.start)).map((d) => d.name)
  expect(gone).toContain(symbol)
  for (const d of before.filter((d) => gone.includes(d.name) && d.name !== symbol && !d.name.startsWith(symbol + ".")))
    expect(`${d.name} starts on line ${d.start}`).toBe(`${d.name} starts on line ${span.start}`)
  return span
}

// Go symbols resolve through goref, built once per process from an empty cache; on a loaded machine
// that build alone can pass the default five seconds.
setDefaultTimeout(60_000)

const begin = (id: string) => `<!-- BEGIN GENERATED: ${id} -->`
const end = (id: string) => `<!-- END GENERATED: ${id} -->`

test("paired markers pass", () => {
  expect(markerProblems([begin("a"), "x", end("a"), begin("b"), end("b")].join("\n"))).toEqual([])
})

test("a deleted END marker is reported, not skipped", () => {
  expect(markerProblems([begin("a"), "stale"].join("\n"))).toEqual(["section a has no END marker"])
})

test("a deleted BEGIN marker is reported", () => {
  expect(markerProblems(["stale", end("a")].join("\n"))).toEqual([`${end("a")} has no BEGIN`])
})

test("mismatched and nested markers are reported", () => {
  expect(markerProblems([begin("a"), end("b")].join("\n"))).toEqual([`${end("b")} closes b but a is open`])
  expect(markerProblems([begin("a"), begin("b"), end("b")].join("\n"))[0]).toBe(`${begin("b")} opens inside the unclosed section a`)
})

test("a misspelled marker line is reported", () => {
  expect(markerProblems("<!-- BEGIN GENERATED: a-->")).toEqual(["malformed marker line: <!-- BEGIN GENERATED: a-->"])
})

test("only an explicit readOnlyHint: true is labelled read", () => {
  expect(toolAccess({ readOnlyHint: true })).toBe("Read")
  expect(toolAccess({ readOnlyHint: false })).toBe("Write")
  expect(toolAccess({})).toBe("Not annotated; may change the service")
  expect(toolAccess(undefined)).toBe("Not annotated; may change the service")
})

test("link targets include titled links and reference definitions", () => {
  const text = ['[a](one.md)', '[b](two.md "Two")', "[c](three.md 'Three')", '![d](assets/x.svg)', "[e][ref]", "", "[ref]: four.md", '  [other]: <five.md> "Five"'].join("\n")
  expect(linkTargets(text)).toEqual(["one.md", "two.md", "three.md", "assets/x.svg", "four.md", "five.md"])
})

// The caller's environment marks the missing module private, which would otherwise make Go
// bypass GOPROXY=off and fetch it from its origin.
const hostile = { GOPRIVATE: "example.invalid", GONOPROXY: "example.invalid", GONOSUMDB: "example.invalid", GOINSECURE: "example.invalid", GOVCS: "*:all", GOTOOLCHAIN: "auto" }

test("the Go environment keeps only PATH from the caller", () => {
  const env = offlineGoEnv({ ...hostile, PATH: "/usr/bin", GOCACHEPROG: "/tmp/helper", HTTPS_PROXY: "http://proxy.example.invalid" }, "/scratch")
  expect(env.PATH).toBe("/usr/bin")
  expect(Object.keys(env).filter((k) => !k.startsWith("GO") && !["PATH", "HOME", "XDG_CONFIG_HOME", "CGO_ENABLED"].includes(k))).toEqual([])
  expect([env.GOCACHEPROG, env.GOPRIVATE, env.GOINSECURE, env.HTTPS_PROXY]).toEqual([undefined, undefined, undefined, undefined])
  expect([env.GONOPROXY, env.GONOSUMDB, env.GOVCS, env.GOTOOLCHAIN, env.GOPROXY]).toEqual(["none", "none", "*:off", "local", "off"])
})

test("an inherited GOCACHEPROG helper never runs", () => {
  // A cache helper that leaves a mark when Go starts it. The control run shows the test can see it.
  const dir = mkdtempSync(join(tmpdir(), "docs-cacheprog-"))
  const mark = join(dir, "ran")
  const helper = join(dir, "helper.sh")
  writeFileSync(helper, `#!/bin/sh\ntouch '${mark}'\nexit 1\n`, { mode: 0o755 })
  writeFileSync(join(dir, "go.mod"), "module example.invalid/probe\n\ngo 1.22\n")
  writeFileSync(join(dir, "main.go"), "package main\n\nfunc main() {}\n")
  const caller = { PATH: process.env.PATH, GOCACHEPROG: helper }
  const build = (env: Record<string, string | undefined>) => Bun.spawnSync(["go", "build", "-o", join(dir, "probe"), "."], { cwd: dir, env })
  build(offlineGoEnv(caller, join(dir, "scratch")))
  const isolated = existsSync(mark)
  build({ ...offlineGoEnv(caller, join(dir, "scratch")), GOCACHEPROG: helper })
  const control = existsSync(mark)
  rmSync(dir, { recursive: true, force: true })
  expect(isolated).toBe(false)
  expect(control).toBe(true)
})

test("the caller's Go telemetry setting does not reach the subprocess", () => {
  // A home whose Go config turns telemetry uploads on, where Linux and macOS look for it.
  const home = mkdtempSync(join(tmpdir(), "docs-telemetry-home-"))
  for (const dir of [join(home, ".config/go/telemetry"), join(home, "Library/Application Support/go/telemetry")]) {
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, "mode"), "on")
  }
  const scratch = mkdtempSync(join(tmpdir(), "docs-telemetry-scratch-"))
  const mode = (env: Record<string, string | undefined>) => Bun.spawnSync(["go", "env", "GOTELEMETRY"], { env }).stdout.toString().trim()
  const caller = { PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: join(home, ".config") }
  const control = mode(caller)
  const isolated = mode(offlineGoEnv(caller, scratch))
  rmSync(home, { recursive: true, force: true })
  rmSync(scratch, { recursive: true, force: true })
  expect(control).toBe("on")
  expect(isolated).toBe("local")
})

test("the Go environment refuses to fetch a missing module", () => {
  const dir = mkdtempSync(join(tmpdir(), "docs-offline-"))
  writeFileSync(join(dir, "go.mod"), "module example.invalid/probe\n\ngo 1.22\n\nrequire example.invalid/missing v1.0.0\n")
  writeFileSync(join(dir, "main.go"), 'package main\n\nimport _ "example.invalid/missing"\n\nfunc main() {}\n')
  // A go.sum entry gets the build past -mod=readonly to the point where it would download.
  const h = "h1:" + "A".repeat(43) + "="
  writeFileSync(join(dir, "go.sum"), `example.invalid/missing v1.0.0 ${h}\nexample.invalid/missing v1.0.0/go.mod ${h}\n`)
  const run = Bun.spawnSync(["go", "build", "./..."], { cwd: dir, env: offlineGoEnv({ ...hostile, PATH: process.env.PATH }, join(dir, "scratch")) })
  rmSync(dir, { recursive: true, force: true })
  expect(run.exitCode).not.toBe(0)
  expect(run.stderr.toString()).toContain("GOPROXY=off")
})

// Code references: {{ref [root:]path[#Symbol]}} resolves to the declaration's lines at build time.

const goSource = [
  "package demo", // 1
  "", // 2
  "// Config is the demo configuration.", // 3
  "type Config struct {", // 4
  '\tListen string `json:"listen"`', // 5
  "\tMaxStreams int // default 64", // 6
  "}", // 7
  "", // 8
  "func load(path string) (Config, error) {", // 9
  "\treturn Config{}, nil", // 10
  "}", // 11
  "", // 12
  "func (c Config) requestPath() string {", // 13
  '\treturn ""', // 14
  "}", // 15
  "", // 16
  "var name = 1", // 17
  "", // 18
  "const (", // 19
  "\tAvailable State = \"available\"", // 20
  ")", // 21
  "", // 22
  "func (s *server) load() {}", // 23
].join("\n")

test("Go declarations resolve to their whole span", () => {
  expect(findDeclaration("x.go", goSource, "Config")).toEqual({ start: 4, end: 7 })
  expect(findDeclaration("x.go", goSource, "load")).toEqual({ start: 9, end: 11 })
  expect(findDeclaration("x.go", goSource, "name")).toEqual({ start: 17, end: 17 })
  expect(findDeclaration("x.go", goSource, "Available")).toEqual({ start: 20, end: 20 })
})

test("Go fields and methods resolve through their type", () => {
  expect(findDeclaration("x.go", goSource, "Config.MaxStreams")).toEqual({ start: 6, end: 6 })
  expect(findDeclaration("x.go", goSource, "Config.requestPath")).toEqual({ start: 13, end: 15 })
  expect(findDeclaration("x.go", goSource, "server.load")).toEqual({ start: 23, end: 23 })
})

test("an embedded field resolves by its type name, pointer or not", () => {
  const src = ["package p", "", "type Embeds struct {", "\tBase", '\t*Extra `json:"extra"`', "}"].join("\n")
  expect(findDeclaration("x.go", src, "Embeds.Base")).toEqual({ start: 4, end: 4 })
  expect(findDeclaration("x.go", src, "Embeds.Extra")).toEqual({ start: 5, end: 5 })
})

test("a missing or ambiguous symbol is an error, never a guess", () => {
  expect(findDeclaration("x.go", goSource, "Missing")).toBe("no declaration of Missing")
  expect(findDeclaration("x.go", goSource, "Config.Missing")).toBe("no declaration of Config.Missing")
  const twice = goSource + "\n\nfunc load() {}\n"
  expect(findDeclaration("x.go", twice, "load")).toBe("load is declared 2 times")
  expect(findDeclaration("x.md", "# x", "x")).toBe("symbols resolve only in .go, .ts and .tsx files")
})

const tsSource = [
  'import { x } from "y"', // 1
  "", // 2
  "export function managedCommands(a: string) {", // 3
  "  return a", // 4
  "}", // 5
  "", // 6
  "export const kept: Set<string> = new Set([", // 7
  '  "run",', // 8
  "])", // 9
  "", // 10
  "export const limit = 64", // 11
  "", // 12
  "export interface Entry {", // 13
  "  name: string", // 14
  "}", // 15
  "", // 16
  "export type Mode = \"a\" | \"b\"", // 17
  "", // 18
  "export async function admit() {", // 19
  "}", // 20
  "", // 21
  "class Local {", // 22
  "}", // 23
].join("\n")

test("TypeScript declarations resolve to their whole span", () => {
  expect(findDeclaration("x.ts", tsSource, "managedCommands")).toEqual({ start: 3, end: 5 })
  expect(findDeclaration("x.ts", tsSource, "kept")).toEqual({ start: 7, end: 9 })
  expect(findDeclaration("x.ts", tsSource, "limit")).toEqual({ start: 11, end: 11 })
  expect(findDeclaration("x.ts", tsSource, "Entry")).toEqual({ start: 13, end: 15 })
  expect(findDeclaration("x.ts", tsSource, "Mode")).toEqual({ start: 17, end: 17 })
  expect(findDeclaration("x.ts", tsSource, "admit")).toEqual({ start: 19, end: 20 })
  expect(findDeclaration("x.ts", tsSource, "Local")).toEqual({ start: 22, end: 23 })
  expect(findDeclaration("x.ts", tsSource, "x")).toBe("no declaration of x")
})

test("ref markers are found outside fenced code only", () => {
  const text = ["See {{ref testifysec/gateway/config.go#Config}} and {{ref infra:arch/x.py}}.", "```", "{{ref not/this.go#X}}", "```", "{{ref a/b.ts#C.d}}"].join("\n")
  expect(parseRefs(text).map(({ raw, index, ...r }) => r)).toEqual([
    { root: "badger", path: "testifysec/gateway/config.go", symbol: "Config" },
    { root: "infra", path: "arch/x.py", symbol: undefined },
    { root: "badger", path: "a/b.ts", symbol: "C.d" },
  ])
})

test("a malformed ref marker is reported", () => {
  expect(refMarkerProblems("{{ref }} {{ref a.go#}} {{ref ../x.go}} {{ref /etc/passwd}} {{refx a.go}}")).toEqual([
    "malformed ref marker {{ref }}",
    "malformed ref marker {{ref a.go#}}",
    "malformed ref marker {{ref ../x.go}}",
    "malformed ref marker {{ref /etc/passwd}}",
    "malformed ref marker {{refx a.go}}",
  ])
  expect(refMarkerProblems("{{ref a/b.go#X}} {{ref infra:c.go}}")).toEqual([])
})

const badger = { name: "badger", version: "4.3.0", sha: "0123456789abcdef0123456789abcdef01234567", url: "https://github.com/aflock-ai/badger" }

test("a resolved ref names the file, the lines and the commit", () => {
  expect(formatRef({ root: "badger", path: "a/b.go", symbol: "X" }, { start: 4, end: 7 }, badger)).toBe(
    "[`a/b.go:4-7`](https://github.com/aflock-ai/badger/blob/0123456789abcdef0123456789abcdef01234567/a/b.go#L4-L7)",
  )
  expect(formatRef({ root: "badger", path: "a/b.go", symbol: "X" }, { start: 9, end: 9 }, badger)).toBe(
    "[`a/b.go:9`](https://github.com/aflock-ai/badger/blob/0123456789abcdef0123456789abcdef01234567/a/b.go#L9)",
  )
  expect(formatRef({ root: "badger", path: "a/b.go", symbol: undefined }, undefined, badger)).toBe(
    "[`a/b.go`](https://github.com/aflock-ai/badger/blob/0123456789abcdef0123456789abcdef01234567/a/b.go)",
  )
})

test("a root with no public URL renders the path and commit as text", () => {
  const infra = { name: "infra", version: undefined, sha: "fedcba9876543210fedcba9876543210fedcba98", url: undefined }
  expect(formatRef({ root: "infra", path: "x/y.go", symbol: "Z" }, { start: 2, end: 3 }, infra)).toBe("`infra:x/y.go:2-3` (fedcba987654)")
})

test("the footer names every root's version and commit and the commit date", () => {
  expect(footer([badger], "2026-10-24")).toBe("*Generated from badger 4.3.0 at 0123456789ab on 2026-10-24.*")
  const infra = { name: "infra", version: undefined, sha: "fedcba9876543210fedcba9876543210fedcba98", url: undefined }
  expect(footer([badger, infra], "2026-10-24")).toBe("*Generated from badger 4.3.0 at 0123456789ab and infra at fedcba987654 on 2026-10-24.*")
})

// git applies the patch to a file holding before and leaves exactly after, with or without a final
// newline on either side, a name with a space included.
test("a replacement patch turns the page into the regenerated one under git apply", () => {
  const cases = [["a\nb\n", "a\nc\nd\n"], ["a\nb", "a\nb\n"], ["a\nb\n", "a\nb"], ["x\n", "x\n\n"], ["", "new\n"]]
  const repo = mkdtempSync(join(tmpdir(), "docs-patch-"))
  Bun.spawnSync(["git", "-C", repo, "init", "-q"])
  mkdirSync(join(repo, "dir"))
  const results = cases.map(([before, after]) => {
    writeFileSync(join(repo, "dir/a page.md"), before)
    const r = Bun.spawnSync(["git", "-C", repo, "apply"], { stdin: Buffer.from(replacePatch("dir/a page.md", before, after)) })
    return [r.exitCode, readFileSync(join(repo, "dir/a page.md"), "utf8")]
  })
  rmSync(repo, { recursive: true, force: true })
  expect(results).toEqual(cases.map(([, after]) => [0, after]))
})

test("hand-typed line citations in prose are found; code blocks are left alone", () => {
  const body = ["The check is in `launch.go:151-178` and gateway/config.go:18.", "```", "--- FAIL: TestX (main_test.go:42)", "```", "Version 1.2:3 is not a citation."].join("\n")
  expect(handTypedCitations(body)).toEqual(["launch.go:151-178", "gateway/config.go:18"])
})

test("a declaration that continues past its first line ends where its brackets close", () => {
  const src = ["package p", "", 'var reserved = map[string]bool{"a": true,', '\t"b": true}', "", "func f(", "\ta int,", ") error {", '\ts := "}"', "\t_ = s", "\treturn nil", "}"].join("\n")
  expect(findDeclaration("x.go", src, "reserved")).toEqual({ start: 3, end: 4 })
  expect(findDeclaration("x.go", src, "f")).toEqual({ start: 6, end: 12 })
})

test("a declaration inside a comment does not resolve; a comment opener inside a string is not a comment", () => {
  const go = ["package x", "", "/*", "func Removed() {}", "*/", "", "// func Gone() {}", "/* func Inline() {} */", "", "var glob = \"src/**/*.go\"", "", "func Kept() {", "}"].join("\n")
  expect(findDeclaration("x.go", go, "Removed")).toBe("no declaration of Removed")
  expect(findDeclaration("x.go", go, "Inline")).toBe("no declaration of Inline")
  expect(findDeclaration("x.go", go, "Kept")).toEqual({ start: 12, end: 13 })
  const ts = ['const pattern = "src/**/*.ts"', "/** docs */", "export function real() {", "}", "/*", "export const old = 1", "*/"].join("\n")
  expect(findDeclaration("x.ts", ts, "real")).toEqual({ start: 3, end: 4 })
  expect(findDeclaration("x.ts", ts, "old")).toBe("no declaration of old")
})

test("a declaration inside a string literal does not resolve", () => {
  const go = ["package x", "", "var doc = `", "func Removed() {}", "func Kept() {}", "`", "", "func Kept() {", "}"].join("\n")
  expect(findDeclaration("x.go", go, "Removed")).toBe("no declaration of Removed")
  expect(findDeclaration("x.go", go, "Kept")).toEqual({ start: 8, end: 9 })
  const ts = ["const help = `", "export function ghost() {}", "`", "export function real() {", "}"].join("\n")
  expect(findDeclaration("x.ts", ts, "ghost")).toBe("no declaration of ghost")
  expect(findDeclaration("x.ts", ts, "real")).toEqual({ start: 4, end: 5 })
})

test("a TypeScript regex literal or escaped backtick does not hide what follows", () => {
  const src = [
    "const tick = /`/", // 1
    "const cls = /[/`]/g.test(x)", // 2
    "const half = a / 2 / b", // 3
    "const t = `a\\`b`", // 4
    "export function Load() {}", // 5
  ].join("\n")
  expect(findDeclaration("x.ts", src, "Load")).toEqual({ start: 5, end: 5 })
  expect(findDeclaration("x.ts", src, "half")).toEqual({ start: 3, end: 3 })
})

test("a Go raw string ends at the first backtick, backslash or not", () => {
  const src = ["package p", "", "var raw = `a\\`", "", "func Load() {}"].join("\n")
  expect(findDeclaration("x.go", src, "Load")).toEqual({ start: 5, end: 5 })
})

test("fields of a struct declared in a type group resolve", () => {
  const src = ["package p", "", "type (", "\tConfig struct {", '\t\tListen string `json:"listen"`', "\t}", "\tOther int", ")"].join("\n")
  expect(findDeclaration("x.go", src, "Config")).toEqual({ start: 4, end: 6 })
  expect(findDeclaration("x.go", src, "Config.Listen")).toEqual({ start: 5, end: 5 })
})

test("a multiline raw string or template literal is inside its declaration's span", () => {
  const go = ["package p", "", "var tmpl = `a", "b", "c`", "", "func Load() {}"].join("\n")
  expect(findDeclaration("x.go", go, "tmpl")).toEqual({ start: 3, end: 5 })
  const ts = ["export const page = `<p>", "{", "</p>`", "", "export function Load() {}"].join("\n")
  expect(findDeclaration("x.ts", ts, "page")).toEqual({ start: 1, end: 3 })
})

test("tilde fences and longer backtick fences hide markers and citations", () => {
  const text = ["~~~", "{{ref a.go#X}} lib.go:4", "~~~", "````md", "```", "{{ref b.go#Y}}", "```", "````", "{{ref c.go#Z}}"].join("\n")
  expect(parseRefs(text).map((r) => r.path)).toEqual(["c.go"])
  expect(handTypedCitations(text)).toEqual([])
})

test("brackets around a multiline literal still count", () => {
  const ts = ["export function page() {", "  return String(`a", "b`)", "}", "", "export function Load() {}"].join("\n")
  expect(findDeclaration("x.ts", ts, "page")).toEqual({ start: 1, end: 4 })
})

test("a struct header with a trailing comment still resolves its fields", () => {
  const src = ["package p", "", "type Config struct { // settings", '\tListen string `json:"listen"`', "}"].join("\n")
  expect(findDeclaration("x.go", src, "Config.Listen")).toEqual({ start: 4, end: 4 })
})

test("an unterminated ref marker is a problem", () => {
  expect(refMarkerProblems("see {{ref x.go#Missing\nnext line")).toEqual(["unterminated ref marker {{ref x.go#Missing"])
  expect(refMarkerProblems("see {{ref x.go#Ok}} and done")).toEqual([])
})

test("a TypeScript identifier ending in $ resolves exactly", () => {
  const src = ["export const state$ = 1", "export const state = 2"].join("\n")
  expect(findDeclaration("x.ts", src, "state$")).toEqual({ start: 1, end: 1 })
  expect(findDeclaration("x.ts", src, "state")).toEqual({ start: 2, end: 2 })
  expect(findDeclaration("x.ts", "export const state$ = 1", "state")).toBe("no declaration of state")
})

test("a class header over several lines ends at its body", () => {
  const src = ["export class C extends Base<", "  string", "> {", "  m() {}", "}", "", "export function Load() {}"].join("\n")
  expect(findDeclaration("x.ts", src, "C")).toEqual({ start: 1, end: 5 })
  expect(findDeclaration("x.ts", src, "C.m")).toEqual({ start: 4, end: 4 })
})

test("an = or => header runs through its bracketed expression, blank lines included", () => {
  const src = ["export const make = () =>", "  build({", "", "    a: 1,", "  })", "", "export function Load() {}"].join("\n")
  expect(findDeclaration("x.ts", src, "make")).toEqual({ start: 1, end: 5 })
  expect(findDeclaration("x.ts", ["export const n =", "  1", "", "export const m = 2"].join("\n"), "n")).toEqual({ start: 1, end: 2 })
})

test("embedded Go fields resolve by type name, pointer or package-qualified", () => {
  const src = ["package p", "", "type Config struct {", "\t*Reader", "\tio.Writer", "\tName string", "}"].join("\n")
  expect(findDeclaration("x.go", src, "Config.Reader")).toEqual({ start: 4, end: 4 })
  expect(findDeclaration("x.go", src, "Config.Writer")).toEqual({ start: 5, end: 5 })
})

test("a multiline arrow signature ending in ) => runs through its expression", () => {
  const src = ["export const f = (", "  a: string,", ") =>", "  a.trim()", "", "export const g = 1"].join("\n")
  expect(findDeclaration("x.ts", src, "f")).toEqual({ start: 1, end: 4 })
})

test("Go names declared together resolve, and members at any indentation", () => {
  expect(findDeclaration("x.go", "package p\n\nvar First, Second int\n", "Second")).toEqual({ start: 3, end: 3 })
  expect(findDeclaration("x.go", "package p\n\nconst (\n\tA, B = 1, 2\n)\n", "B")).toEqual({ start: 4, end: 4 })
  const ts = ["export class C {", "    run() {", "        return 1", "    }", "}"].join("\n")
  expect(findDeclaration("x.ts", ts, "C.run")).toEqual({ start: 2, end: 4 })
})

test("a multiline union runs through every variant", () => {
  const src = ["export type T =", "  | A", "  | B", "  | C", "", "export const x = 1"].join("\n")
  expect(findDeclaration("x.ts", src, "T")).toEqual({ start: 1, end: 4 })
})

test("fences in blockquotes and list items hide their markers", () => {
  expect(parseRefs("> ```\n> {{ref a.go#X}}\n> ```\n")).toEqual([])
  expect(parseRefs("- item\n\n    ```\n    {{ref b.go#Y}}\n    ```\n")).toEqual([])
})

test("a method chain on the next lines belongs to the declaration", () => {
  const src = ["export const Schema = z.string()", "  .min(8)", "  ?.max(64)", "", "export const y = 1"].join("\n")
  expect(findDeclaration("x.ts", src, "Schema")).toEqual({ start: 1, end: 3 })
})

test("a keyword inside an expression does not make a declaration need a body", () => {
  const src = ['export const Mode = z.enum(["a", "b"])', "", "export const Other = 1"].join("\n")
  expect(findDeclaration("x.ts", src, "Mode")).toEqual({ start: 1, end: 1 })
})

// The resolver's supported forms are frozen (docs/README.md, "Citing code"). Every form outside them
// is an error that names it, never a guessed span.
test("unsupported forms are errors that name the form", () => {
  expect(findDeclaration("x.go", "package p\n\nfunc F() {\n\tlocal := 1\n\t_ = local\n}\n", "local")).toBe("no declaration of local")
  expect(findDeclaration("x.py", "def f():\n    pass\n", "f")).toBe("symbols resolve only in .go, .ts and .tsx files")
  expect(refMarkerProblems("{{ref x.go#A.B.C}}")).toEqual(["malformed ref marker {{ref x.go#A.B.C}}"])
  expect(findDeclaration("x.ts", "export default function () {}", "default")).toBe("no declaration of default")
})

test("a fence in a blockquote ends with the blockquote; one in a list item ends with the item", () => {
  expect(parseRefs("> ~~~\n> example\n\n{{ref missing.go#X}}\n").map((r) => r.path)).toEqual(["missing.go"])
  expect(parseRefs("- item\n\n  ```\n  code\n\nafter {{ref b.go#Y}}\n").map((r) => r.path)).toEqual(["b.go"])
})

test("members resolve only in a class, interface or object literal, never in a function body", () => {
  expect(findDeclaration("x.ts", "export function F() {\n  missing()\n}", "F.missing")).toBe("no declaration of F.missing")
  expect(findDeclaration("x.ts", "export const O = {\n  a: 1,\n}", "O.a")).toEqual({ start: 2, end: 2 })
})

test("an indented fence outside a list keeps unindented lines inside it", () => {
  expect(parseRefs("  ```\n{{ref missing.go#X}}\n  ```\n")).toEqual([])
  expect(parseRefs("1. step\n\n   ```\n   code\n\n{{ref after.go#Y}}\n").map((r) => r.path)).toEqual(["after.go"])
})

test("a continuation line led by an operator belongs to the declaration", () => {
  const src = ["export const value = ready", "  ? load()", "  : fallback()", "", "export const y = 1"].join("\n")
  expect(findDeclaration("x.ts", src, "value")).toEqual({ start: 1, end: 3 })
  expect(findDeclaration("x.ts", ["export const s = a", "  + b", "  || c", "", "export const t = 1"].join("\n"), "s")).toEqual({ start: 1, end: 3 })
})

test("a Go field followed by an embedded pointer field is one line", () => {
  const src = ["package p", "", "type Config struct {", "\tName string", "\t*Reader", "}"].join("\n")
  expect(findDeclaration("x.go", src, "Config.Name")).toEqual({ start: 4, end: 4 })
})

test("a line ending in an operator continues the declaration", () => {
  const src = ["export const total = left +", "  right", "", "export const y = 1"].join("\n")
  expect(findDeclaration("x.ts", src, "total")).toEqual({ start: 1, end: 2 })
})

test("a regex initializer is not a trailing division, and Go continues after a trailing operator", () => {
  const ts = ["export const pattern = /x/", "", "export function next() {", "  return 1", "}"].join("\n")
  expect(findDeclaration("x.ts", ts, "pattern")).toEqual({ start: 1, end: 1 })
  const go = ["package p", "", 'const Help = "first" +', '\t"second"', "", "func F() {}"].join("\n")
  expect(findDeclaration("x.go", go, "Help")).toEqual({ start: 3, end: 4 })
})

test("JSX closing tags are not regex literals, and an unterminated / never eats a line", () => {
  expect(findDeclaration("x.tsx", "const view = <div></div>\nexport function Load() {}", "Load")).toEqual({ start: 2, end: 2 })
  expect(findDeclaration("x.ts", "call(/\nexport function L() {}\n", "L")).toStartWith("x.ts does not parse as TypeScript")
})

// The parser reads every form the language allows at these levels, so forms the line scanner had to
// refuse now resolve.
test("members on the declaration's own line and Go interface methods resolve", () => {
  expect(findDeclaration("x.ts", "export interface Entry { name: string }", "Entry.name")).toEqual({ start: 1, end: 1 })
  expect(findDeclaration("x.go", "package p\n\ntype R interface {\n\tRead(p []byte) (int, error)\n}\n", "R.Read")).toEqual({ start: 4, end: 4 })
  expect(findDeclaration("x.ts", "export enum E {\n  A = 1,\n  B,\n}", "E.B")).toEqual({ start: 3, end: 3 })
  expect(findDeclaration("x.ts", "export const O = {\n  a: 1,\n} as const", "O.a")).toEqual({ start: 2, end: 2 })
})

test("a file that does not parse is an error, never a scan", () => {
  expect(findDeclaration("x.go", "package p\n\nfunc F( {\n", "F")).toStartWith("x.go does not parse as Go")
  expect(findDeclaration("x.go", "func F() {}\n", "F")).toStartWith("x.go does not parse as Go")
  expect(findDeclaration("x.ts", "export function F( {\n", "F")).toStartWith("x.ts does not parse as TypeScript")
  expect(findDeclaration("x.ts", "const v = <div></div>\nexport function L() {}", "L")).toStartWith("x.ts does not parse as TypeScript")
})

test("a span whose first line does not name the symbol is an error", () => {
  expect(findDeclaration("x.ts", "@sealed\nexport class C {}\n", "C")).toBe("C: its declaration starts on line 1, which does not name it; cite the file")
})

test("an overloaded function or a getter and setter pair is ambiguous", () => {
  expect(findDeclaration("x.ts", "export function f(a: string): void\nexport function f(a: any) {}\n", "f")).toBe("f is declared 2 times")
  expect(findDeclaration("x.ts", "class C {\n  get v() { return 1 }\n  set v(x) {}\n}\n", "C.v")).toBe("C.v is declared 2 times")
})

test("Go methods on generic types and doc comments outside the span", () => {
  const src = ["package p", "", "type L[T any] struct{ v T }", "", "// Len counts.", "func (l *L[T]) Len() int {", "\treturn 0", "}"].join("\n")
  expect(findDeclaration("x.go", src, "L.Len")).toEqual({ start: 6, end: 8 })
  expect(findDeclaration("x.go", src, "L.v")).toEqual({ start: 3, end: 3 })
})

// Property: every symbol docs/ cites resolves, and its span passes the checks findDeclaration (above)
// makes on every span.
test("every symbol cited in docs/ resolves to a span that names it and holds exactly that declaration", () => {
  const repo = join(import.meta.dir, "../..")
  let cited = 0
  for (const page of new Bun.Glob("**/*.md").scanSync(join(repo, "docs"))) {
    const text = readFileSync(join(repo, "docs", page), "utf8")
    // The configuration reference names each field's source as `Type.Field` in `file.go`.
    const named = [...text.matchAll(/`([A-Za-z_]\w*\.[A-Za-z_]\w*)` in `([\w./-]+\.go)`/g)].map((m) => ({ raw: m[0], root: "badger", path: m[2], symbol: m[1] }))
    for (const ref of [...parseRefs(text), ...named]) {
      if (ref.root !== "badger" || !ref.symbol) continue
      const span = findDeclaration(ref.path, readFileSync(join(repo, ref.path), "utf8"), ref.symbol)
      expect(`${page}: ${ref.raw}: ${typeof span === "string" ? span : "ok"}`).toBe(`${page}: ${ref.raw}: ok`)
      cited++
    }
  }
  console.log(`checked ${cited} cited symbols`)
})

test("citing a Go symbol without a Go toolchain says so", () => {
  // A PATH holding bun alone: bun's own directory may hold go too.
  const bunDir = mkdtempSync(join(tmpdir(), "docs-nogo-"))
  symlinkSync(process.execPath, join(bunDir, "bun"))
  const script = `import { findDeclaration } from ${JSON.stringify(join(import.meta.dir, "lib.ts"))}; console.log(findDeclaration("x.go", "package p\\n\\nfunc F() {}\\n", "F"))`
  const run = Bun.spawnSync([process.execPath, "-e", script], { env: { PATH: bunDir }, cwd: import.meta.dir })
  rmSync(bunDir, { recursive: true, force: true })
  expect(run.stdout.toString().trim()).toBe("citing a Go symbol needs the go command on PATH (docs/tools/goref parses the file)")
})

// GitHub numbers lines by \n alone. TypeScript's own line map also breaks at U+2028, U+2029 and a
// lone \r, and go/token follows //line directives; either would shift every later citation.
test("line numbers count \\n only, whatever the parser's line map says", () => {
  expect(findDeclaration("x.ts", 'const s = "a b c"\nexport function F() {}\n', "F")).toEqual({ start: 2, end: 2 })
  expect(findDeclaration("x.ts", "const s = 1 // a\rb\nexport function F() {}\n", "F")).toEqual({ start: 2, end: 2 })
  expect(findDeclaration("x.go", "package p\n\n//line other.go:100\nfunc F() {}\n", "F")).toEqual({ start: 4, end: 4 })
})

// CommonMark: a fence is indented at most three spaces past its container (none, a blockquote's
// "> ", or a list item's content column); four or more is an indented code line, not a fence.
test("a run of backticks or tildes indented four spaces opens no fence", () => {
  expect(parseRefs("    ~~~\n\n{{ref missing.go#X}}\n").map((r) => r.path)).toEqual(["missing.go"])
  expect(parseRefs("\t~~~\n\n{{ref tabbed.go#X}}\n").map((r) => r.path)).toEqual(["tabbed.go"])
  expect(parseRefs(">     ```\n\n{{ref quoted.go#X}}\n").map((r) => r.path)).toEqual(["quoted.go"])
  expect(parseRefs("- item\n\n      ```\n\n{{ref listed.go#X}}\n").map((r) => r.path)).toEqual(["listed.go"])
  expect(parseRefs("```\n    ```\n{{ref inside.go#X}}\n```\n")).toEqual([])
})

test("a fence in a nested blockquote ends when the quote gets shallower", () => {
  const text = "> > ~~~\n> > example\n>\n> {{ref missing.go#X}}\n"
  expect(parseRefs(text).map((r) => r.path)).toEqual(["missing.go"])
  expect(parseRefs("> > ~~~\n> > {{ref hidden.go#X}}\n> > ~~~\n")).toEqual([])
})

// A tab after a list marker advances to the next tab stop: "-\titem" has its content at column 4,
// so a line indented two spaces is outside the item and its marker is prose.
test("a fence opened on a list marker's line hides its markers", () => {
  expect(parseRefs("- ```\n  {{ref a.go#X}}\n  ```\n\n{{ref b.go#Y}}\n").map((r) => r.path)).toEqual(["b.go"])
})

test("list indentation is measured in tab-expanded columns", () => {
  expect(parseRefs("-\titem\n    ~~~\n    example\n\n  {{ref missing.go#X}}\n").map((r) => r.path)).toEqual(["missing.go"])
})

// Only a run at the opener's own quote depth closes a fence: "> > ```" inside a fence opened at "> "
// is a code line that reads "> ```", and the fence goes on to the "> ```" after it.
test("a fence closes only at its own blockquote depth", () => {
  expect(parseRefs("> ```\n> > ```\n> ```\n> {{ref missing.go#X}}\n").map((r) => r.path)).toEqual(["missing.go"])
  expect(parseRefs("> ```\n> > ```\n> {{ref hidden.go#X}}\n> ```\n")).toEqual([])
})

// go/scanner drops \r from a raw string's value, and the literal's End is computed from that value,
// so in a CRLF file a multiline raw string would end its span early.
test("a multiline raw string in a CRLF Go file is cited to its closing backtick", () => {
  const src = "package p\r\n\r\nvar x = `a\r\n\r\n\r\n`\r\n\r\ntype T struct {\r\n\tF int `json:\"f\"`\r\n}\r\n\r\nfunc G() {}\r\n"
  expect(findDeclaration("x.go", src, "x")).toEqual({ start: 3, end: 6 })
  expect(findDeclaration("x.go", src, "T.F")).toEqual({ start: 9, end: 9 })
})
