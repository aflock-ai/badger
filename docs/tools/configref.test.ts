// The config extractor (configref/) on a fixture package: every field a JSON decoder reads, with
// its key, type, default and comment, and the line it is declared on.
import { afterAll, expect, setDefaultTimeout, test } from "bun:test"
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { offlineGoEnv } from "./lib"

// go run of the extractor builds from an empty cache; on a loaded machine that alone can pass the
// default five seconds.
setDefaultTimeout(60_000)

const dir = mkdtempSync(join(tmpdir(), "docs-configref-"))
afterAll(() => rmSync(dir, { recursive: true, force: true }))
mkdirSync(join(dir, "pkg"))
writeFileSync(
  join(dir, "pkg/config.go"),
  [
    "package pkg", // 1
    "", // 2
    'import "encoding/json"', // 3
    "", // 4
    "type Config struct {", // 5
    '\tListen string `json:"listen"` // e.g. ":8443"', // 6
    "\t// MaxStreams bounds the pod; zero takes the default.", // 7
    '\tMaxStreams int `json:"maxStreams"` // default 64', // 8
    '\tIdleMinutes *int `json:"idleMinutes"` // absent: 30; 0: never', // 9
    '\tSources []source `json:"connectors"`', // 10
    "\tNested struct {", // 11
    '\t\tAdmin string `json:"admin"`', // 12
    '\t} `json:"nested"`', // 13
    '\tRaw json.RawMessage `json:"raw,omitempty"`', // 14
    '\tSkipped string `json:"-"`', // 15
    "\thidden []string", // 16
    "\tUntagged bool", // 17
    "}", // 18
    "", // 19
    "type source struct {", // 20
    '\tName string `json:"name"`', // 21
    '\tGrants []grant `json:"grants"`', // 22
    "}", // 23
    "", // 24
    "type grant struct {", // 25
    '\tWorkspaces []string `json:"workspaces"`', // 26
    "\tself *grant", // 27
    "}", // 28
    "", // 29
    "type claim struct {", // 30
    "\tPath []string", // 31
    "}", // 32
    "", // 33
    "func (c *claim) UnmarshalJSON(b []byte) error { return nil }", // 34
    "", // 35
    "type Holder struct {", // 36
    "\tUI struct {", // 37
    '\t\tNav []grant `json:"nav"`', // 38
    '\t} `json:"ui"`', // 39
    '\tMapping map[string]claim `json:"mapping"`', // 40
    "}", // 41
  ].join("\n") + "\n",
)
writeFileSync(
  join(dir, "pkg/embed.go"),
  [
    "package pkg", // 1
    "", // 2
    "type Base struct {", // 3
    '\tRegion string `json:"region"`', // 4
    "}", // 5
    "", // 6
    "type Extra struct {", // 7
    '\tLevel int `json:"level"`', // 8
    "}", // 9
    "", // 10
    "type Embeds struct {", // 11
    "\tBase", // 12
    '\t*Extra `json:"extra,omitempty"`', // 13
    "\tlabel", // 14
    "}", // 15
    "", // 16
    "type label string", // 17
  ].join("\n") + "\n",
)
writeFileSync(join(dir, "pkg/config_test.go"), "package pkg\n\ntype Config2 struct{}\n")

const extract = (...specs: string[]) => {
  const run = Bun.spawnSync(["go", "run", ".", dir, ...specs], { cwd: join(import.meta.dir, "configref"), env: offlineGoEnv(process.env, join(dir, "scratch")) })
  return { code: run.exitCode, out: run.stdout.toString(), err: run.stderr.toString() }
}

test("every decoded field, nested types expanded, with its line", () => {
  const r = extract("demo=pkg#Config")
  expect(r.err).toBe("")
  const [c] = JSON.parse(r.out)
  expect(c.component).toBe("demo")
  expect(c.fields.map((f: { key: string; type: string; line: number; symbol: string }) => [f.key, f.type, f.line, f.symbol])).toEqual([
    ["listen", "string", 6, "Config.Listen"],
    ["maxStreams", "int", 8, "Config.MaxStreams"],
    ["idleMinutes", "*int", 9, "Config.IdleMinutes"],
    ["connectors", "[]source", 10, "Config.Sources"],
    ["connectors[].name", "string", 21, "source.Name"],
    ["connectors[].grants", "[]grant", 22, "source.Grants"],
    ["connectors[].grants[].workspaces", "[]string", 26, "grant.Workspaces"],
    ["nested", "struct", 11, "Config.Nested"],
    ["nested.admin", "string", 12, "Config.Nested"],
    ["raw", "json.RawMessage", 14, "Config.Raw"],
    ["Untagged", "bool", 17, "Config.Untagged"],
  ])
  const by = Object.fromEntries(c.fields.map((f: { key: string }) => [f.key, f]))
  expect(by.maxStreams.default).toBe("64")
  expect(by.maxStreams.doc).toBe("MaxStreams bounds the pod; zero takes the default. default 64")
  expect(by.idleMinutes.default).toBe("30")
  expect(by.listen.default).toBe("")
  expect(by.raw.optional).toBe(true)
  expect(by.listen.optional).toBe(false)
  expect(by.listen.file).toBe("pkg/config.go")
})

test("named types inside an anonymous struct keep their symbol; a custom JSON form is not expanded", () => {
  const [c] = JSON.parse(extract("demo=pkg#Holder").out)
  expect(c.fields.map((f: { key: string; symbol: string }) => [f.key, f.symbol])).toEqual([
    ["ui", "Holder.UI"],
    ["ui.nav", "Holder.UI"],
    ["ui.nav[].workspaces", "grant.Workspaces"],
    ["mapping", "Holder.Mapping"],
  ])
})

test("an untagged embedded struct is promoted; a tagged one is a field under its key", () => {
  const r = extract("demo=pkg#Embeds")
  expect(r.err).toBe("")
  const [c] = JSON.parse(r.out)
  expect(c.fields.map((f: { key: string; type: string; line: number; symbol: string; optional: boolean }) => [f.key, f.type, f.line, f.symbol, f.optional])).toEqual([
    ["region", "string", 4, "Base.Region", false],
    ["extra", "*Extra", 13, "Embeds.Extra", true],
    ["extra.level", "int", 8, "Extra.Level", false],
  ])
})

test("a prefix puts a second type under a key of the first", () => {
  const [c] = JSON.parse(extract("demo=pkg#Config", "demo=pkg#grant@portal").out)
  expect(c.fields.slice(-1)[0]).toMatchObject({ key: "portal.workspaces", symbol: "grant.Workspaces" })
})

test("a missing type or directory fails", () => {
  const missing = extract("demo=pkg#Missing")
  expect(missing.code).toBe(1)
  expect(missing.err).toContain("configref: demo: no struct type Missing in pkg\n")
  expect(extract("demo=nope#Config").code).toBe(1)
  expect(extract("bad spec").err).toContain("configref: not <component>=<dir>#<Type>")
})
