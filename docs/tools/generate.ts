// Checks the docs tree and the reference sections generated from source, and prints the published
// pages. It writes no file: it is a function from the commit to bytes on stdout, and putting the
// output in place is the build's job.
//
//   bun docs/tools/generate.ts --check           exit 1 if a section is stale or a page is malformed
//   bun docs/tools/generate.ts --diff            the same checks; then print, as a patch for git apply,
//                                                the pages with their stale sections regenerated
//   bun docs/tools/generate.ts --list            check, then print every published page and asset path
//   bun docs/tools/generate.ts --render <path>   check, then print that published page or asset
//   bun docs/tools/generate.ts --bundle          check, then print every page as one JSON document (the docs MCP server's)
//
// A stale section fails the check, which prints the command that regenerates it:
// bun docs/tools/generate.ts --diff | git -C <checkout> apply. git writes the pages.
//
// Options: --docs <dir> checks another page tree (a private layer) with the same rules; --root
// <name>=<checkout> lets its pages cite that checkout as {{ref name:path#Symbol}}.
//
// Pages cite code with {{ref path#Symbol}}. The marker stays in the source page; rendering replaces
// it with the file, the declaration's lines and a link pinned to the commit, and adds a footer naming
// the version and commit. Line numbers are never typed by hand: the check refuses them. Cited code,
// VERSION and the pages themselves are read from git at each checkout's commit, never from the
// working tree, so what is checked and published is exactly that commit.
//
// A generated section sits between two comment lines in a page:
//
//   <!-- BEGIN GENERATED: portal-api -->
//   <!-- END GENERATED: portal-api -->
//
// Everything outside the markers is written by hand. The check also holds every page to the
// format the testifysec.com importer reads (docs/README.md): front matter with exactly the four
// keys, no raw HTML, and relative links that resolve to a file in this tree.
import { existsSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, relative, resolve } from "node:path"
import { Controlled } from "../../testifysec/marking/marking"
import { blankFences, findDeclaration, footer, formatRef, handTypedCitations, linkTargets, markerProblems, offlineGoEnv, parseRefs, refMarkerProblems, replacePatch, toolAccess, type Root, type Span } from "./lib"

const repo = resolve(import.meta.dir, "../..")
const args = process.argv.slice(2)
const die = (message: string): never => {
  console.error(message)
  process.exit(1)
}
const option = (name: string) => {
  const i = args.indexOf(name)
  if (i >= 0 && !args[i + 1]) die(`${name} needs a value`)
  return i >= 0 ? args[i + 1] : undefined
}
// Every argument is a known option, so a mistyped or unsupported one (there is no --release here)
// stops the run instead of being ignored.
const valued = new Set(["--docs", "--render", "--root"])
const modes = ["--check", "--diff", "--list", "--render", "--bundle"]
for (let i = 0; i < args.length; i++) {
  if (valued.has(args[i])) i++
  else if (!modes.includes(args[i])) die(`unknown option ${args[i]}`)
}
// Exactly one mode: each prints one thing, so stdout is never two outputs run together.
const mode = modes.filter((m) => args.includes(m))
if (mode.length !== 1) die("give exactly one of --check, --diff, --list, --render <path> or --bundle")
const diff = mode[0] === "--diff"
const renderPath = option("--render")
const publishing = mode[0] === "--list" || mode[0] === "--render" || mode[0] === "--bundle"
const docs = resolve(option("--docs") ?? join(repo, "docs"))
// Every citation's span, as the checks resolved it (see resolveRef), and each checkout's commit.
const resolved = new Map<string, Span | undefined | string>()
const heads: Record<string, string> = {}
// Git reads only the local object store: in a partial clone a missing object is an error, never a
// fetch from the remote.
const gitEnv = { ...process.env, GIT_NO_LAZY_FETCH: "1" }
const roots: Record<string, string> = { badger: repo }
args.forEach((a, i) => {
  if (a !== "--root") return
  const m = /^([a-z][a-z0-9-]*)=(.+)$/.exec(args[i + 1] ?? "")
  if (!m || m[1] === "badger") return die("--root needs <name>=<checkout>, and badger is this repository")
  roots[m[1]] = resolve(m[2])
})

// The pages and assets, from the commit (fromCommit, below): set before anything reads them.
let pages: string[] = []
let assets: string[] = []
const problems: string[] = []
const keys = ["title", "description", "sidebarLabel", "sidebarPosition"]

// VERSION goes into every footer and the bundle as Markdown, so each root's must be a regular file
// (never a symlink) holding a plain version string. It is read at the root's commit.
const versions: Record<string, string | undefined> = {}
for (const name of Object.keys(roots)) {
  const v = blobAt(name, "VERSION")
  if (v === undefined) continue
  if (typeof v === "string") problems.push(`${name}: VERSION must be a regular file, not a symlink`)
  else if (!/^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$/.test(v.toString("utf8").trim()))
    problems.push(`${name}: VERSION must be a plain version (letters, digits, . + -), not ${JSON.stringify(v.toString("utf8").trim().slice(0, 40))}`)
  else versions[name] = v.toString("utf8").trim()
}

// Nothing is read in a tree that fails these: a page symlink could point outside it.
if (problems.length) {
  console.error(problems.join("\n"))
  process.exit(1)
}

// Every page and asset is read once, here, from the owning checkout's commit, in every mode: nothing
// in the working tree (an uncommitted edit, a symlink, a swapped directory) is read.
const inputs = fromCommit()
const textOf = (p: string) => inputs.get(p)!.data.toString("utf8")
// The checkout that holds the pages, and the command that regenerates its stale sections.
const owner = ownerOf()!
const q = (s: string) => (/^[\w./=:@+-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`)
const given = [...(option("--docs") ? ["--docs", docs] : []), ...Object.entries(roots).filter(([n]) => n !== "badger").flatMap(([n, p]) => ["--root", `${n}=${p}`])]
const fix = `${["bun", import.meta.path, "--diff", ...given].map(q).join(" ")} | git -C ${q(realpathSync(roots[owner]))} apply`

for (const page of pages) {
  const name = relative(repo, page)
  const text = textOf(page)
  const fm = /^---\n([\s\S]*?)\n---\n/.exec(text)
  if (!fm) {
    problems.push(`${name}: no front matter`)
    continue
  }
  const seen = fm[1].split("\n").map((line) => /^([A-Za-z]+): (.+)$/.exec(line))
  if (seen.some((m) => !m)) problems.push(`${name}: front matter lines must be "key: value"`)
  const got = seen.flatMap((m) => (m ? [m[1]] : []))
  if (got.join() !== keys.join()) problems.push(`${name}: front matter keys must be ${keys.join(", ")} in that order`)
  const position = seen.find((m) => m?.[1] === "sidebarPosition")?.[2]
  if (position !== undefined && !/^\d+$/.test(position)) problems.push(`${name}: sidebarPosition must be an integer`)
  // Front matter is metadata: a marker there would be rendered into it and is refused.
  if (/\{\{\s*ref\b/.test(fm[1])) problems.push(`${name}: a ref marker in front matter; cite code in the page body`)
  const body = text.slice(fm[0].length)
  // The importer renders Markdown, not HTML: a tag would be dropped on testifysec.com.
  const prose = blankFences(body).replace(/`[^`\n]*`/g, "")
  for (const tag of prose.match(/<\/?[A-Za-z][^>\n]*>/g) ?? []) problems.push(`${name}: raw HTML ${tag}`)
  if (!/^# .+/m.test(body)) problems.push(`${name}: no "# " title heading`)
  for (const target of linkTargets(prose)) {
    if (/^[a-z]+:/.test(target) || target.startsWith("#")) continue
    const file = resolve(dirname(page), target.split("#")[0])
    if (!file.startsWith(docs + "/") || !inputs.has(file)) problems.push(`${name}: link ${target} does not resolve to a page or an asset (docs/assets/) in the commit`)
    else if (!/\.(md|svg)$/.test(file)) problems.push(`${name}: link ${target} must name a .md page or an .svg figure`)
  }
  problems.push(...refMarkerProblems(body).map((p) => `${name}: ${p}`))
  for (const ref of parseRefs(body)) {
    const span = resolveRef(ref)
    if (typeof span === "string") problems.push(`${name}: ${ref.raw}: ${span}`)
  }
  for (const c of handTypedCitations(body)) problems.push(`${name}: hand-typed citation ${c}; cite code with {{ref path#Symbol}}`)
}

// Git in one root, with file names as paths, never pathspec magic.
function gitIn(name: string, ...a: string[]): Buffer {
  const r = Bun.spawnSync(["git", "-C", roots[name], "--literal-pathspecs", ...a], { env: gitEnv })
  if (r.exitCode !== 0) die(`${name}: git ${a.join(" ")} failed: ${r.stderr.toString().trim()}`)
  return r.stdout
}

// The commit a root is read at: its HEAD. A root is a checkout's top, so its paths are the repository's.
function head(name: string): string {
  if (!heads[name]) {
    if (gitIn(name, "rev-parse", "--show-prefix").toString().trim()) die(`${name}: ${roots[name]} is not the top of its checkout`)
    heads[name] = gitIn(name, "rev-parse", "HEAD").toString().trim()
  }
  return heads[name]
}

// A file's bytes at its root's commit: undefined if the commit has no file there, a reason if the
// entry is a symlink or a directory. Nothing in the working tree is read, so nothing there (an
// uncommitted edit, a symlink, a swapped directory) changes what is cited.
function blobAt(name: string, path: string): Buffer | string | undefined {
  const entry = gitIn(name, "ls-tree", "-z", head(name), "--", path).toString()
  const m = /^(\d+) (\w+) ([0-9a-f]+)\t([^\0]*)\0$/.exec(entry)
  if (!m || m[4] !== path) return undefined
  if (m[1] === "120000") return `${path} is a symlink; cite the file itself`
  if (m[2] !== "blob") return `${path} is not a file`
  return gitIn(name, "cat-file", "blob", m[3])
}

// The declaration a ref names, undefined for a whole file, or why it does not resolve, from the
// cited file at its root's commit. Resolved once per run: publishing uses the spans the checks saw.
function resolveRef(ref: { root: string; path: string; symbol: string | undefined }): Span | undefined | string {
  const key = `${ref.root}:${ref.path}#${ref.symbol ?? ""}`
  if (!resolved.has(key)) {
    const b = roots[ref.root] ? blobAt(ref.root, ref.path) : `no root named ${ref.root}; pass --root ${ref.root}=<checkout>`
    resolved.set(
      key,
      b === undefined
        ? `${ref.path} is not a file in ${ref.root} at ${head(ref.root).slice(0, 12)} (citations read the commit)`
        : typeof b === "string"
          ? b
          : ref.symbol
            ? findDeclaration(ref.path, b.toString("utf8"), ref.symbol)
            : undefined,
    )
  }
  return resolved.get(key)
}

// The root that holds the page tree: the one whose checkout the tree is in, as git itself finds it
// (a nested checkout or a submodule is its own). Undefined if the tree is in no checkout; a checkout
// that no root names is refused, since a root above it reads none of its pages from its own commit.
function ownerOf(): string | undefined {
  const r = Bun.spawnSync(["git", "-C", realpathSync(docs), "rev-parse", "--show-toplevel"], { env: gitEnv })
  if (r.exitCode !== 0) return undefined
  const top = realpathSync(r.stdout.toString().trim())
  return (
    Object.keys(roots).find((n) => realpathSync(roots[n]) === top) ??
    die(`${docs} is in the checkout ${top}, which no --root names; pass --root <name>=${top}`)
  )
}

// The pages and assets, read from the owning checkout's commit. The page tree must be in a checkout
// and have no uncommitted change (git status), so nothing checked silently differs from what is on
// disk, and a patch from --diff applies to exactly what was read. A symlink in the tree is refused: the tree holds regular files only.
function fromCommit(): Map<string, { data: Buffer; path: string }> {
  const owner = ownerOf() ?? die(`${docs} is in no checkout; pages are read from a commit`)
  const tree = relative(realpathSync(roots[owner]), realpathSync(docs)) || "."
  const relOf = (path: string) => (tree === "." ? path : relative(tree, path))
  // A page (.md outside tools/ and assets/, not the README) or an asset (under assets/); the
  // generator's own files under tools/ are neither.
  const kind = (rel: string) => {
    const dirs = rel.split("/").slice(0, -1)
    if (dirs[0] === "assets") return "asset"
    return rel.endsWith(".md") && rel !== "README.md" && !dirs.some((d) => d === "tools" || d === "assets") ? "page" : undefined
  }
  // git lists a nested checkout as its directory ("docs/admin/"): it may hold pages, so it counts as one.
  const entryKind = (path: string) => kind(relOf(path.endsWith("/") ? `${path}x.md` : path))
  const changed = gitIn(owner, "status", "--porcelain", "-z", "--no-renames", "--untracked-files=all", "--", tree).toString().split("\0").filter(Boolean)
  if (changed.some((e) => entryKind(e.slice(3))))
    die(`${owner}: ${tree} has uncommitted changes to pages or assets; pages are read from the commit, so commit them first`)
  // An ignored page is in no commit, so it would never be checked: a nested checkout not named with
  // --root, or a page the checkout ignores.
  const ignored = gitIn(owner, "status", "--porcelain", "-z", "--ignored=traditional", "--untracked-files=all", "--", tree).toString().split("\0").filter((e) => e.startsWith("!! "))
  const hidden = ignored.find((e) => entryKind(e.slice(3)) === "page")
  if (hidden) die(`${owner}: ${hidden.slice(3)} is ignored, so its pages are in no commit and would go unchecked; commit them, or name their checkout with --root`)
  const out = new Map<string, { data: Buffer; path: string }>()
  pages = []
  assets = []
  for (const entry of gitIn(owner, "ls-tree", "-r", "-z", head(owner), "--", tree).toString().split("\0").filter(Boolean)) {
    const [, mode, oid, path] = /^(\d+) \w+ ([0-9a-f]+)\t(.*)$/s.exec(entry)!
    const rel = relOf(path)
    if (mode === "120000" && rel.split("/")[0] !== "tools")
      die(`${relative(dirname(docs), join(docs, rel))} is a symlink; the page tree holds regular files only`)
    // A submodule's pages are in its own commits, not this one: check it as its own page tree.
    if (mode === "160000")
      die(`${relative(dirname(docs), join(docs, rel))} is a submodule; its pages are not in this commit, so check it with --docs and --root`)
    const asset = kind(rel) === "asset"
    if (!kind(rel)) continue
    out.set(join(docs, rel), { data: gitIn(owner, "cat-file", "blob", oid), path })
    ;(asset ? assets : pages).push(join(docs, rel))
  }
  pages.sort()
  return out
}

// Each generator returns the Markdown for its section from the source it documents.
const generators: Record<string, () => string> = {
  "managed-commands": managedCommands,
  "portal-api": portalApi,
  "connector-tools": connectorTools,
  "config-reference": configReference,
  "marking-levels": markingLevels,
}

// A table cell: one line, pipes escaped.
const cell = (s: unknown) => String(s ?? "").replace(/\s+/g, " ").replace(/\|/g, "\\|").trim()
const table = (head: string[], rows: string[][]) =>
  [`| ${head.join(" | ")} |`, `|${head.map(() => "---").join("|")}|`, ...rows.map((r) => `| ${r.map(cell).join(" | ")} |`)].join("\n")

// The commands a managed build keeps, read from the set the build enforces.
function managedCommands() {
  const source = "packages/cli/src/managed.ts"
  const m = /export const kept\b[^=]*= new Set\(\[([^\]]*)\]\)/.exec(readFileSync(join(repo, source), "utf8"))
  if (!m) throw new Error(`${source}: no kept command set`)
  const kept = [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1])
  return [
    `The managed build keeps these commands and refuses every other one (\`kept\` in \`${source}\`):`,
    "",
    ...kept.map((name) => `- \`badger ${name}\``),
  ].join("\n")
}

type Schema = Record<string, any>

// The HTTP API, read from the portal's OpenAPI document.
function portalApi() {
  const source = "testifysec/portal/api/openapi.yaml"
  if (!existsSync(join(repo, source)))
    return `\`${source}\` is not on this branch yet, so there is nothing to generate. The portal and its specification are in [PR #173](https://github.com/aflock-ai/badger/pull/173); this section is generated from the file once it lands.`
  const doc: Schema = Bun.YAML.parse(readFileSync(join(repo, source), "utf8")) as Schema
  const ref = (s: Schema): Schema => {
    if (!s?.$ref) return s
    const parts = String(s.$ref).replace(/^#\//, "").split("/")
    return parts.reduce((o: Schema, k) => o[k], doc)
  }
  const refName = (s: Schema) => String(s.$ref).split("/").pop()
  const type = (s: Schema): string => {
    if (s.$ref) return `\`${refName(s)}\``
    if ("const" in s) return `\`${JSON.stringify(s.const)}\``
    if (s.enum) return s.enum.map((v: unknown) => `\`${v}\``).join(", ")
    if (s.type === "array") {
      const n = [s.minItems !== undefined && `at least ${s.minItems}`, s.maxItems !== undefined && `at most ${s.maxItems}`].filter(Boolean)
      return `array of ${type(s.items ?? {})}${n.length ? ` (${n.join(", ")})` : ""}`
    }
    const facts = [
      s.format,
      s.pattern && `pattern \`${s.pattern}\``,
      s.minimum !== undefined && `minimum ${s.minimum}`,
      s.maximum !== undefined && `maximum ${s.maximum}`,
    ].filter(Boolean)
    return `${s.type ?? "any"}${facts.length ? ` (${facts.join(", ")})` : ""}`
  }
  const fields = (raw: Schema) => {
    const s = ref(raw)
    const required = new Set<string>(s.required ?? [])
    return table(
      ["Field", "Type", "Required", "Description"],
      Object.entries<Schema>(s.properties ?? {}).map(([name, p]) => [`\`${name}\``, type(p), required.has(name) ? "yes" : "no", p.description ?? ""]),
    )
  }
  const body = (content: Schema | undefined) => {
    const [media, value] = Object.entries<Schema>(content ?? {})[0] ?? []
    if (!media) return []
    const s = value.schema ?? {}
    return s.$ref ? [`\`${media}\`: ${type(s)}`] : [`\`${media}\`:`, "", fields(s)]
  }
  const ops = Object.entries<Schema>(doc.paths ?? {}).flatMap(([path, item]) =>
    ["get", "put", "post", "delete", "patch"].filter((m) => item[m]).map((m) => ({ path, method: m.toUpperCase(), op: item[m] as Schema, params: [...(item.parameters ?? []), ...(item[m].parameters ?? [])] })),
  )
  const status = (op: Schema) => (op["x-badger-status"] === "implemented" ? "implemented" : "specified, not built")
  const auth = (op: Schema) => {
    const names = (op.security ?? doc.security ?? []).flatMap((req: Schema) => Object.keys(req))
    return names.length ? names.map((n: string) => `\`${n}\``).join(" or ") : "none"
  }
  const out = [
    `Generated from \`${source}\`: ${doc.info.title}, version ${doc.info.version}, OpenAPI ${doc.openapi}.`,
    "",
    table(["Method", "Path", "Status", "Summary"], ops.map((o) => [o.method, `\`${o.path}\``, status(o.op), o.op.summary ?? ""])),
  ]
  for (const o of ops) {
    out.push("", `### ${o.method} ${o.path}`, "", `${o.op.summary ?? ""}`.trim(), "")
    if (o.op.description) out.push(String(o.op.description).trim(), "")
    out.push(`Status: ${status(o.op)}. Authentication: ${auth(o.op)}.`)
    const params = o.params.map(ref)
    if (params.length) out.push("", table(["Parameter", "In", "Type", "Required"], params.map((p) => [`\`${p.name}\``, p.in, type(p.schema ?? {}), p.required ? "yes" : "no"])))
    if (o.op.requestBody) out.push("", "Request body:", "", ...body(ref(o.op.requestBody).content))
    for (const [code, raw] of Object.entries<Schema>(o.op.responses ?? {})) {
      const r = ref(raw)
      out.push("", `Response \`${code}\`: ${r.description ?? ""}`.trim())
      const b = body(r.content)
      if (b.length) out.push("", ...b)
    }
  }
  const schemas = Object.entries<Schema>(doc.components?.schemas ?? {})
  if (schemas.length) out.push("", "### Schemas")
  for (const [name, s] of schemas) {
    out.push("", `#### ${name}`, "")
    if (s.description) out.push(String(s.description).trim(), "")
    out.push(s.properties ? fields(s) : type(s))
  }
  return out.join("\n")
}

// Every connector's tools, read from the connector itself over MCP (tools/list), with writes on.
function connectorTools() {
  const dir = join(repo, "testifysec/connectors")
  const names = readdirSync(dir).filter((n) => n !== "internal" && existsSync(join(dir, n, "main.go"))).sort()
  const marking = existsSync(join(dir, "internal/marking"))
  // One scratch home and cache for every connector in this run; see offlineGoEnv.
  const scratch = mkdtempSync(join(tmpdir(), "badger-docs-go-"))
  process.on("exit", () => rmSync(scratch, { recursive: true, force: true }))
  const out: string[] = []
  for (const name of names) {
    const args = ["run", `./${name}`, "--base-url", "https://connector.example.invalid", "--token-file", "/dev/null", "--enable-writes"]
    if (marking) args.push("--classification", "UNCLASSIFIED")
    const input = ['{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}', '{"jsonrpc":"2.0","id":2,"method":"tools/list"}', ""].join("\n")
    const run = Bun.spawnSync(["go", ...args], { cwd: dir, stdin: Buffer.from(input), env: offlineGoEnv(process.env, scratch) })
    const reply = run.stdout
      .toString()
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l))
      .find((m) => m.id === 2)
    if (!reply?.result?.tools) throw new Error(`connector ${name}: no tools/list reply\n${run.stderr.toString()}`)
    const source = readFileSync(join(dir, name, "main.go"), "utf8")
    out.push(`### ${name}`, "")
    if (/It is not shipped/.test(source)) out.push("Reference connector for authors; not shipped.", "")
    for (const tool of reply.result.tools as Schema[]) {
      out.push(`#### \`${tool.name}\``, "", `${toolAccess(tool.annotations)}. ${cell(tool.description)}`, "")
      const schema = tool.inputSchema ?? {}
      const required = new Set<string>(schema.required ?? [])
      const props = Object.entries<Schema>(schema.properties ?? {})
      if (!props.length) {
        out.push("No parameters.", "")
        continue
      }
      const kind = (p: Schema): string => {
        const bounds = [p.minimum !== undefined && `minimum ${p.minimum}`, p.maximum !== undefined && `maximum ${p.maximum}`, p.maxItems !== undefined && `at most ${p.maxItems}`]
        const base = p.type === "array" ? `array of ${p.items?.type ?? "any"}` : (p.type ?? "any")
        const extra = [...bounds, p.enum && `one of ${p.enum.map((v: unknown) => `\`${v}\``).join(", ")}`].filter(Boolean)
        return `${base}${extra.length ? ` (${extra.join(", ")})` : ""}`
      }
      out.push(table(["Parameter", "Type", "Required", "Description"], props.map(([n, p]) => [`\`${n}\``, kind(p), required.has(n) ? "yes" : "no", p.description ?? ""])), "")
    }
  }
  return out.join("\n")
}

// The classification levels the marking parser accepts, lowest first, from its token table.
// The controlled unclassified level is described, not spelled: its token would trip the leak check,
// which scans every committed line. The parser's own constant names it (Controlled).
function markingLevels() {
  const source = "testifysec/connectors/internal/marking/tokens.json"
  const levels: { banner: string; portion: string }[] = JSON.parse(readFileSync(join(repo, source), "utf8")).levels
  const cell = (l: { banner: string; portion: string }, i: number) =>
    i === Controlled ? ["the controlled unclassified level (banner and portion mark in `tokens.json`)", "same"] : [`\`${l.banner}\``, `\`${l.portion}\``]
  return [
    `From \`${source}\`, lowest first. Each level dominates the ones above it in this table.`,
    "",
    table(["Level", "Banner", "Portion mark"], levels.map((l, i) => [String(i), ...cell(l, i)])),
  ].join("\n")
}

// The JSON configuration each component reads, from its Go structs (configref/). A spec is
// <package dir>#<Type>, with @<key> for a section the command decodes on its own.
const configComponents = [
  { id: "gateway", title: "Model gateway (hardened-gateway)", specs: ["testifysec/gateway#Config"] },
  { id: "platform", title: "Platform session check (the gateway's platformConfigFile)", specs: ["testifysec/platform#Config"] },
  { id: "badger-broker", title: "Model broker and portal (badger-broker)", specs: ["testifysec/model-broker#FileConfig", "testifysec/portal/cmd/badger-broker#portalConfig@portal"] },
  { id: "conngw", title: "Connector gateway (conngw)", specs: ["testifysec/connectors/cmd/conngw#config"] },
]
type ConfigField = { key: string; type: string; optional: boolean; default: string; doc: string; file: string; line: number; symbol: string }
let configCache: { component: string; title: string; fields: ConfigField[] }[] | undefined
function configData() {
  if (configCache) return configCache
  const scratch = mkdtempSync(join(tmpdir(), "badger-docs-configref-"))
  process.on("exit", () => rmSync(scratch, { recursive: true, force: true }))
  const specs = configComponents.flatMap((c) => c.specs.map((s) => `${c.id}=${s}`))
  const run = Bun.spawnSync(["go", "run", ".", repo, ...specs], { cwd: join(import.meta.dir, "configref"), env: offlineGoEnv(process.env, scratch) })
  if (run.exitCode !== 0) throw new Error(`configref failed\n${run.stderr.toString()}`)
  const got: { component: string; fields: ConfigField[] }[] = JSON.parse(run.stdout.toString())
  configCache = configComponents.map((c) => ({ component: c.id, title: c.title, fields: got.find((g) => g.component === c.id)?.fields ?? [] }))
  return configCache
}

function configReference() {
  const out = [
    "Generated from the Go structs each component decodes its configuration into. A default is shown where the source comment states one; otherwise the loader decides, and the source cited is where to look.",
  ]
  for (const c of configData()) {
    out.push("", `### ${c.title}`, "", `Component \`${c.component}\`.`, "")
    out.push(
      table(
        ["Key", "Type", "Default", "Description", "Source"],
        c.fields.map((f) => [`\`${f.key}\``, `\`${f.type}\`${f.optional ? " (optional)" : ""}`, f.default && `\`${f.default}\``, f.doc.replace(/</g, "&lt;").replace(/>/g, "&gt;"), `\`${f.symbol}\` in \`${f.file}\``]),
      ),
    )
  }
  return out.join("\n")
}

const stale: string[] = []
const patches: string[] = []
const sections = /<!-- BEGIN GENERATED: ([a-z-]+) -->\n[\s\S]*?<!-- END GENERATED: \1 -->/g
for (const page of pages) {
  const text = textOf(page)
  problems.push(...markerProblems(text).map((p) => `${relative(repo, page)}: ${p}`))
  const next = text.replace(sections, (_, id: string) => {
    const generate = generators[id]
    if (!generate) {
      problems.push(`${relative(repo, page)}: no generator named ${id}`)
      return _
    }
    return `<!-- BEGIN GENERATED: ${id} -->\n${generate().trimEnd()}\n<!-- END GENERATED: ${id} -->`
  })
  if (next === text) continue
  stale.push(page)
  // git quotes a name with these in a patch; a plain one is written as is.
  if (!/^[\x20-\x7e]+$/.test(inputs.get(page)!.path) || /["\\]/.test(inputs.get(page)!.path)) problems.push(`${relative(repo, page)}: a page name with a quote, backslash or non-ASCII character cannot be patched; rename it`)
  else patches.push(replacePatch(inputs.get(page)!.path, text, next))
}

// A stale section alone is fixed by the patch; anything else must be fixed by hand first.
if (problems.length || (stale.length && !diff)) {
  console.error([...problems, ...stale.map((p) => `${relative(repo, p)}: generated section is stale`)].join("\n"))
  if (stale.length && !problems.length) console.error(`regenerate with: ${fix}`)
  process.exit(1)
}
if (diff) process.stdout.write(patches.join(""))
else if (publishing) publish()
else console.log(`docs: ${pages.length} pages current`)

// Version and commit of each root, read from git. The date is the commit's, not the clock's, so two
// renders of one commit are identical.
function rootInfo(name: string): Root & { date: string } {
  const url = name === "badger" ? "https://github.com/aflock-ai/badger" : undefined
  return { name, version: versions[name], sha: head(name), url, date: gitIn(name, "log", "-1", "--format=%cs", head(name)).toString().trim() }
}

function publish() {
  const texts = new Map(pages.map((p) => [p, textOf(p)]))
  const used = ["badger", ...Object.keys(roots).filter((n) => n !== "badger")]
  const info = Object.fromEntries(used.map((n) => [n, rootInfo(n)]))
  const date = info.badger.date
  const topics = [...texts].map(([page, text]) => {
    const fm = /^---\n([\s\S]*?)\n---\n/.exec(text)!
    const meta = Object.fromEntries(fm[1].split("\n").map((l) => /^([A-Za-z]+): (.+)$/.exec(l)!.slice(1, 3)))
    // Markers resolve in the body only; validation refuses them in front matter.
    const refs = parseRefs(text).filter((r) => r.index >= fm[0].length)
    // badger, the checkout that holds the pages, and every checkout the page cites.
    const pageRoots = ["badger", ...new Set([...(owner ? [owner] : []), ...refs.map((r) => r.root)].filter((n) => n !== "badger"))].map((n) => info[n])
    let out = ""
    let at = 0
    for (const r of refs) {
      const span = resolveRef(r)
      if (typeof span === "string") die(`${relative(repo, page)}: ${r.raw}: ${span}`)
      out += text.slice(at, r.index) + formatRef(r, span as Span | undefined, info[r.root])
      at = r.index + r.raw.length
    }
    out = `${(out + text.slice(at)).trimEnd()}\n\n${footer(pageRoots, date)}\n`
    const id = relative(docs, page).replace(/\.md$/, "")
    return { page, id, out, meta, body: out.slice(fm[0].length) }
  })
  // Every published path: each page as rendered, each asset as committed.
  const published = new Map<string, Buffer>([
    ...topics.map((t) => [relative(docs, t.page), Buffer.from(t.out)] as const),
    ...assets.map((p) => [relative(docs, p), inputs.get(p)!.data] as const),
  ])
  if (mode[0] === "--list") process.stdout.write([...published.keys()].sort().map((p) => `${p}\n`).join(""))
  if (renderPath !== undefined) {
    const bytes = published.get(renderPath) ?? die(`${renderPath} is not a published page or asset (bun docs/tools/generate.ts --list names them)`)
    process.stdout.write(bytes)
  }
  if (mode[0] === "--bundle") {
    const bundle = {
      schema: 1,
      date,
      // dirty stays in the schema for readers of older bundles; a published commit is never dirty.
      roots: used.map((n) => ({ name: n, version: info[n].version ?? "", commit: info[n].sha, dirty: false })),
      topics: topics.map((t) => ({
        id: t.id,
        section: t.id.includes("/") ? t.id.split("/")[0] : "",
        title: t.meta.title,
        description: t.meta.description,
        sidebarLabel: t.meta.sidebarLabel,
        sidebarPosition: Number(t.meta.sidebarPosition),
        body: t.body,
      })),
      // Only for the badger tree: a private layer has no configuration of its own here.
      config: docs === join(repo, "docs") ? configData().map((c) => ({ ...c, root: "badger" })) : [],
    }
    process.stdout.write(JSON.stringify(bundle, null, 1) + "\n")
  }
}
