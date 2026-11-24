// generate.ts end to end on a page tree of its own (--docs), citing a git checkout of its own (--root).
import { afterAll, expect, setDefaultTimeout, test } from "bun:test"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

// Each run that resolves a Go symbol builds goref offline from an empty cache (lib.ts), about two
// seconds, and some tests run the generator several times.
setDefaultTimeout(60_000)
const dir = mkdtempSync(join(tmpdir(), "docs-generate-"))
afterAll(() => rmSync(dir, { recursive: true, force: true }))
const generate = join(import.meta.dir, "generate.ts")
const git = (...a: string[]) => Bun.spawnSync(["git", "-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...a])
const run = (...a: string[]) => {
  const r = Bun.spawnSync(["bun", generate, "--docs", join(dir, "docs"), "--root", `fx=${dir}`, ...a])
  return { code: r.exitCode, out: r.stdout.toString() + r.stderr.toString(), stdout: r.stdout.toString() }
}
// What git sees in the fixture, ignored files included: the generator writes nothing, so a run
// leaves it as it was.
const status = () => git("status", "--porcelain", "--untracked-files=all", "--ignored").stdout.toString()
const page = (title: string, body: string) => `---\ntitle: ${title}\ndescription: A test page.\nsidebarLabel: ${title}\nsidebarPosition: 1\n---\n\n# ${title}\n\n${body}\n`

mkdirSync(join(dir, "docs/admin"), { recursive: true })
writeFileSync(join(dir, "lib.go"), "package lib\n\n// Load reads it.\nfunc Load() error {\n\treturn nil\n}\n")
writeFileSync(join(dir, "docs/index.md"), page("Home", "See [admin](admin/install.md)."))
writeFileSync(join(dir, "docs/admin/install.md"), page("Install", "The loader is {{ref fx:lib.go#Load}}.\n\n```\n{{ref fx:shown.go#AsAnExample}}\n```"))
git("init", "-q")
git("add", ".")
git("commit", "-qm", "fixture")
const sha = git("rev-parse", "HEAD").stdout.toString().trim()
// Citations, VERSION and pages are read at the commit, so tests commit what they change.
const commit = (msg: string, ...paths: string[]) => {
  git("add", "-A", "--", ...paths)
  git("commit", "-qm", msg)
}
// Commits the page tree as a test changed it, runs fn, then puts the fixture's commit and files back.
const committed = <T>(fn: () => T): T => {
  const before = git("rev-parse", "HEAD").stdout.toString().trim()
  commit("test pages", "docs")
  try {
    return fn()
  } finally {
    git("reset", "-q", "--hard", before)
  }
}

test("the check resolves every ref at the commit and writes nothing", () => {
  const before = status()
  const r = run("--check")
  expect(r.out).toContain("2 pages current")
  expect(r.code).toBe(0)
  expect(status()).toBe(before)
})

test("render and bundle print refs resolved to lines and the commit, with a footer, and write nothing", () => {
  const before = status()
  const page = run("--render", "admin/install.md")
  const b = run("--bundle")
  expect(status()).toBe(before)
  expect([page.code, b.code]).toEqual([0, 0])
  expect(page.stdout).toContain(`The loader is \`fx:lib.go:4-6\` (${sha.slice(0, 12)}).`)
  expect(page.stdout).toContain("{{ref fx:shown.go#AsAnExample}}")
  expect(page.stdout).toMatch(new RegExp(`\\*Generated from badger \\S+ at [0-9a-f]{12} and fx at ${sha.slice(0, 12)} on \\d{4}-\\d{2}-\\d{2}\\.\\*\\n$`))
  const bundle = JSON.parse(b.stdout)
  expect(bundle.roots.find((x: { name: string }) => x.name === "fx")).toEqual({ name: "fx", version: "", commit: sha, dirty: false })
  expect(bundle.topics.map((t: { id: string; section: string }) => [t.id, t.section])).toEqual([["admin/install", "admin"], ["index", ""]])
  expect(bundle.topics[0].body).toContain("`fx:lib.go:4-6`")
  // The rendered page is the bundle topic's body under the same front matter.
  expect(page.stdout.endsWith(bundle.topics[0].body)).toBe(true)
})

// The build renders the site by listing what is published and printing each one.
test("--list names every published page and asset, and --render prints each one", () => {
  const listed = run("--list")
  expect(listed.code).toBe(0)
  const paths = listed.stdout.trim().split("\n")
  expect(paths).toContain("index.md")
  expect(paths).toContain("admin/install.md")
  for (const p of paths) expect(run("--render", p).code).toBe(0)
  const missing = run("--render", "admin/missing.md")
  expect(missing.code).toBe(1)
  expect(missing.stdout).toBe("")
  expect(missing.out).toContain("admin/missing.md is not a published page or asset")
})

test("a ref whose symbol is gone at the commit fails the check", () => {
  const before = readFileSync(join(dir, "lib.go"), "utf8")
  writeFileSync(join(dir, "lib.go"), "package lib\n\nfunc Read() error {\n\treturn nil\n}\n")
  commit("drop Load", "lib.go")
  const r = run("--check")
  writeFileSync(join(dir, "lib.go"), before)
  commit("restore Load", "lib.go")
  expect(r.code).toBe(1)
  expect(r.out).toContain("docs/admin/install.md: {{ref fx:lib.go#Load}}: no declaration of Load")
})

test("an uncommitted change to a cited file changes nothing: the commit is cited", () => {
  writeFileSync(join(dir, "lib.go"), "package lib\n\nfunc Read() error {\n\treturn nil\n}\n")
  const r = run("--check")
  git("checkout", "--", "lib.go")
  expect(r.code).toBe(0)
})

test("a hand-typed line number fails the check", () => {
  writeFileSync(join(dir, "docs/index.md"), page("Home", "See `lib.go:4` and [admin](admin/install.md)."))
  const r = committed(() => run("--check"))
  expect(r.code).toBe(1)
  expect(r.out).toContain("hand-typed citation lib.go:4")
})

test("a symlink cannot cite a file outside its checkout", () => {
  const outside = mkdtempSync(join(tmpdir(), "docs-outside-"))
  writeFileSync(join(outside, "secret.go"), "package secret\n\nfunc Leak() {}\n")
  symlinkSync(join(outside, "secret.go"), join(dir, "link.go"))
  writeFileSync(join(dir, "docs/admin/link.md"), page("Link", "{{ref fx:link.go#Leak}}"))
  const r = committed(() => run("--check"))
  rmSync(join(dir, "link.go"))
  rmSync(outside, { recursive: true, force: true })
  expect(r.code).toBe(1)
  expect(r.out).toContain("{{ref fx:link.go#Leak}}: link.go is not a file in fx")
})

test("VERSION must be a file inside its checkout", () => {
  const outside = mkdtempSync(join(tmpdir(), "docs-outside-"))
  writeFileSync(join(outside, "secret"), "not-a-version\n")
  symlinkSync(join(outside, "secret"), join(dir, "VERSION"))
  git("add", "VERSION")
  git("commit", "-qm", "VERSION points outside")
  const r = run("--check")
  git("rm", "-q", "VERSION")
  git("commit", "-qm", "drop VERSION")
  rmSync(outside, { recursive: true, force: true })
  expect(r.code).toBe(1)
  expect(r.out).toContain("fx: VERSION must be a regular file, not a symlink")
  expect(r.out).not.toContain("not-a-version")
})

test("VERSION is the commit's, whatever the working tree holds", () => {
  writeFileSync(join(dir, "VERSION"), "1.0.0\n")
  commit("VERSION", "VERSION")
  writeFileSync(join(dir, "VERSION"), "not a version\n")
  const r = run("--check")
  git("checkout", "--", "VERSION")
  expect(r.code).toBe(0)
})

test("the bundle's VERSION is the commit's, whatever the working tree holds", () => {
  writeFileSync(join(dir, "VERSION"), "1.0.0\n")
  commit("VERSION", "VERSION")
  writeFileSync(join(dir, "VERSION"), "9.9.9\n")
  const r = run("--bundle")
  git("checkout", "--", "VERSION")
  expect(r.code).toBe(0)
  expect(JSON.parse(r.stdout).roots.find((x: { name: string }) => x.name === "fx").version).toBe("1.0.0")
})

test("a committed VERSION symlink to an ignored file is refused", () => {
  writeFileSync(join(dir, ".gitignore"), "gen.go\ndocs/assets/local.svg\n.env\n")
  writeFileSync(join(dir, ".env"), "TOKEN=leak\n")
  rmSync(join(dir, "VERSION"))
  symlinkSync(".env", join(dir, "VERSION"))
  git("add", ".")
  git("commit", "-qm", "VERSION -> .env")
  const r = run("--check")
  git("rm", "-q", "VERSION")
  writeFileSync(join(dir, "VERSION"), "1.0.0\n")
  git("add", "VERSION")
  git("commit", "-qm", "VERSION back")
  expect(r.code).toBe(1)
  expect(r.out).toContain("fx: VERSION must be a regular file, not a symlink")
  expect(r.out).not.toContain("leak")
})

test("an ignored asset symlink is never read: it is not in the commit", () => {
  mkdirSync(join(dir, "docs/assets"), { recursive: true })
  writeFileSync(join(dir, "docs/assets/kept.svg"), "<svg/>")
  git("add", "docs/assets/kept.svg")
  git("commit", "-qm", "an asset")
  writeFileSync(join(dir, ".gitignore"), "gen.go\ndocs/assets/local.svg\n.env\ndocs/assets/alias.svg\n")
  git("add", ".gitignore")
  git("commit", "-qm", "ignore an alias")
  symlinkSync("kept.svg", join(dir, "docs/assets/alias.svg"))
  const r = run("--check")
  rmSync(join(dir, "docs/assets/alias.svg"))
  expect(r.code).toBe(0)
})

test("pages at a checkout's root are checked, and an uncommitted deletion is refused", () => {
  const top = mkdtempSync(join(tmpdir(), "docs-top-"))
  const g = (...a: string[]) => Bun.spawnSync(["git", "-C", top, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...a])
  writeFileSync(join(top, "index.md"), page("Top", "A page at the root."))
  g("init", "-q")
  g("add", ".")
  g("commit", "-qm", "root page")
  const check = () => {
    const r = Bun.spawnSync(["bun", generate, "--docs", top, "--root", `fx=${top}`, "--check"])
    return { code: r.exitCode, out: r.stdout.toString() + r.stderr.toString() }
  }
  const atRoot = check()
  rmSync(join(top, "index.md"))
  const gone = check()
  rmSync(top, { recursive: true, force: true })
  expect(atRoot.out).toContain("1 pages current")
  expect(atRoot.code).toBe(0)
  expect(gone.code).toBe(1)
  expect(gone.out).toContain("has uncommitted changes")
})

test("every page's footer names the checkout that holds it, cited or not", () => {
  const r = run("--render", "index.md")
  expect(r.code).toBe(0)
  expect(r.stdout).toMatch(/ and fx (\S+ )?at [0-9a-f]{12}/)
})

test("an ignored directory symlink in the page tree is never read", () => {
  mkdirSync(join(dir, "shared"), { recursive: true })
  writeFileSync(join(dir, "shared/pic.svg"), "<svg/>")
  writeFileSync(join(dir, ".gitignore"), "gen.go\ndocs/assets/local.svg\n.env\ndocs/assets/alias.svg\ndocs/assets/alias\n")
  git("add", ".")
  git("commit", "-qm", "a shared asset, an ignored directory alias")
  symlinkSync("../../shared", join(dir, "docs/assets/alias"))
  const r = run("--check")
  rmSync(join(dir, "docs/assets/alias"))
  expect(r.code).toBe(0)
})

test("a symlinked assets directory is refused", () => {
  rmSync(join(dir, "docs/assets"), { recursive: true, force: true })
  symlinkSync("../shared", join(dir, "docs/assets"))
  git("add", "-A")
  git("commit", "-qm", "assets -> ../shared")
  const r = run("--check")
  rmSync(join(dir, "docs/assets"))
  git("checkout", "HEAD~1", "--", "docs/assets")
  git("add", "-A")
  git("commit", "-qm", "assets back")
  expect(r.code).toBe(1)
  expect(r.out).toContain("docs/assets is a symlink")
})

test("a symlink in the page tree to an ignored file is refused, committed or not", () => {
  writeFileSync(join(dir, ".env"), "TOKEN=leak\n")
  symlinkSync("../../.env", join(dir, "docs/assets/credentials.txt"))
  const r = run("--check")
  const c = committed(() => run("--check"))
  rmSync(join(dir, "docs/assets/credentials.txt"), { force: true })
  expect(r.code).toBe(1)
  expect(r.out).toContain("has uncommitted changes")
  expect(c.code).toBe(1)
  expect(c.out).toContain("docs/assets/credentials.txt is a symlink")
  expect(r.out + c.out).not.toContain("TOKEN=leak")
})

test("a symlink is never cited, even to a committed file", () => {
  symlinkSync("lib.go", join(dir, "committed-alias.go"))
  writeFileSync(join(dir, "docs/admin/calias.md"), page("Calias", "{{ref fx:committed-alias.go#Load}}"))
  git("add", "committed-alias.go", "docs/admin/calias.md")
  git("commit", "-qm", "cite a committed symlink")
  const r = run("--check")
  git("rm", "-q", "committed-alias.go", "docs/admin/calias.md")
  git("commit", "-qm", "drop it")
  expect(r.code).toBe(1)
  expect(r.out).toContain("committed-alias.go is a symlink; cite the file itself")
})

// A root named through a short symlink still owns the pages under it: ownership is ranked by the
// canonical path, so the checkout above it (here, fx) never takes over and finds no pages.
test("a page tree in a nested checkout named through a symlink is read from that checkout", () => {
  const inner = join(dir, "inner")
  mkdirSync(join(inner, "docs"), { recursive: true })
  writeFileSync(join(dir, ".git/info/exclude"), "inner/\n")
  writeFileSync(join(inner, "docs/index.md"), page("Inner", "See {{ref p:gone.go#Missing}}."))
  const g = (...a: string[]) => Bun.spawnSync(["git", "-C", inner, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...a])
  g("init", "-q")
  g("add", ".")
  g("commit", "-qm", "inner page")
  const link = mkdtempSync(join(tmpdir(), "l"))
  symlinkSync(inner, join(link, "p"))
  const r = Bun.spawnSync(["bun", generate, "--docs", join(link, "p/docs"), "--root", `fx=${dir}`, "--root", `p=${join(link, "p")}`, "--check"])
  // Without --root p, no root names the tree's checkout: refused, never passed with no pages read.
  const unnamed = Bun.spawnSync(["bun", generate, "--docs", join(inner, "docs"), "--root", `fx=${dir}`, "--check"])
  rmSync(link, { recursive: true, force: true })
  rmSync(inner, { recursive: true, force: true })
  writeFileSync(join(dir, ".git/info/exclude"), "")
  const out = r.stdout.toString() + r.stderr.toString()
  expect(r.exitCode).toBe(1)
  expect(out).toContain("{{ref p:gone.go#Missing}}: gone.go is not a file in p")
  expect(unnamed.exitCode).toBe(1)
  expect(unnamed.stderr.toString()).toContain("which no --root names")
})

// The pages are read from the checkout that holds them, never from one above it: a committed
// submodule's pages are a gitlink in the parent's commit, so the parent would read none of them.
test("a page tree in a submodule no --root names is refused, never passed with no pages read", () => {
  const sub = mkdtempSync(join(tmpdir(), "docs-sub-"))
  const g = (cwd: string, ...a: string[]) => Bun.spawnSync(["git", "-C", cwd, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "protocol.file.allow=always", ...a])
  mkdirSync(join(sub, "docs"))
  writeFileSync(join(sub, "docs/index.md"), page("Sub", "See {{ref fx:gone.go#Missing}}."))
  g(sub, "init", "-q")
  g(sub, "add", ".")
  g(sub, "commit", "-qm", "sub page")
  const before = git("rev-parse", "HEAD").stdout.toString().trim()
  g(dir, "submodule", "add", "-q", sub, "vendored")
  g(dir, "commit", "-qm", "a submodule")
  const r = Bun.spawnSync(["bun", generate, "--docs", join(dir, "vendored/docs"), "--root", `fx=${dir}`, "--check"])
  git("reset", "-q", "--hard", before)
  rmSync(join(dir, "vendored"), { recursive: true, force: true })
  rmSync(join(dir, ".git/modules"), { recursive: true, force: true })
  rmSync(sub, { recursive: true, force: true })
  expect(r.exitCode).toBe(1)
  expect(r.stderr.toString()).toContain("is in the checkout")
  expect(r.stderr.toString()).toContain("which no --root names")
})

// A page the checkout ignores is in no commit, so it is refused rather than left unchecked.
test("an ignored page in the page tree is refused", () => {
  writeFileSync(join(dir, ".git/info/exclude"), "docs/admin/local.md\n")
  writeFileSync(join(dir, "docs/admin/local.md"), page("Local", "See {{ref fx:gone.go#Missing}}."))
  const r = run("--check")
  rmSync(join(dir, "docs/admin/local.md"))
  writeFileSync(join(dir, ".git/info/exclude"), "")
  expect(r.code).toBe(1)
  expect(r.out).toContain("docs/admin/local.md is ignored")
})

// A checkout nested inside the page tree holds pages in no commit of the owner: a committed
// submodule is a gitlink in the owner's tree, an uncommitted one an untracked directory. Both are
// refused, never skipped.
test("a submodule or a nested checkout inside the page tree is refused", () => {
  const sub = mkdtempSync(join(tmpdir(), "docs-inner-sub-"))
  const g = (cwd: string, ...a: string[]) => Bun.spawnSync(["git", "-C", cwd, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "protocol.file.allow=always", ...a])
  writeFileSync(join(sub, "index.md"), page("Sub", "See {{ref fx:gone.go#Missing}}."))
  g(sub, "init", "-q")
  g(sub, "add", ".")
  g(sub, "commit", "-qm", "sub page")
  const before = git("rev-parse", "HEAD").stdout.toString().trim()
  g(dir, "submodule", "add", "-q", sub, "docs/vendor")
  g(dir, "commit", "-qm", "a submodule in the page tree")
  const committed = run("--check")
  git("reset", "-q", "--hard", before)
  rmSync(join(dir, "docs/vendor"), { recursive: true, force: true })
  rmSync(join(dir, ".git/modules"), { recursive: true, force: true })
  rmSync(join(dir, ".gitmodules"), { force: true })
  g(dir, "clone", "-q", sub, "docs/nested")
  const untracked = run("--check")
  rmSync(join(dir, "docs/nested"), { recursive: true, force: true })
  rmSync(sub, { recursive: true, force: true })
  expect(committed.code).toBe(1)
  expect(committed.out).toContain("docs/vendor is a submodule")
  expect(untracked.code).toBe(1)
  expect(untracked.out).toContain("has uncommitted changes")
})

// In a partial clone a missing object is fetched from the remote on demand. The check reads objects
// only from the local store: a missing one fails the run, and nothing is fetched.
test("a blob missing from a partial clone fails the check and is never fetched", () => {
  git("config", "uploadpack.allowFilter", "true")
  const clone = mkdtempSync(join(tmpdir(), "docs-partial-"))
  // Only docs/ is checked out (non-cone, so not even top-level files): lib.go, the cited file, is
  // never fetched.
  Bun.spawnSync(["git", "-c", "protocol.file.allow=always", "clone", "-q", "--filter=blob:none", "--no-checkout", `file://${dir}`, clone])
  Bun.spawnSync(["git", "-C", clone, "sparse-checkout", "set", "--no-cone", "/docs/"])
  Bun.spawnSync(["git", "-C", clone, "checkout", "-q"])
  const oid = Bun.spawnSync(["git", "-C", clone, "rev-parse", "HEAD:lib.go"]).stdout.toString().trim()
  const offline = { ...process.env, GIT_NO_LAZY_FETCH: "1" }
  const missingBefore = Bun.spawnSync(["git", "-C", clone, "cat-file", "-e", oid], { env: offline }).exitCode !== 0
  const r = Bun.spawnSync(["bun", generate, "--docs", join(clone, "docs"), "--root", `fx=${clone}`, "--check"])
  const missingAfter = Bun.spawnSync(["git", "-C", clone, "cat-file", "-e", oid], { env: offline }).exitCode !== 0
  rmSync(clone, { recursive: true, force: true })
  expect(missingBefore).toBe(true)
  expect(r.exitCode).toBe(1)
  expect(missingAfter).toBe(true)
})

test("pages outside every checkout cannot be checked: there is no commit to read", () => {
  const loose = mkdtempSync(join(tmpdir(), "docs-loose2-"))
  writeFileSync(join(loose, "index.md"), page("Loose", "No citations."))
  const r = Bun.spawnSync(["bun", generate, "--docs", loose, "--root", `fx=${dir}`, "--check"])
  rmSync(loose, { recursive: true, force: true })
  expect(r.exitCode).toBe(1)
  expect(r.stderr.toString()).toContain("is in no checkout")
})

test("an unknown option is refused, and so is a run that names no mode or two", () => {
  for (const extra of ["--release", "--relase"]) {
    const r = run("--check", extra, join(dir, "unknown"))
    expect(r.code).toBe(1)
    expect(r.out).toContain(`unknown option ${extra}`)
  }
  expect(existsSync(join(dir, "unknown"))).toBe(false)
  for (const r of [run(), run("--check", "--diff"), run("--diff", "--bundle"), run("--bundle", "--render", "index.md")]) {
    expect(r.code).toBe(1)
    expect(r.out).toContain("give exactly one of --check, --diff, --list, --render <path> or --bundle")
  }
})

test("VERSION must be a plain version string", () => {
  const before = readFileSync(join(dir, "VERSION"), "utf8")
  writeFileSync(join(dir, "VERSION"), "![x](https://attacker.example/pixel)\n")
  commit("hostile VERSION", "VERSION")
  const r = run("--check")
  writeFileSync(join(dir, "VERSION"), before)
  commit("restore VERSION", "VERSION")
  expect(r.code).toBe(1)
  expect(r.out).toContain("fx: VERSION must be a plain version")
})

test("--check refuses a symlink in the page tree", () => {
  symlinkSync("kept.svg", join(dir, "docs/assets/check-alias.svg"))
  const r = committed(() => run("--check"))
  rmSync(join(dir, "docs/assets/check-alias.svg"), { force: true })
  expect(r.code).toBe(1)
  expect(r.out).toContain("docs/assets/check-alias.svg is a symlink")
})

test("a page symlink is refused before anything is read, by --diff too", () => {
  const outside = mkdtempSync(join(tmpdir(), "docs-outside-page-"))
  const external = join(outside, "ext.md")
  const original = page("Ext", "<!-- BEGIN GENERATED: managed-commands -->\nold\n<!-- END GENERATED: managed-commands -->")
  writeFileSync(external, original)
  symlinkSync(external, join(dir, "docs/admin/ext.md"))
  const r = run("--diff")
  const c = committed(() => run("--diff"))
  rmSync(join(dir, "docs/admin/ext.md"), { force: true })
  const after = readFileSync(external, "utf8")
  rmSync(outside, { recursive: true, force: true })
  expect(r.code).toBe(1)
  expect(r.out).toContain("has uncommitted changes")
  expect(c.code).toBe(1)
  expect(c.out).toContain("docs/admin/ext.md is a symlink")
  expect(after).toBe(original)
})

test("a ref marker in front matter is refused", () => {
  writeFileSync(join(dir, "docs/admin/fm.md"), "---\ntitle: Fm\ndescription: Uses {{ref fx:lib.go#Load}} here.\nsidebarLabel: Fm\nsidebarPosition: 1\n---\n\n# Fm\n\nBody.\n")
  const r = committed(() => run("--check"))
  expect(r.code).toBe(1)
  expect(r.out).toContain("a ref marker in front matter")
})

test("a page name is a path, never pathspec magic", () => {
  const top = mkdtempSync(join(tmpdir(), "docs-magic-"))
  const g = (...a: string[]) => Bun.spawnSync(["git", "-C", top, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...a])
  writeFileSync(join(top, "index.md"), page("Top", "A page."))
  writeFileSync(join(top, ":(exclude)*.md"), page("Magic", "A page with a hostile name."))
  g("init", "-q")
  g("add", "--", "index.md", ":(literal):(exclude)*.md")
  g("commit", "-qm", "pages")
  writeFileSync(join(top, "index.md"), page("Top", "Changed."))
  const r = Bun.spawnSync(["bun", generate, "--docs", top, "--root", `fx=${top}`, "--check"])
  rmSync(top, { recursive: true, force: true })
  expect(r.exitCode).toBe(1)
  expect(r.stderr.toString()).toContain("has uncommitted changes")
})

test("an .svg figure outside assets/ is refused, since only assets/ is published with the pages", () => {
  writeFileSync(join(dir, "docs/admin/diagram.svg"), "<svg/>")
  writeFileSync(join(dir, "docs/admin/fig.md"), page("Fig", "![d](diagram.svg)"))
  const r = committed(() => run("--check"))
  expect(r.code).toBe(1)
  expect(r.out).toContain("link diagram.svg does not resolve to a page or an asset (docs/assets/) in the commit")
})

test("a file swapped for a symlink mid-run is never published", () => {
  const bin = mkdtempSync(join(tmpdir(), "docs-swap-bin-"))
  const secret = join(dir, "swap-secret.txt") // inside the checkout, as an ignored .env would be
  writeFileSync(secret, "TOKEN-DO-NOT-PUBLISH")
  mkdirSync(join(dir, "docs/assets"), { recursive: true })
  const asset = join(dir, "docs/assets/swap.svg")
  writeFileSync(asset, "<svg/>")
  commit("an asset", "docs/assets/swap.svg")
  const realGo = Bun.which("go")!
  writeFileSync(join(bin, "go"), `#!/bin/sh\nrm -f '${asset}'\nln -s '${secret}' '${asset}'\nexec '${realGo}' "$@"\n`, { mode: 0o755 })
  const r = Bun.spawnSync(["bun", generate, "--docs", join(dir, "docs"), "--root", `fx=${dir}`, "--render", "assets/swap.svg"], {
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
  })
  const published = r.stdout.toString()
  rmSync(asset, { force: true })
  rmSync(secret, { force: true })
  commit("drop the asset", "docs/assets/swap.svg")
  rmSync(bin, { recursive: true, force: true })
  expect(r.exitCode).toBe(0)
  expect(r.stdout.toString() + r.stderr.toString()).not.toContain("TOKEN-DO-NOT-PUBLISH")
  expect(published).toBe("<svg/>")
})

// A "git" first on PATH swaps a page for a symlink to a secret on the first git call: pages come from
// the commit, so the secret is never read, and the changed tree is refused.
test("a page swapped for a symlink mid-run is never read", () => {
  const bin = mkdtempSync(join(tmpdir(), "docs-gitswap-"))
  const secret = join(bin, "secret.md")
  writeFileSync(secret, "TOKEN-DO-NOT-READ")
  const index = join(dir, "docs/index.md")
  const before = readFileSync(index, "utf8")
  writeFileSync(join(bin, "git"), `#!/bin/sh\nif [ ! -e '${bin}/done' ]; then touch '${bin}/done'; rm -f '${index}'; ln -s '${secret}' '${index}'; fi\nexec '${Bun.which("git")}' "$@"\n`, { mode: 0o755 })
  const r = Bun.spawnSync(["bun", generate, "--docs", join(dir, "docs"), "--root", `fx=${dir}`, "--check"], { env: { ...process.env, PATH: `${bin}:${process.env.PATH}` } })
  rmSync(index, { force: true })
  writeFileSync(index, before)
  rmSync(bin, { recursive: true, force: true })
  const out = r.stdout.toString() + r.stderr.toString()
  expect(r.exitCode).toBe(1)
  expect(out).toContain("has uncommitted changes")
  expect(out).not.toContain("TOKEN-DO-NOT-READ")
})

// A stale section fails the check, which names the command that fixes it. That command's generator
// half only prints a patch; git applies it, and the regenerated page then passes.
test("a stale section fails the check with the command that regenerates it through git apply", () => {
  const gen = join(dir, "docs/admin/gen.md")
  writeFileSync(gen, page("Gen", "<!-- BEGIN GENERATED: managed-commands -->\nold\n<!-- END GENERATED: managed-commands -->"))
  commit("a stale page", "docs/admin/gen.md")
  const before = status()
  const checked = run("--check")
  const printed = run("--diff")
  const unchanged = status() === before
  const fix = /regenerate with: (.*)/.exec(checked.out)?.[1] ?? ""
  const applied = Bun.spawnSync(["sh", "-c", fix], { cwd: tmpdir() })
  const regenerated = readFileSync(gen, "utf8")
  commit("regenerated", "docs/admin/gen.md")
  const after = run("--check")
  rmSync(gen)
  commit("drop the page", "docs/admin/gen.md")
  expect(checked.code).toBe(1)
  expect(checked.out).toContain("docs/admin/gen.md: generated section is stale")
  expect(fix).toContain(" --diff ")
  expect(fix).toContain(`| git -C ${realpathSync(dir)} apply`)
  expect(printed.code).toBe(0)
  expect(printed.stdout).toStartWith("diff --git a/docs/admin/gen.md b/docs/admin/gen.md\n")
  expect(unchanged).toBe(true)
  expect(applied.exitCode).toBe(0)
  expect(regenerated).toContain("- `badger ")
  expect(regenerated).not.toContain("\nold\n")
  expect(after.code).toBe(0)
})

test("--diff prints no patch while another problem needs fixing by hand", () => {
  writeFileSync(join(dir, "docs/admin/gen.md"), page("Gen", "See lib.go:4.\n\n<!-- BEGIN GENERATED: managed-commands -->\nold\n<!-- END GENERATED: managed-commands -->"))
  const r = committed(() => run("--diff"))
  expect(r.code).toBe(1)
  expect(r.stdout).toBe("")
  expect(r.out).toContain("hand-typed citation lib.go:4")
  expect(r.out).not.toContain("regenerate with")
})
