// The docs MCP server (testifysec/docsmcp) built with this tree's real bundle: every topic is listed
// and readable, search finds configuration keys, and the version is this commit's.
import { afterAll, expect, test } from "bun:test"
import { chmodSync, cpSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { offlineGoEnv } from "./lib"

const repo = resolve(import.meta.dir, "../..")
const dir = mkdtempSync(join(tmpdir(), "docs-mcp-"))
afterAll(() => rmSync(dir, { recursive: true, force: true }))
const env = offlineGoEnv(process.env, join(dir, "scratch"))

// The module is built from a copy, so the test writes nothing into the checkout. A copy has no VCS
// stamp, so the build check is skipped here; testifysec/docsmcp's own tests cover it.
const gen = Bun.spawnSync(["bun", join(import.meta.dir, "generate.ts"), "--bundle"])
writeFileSync(join(dir, "docs.json"), gen.stdout)
const bundle = JSON.parse(gen.stdout.toString())
cpSync(join(repo, "testifysec/docsmcp"), join(dir, "mod"), { recursive: true, filter: (p) => !p.endsWith("docs.json") })
mkdirSync(join(dir, "mod/bundle"), { recursive: true })
cpSync(join(dir, "docs.json"), join(dir, "mod/bundle/docs.json"))
const build = Bun.spawnSync(["go", "build", "-buildvcs=false", "-o", join(dir, "badger-docs"), "."], { cwd: join(dir, "mod"), env })
const head = Bun.spawnSync(["git", "-C", repo, "rev-parse", "HEAD"]).stdout.toString().trim()
const version = readFileSync(join(repo, "VERSION"), "utf8").trim()

function session(requests: object[], ...args: string[]) {
  return sessionIn(undefined, requests, ...args)
}
function sessionIn(cwd: string | undefined, requests: object[], ...args: string[]) {
  const input = requests.map((r, i) => JSON.stringify({ jsonrpc: "2.0", id: i + 1, ...r })).join("\n") + "\n"
  const run = Bun.spawnSync([join(dir, "badger-docs"), "mcp", ...args], { stdin: Buffer.from(input), env: { PATH: process.env.PATH }, cwd })
  expect(run.stderr.toString()).toBe("")
  return run.stdout.toString().trim().split("\n").map((l) => JSON.parse(l))
}
const call = (name: string, args: object) => ({ method: "tools/call", params: { name, arguments: args } })
const text = (reply: any) => {
  expect(reply.result.isError).toBe(false)
  return reply.result.content[0].text as string
}

test("the bundle and the binary build", () => {
  expect(gen.exitCode).toBe(0)
  expect(build.stderr.toString()).toBe("")
  expect(build.exitCode).toBe(0)
})

test("every topic is listed and readable", () => {
  const ids: string[] = bundle.topics.map((t: { id: string }) => t.id)
  expect(ids.length).toBeGreaterThan(10)
  const [list, ...reads] = session([call("list_topics", {}), ...ids.map((id) => call("read", { topic: id }))])
  for (const id of ids) expect(text(list)).toContain(`- ${id} (`)
  reads.forEach((r, i) => expect(text(r)).toContain(`# ${bundle.topics[i].title}`))
})

test("search finds configuration keys, and every component has its reference", () => {
  const components: string[] = bundle.config.map((c: { component: string }) => c.component)
  expect(components).toEqual(["gateway", "platform", "badger-broker", "conngw"])
  const [search, issuers, ...refs] = session([
    call("search", { query: "maxStreamsPerWorkspace" }),
    call("search", { query: "issuers audience" }),
    ...components.map((c) => call("get_config_reference", { component: c })),
  ])
  expect(text(search)).toContain("- config conngw maxStreamsPerWorkspace (int, default 8)")
  expect(text(issuers)).toContain("- config badger-broker issuers[].audience")
  refs.forEach((r, i) => expect(text(r)).toContain(`${bundle.config[i].fields[0].file}:${bundle.config[i].fields[0].line}`))
})

test("the version is this tree's, from the CLI and from the server", () => {
  const cli = Bun.spawnSync([join(dir, "badger-docs"), "version"]).stdout.toString()
  expect(cli).toContain(`badger-docs: badger ${version} at ${head}`)
  const [v] = session([call("version", {})])
  const got = JSON.parse(text(v))
  expect([got.badger.version, got.badger.commit]).toEqual([version, head])
})

test("an overlay adds its topics under its own name", () => {
  const [list, read] = session([call("list_topics", { section: "overlay/overlay" }), call("read", { topic: "overlay/overlay/index" })], "--overlay", join(repo, "testifysec/docsmcp/testdata/overlay"))
  expect(text(list)).toContain("- overlay/overlay/index (Site guide)")
  expect(text(read)).toContain("built against badger 4.2.0")
})

test("an overlay named . or .. takes the directory's real name", () => {
  const site = join(dir, "site")
  mkdirSync(join(site, "sub"), { recursive: true })
  cpSync(join(repo, "testifysec/docsmcp/testdata/overlay/bundle.json"), join(site, "bundle.json"))
  for (const [cwd, arg] of [[site, "."], [join(site, "sub"), ".."]]) {
    const [list] = sessionIn(cwd, [call("list_topics", { section: "overlay/site" })], "--overlay", arg)
    expect(text(list)).toContain("- overlay/site/index (Site guide)")
  }
})

// bundle.ts, which the build uses, writes the bundle in a private directory and renames it over the
// target: a symlink planted there, to a file or to a directory, is replaced and never followed, and
// a directory others can write is refused before anything is made.
test("bundle.ts replaces a planted symlink, never writes through it, and refuses a shared directory", () => {
  const out = mkdtempSync(join(tmpdir(), "docs-bundlets-"))
  const victim = join(out, "victim.txt")
  const elsewhere = join(out, "elsewhere")
  writeFileSync(victim, "keep")
  mkdirSync(elsewhere)
  const place = (target: string) => Bun.spawnSync(["bun", join(import.meta.dir, "bundle.ts"), target])
  symlinkSync(victim, join(out, "a.json"))
  symlinkSync(elsewhere, join(out, "b.json"))
  const a = place(join(out, "a.json"))
  const b = place(join(out, "b.json"))
  const results = {
    codes: [a.exitCode, b.exitCode],
    links: [lstatSync(join(out, "a.json")).isSymbolicLink(), lstatSync(join(out, "b.json")).isSymbolicLink()],
    schema: JSON.parse(readFileSync(join(out, "b.json"), "utf8")).schema,
    victim: readFileSync(victim, "utf8"),
    elsewhere: readdirSync(elsewhere),
    left: readdirSync(out).sort(),
  }
  chmodSync(out, 0o777)
  const shared = place(join(out, "c.json"))
  chmodSync(out, 0o700)
  const sharedLeft = readdirSync(out).sort()
  rmSync(out, { recursive: true, force: true })
  expect(results).toEqual({ codes: [0, 0], links: [false, false], schema: 1, victim: "keep", elsewhere: [], left: ["a.json", "b.json", "elsewhere", "victim.txt"] })
  expect(shared.exitCode).toBe(1)
  expect(shared.stderr.toString()).toContain("must be a directory of your own")
  expect(sharedLeft).toEqual(results.left)
}, 180_000)

// The target directory renamed away while the bundle is generated, and another put at its path:
// bundle.ts works in the directory it entered, so the bundle lands there and the newcomer is
// never touched.
test("bundle.ts keeps to the directory it entered when that directory is moved mid-run", async () => {
  const top = mkdtempSync(join(tmpdir(), "docs-bundlemv-"))
  const target = join(top, "out")
  mkdirSync(target, { mode: 0o700 })
  const run = Bun.spawn(["bun", join(import.meta.dir, "bundle.ts"), join(target, "docs.json")], { stderr: "pipe" })
  // Wait for its staging directory: the generator is running from then on.
  for (let i = 0; i < 600 && !readdirSync(target).some((e) => e.startsWith(".docs.json.")); i++) await Bun.sleep(50)
  renameSync(target, join(top, "moved"))
  mkdirSync(target, { mode: 0o700 })
  writeFileSync(join(target, "keep.txt"), "mine")
  const code = await run.exited
  const moved = readdirSync(join(top, "moved")).sort()
  const newcomer = readdirSync(target).sort()
  rmSync(top, { recursive: true, force: true })
  expect(code).toBe(0)
  expect(moved).toEqual(["docs.json"])
  expect(newcomer).toEqual(["keep.txt"])
}, 180_000)
