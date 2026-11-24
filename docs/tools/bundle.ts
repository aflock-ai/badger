// bundle.ts <file>: put the docs bundle (generate.ts --bundle) at <file>, for the build.
//
// The process changes into <file>'s directory first and works only relative to it from then on, so
// every step happens in that one directory even if it, or any directory above it, is renamed or
// replaced meanwhile. The directory must be the user's own (owned by them and not writable by its
// group or others), and still at the path given when entered. The bundle is written into a new
// private directory there (0700) and renamed over <file> once complete: rename(2) replaces a symlink
// at <file>, to a file or a directory, instead of following it, and a failed run leaves nothing.
import { closeSync, mkdtempSync, openSync, realpathSync, renameSync, rmSync, statSync } from "node:fs"
import { basename, dirname, join, resolve } from "node:path"

const die = (message: string): never => {
  console.error(message)
  process.exit(1)
}
if (process.argv.length !== 3) die("usage: bun docs/tools/bundle.ts <file>")
const out = resolve(process.argv[2])
const name = basename(out)
const generate = join(import.meta.dir, "generate.ts")
const want = realpathSync(dirname(out))
process.chdir(want)
const here = statSync(".")
// The directory entered, by its own identity: owned by this user, writable by no one else, and
// where the path pointed (process.cwd() names the directory actually entered, wherever it now is).
if (here.uid !== process.getuid!() || (here.mode & 0o022) !== 0) die(`${want} must be a directory of your own, not writable by its group or others; the bundle is not written`)
if (process.cwd() !== want) die(`${want} changed while it was entered; the bundle is not written`)
const stage = mkdtempSync(`.${name}.`)
let ok = false
try {
  const fd = openSync(join(stage, name), "wx", 0o644)
  const gen = Bun.spawnSync(["bun", generate, "--bundle"], { cwd: "/", stdout: fd, stderr: "inherit" })
  closeSync(fd)
  if (gen.exitCode === 0) {
    renameSync(join(stage, name), name)
    ok = true
  }
} finally {
  rmSync(stage, { recursive: true, force: true })
}
if (!ok) process.exit(1)
