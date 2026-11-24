// jade:ring local
import { expect, test } from "bun:test"
import { spawnSync } from "node:child_process"
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { pathToFileURL } from "node:url"

// build.py stages these files, and only these, beside managed/ for the admission bundle.
// Importing marking.ts from a tree that holds nothing else proves the staged set is complete.
test("build.py stages every file marking.ts imports", async () => {
  const run = spawnSync("python3", [join(import.meta.dir, "build.py"), "--list-shared"], { encoding: "utf8" })
  expect(run.stderr).toBe("")
  expect(run.status).toBe(0)
  const stage = mkdtempSync(join(tmpdir(), "admission-stage-"))
  try {
    for (const name of run.stdout.trim().split("\n")) {
      mkdirSync(dirname(join(stage, name)), { recursive: true })
      copyFileSync(join(import.meta.dir, "..", name), join(stage, name))
    }
    const marking = await import(pathToFileURL(join(stage, "marking/marking.ts")).href)
    expect(typeof marking.preset).toBe("function")
  } finally {
    rmSync(stage, { recursive: true, force: true })
  }
})
