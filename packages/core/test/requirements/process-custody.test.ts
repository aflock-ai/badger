import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import { Bearer } from "@opencode/core/requirements/bearer"
import { MemoryCustody } from "@opencode/util/memory-custody"

test("holding a bearer restricts this process's memory diagnostics", () => {
  new Bearer("synthetic", Date.now() + 60_000)
  expect(MemoryCustody.restricted()).toBe(true)
})

// The bearer's custody assumes a tool's child process cannot read its parent's memory. On Linux
// that holds when Yama ptrace_scope >= 1 (a child is never its parent's ancestor). This checks
// the expectation where it can be checked: Linux with Yama. Elsewhere it is skipped, and the
// skip is the honest result: macOS relies on hardened runtime, which a test process does not have.
const scope = await fs.readFile("/proc/sys/kernel/yama/ptrace_scope", "utf8").then(
  (text) => Number(text.trim()),
  () => undefined,
)
test.skipIf(process.platform !== "linux" || scope === undefined || scope < 1)(
  "a child process cannot read its parent's memory (Linux, Yama ptrace_scope >= 1)",
  async () => {
    const marker = `custody-marker-${crypto.randomUUID()}`
    const held = Buffer.from(marker) // keep the marker resident in this process
    const child = Bun.spawn(
      [
        process.execPath,
        "-e",
        `const fs = require("node:fs");
         try { const fd = fs.openSync("/proc/" + process.ppid + "/mem", "r"); fs.closeSync(fd); console.log("opened") }
         catch (e) { console.log(e.code) }`,
      ],
      { stdout: "pipe", stderr: "pipe" },
    )
    const out = (await new Response(child.stdout).text()).trim()
    await child.exited
    expect(held.toString()).toBe(marker)
    expect(["EACCES", "EPERM"]).toContain(out)
  },
)
