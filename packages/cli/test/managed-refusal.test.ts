import { expect, test } from "bun:test"
import path from "node:path"

const entry = path.resolve(import.meta.dir, "../src/index.ts")

async function managed(...args: string[]) {
  const child = Bun.spawn(
    [process.execPath, "--define", "HARDENED_BUILD:true", "--define", "TESTIFYSEC_MANAGED_WORKER:true", entry, ...args],
    { stdout: "pipe", stderr: "pipe" },
  )
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ])
  return { stdout, stderr, code }
}

// A refusal is an answer, not a crash: one line on stderr, a nonzero exit, and no stack trace that
// would show internal build paths.
test("a managed build refuses a command with one clean line", async () => {
  for (const command of [["upgrade"], ["plugin", "add", "example"], ["auth", "login"]]) {
    const result = await managed(...command)
    expect(result.code).toBe(1)
    expect(result.stdout).toBe("")
    expect(result.stderr).toBe("This command is not available in this build\n")
  }
}, 120_000)

test("a managed build refuses the auto-approve flags with one clean line", async () => {
  const result = await managed("run", "--auto", "hello")
  expect(result.code).toBe(1)
  expect(result.stdout).toBe("")
  expect(result.stderr).toBe("--auto, --yolo and --dangerously-skip-permissions are not available in this build\n")
}, 120_000)

// Without its gateway a managed build says where the gateway should be, in one line, not a crash.
test("a managed build without its gateway says so in one line", async () => {
  const result = await managed("run", "hello")
  expect(result.code).toBe(1)
  expect(result.stdout).toBe("")
  expect(result.stderr).toBe(
    "The model gateway is not available at /run/hardened-gateway/gateway.sock (ENOENT). Ask your administrator to start it.\n",
  )
}, 120_000)
