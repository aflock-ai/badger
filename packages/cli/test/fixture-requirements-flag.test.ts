import { expect, test } from "bun:test"
import path from "node:path"

// The release check refuses any https://localhost origin, but the flag must also refuse an origin
// that is not exactly https://localhost:<port>, before anything is built.
test("--fixture-requirements refuses anything but https://localhost with an explicit port", async () => {
  for (const origin of [
    "https://localhost",
    "https://localhost:443",
    "http://localhost:4443",
    "https://127.0.0.1:4443",
    "https://localhost:4443/x",
  ]) {
    const child = Bun.spawn(
      [
        process.execPath,
        "run",
        "script/build.ts",
        "--single",
        "--skip-install",
        "--skip-web-ui",
        "--managed",
        `--fixture-requirements=${origin}`,
        "--outdir=/nonexistent",
      ],
      { cwd: path.join(import.meta.dir, ".."), stdout: "ignore", stderr: "pipe" },
    )
    const [stderr, code] = await Promise.all([new Response(child.stderr).text(), child.exited])
    expect({ origin, code, refused: stderr.includes("--fixture-requirements takes https://localhost:<port>") }).toEqual(
      { origin, code: 1, refused: true },
    )
  }
}, 120_000)
