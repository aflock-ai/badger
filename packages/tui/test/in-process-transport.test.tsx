import { expect, test } from "bun:test"
import { createAppFixture } from "./fixture/app"

// The managed build runs the server in-process: the TUI reaches it through a fetch function, and
// nothing listens. The base URL is unroutable, so any request that bypassed the fetch would fail.
test("the TUI runs against a server reached only through a fetch function", async () => {
  const paths: string[] = []
  await using setup = await createAppFixture({
    transport: "fetch",
    fetch: (url) => {
      paths.push(url.pathname)
      return undefined
    },
  })
  await setup.ready
  await setup.waitForFrame((frame) => frame.includes("commands"))
  expect(paths).toContain("/api/event")
  expect(paths.length).toBeGreaterThan(1)
})
