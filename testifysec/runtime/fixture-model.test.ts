import { afterAll, expect, test } from "bun:test"
import { rmSync } from "node:fs"
import { serveFixture } from "./fixture-model"

const server = serveFixture()
afterAll(() => {
  server.stop(true)
  rmSync("/tmp/hardened-fixture-model.sock", { force: true })
})

function write(properties: Record<string, unknown>) {
  return { type: "function", function: { name: "write", parameters: { type: "object", properties } } }
}

async function firstCall(tools: unknown[]) {
  const response = await fetch("http://fixture/v1/chat/completions", {
    unix: "/tmp/hardened-fixture-model.sock",
    method: "POST",
    body: JSON.stringify({ model: "approved", messages: [{ role: "user", content: "go" }], tools }),
  })
  const data = (await response.text()).split("\n").find((line) => line.includes("tool_calls"))!
  return JSON.parse(JSON.parse(data.slice("data: ".length)).choices[0].delta.tool_calls[0].function.arguments)
}

// OpenCode 2.0's write tool names its target `path`; 1.x named it `filePath`. The fixture follows
// whichever the advertised tool declares, so it exercises the real tool loop on either base.
test("the first write names its file the way the advertised write tool does", async () => {
  expect(await firstCall([write({ path: { type: "string" }, content: { type: "string" } })])).toEqual({
    path: "/workspace/result.txt",
    content: "hardened-worker-verified\n",
  })
  expect(await firstCall([write({ filePath: { type: "string" }, content: { type: "string" } })])).toEqual({
    filePath: "/workspace/result.txt",
    content: "hardened-worker-verified\n",
  })
})
