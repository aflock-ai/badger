// jade:ring local
// A compile-time-only UAT provider. It exercises the actual upstream tool loop;
// it is not a real model and is not enabled in customer builds.
export function serveFixture() {
  let calls = 0
  return Bun.serve({
    unix: "/tmp/hardened-fixture-model.sock",
    async fetch(request) {
      if (request.method !== "POST" || new URL(request.url).pathname !== "/v1/chat/completions")
        return new Response("unavailable", { status: 404 })
      const body = await request.json() as { model?: string; messages?: { role: string; content: unknown }[]; tools?: { function: { name: string; parameters?: { properties?: Record<string, unknown> } } }[] }
      if (body.model !== "approved" || !Array.isArray(body.messages)) return new Response("invalid", { status: 400 })
      calls++
      const names = body.tools?.map((tool) => tool.function.name) ?? []
      if (names.some((name) => ["task", "webfetch", "websearch", "lsp", "skill", "question"].includes(name)))
        return new Response("unapproved tool advertised", { status: 400 })
      const toolResults = body.messages.filter((message) => message.role === "tool")
      // Title/summary calls have no tools; answer without changing the coding flow.
      // OpenCode 2.0's write tool names its target `path`, 1.x's `filePath`: follow the advertised one.
      const writeTool = body.tools?.find((tool) => tool.function.name === "write")
      const target = writeTool?.function.parameters?.properties?.path ? "path" : "filePath"
      const operation = names.includes("write") && toolResults.length === 0
        ? { name: "write", arguments: JSON.stringify({ [target]: "/workspace/result.txt", content: "hardened-worker-verified\n" }) }
        : (names.includes("bash") || names.includes("shell")) && toolResults.length === 1
          ? { name: names.includes("bash") ? "bash" : "shell", arguments: JSON.stringify({ command: "test \"$(cat result.txt)\" = hardened-worker-verified && printf 'HARNESS_TEST_PASSED\\n'", description: "Check the generated file", timeout: 10000 }) }
          : undefined
      const chunk = (delta: unknown, finish_reason: string | null = null) => ({
        id: "fixture-" + calls, object: "chat.completion.chunk", created: 1, model: "approved",
        choices: [{ index: 0, delta, finish_reason }],
      })
      const events = operation
        ? [chunk({ role: "assistant", tool_calls: [{ index: 0, id: "call-" + calls, type: "function", function: operation }] }), chunk({}, "tool_calls")]
        : [chunk({ role: "assistant", content: names.length ? "The file was written and its test completed." : "Managed verification" }), chunk({}, "stop")]
      return new Response(events.map((event) => "data: " + JSON.stringify(event) + "\n\n").join("") + "data: [DONE]\n\n", {
        headers: { "content-type": "text/event-stream" },
      })
    },
  })
}
