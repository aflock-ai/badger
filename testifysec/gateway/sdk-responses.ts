// jade:ring local
// The 2.0 provider client (@opencode/ai's OpenAI Responses route) talking to the native gateway over the
// managed build's own gateway fetch. No live model or OAuth flow.
import assert from "node:assert/strict"
import { Effect, Layer, Stream } from "effect"
import { FetchHttpClient, HttpClient } from "effect/http"
import { AIClient, LLM, Message, ToolCallPart, ToolDefinition, ToolResultPart } from "@opencode/ai"
import { OpenAI } from "@opencode/ai/providers"
import { RequestExecutor } from "@opencode/ai/route/executor"
import { ManagedProfile } from "../../packages/server/src/managed"

const socket = process.argv[2]
assert.ok(socket?.startsWith("/"))
const modelID = process.argv[3] ?? "gpt-5.4"
assert.ok(modelID === "gpt-5.4" || modelID === "gpt-6-astra")
const effort = modelID === "gpt-6-astra" ? "max" : "low"

// The managed build's transport, recording each request body the client sends.
const requests: Record<string, unknown>[] = []
const gateway = ManagedProfile.gatewayFetch(socket)
const recording = Object.assign(
  async (input: string | URL | Request, init?: RequestInit) => {
    const request = new Request(input, init)
    assert.equal(request.url, `http://${ManagedProfile.gatewayHost}/v1/responses`)
    requests.push(JSON.parse(await request.clone().text()))
    return gateway(request)
  },
  { preconnect: () => {} },
)
// As in ManagedProfile.gatewayHttpClient: the fetch is fixed on every request, since the client reads it per request.
const http = Layer.effect(
  HttpClient.HttpClient,
  Effect.map(HttpClient.HttpClient, (client) =>
    HttpClient.transform(client, (effect) => Effect.provideService(effect, FetchHttpClient.Fetch, recording)),
  ),
).pipe(Layer.provide(FetchHttpClient.layer))
const transport = RequestExecutor.layer.pipe(Layer.provide(http))

const model = OpenAI.configure({
  apiKey: "synthetic-sdk-credential-must-not-reach-provider",
  baseURL: `http://${ManagedProfile.gatewayHost}/v1`,
}).responses(modelID)
const providerOptions = { store: false, reasoningEffort: effort, include: ["reasoning.encrypted_content"] } as const
const read = ToolDefinition.make({
  name: "read",
  description: "Read a file.",
  inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false },
})

const program = Effect.gen(function* () {
  const generated = yield* LLM.generate({ model, prompt: "synthetic SDK input", providerOptions })
  assert.equal(generated.text, "fixture response")

  const events = yield* LLM.stream({ model, prompt: "synthetic SDK input", providerOptions }).pipe(Stream.runCollect)
  const list = [...events]
  assert.ok(list.some((event) => event.type === "text-delta" && event.text === "fixture response"))
  assert.ok(list.some((event) => event.type === "finish" && event.reason.normalized === "stop"))

  // A replayed history: encrypted reasoning, a tool call and its result, all stateless (store: false).
  const history = yield* LLM.generate({
    model,
    messages: [
      Message.user("synthetic SDK input"),
      Message.assistant([
        { type: "reasoning", text: "", providerMetadata: { openai: { itemId: "rs_fixture", reasoningEncryptedContent: "synthetic-opaque" } } },
        ToolCallPart.make({ id: "call_fixture", name: "read", input: { path: "sample.txt" } }),
      ]),
      Message.tool(ToolResultPart.make({ id: "call_fixture", name: "read", result: "synthetic file bytes", resultType: "text" })),
    ],
    tools: [read],
    providerOptions,
  })
  assert.ok(history.text.length > 0)
  return list.map((event) => event.type)
})

const eventTypes = await Effect.runPromise(program.pipe(Effect.provide(AIClient.layerWith(transport))))
assert.equal(requests.length, 3)
assert.equal(requests[0]!.store, false)
assert.deepEqual(requests[0]!.include, ["reasoning.encrypted_content"])
assert.equal(requests[1]!.stream, true)
const input = requests[2]!.input as { type?: string; encrypted_content?: string }[]
assert.ok(input.some((item) => item.type === "function_call") && input.some((item) => item.type === "function_call_output"))
assert.ok(input.some((item) => item.type === "reasoning" && item.encrypted_content === "synthetic-opaque"))
assert.ok(!input.some((item) => item.type === "item_reference"))
for (const body of requests as { model: string; reasoning: { effort: string }; temperature?: unknown; top_p?: unknown }[]) {
  assert.equal(body.model, modelID)
  assert.equal(body.reasoning.effort, effort)
  assert.equal(body.temperature, undefined)
  assert.equal(body.top_p, undefined)
}
console.log(JSON.stringify({ passed: true, modelID, effort, requests, eventTypes, liveProvider: false }))
